"""Batch scheduler data model, retained state, and ordering algorithms.

The scheduler is intentionally transport-agnostic.  This module keeps the
value objects, retained scratch/state pools, WFQ helpers, class selection, lag
feedback, and batch ordering algorithms.  The small stateful facade lives in
``batch_scheduler``.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Optional

from .flow import (
    MAX_UINT64,
    saturating_add,
    saturating_mul,
    saturating_mul_div_ceil,
    saturating_mul_div_floor,
)
from .queue import DEFAULT_URGENCY_RANK, MAX_REQUEST_COST
from .write_plan import DEFAULT_WRITE_BURST_FRAMES, write_burst_limit
from ..config import default_settings
from ..protocol import MAX_VARINT62, SchedulerHint

WFQ_TAG_SCALE = 256
MAX_SIGNED_INT64 = (1 << 63) - 1
SYNTHETIC_STREAM_KEY_BIT = 1 << 63

MAX_EXPLICIT_GROUPS = 16
FALLBACK_GROUP_BUCKET = MAX_UINT64

INTERACTIVE_BURST_LIMIT = 8
BULK_RESERVE_WINDOW = 4
BULK_ENTRY_MULTIPLIER = 2
AGING_ROUND_THRESHOLD = 2
CLASS_SCORE_SCALE = 8

BATCH_SCRATCH_RETAIN_MIN_CAP = 256
BATCH_SCRATCH_RETAIN_FACTOR = 4
_DEFAULT_MAX_FRAME_PAYLOAD = default_settings().max_frame_payload


class TrafficClass(IntEnum):
    INTERACTIVE = 0
    BULK = 1


@dataclass(frozen=True)
class GroupKey:
    kind: int = 0
    value: int = 0

    def __post_init__(self) -> None:
        kind = _uint64(self.kind, "kind")
        if kind not in (0, 1, 2):
            raise ValueError("kind must be 0, 1, or 2")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "value", _uint64(self.value, "value"))

    @classmethod
    def stream(cls, stream_id: int) -> "GroupKey":
        return cls(0, _uint64(stream_id, "stream_id"))

    @classmethod
    def explicit(cls, group_id: int) -> "GroupKey":
        return cls(1, _uint64(group_id, "group_id"))

    @classmethod
    def transient(cls, index: int) -> "GroupKey":
        return cls(2, _uint64(index, "index"))

    def is_transient(self) -> bool:
        return self.kind == 2


@dataclass(frozen=True)
class RequestMeta:
    group_key: GroupKey = field(default_factory=GroupKey)
    stream_id: int = 0
    stream_scoped: bool = False
    is_priority_update: bool = False
    opening_frame: bool = False
    cost: int = 1
    urgency_rank: int = DEFAULT_URGENCY_RANK

    def __post_init__(self) -> None:
        if not isinstance(self.group_key, GroupKey):
            raise TypeError("group_key must be GroupKey")
        object.__setattr__(self, "stream_id", _uint64(self.stream_id, "stream_id"))
        object.__setattr__(
            self,
            "stream_scoped",
            _require_bool(self.stream_scoped, "stream_scoped"),
        )
        object.__setattr__(
            self,
            "is_priority_update",
            _require_bool(self.is_priority_update, "is_priority_update"),
        )
        object.__setattr__(
            self,
            "opening_frame",
            _require_bool(self.opening_frame, "opening_frame"),
        )
        object.__setattr__(self, "cost", normalize_cost(self.cost))
        object.__setattr__(self, "urgency_rank", _int64(self.urgency_rank, "urgency_rank"))


@dataclass(frozen=True)
class StreamMeta:
    priority: int = 0
    group: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "priority", _varint62(self.priority, "priority"))
        object.__setattr__(self, "group", _varint62(self.group, "group"))


@dataclass(frozen=True)
class BatchItem:
    request: RequestMeta = field(default_factory=RequestMeta)
    stream: StreamMeta = field(default_factory=StreamMeta)

    def __post_init__(self) -> None:
        if not isinstance(self.request, RequestMeta):
            raise TypeError("request must be RequestMeta")
        if not isinstance(self.stream, StreamMeta):
            raise TypeError("stream must be StreamMeta")


@dataclass(frozen=True)
class BatchConfig:
    urgent: bool = False
    group_fair: bool = False
    scheduler_hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED
    max_frame_payload: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "urgent", _require_bool(self.urgent, "urgent"))
        object.__setattr__(self, "group_fair", _require_bool(self.group_fair, "group_fair"))
        object.__setattr__(self, "scheduler_hint", coerce_scheduler_hint(self.scheduler_hint))
        max_payload = _uint64(self.max_frame_payload, "max_frame_payload")
        if max_payload == 0:
            max_payload = _DEFAULT_MAX_FRAME_PAYLOAD
        object.__setattr__(self, "max_frame_payload", max_payload)


@dataclass
class BatchScratch:
    """Reusable scheduler scratch for batch-local structures.

    The objects stored here are private to the scheduler.  Callers must not
    retain ``BatchBuildResult`` instances across scheduler calls.
    """

    group_order: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    group_state: Dict[GroupKey, Dict[int, list]] = field(default_factory=dict)
    group_queues: list = field(default_factory=list)
    group_queue_count: int = 0
    group_queue_entries: list = field(default_factory=list)
    group_queue_entry_count: int = 0
    stream_order: Dict[GroupKey, list] = field(default_factory=dict)
    stream_order_entries: list = field(default_factory=list)
    stream_order_entry_count: int = 0
    queued_bytes: Dict[int, int] = field(default_factory=dict)
    stream_meta: Dict[int, StreamMeta] = field(default_factory=dict)
    prepared_streams: Dict[int, object] = field(default_factory=dict)
    bypass_selections: Dict[int, int] = field(default_factory=dict)
    interactive_active_streams: list = field(default_factory=list)
    bulk_active_streams: list = field(default_factory=list)
    interactive_candidates: list = field(default_factory=list)
    bulk_candidates: list = field(default_factory=list)
    transient_stream_finish: Dict[int, int] = field(default_factory=dict)
    transient_stream_last_served: Dict[int, int] = field(default_factory=dict)
    transient_group_virtual: Dict[GroupKey, int] = field(default_factory=dict)
    transient_group_finish: Dict[GroupKey, int] = field(default_factory=dict)
    transient_group_last_served: Dict[GroupKey, int] = field(default_factory=dict)
    tie_pref_streams: Dict[GroupKey, int] = field(default_factory=dict)
    ordered: list = field(default_factory=list)
    selected: list = field(default_factory=list)
    recorded_group_head: list = field(default_factory=list)
    last_build_cap_hint: int = 0

    def _drop_build_refs(self) -> None:
        self.group_order = []
        self.groups = []
        self.group_state = {}
        self.group_queues = []
        self.group_queue_count = 0
        self.group_queue_entries = []
        self.group_queue_entry_count = 0
        self.stream_order = {}
        self.stream_order_entries = []
        self.stream_order_entry_count = 0
        self.queued_bytes = {}
        self.stream_meta = {}
        self.prepared_streams = {}
        self.bypass_selections = {}
        self.interactive_active_streams = []
        self.bulk_active_streams = []
        self.interactive_candidates = []
        self.bulk_candidates = []
        self.transient_stream_finish = {}
        self.transient_stream_last_served = {}
        self.transient_group_virtual = {}
        self.transient_group_finish = {}
        self.transient_group_last_served = {}
        self.tie_pref_streams = {}

    def clear(self) -> None:
        self._drop_build_refs()
        self.ordered = []
        self.selected = []
        self.recorded_group_head = []
        self.last_build_cap_hint = 0

    def clear_refs(self) -> None:
        self.group_order.clear()
        self.groups.clear()
        self.group_state.clear()
        for queues in self.group_queues:
            queues.clear()
        self.group_queue_count = 0
        self.group_queue_entries.clear()
        self.group_queue_entry_count = 0
        self.stream_order.clear()
        self.stream_order_entries.clear()
        self.stream_order_entry_count = 0
        self.queued_bytes.clear()
        self.stream_meta.clear()
        self.prepared_streams.clear()
        self.bypass_selections.clear()
        self.interactive_active_streams.clear()
        self.bulk_active_streams.clear()
        self.interactive_candidates.clear()
        self.bulk_candidates.clear()
        self.transient_stream_finish.clear()
        self.transient_stream_last_served.clear()
        self.transient_group_virtual.clear()
        self.transient_group_finish.clear()
        self.transient_group_last_served.clear()
        self.tie_pref_streams.clear()
        self.ordered.clear()
        self.selected.clear()
        self.recorded_group_head.clear()
        self.last_build_cap_hint = 0

    def clear_build_refs(self) -> None:
        self._drop_build_refs()


@dataclass
class BatchState:
    root_virtual_time: int = 0
    group_virtual_time: Dict[GroupKey, int] = field(default_factory=dict)
    group_finish_tag: Dict[GroupKey, int] = field(default_factory=dict)
    group_last_service: Dict[GroupKey, int] = field(default_factory=dict)
    group_lag: Dict[GroupKey, int] = field(default_factory=dict)
    stream_finish_tag: Dict[int, int] = field(default_factory=dict)
    stream_last_service: Dict[int, int] = field(default_factory=dict)
    stream_lag: Dict[int, int] = field(default_factory=dict)
    stream_class: Dict[int, TrafficClass] = field(default_factory=dict)
    stream_last_seen_batch: Dict[int, int] = field(default_factory=dict)
    small_burst_disarmed: Dict[int, None] = field(default_factory=dict)
    preferred_group_head: GroupKey = field(default_factory=GroupKey)
    has_preferred_group_head: bool = False
    preferred_stream_head: Dict[GroupKey, int] = field(default_factory=dict)
    service_seq: int = 0
    batch_seq: int = 0
    interactive_streak: int = 0
    class_selections_since_bulk: int = 0
    scratch: BatchScratch = field(default_factory=BatchScratch)

    def has_retained_real_state(self) -> bool:
        return (
                bool(self.group_virtual_time)
                or bool(self.group_finish_tag)
                or bool(self.group_last_service)
                or bool(self.stream_finish_tag)
                or bool(self.stream_last_service)
                or bool(self.stream_class)
                or bool(self.stream_last_seen_batch)
                or bool(self.small_burst_disarmed)
                or bool(self.preferred_stream_head)
                or self.has_preferred_group_head
        )

    def has_any_retained_state(self) -> bool:
        return (
                self.has_retained_real_state()
                or bool(self.group_lag)
                or bool(self.stream_lag)
        )


@dataclass(frozen=True)
class WFQStreamCandidate:
    stream_id: int = 0
    req_idx: int = 0
    queue_pos: int = 0
    cost: int = 1
    base_weight: int = 1
    weight: int = 1
    stream_virtual: int = 0
    stream_start: int = 0
    stream_finish: int = 0
    stream_last_served: int = 0
    eligible: bool = False
    is_priority_update: bool = False
    stream_order: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "stream_id", _uint64(self.stream_id, "stream_id"))
        object.__setattr__(self, "req_idx", _uint64(self.req_idx, "req_idx"))
        object.__setattr__(self, "queue_pos", _uint64(self.queue_pos, "queue_pos"))
        object.__setattr__(self, "cost", normalize_cost(self.cost))
        object.__setattr__(
            self,
            "base_weight",
            max(1, _uint64(self.base_weight, "base_weight")),
        )
        object.__setattr__(self, "weight", max(1, _uint64(self.weight, "weight")))
        object.__setattr__(
            self,
            "stream_virtual",
            _uint64(self.stream_virtual, "stream_virtual"),
        )
        object.__setattr__(
            self,
            "stream_start",
            _uint64(self.stream_start, "stream_start"),
        )
        object.__setattr__(
            self,
            "stream_finish",
            _uint64(self.stream_finish, "stream_finish"),
        )
        object.__setattr__(
            self,
            "stream_last_served",
            _uint64(self.stream_last_served, "stream_last_served"),
        )
        object.__setattr__(self, "eligible", _require_bool(self.eligible, "eligible"))
        object.__setattr__(
            self,
            "is_priority_update",
            _require_bool(self.is_priority_update, "is_priority_update"),
        )
        object.__setattr__(self, "stream_order", _uint64(self.stream_order, "stream_order"))


@dataclass(frozen=True)
class WFQGroupCandidate:
    group_key: GroupKey = field(default_factory=GroupKey)
    group_virtual: int = 0
    group_start: int = 0
    group_finish: int = 0
    group_last_served: int = 0
    eligible: bool = False
    group_order: int = 0
    traffic_class: TrafficClass = TrafficClass.INTERACTIVE
    base_group_weight: int = 1
    group_weight: int = 1
    total_base_stream_weight: int = 1
    total_stream_weight: int = 1
    stream: WFQStreamCandidate = field(default_factory=WFQStreamCandidate)

    def __post_init__(self) -> None:
        object.__setattr__(self, "group_virtual", _uint64(self.group_virtual, "group_virtual"))
        object.__setattr__(self, "group_start", _uint64(self.group_start, "group_start"))
        object.__setattr__(self, "group_finish", _uint64(self.group_finish, "group_finish"))
        object.__setattr__(
            self,
            "group_last_served",
            _uint64(self.group_last_served, "group_last_served"),
        )
        object.__setattr__(self, "eligible", _require_bool(self.eligible, "eligible"))
        object.__setattr__(self, "group_order", _uint64(self.group_order, "group_order"))
        object.__setattr__(self, "traffic_class", coerce_traffic_class(self.traffic_class))
        object.__setattr__(
            self,
            "base_group_weight",
            max(1, _uint64(self.base_group_weight, "base_group_weight")),
        )
        object.__setattr__(
            self,
            "group_weight",
            max(1, _uint64(self.group_weight, "group_weight")),
        )
        object.__setattr__(
            self,
            "total_base_stream_weight",
            max(1, _uint64(self.total_base_stream_weight, "total_base_stream_weight")),
        )
        object.__setattr__(
            self,
            "total_stream_weight",
            max(1, _uint64(self.total_stream_weight, "total_stream_weight")),
        )


@dataclass(frozen=True)
class BatchTiePrefs:
    has_group: bool = False
    group: GroupKey = field(default_factory=GroupKey)
    streams: Dict[GroupKey, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "has_group", _require_bool(self.has_group, "has_group"))
        if not isinstance(self.group, GroupKey):
            raise TypeError("group must be GroupKey")
        if not isinstance(self.streams, dict):
            raise TypeError("streams must be a dict")
        for key, value in self.streams.items():
            if not isinstance(key, GroupKey):
                raise TypeError("streams keys must be GroupKey")
            _uint64(value, "streams value")


@dataclass(frozen=True)
class BatchStreamSelection:
    req_idx: int = 0
    queue_pos: int = 0
    cost: int = 1
    base_weight: int = 1
    is_priority_update: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "req_idx", _uint64(self.req_idx, "req_idx"))
        object.__setattr__(self, "queue_pos", _uint64(self.queue_pos, "queue_pos"))
        object.__setattr__(self, "cost", normalize_cost(self.cost))
        object.__setattr__(self, "base_weight", max(1, _uint64(self.base_weight, "base_weight")))
        object.__setattr__(
            self,
            "is_priority_update",
            _require_bool(self.is_priority_update, "is_priority_update"),
        )


@dataclass
class BatchPreparedStream:
    meta: StreamMeta = field(default_factory=StreamMeta)
    selection: BatchStreamSelection = field(default_factory=BatchStreamSelection)
    queued_bytes: int = 0
    traffic_class: TrafficClass = TrafficClass.INTERACTIVE
    selection_epoch: int = 0
    small_burst_armed: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.meta, StreamMeta):
            raise TypeError("meta must be StreamMeta")
        if not isinstance(self.selection, BatchStreamSelection):
            raise TypeError("selection must be BatchStreamSelection")
        self.queued_bytes = _uint64(self.queued_bytes, "queued_bytes")
        self.traffic_class = coerce_traffic_class(self.traffic_class)
        self.selection_epoch = _uint64(self.selection_epoch, "selection_epoch")
        self.small_burst_armed = _require_bool(self.small_burst_armed, "small_burst_armed")


@dataclass
class BatchBuiltGroup:
    key: GroupKey = field(default_factory=GroupKey)
    queues: Dict[int, list] = field(default_factory=dict)
    streams: list = field(default_factory=list)


@dataclass
class BatchBuildResult:
    group_order: list = field(default_factory=list)
    group_state: Dict[GroupKey, Dict[int, list]] = field(default_factory=dict)
    groups: list = field(default_factory=list)
    stream_order: Dict[GroupKey, list] = field(default_factory=dict)
    queued_bytes: Dict[int, int] = field(default_factory=dict)
    stream_meta: Dict[int, StreamMeta] = field(default_factory=dict)
    prepared_streams: Dict[int, BatchPreparedStream] = field(default_factory=dict)
    has_real_stream_scoped: bool = False
    has_priority_update: bool = False


@dataclass
class BatchTransientState:
    stream_finish: Dict[int, int] = field(default_factory=dict)
    stream_last_served: Dict[int, int] = field(default_factory=dict)
    group_virtual: Dict[GroupKey, int] = field(default_factory=dict)
    group_finish: Dict[GroupKey, int] = field(default_factory=dict)
    group_last_served: Dict[GroupKey, int] = field(default_factory=dict)


@dataclass(frozen=True)
class StreamGroupBinding:
    group: int = 0
    bucket: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "group", _varint62(self.group, "group"))
        object.__setattr__(self, "bucket", _uint64(self.bucket, "bucket"))


@dataclass(frozen=True)
class GroupClassCandidatePair:
    interactive: WFQGroupCandidate = field(default_factory=WFQGroupCandidate)
    bulk: WFQGroupCandidate = field(default_factory=WFQGroupCandidate)
    has_interactive: bool = False
    has_bulk: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.interactive, WFQGroupCandidate):
            raise TypeError("interactive must be WFQGroupCandidate")
        if not isinstance(self.bulk, WFQGroupCandidate):
            raise TypeError("bulk must be WFQGroupCandidate")
        object.__setattr__(
            self,
            "has_interactive",
            _require_bool(self.has_interactive, "has_interactive"),
        )
        object.__setattr__(self, "has_bulk", _require_bool(self.has_bulk, "has_bulk"))


def normalize_batch_state(state: Optional[BatchState] = None) -> BatchState:
    return state if state is not None else BatchState()


def has_retained_real_batch_state(state: Optional[BatchState]) -> bool:
    return False if state is None else state.has_retained_real_state()


def scrub_idle_retained_batch_state(state: Optional[BatchState]) -> None:
    if state is None:
        return
    state.root_virtual_time = 0
    state.preferred_group_head = GroupKey()
    state.has_preferred_group_head = False
    state.preferred_stream_head.clear()
    state.group_lag.clear()
    state.stream_lag.clear()
    state.stream_class.clear()
    state.stream_last_seen_batch.clear()
    state.small_burst_disarmed.clear()
    state.service_seq = 0
    state.batch_seq = 0
    state.interactive_streak = 0
    state.class_selections_since_bulk = 0


def release_idle_batch_state_storage(state: Optional[BatchState]) -> None:
    if state is None:
        return
    state.group_virtual_time.clear()
    state.group_finish_tag.clear()
    state.group_last_service.clear()
    state.group_lag.clear()
    state.stream_finish_tag.clear()
    state.stream_last_service.clear()
    state.stream_lag.clear()
    state.stream_class.clear()
    state.stream_last_seen_batch.clear()
    state.small_burst_disarmed.clear()
    state.preferred_stream_head.clear()
    state.scratch.clear()


def batch_scratch_retain_limit(hint: int) -> int:
    hint = _uint64(hint, "hint")
    if hint == 0 or hint < BATCH_SCRATCH_RETAIN_MIN_CAP:
        return BATCH_SCRATCH_RETAIN_MIN_CAP
    if hint > sys.maxsize // BATCH_SCRATCH_RETAIN_FACTOR:
        return sys.maxsize
    return hint * BATCH_SCRATCH_RETAIN_FACTOR


def batch_scratch_oversized(retained_capacity: int, hint: int) -> bool:
    retained_capacity = _uint64(retained_capacity, "retained_capacity")
    if retained_capacity == 0:
        return False
    return retained_capacity > batch_scratch_retain_limit(hint)


def prepare_batch_scratch_for_build(state: Optional[BatchState], cap_hint: int) -> None:
    if state is None:
        return
    cap_hint = _uint64(cap_hint, "cap_hint")
    if batch_scratch_oversized(state.scratch.last_build_cap_hint, cap_hint):
        state.scratch.clear_build_refs()
    state.scratch.last_build_cap_hint = cap_hint


def group_state_map(
        state: Optional[BatchState],
        cap_hint: int,
) -> Dict[GroupKey, Dict[int, list]]:
    if state is None:
        return {}
    cap_hint = _uint64(cap_hint, "cap_hint")
    scratch = state.scratch
    scratch.group_queue_count = 0
    scratch.group_queue_entry_count = 0
    if batch_scratch_oversized(len(scratch.group_queues), cap_hint):
        scratch.group_queues = []
    if batch_scratch_oversized(len(scratch.group_queue_entries), cap_hint):
        scratch.group_queue_entries = []
    else:
        scratch.group_queue_entries.clear()
    scratch.group_state.clear()
    return scratch.group_state


def group_build_list(state: Optional[BatchState], cap_hint: int) -> list:
    if state is None:
        return []
    cap_hint = _uint64(cap_hint, "cap_hint")
    scratch = state.scratch
    if batch_scratch_oversized(len(scratch.groups), cap_hint):
        scratch.groups = []
    scratch.groups.clear()
    return scratch.groups


def group_order_list(state: Optional[BatchState], cap_hint: int) -> list:
    if state is None:
        return []
    cap_hint = _uint64(cap_hint, "cap_hint")
    scratch = state.scratch
    if batch_scratch_oversized(len(scratch.group_order), cap_hint):
        scratch.group_order = []
    scratch.group_order.clear()
    return scratch.group_order


def next_group_queue_map(state: Optional[BatchState]) -> Dict[int, list]:
    if state is None:
        return {}
    scratch = state.scratch
    if scratch.group_queue_count < len(scratch.group_queues):
        out = scratch.group_queues[scratch.group_queue_count]
        recycle_group_queue_entry_lists(state, out)
        out.clear()
    else:
        out = {}
        scratch.group_queues.append(out)
    scratch.group_queue_count += 1
    return out


def clear_unused_group_queue_maps(state: Optional[BatchState]) -> None:
    if state is None:
        return
    scratch = state.scratch
    for queues in scratch.group_queues[scratch.group_queue_count:]:
        if queues:
            recycle_group_queue_entry_lists(state, queues)
            queues.clear()


def stream_order_map(state: Optional[BatchState], cap_hint: int) -> Dict[GroupKey, list]:
    if state is None:
        return {}
    cap_hint = _uint64(cap_hint, "cap_hint")
    scratch = state.scratch
    scratch.stream_order_entry_count = 0
    if batch_scratch_oversized(len(scratch.stream_order_entries), cap_hint):
        scratch.stream_order_entries = []
    else:
        scratch.stream_order_entries.clear()
    if scratch.stream_order:
        recycle_stream_order_lists(state, scratch.stream_order)
        scratch.stream_order.clear()
    return scratch.stream_order


def _recycle_scratch_lists(
        state: Optional[BatchState],
        values,
        entries_attr: str,
) -> None:
    if state is None:
        return
    entries = getattr(state.scratch, entries_attr)
    for scratch_list in values:
        if batch_scratch_oversized(len(scratch_list), state.scratch.last_build_cap_hint):
            continue
        scratch_list.clear()
        entries.append(scratch_list)


def _next_scratch_list(
        state: Optional[BatchState],
        entries_attr: str,
        count_attr: str,
) -> list:
    if state is None:
        return []
    scratch = state.scratch
    count = getattr(scratch, count_attr)
    entries = getattr(scratch, entries_attr)
    if count >= len(entries):
        return []
    out = entries[count]
    setattr(scratch, count_attr, count + 1)
    out.clear()
    return out


def recycle_group_queue_entry_lists(
        state: Optional[BatchState],
        queues: Dict[int, list],
) -> None:
    _recycle_scratch_lists(state, queues.values(), "group_queue_entries")


def next_group_queue_entry_list(state: Optional[BatchState]) -> list:
    return _next_scratch_list(
        state,
        "group_queue_entries",
        "group_queue_entry_count",
    )


def recycle_stream_order_lists(
        state: Optional[BatchState],
        orders: Dict[GroupKey, list],
) -> None:
    _recycle_scratch_lists(state, orders.values(), "stream_order_entries")


def next_stream_order_list(state: Optional[BatchState]) -> list:
    return _next_scratch_list(
        state,
        "stream_order_entries",
        "stream_order_entry_count",
    )


def queued_bytes_map(state: Optional[BatchState]) -> Dict[int, int]:
    if state is None:
        return {}
    state.scratch.queued_bytes.clear()
    return state.scratch.queued_bytes


def _scratch_map(state: Optional[BatchState], attr: str, cap_hint: int):
    if state is None:
        return {}
    cap_hint = _uint64(cap_hint, "cap_hint")
    values = getattr(state.scratch, attr)
    if batch_scratch_oversized(len(values), cap_hint):
        values = {}
        setattr(state.scratch, attr, values)
    else:
        values.clear()
    return values


def batch_stream_meta_map(state: Optional[BatchState], cap_hint: int) -> Dict[int, StreamMeta]:
    return _scratch_map(state, "stream_meta", cap_hint)


def prepared_stream_map(
        state: Optional[BatchState],
        cap_hint: int,
) -> Dict[int, BatchPreparedStream]:
    return _scratch_map(state, "prepared_streams", cap_hint)


def bypass_selections_map(state: Optional[BatchState], cap_hint: int) -> Dict[int, int]:
    return _scratch_map(state, "bypass_selections", cap_hint)


def _bulk_scratch_list(
        state: Optional[BatchState],
        bulk: bool,
        cap_hint: int,
        interactive_attr: str,
        bulk_attr: str,
) -> list:
    if state is None:
        return []
    bulk = _require_bool(bulk, "bulk")
    cap_hint = _uint64(cap_hint, "cap_hint")
    attr = bulk_attr if bulk else interactive_attr
    scratch_list = getattr(state.scratch, attr)
    if batch_scratch_oversized(len(scratch_list), cap_hint):
        scratch_list = []
        setattr(state.scratch, attr, scratch_list)
    scratch_list.clear()
    return scratch_list


def active_stream_list(state: Optional[BatchState], bulk: bool, cap_hint: int) -> list:
    return _bulk_scratch_list(
        state,
        bulk,
        cap_hint,
        "interactive_active_streams",
        "bulk_active_streams",
    )


def group_candidate_list(state: Optional[BatchState], bulk: bool, cap_hint: int) -> list:
    return _bulk_scratch_list(
        state,
        bulk,
        cap_hint,
        "interactive_candidates",
        "bulk_candidates",
    )


def _bool_scratch_list(state: Optional[BatchState], n: int, attr: str) -> list:
    if state is None:
        return [False] * _uint64(n, "n")
    n = _uint64(n, "n")
    scratch_list = getattr(state.scratch, attr)
    if batch_scratch_oversized(len(scratch_list), n):
        scratch_list = []
        setattr(state.scratch, attr, scratch_list)
    scratch_list[:] = [False] * n
    return scratch_list


def transient_stream_finish_map(state: Optional[BatchState], cap_hint: int) -> Dict[int, int]:
    return _scratch_map(state, "transient_stream_finish", cap_hint)


def transient_stream_last_served_map(
        state: Optional[BatchState],
        cap_hint: int,
) -> Dict[int, int]:
    return _scratch_map(state, "transient_stream_last_served", cap_hint)


def transient_group_virtual_map(
        state: Optional[BatchState],
        cap_hint: int,
) -> Dict[GroupKey, int]:
    return _scratch_map(state, "transient_group_virtual", cap_hint)


def transient_group_finish_map(
        state: Optional[BatchState],
        cap_hint: int,
) -> Dict[GroupKey, int]:
    return _scratch_map(state, "transient_group_finish", cap_hint)


def transient_group_last_served_map(
        state: Optional[BatchState],
        cap_hint: int,
) -> Dict[GroupKey, int]:
    return _scratch_map(state, "transient_group_last_served", cap_hint)


def tie_pref_streams_map(state: Optional[BatchState], cap_hint: int) -> Dict[GroupKey, int]:
    return _scratch_map(state, "tie_pref_streams", cap_hint)


def ordered_list(state: Optional[BatchState], cap_hint: int) -> list:
    if state is None:
        return []
    cap_hint = _uint64(cap_hint, "cap_hint")
    if batch_scratch_oversized(len(state.scratch.ordered), cap_hint):
        state.scratch.ordered = []
    state.scratch.ordered.clear()
    return state.scratch.ordered


def selected_list(state: Optional[BatchState], n: int) -> list:
    return _bool_scratch_list(state, n, "selected")


def recorded_group_head_list(state: Optional[BatchState], n: int) -> list:
    return _bool_scratch_list(state, n, "recorded_group_head")


def service_tag(cost: int, weight: int) -> int:
    c = normalize_cost(cost)
    weight = max(1, _uint64(weight, "weight"))
    total = saturating_mul_div_ceil(c, WFQ_TAG_SCALE, weight)
    return max(1, total)


def max64(a: int, b: int) -> int:
    return max(_uint64(a, "a"), _uint64(b, "b"))


def min64(a: int, b: int) -> int:
    return min(_int64(a, "a"), _int64(b, "b"))


def scheduler_quantum(max_payload: int) -> int:
    max_payload = _uint64(max_payload, "max_payload")
    return max_payload or _DEFAULT_MAX_FRAME_PAYLOAD


def stream_weight(
        priority: int,
        queued_bytes: int,
        hint: SchedulerHint,
        max_payload: int,
) -> int:
    priority = _uint64(priority, "priority")
    queued_bytes = _uint64(queued_bytes, "queued_bytes")
    hint = coerce_scheduler_hint(hint)
    base = priority_weight(priority, hint)
    short_window = scheduler_quantum(max_payload)
    if short_window == 0:
        return max(base, 1)

    if hint is SchedulerHint.LATENCY:
        if queued_bytes <= short_window:
            base = saturating_mul(base, 4)
        elif queued_bytes <= saturating_mul(short_window, 2):
            base = saturating_mul(base, 2)
    elif hint in (
            SchedulerHint.BALANCED_FAIR,
            SchedulerHint.UNSPECIFIED_OR_BALANCED,
            SchedulerHint.GROUP_FAIR,
    ):
        if queued_bytes <= short_window:
            base = saturating_mul(base, 2)
    elif hint is SchedulerHint.BULK_THROUGHPUT:
        if short_window > 1 and queued_bytes <= short_window // 2:
            base = saturating_add(base, base // 2)

    return max(base, 1)


def feedback_window(hint: SchedulerHint, max_payload: int) -> int:
    hint = coerce_scheduler_hint(hint)
    window = scheduler_quantum(max_payload)
    if hint is SchedulerHint.LATENCY:
        window = saturating_mul(window, 6)
    elif hint is SchedulerHint.BULK_THROUGHPUT:
        window = saturating_mul(window, 2)
    else:
        window = saturating_mul(window, 4)
    if window == 0:
        return 1
    return min(window, MAX_SIGNED_INT64)


def adjust_weight_for_lag(base: int, lag: int, window: int, fresh: bool) -> int:
    base = max(1, _uint64(base, "base"))
    lag = _int64(lag, "lag")
    window = _int64(window, "window")
    fresh = _require_bool(fresh, "fresh")
    if fresh:
        base = saturating_add(base, max(base // 2, 1))
    if window <= 0 or lag == 0:
        return max(base, 1)
    if lag > 0:
        boost = lag_scaled_weight(base, min(lag, window), window)
        return max(saturating_add(base, max(boost, 1)), 1)
    magnitude = min(_saturating_abs_i64(lag), window)
    penalty = lag_scaled_weight(base, magnitude, saturating_mul(window, 2))
    return max(base - min(base, penalty), 1)


def lag_scaled_weight(base: int, magnitude: int, divisor: int) -> int:
    base = _uint64(base, "base")
    magnitude = _int64(magnitude, "magnitude")
    divisor = _uint64(divisor, "divisor")
    if base == 0 or magnitude <= 0 or divisor == 0:
        return 0
    return saturating_mul_div_floor(base, magnitude, divisor)


def classify_stream_class(
        queued_bytes: int,
        priority: int,
        hint: SchedulerHint,
        previous: Optional[TrafficClass] = None,
        has_previous: bool = False,
        interactive_quantum: int = 0,
) -> TrafficClass:
    queued_bytes = _uint64(queued_bytes, "queued_bytes")
    priority = _uint64(priority, "priority")
    hint = coerce_scheduler_hint(hint)
    has_previous = _require_bool(has_previous, "has_previous")
    if interactive_quantum == 0:
        interactive_quantum = scheduler_quantum(0)
    else:
        interactive_quantum = _uint64(interactive_quantum, "interactive_quantum")
    bulk_threshold = saturating_mul(interactive_quantum, BULK_ENTRY_MULTIPLIER)
    if queued_bytes <= interactive_quantum:
        return TrafficClass.INTERACTIVE
    if queued_bytes > bulk_threshold:
        return TrafficClass.BULK
    if previous is not None:
        has_previous = True
        previous = coerce_traffic_class(previous)
    if has_previous:
        return previous if previous is not None else TrafficClass.INTERACTIVE
    if hint is SchedulerHint.BULK_THROUGHPUT:
        return TrafficClass.BULK
    if hint is SchedulerHint.LATENCY or priority >= 4:
        return TrafficClass.INTERACTIVE
    if write_burst_limit(priority, hint) >= DEFAULT_WRITE_BURST_FRAMES:
        return TrafficClass.BULK
    return TrafficClass.INTERACTIVE


def choose_traffic_class(
        prefs: BatchTiePrefs,
        hint: SchedulerHint,
        interactive: Optional[WFQGroupCandidate],
        bulk: Optional[WFQGroupCandidate],
        interactive_streak: int,
        class_selections_since_bulk: int,
) -> TrafficClass:
    hint = coerce_scheduler_hint(hint)
    interactive_streak = _uint64(interactive_streak, "interactive_streak")
    class_selections_since_bulk = _uint64(
        class_selections_since_bulk,
        "class_selections_since_bulk",
    )
    if not _candidate_present(interactive):
        return TrafficClass.BULK
    if not _candidate_present(bulk):
        return TrafficClass.INTERACTIVE
    if (
            interactive_streak >= INTERACTIVE_BURST_LIMIT
            or class_selections_since_bulk >= max(0, BULK_RESERVE_WINDOW - 1)
    ):
        return TrafficClass.BULK
    if better_class_candidate(prefs, interactive, bulk, hint):
        return TrafficClass.INTERACTIVE
    return TrafficClass.BULK


def better_class_candidate(
        prefs: BatchTiePrefs,
        left: Optional[WFQGroupCandidate],
        right: Optional[WFQGroupCandidate],
        hint: SchedulerHint,
) -> bool:
    hint = coerce_scheduler_hint(hint)
    if not _candidate_present(left):
        return False
    if not _candidate_present(right):
        return True
    assert left is not None and right is not None
    if left.eligible != right.eligible:
        return left.eligible
    left_primary, right_primary = _scaled_candidate_tag_pair(
        left,
        right,
        hint,
        prefer_finish=left.eligible,
    )
    if left_primary != right_primary:
        return left_primary < right_primary
    left_secondary, right_secondary = _scaled_candidate_tag_pair(
        left,
        right,
        hint,
        prefer_finish=not left.eligible,
    )
    if left_secondary != right_secondary:
        return left_secondary < right_secondary
    return better_group_candidate(prefs, left, right)


def _scaled_candidate_tag_pair(
        left: WFQGroupCandidate,
        right: WFQGroupCandidate,
        hint: SchedulerHint,
        *,
        prefer_finish: bool,
) -> tuple[int, int]:
    left_tag = left.group_finish if prefer_finish else left.group_start
    right_tag = right.group_finish if prefer_finish else right.group_start
    return scaled_class_tag(left, hint, left_tag), scaled_class_tag(right, hint, right_tag)


def scaled_class_tag(
        candidate: WFQGroupCandidate,
        hint: SchedulerHint,
        tag: int,
) -> int:
    tag = _uint64(tag, "tag")
    weight = class_bias_weight(candidate.traffic_class, hint)
    if weight == 0:
        return tag
    return saturating_mul_div_floor(tag, CLASS_SCORE_SCALE, weight)


def class_bias_weight(traffic_class: TrafficClass, hint: SchedulerHint) -> int:
    traffic_class = coerce_traffic_class(traffic_class)
    hint = coerce_scheduler_hint(hint)
    if hint is SchedulerHint.LATENCY:
        return 8 if traffic_class is TrafficClass.INTERACTIVE else 2
    if hint is SchedulerHint.BULK_THROUGHPUT:
        return 2 if traffic_class is TrafficClass.INTERACTIVE else 8
    return 6 if traffic_class is TrafficClass.INTERACTIVE else 4


def better_eligible_window(
        left_eligible: bool,
        left_start: int,
        left_finish: int,
        right_start: int,
        right_finish: int,
) -> Optional[bool]:
    left_eligible = _require_bool(left_eligible, "left_eligible")
    left_start = _uint64(left_start, "left_start")
    left_finish = _uint64(left_finish, "left_finish")
    right_start = _uint64(right_start, "right_start")
    right_finish = _uint64(right_finish, "right_finish")
    if not left_eligible:
        if left_start != right_start:
            return left_start < right_start
        if left_finish != right_finish:
            return left_finish < right_finish
        return None
    if left_finish != right_finish:
        return left_finish < right_finish
    if left_start != right_start:
        return left_start < right_start
    return None


def better_group_candidate(
        prefs: BatchTiePrefs,
        left: Optional[WFQGroupCandidate],
        right: Optional[WFQGroupCandidate],
) -> bool:
    if not _candidate_present(left):
        return False
    if not _candidate_present(right):
        return True
    assert left is not None and right is not None
    if left.eligible != right.eligible:
        return left.eligible
    better = better_eligible_window(
        left.eligible,
        left.group_start,
        left.group_finish,
        right.group_start,
        right.group_finish,
    )
    if better is not None:
        return better
    if prefs.has_group:
        left_preferred = left.group_key == prefs.group
        right_preferred = right.group_key == prefs.group
        if left_preferred != right_preferred:
            return left_preferred
    if left.stream.stream_finish != right.stream.stream_finish:
        return left.stream.stream_finish < right.stream.stream_finish
    if left.stream.stream_start != right.stream.stream_start:
        return left.stream.stream_start < right.stream.stream_start
    if left.group_last_served != right.group_last_served:
        return left.group_last_served < right.group_last_served
    if left.stream.stream_last_served != right.stream.stream_last_served:
        return left.stream.stream_last_served < right.stream.stream_last_served
    if left.group_order != right.group_order:
        return left.group_order < right.group_order
    return left.stream.stream_order < right.stream.stream_order


def bypass_count(bypass_selections: Dict[int, int], stream_id: int) -> int:
    return _uint64(bypass_selections.get(_uint64(stream_id, "stream_id"), 0), "bypass_count")


def should_apply_aging(
        stream_id: int,
        active_class_streams: int,
        bypass_selections: Dict[int, int],
) -> bool:
    active_class_streams = _uint64(active_class_streams, "active_class_streams")
    if active_class_streams <= 1:
        return False
    threshold = saturating_mul(active_class_streams, AGING_ROUND_THRESHOLD)
    return bypass_count(bypass_selections, stream_id) >= threshold


def class_adjusted_weight(
        base_weight: int,
        effective_weight: int,
        queued_bytes: int,
        small_burst_armed: bool,
        interactive_quantum: int,
        age_boost: bool,
) -> int:
    base_weight = _uint64(base_weight, "base_weight")
    adjusted = max(1, _uint64(effective_weight, "effective_weight"))
    queued_bytes = _uint64(queued_bytes, "queued_bytes")
    interactive_quantum = _uint64(interactive_quantum, "interactive_quantum")
    small_burst_armed = _require_bool(small_burst_armed, "small_burst_armed")
    age_boost = _require_bool(age_boost, "age_boost")
    if small_burst_armed and queued_bytes <= interactive_quantum:
        adjusted = saturating_add(adjusted, max(base_weight, 1))
    if age_boost:
        adjusted = saturating_add(adjusted, max(base_weight, max(adjusted // 2, 1)))
    return max(adjusted, 1)


def fair_share(cost: int, weight: int, total_weight: int) -> int:
    cost = _int64(cost, "cost")
    weight = _uint64(weight, "weight")
    total_weight = _uint64(total_weight, "total_weight")
    if cost <= 0 or weight == 0 or total_weight == 0:
        return 0
    share = saturating_mul_div_ceil(cost, weight, total_weight)
    return min(share, MAX_SIGNED_INT64)


def clamp_lag(value: int, window: int) -> int:
    value = _int64(value, "value")
    window = _int64(window, "window")
    if window <= 0:
        return 0
    limit = MAX_SIGNED_INT64
    if window <= MAX_SIGNED_INT64 // 2:
        limit = window * 2
    if value > limit:
        return limit
    if value < -limit:
        return -limit
    return value


def apply_lag_feedback(current: int, expected: int, actual: int, window: int) -> int:
    current = _int64(current, "current")
    expected = _int64(expected, "expected")
    actual = _int64(actual, "actual")
    window = _int64(window, "window")
    if window <= 0:
        return 0
    if expected >= actual:
        delta = expected - actual
        if current > MAX_SIGNED_INT64 - delta:
            return clamp_lag(MAX_SIGNED_INT64, window)
        return clamp_lag(current + delta, window)

    delta = actual - expected
    floor = -MAX_SIGNED_INT64
    if current < floor + delta:
        return clamp_lag(floor, window)
    return clamp_lag(current - delta, window)


def is_fresh_stream(state: Optional[BatchState], stream_id: int) -> bool:
    stream_id = _uint64(stream_id, "stream_id")
    if state is None or is_synthetic_stream_key(stream_id):
        return False
    return (
            stream_id not in state.stream_finish_tag
            and stream_id not in state.stream_last_service
            and stream_id not in state.stream_lag
    )


def is_fresh_group(state: Optional[BatchState], group_key: GroupKey) -> bool:
    if state is None or is_transient_group_key(group_key):
        return False
    return (
            group_key not in state.group_finish_tag
            and group_key not in state.group_last_service
            and group_key not in state.group_lag
    )


def group_lag(state: Optional[BatchState], group_key: GroupKey) -> int:
    if state is None:
        return 0
    return state.group_lag.get(group_key, 0)


def set_group_lag(state: Optional[BatchState], group_key: GroupKey, value: int) -> None:
    if state is None or is_transient_group_key(group_key):
        return
    state.group_lag[group_key] = _int64(value, "value")


def stream_lag(state: Optional[BatchState], stream_id: int) -> int:
    if state is None:
        return 0
    return state.stream_lag.get(_uint64(stream_id, "stream_id"), 0)


def set_stream_lag(state: Optional[BatchState], stream_id: int, value: int) -> None:
    stream_id = _uint64(stream_id, "stream_id")
    if state is None or is_synthetic_stream_key(stream_id):
        return
    state.stream_lag[stream_id] = _int64(value, "value")


def is_synthetic_stream_key(stream_id: int) -> bool:
    return (_uint64(stream_id, "stream_id") & SYNTHETIC_STREAM_KEY_BIT) != 0


def is_transient_group_key(group_key: GroupKey) -> bool:
    return group_key.is_transient()


def group_weight(group_key: GroupKey, stream_weight_value: int, hint: SchedulerHint) -> int:
    hint = coerce_scheduler_hint(hint)
    if group_key.kind != 1:
        return max(_uint64(stream_weight_value, "stream_weight"), 1)
    if hint is SchedulerHint.LATENCY:
        return 32
    if hint is SchedulerHint.BULK_THROUGHPUT:
        return 16
    return 24


def priority_weight(priority: int, hint: SchedulerHint) -> int:
    priority = _uint64(priority, "priority")
    hint = coerce_scheduler_hint(hint)
    if hint is SchedulerHint.LATENCY:
        return banded_weight(priority, 16, 24, 32, 48, 64, 96)
    if hint is SchedulerHint.BULK_THROUGHPUT:
        return banded_weight(priority, 16, 18, 20, 24, 28, 32)
    return banded_weight(priority, 16, 20, 24, 32, 48, 72)


def banded_weight(
        priority: int,
        base: int,
        mild: int,
        medium: int,
        strong: int,
        xstrong: int,
        saturated: int,
) -> int:
    priority = _uint64(priority, "priority")
    if priority >= 32:
        return _uint64(saturated, "saturated")
    if priority >= 16:
        return _uint64(xstrong, "xstrong")
    if priority >= 8:
        return _uint64(strong, "strong")
    if priority >= 4:
        return _uint64(medium, "medium")
    if priority >= 1:
        return _uint64(mild, "mild")
    return _uint64(base, "base")


def normalize_cost(cost: int) -> int:
    if isinstance(cost, bool) or not isinstance(cost, int):
        raise TypeError("cost must be an integer")
    if cost <= 0:
        return 1
    return min(cost, MAX_REQUEST_COST)


def coerce_batch_config(cfg: Optional[BatchConfig]) -> BatchConfig:
    if cfg is None:
        return BatchConfig()
    if isinstance(cfg, BatchConfig):
        return cfg
    raise TypeError("cfg must be BatchConfig")


def coerce_scheduler_hint(value: SchedulerHint) -> SchedulerHint:
    if isinstance(value, SchedulerHint):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("scheduler_hint must be a SchedulerHint or integer")
    return SchedulerHint.from_code(value)


def coerce_traffic_class(value: TrafficClass) -> TrafficClass:
    if isinstance(value, TrafficClass):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("traffic_class must be a TrafficClass or integer")
    return TrafficClass(value)


def build_batch_groups(
        state: Optional[BatchState],
        items: Sequence[BatchItem],
) -> BatchBuildResult:
    prepare_batch_scratch_for_build(state, len(items))
    result = BatchBuildResult(
        group_order=group_order_list(state, len(items)),
        group_state=group_state_map(state, len(items)),
        groups=group_build_list(state, len(items)),
        stream_order=stream_order_map(state, len(items)),
        queued_bytes=queued_bytes_map(state),
        stream_meta=batch_stream_meta_map(state, len(items)),
    )
    for index, item in enumerate(items):
        req = item.request
        group_key = req.group_key if req.stream_scoped else GroupKey.transient(index)
        queues = result.group_state.get(group_key)
        if queues is None:
            result.group_order.append(group_key)
            queues = next_group_queue_map(state)
            result.group_state[group_key] = queues
            result.stream_order[group_key] = next_stream_order_list(state)
        stream_key = synthetic_stream_key(req, index)
        queue = queues.get(stream_key)
        if queue is None:
            result.stream_order[group_key].append(stream_key)
            queue = next_group_queue_entry_list(state)
            queues[stream_key] = queue
        queue.append(index)
        result.queued_bytes[stream_key] = saturating_add(
            result.queued_bytes.get(stream_key, 0),
            normalize_cost(req.cost),
        )
        if req.stream_scoped:
            result.has_real_stream_scoped = True
            result.stream_meta[req.stream_id] = item.stream
        if req.is_priority_update:
            result.has_priority_update = True

    for group_key in result.group_order:
        result.groups.append(
            BatchBuiltGroup(
                key=group_key,
                queues=result.group_state[group_key],
                streams=list(result.stream_order[group_key]),
            )
        )
    clear_unused_group_queue_maps(state)
    return result


def synthetic_stream_key(req: RequestMeta, index: int) -> int:
    if req.stream_scoped:
        return req.stream_id
    return SYNTHETIC_STREAM_KEY_BIT | _uint64(index, "index")


def pick_next_transient_ordinary_head(
        groups: Sequence[BatchBuiltGroup],
) -> tuple[int, int, int, list, bool]:
    for group_index, group in enumerate(groups):
        if not is_transient_group_key(group.key):
            continue
        for stream_id in group.streams:
            queue = group.queues.get(stream_id, [])
            if not queue:
                continue
            return group_index, stream_id, queue[0], remove_queue_entry(queue, 0), True
    return 0, 0, 0, [], False


def peek_stream_candidate(
        queue: Sequence[int],
        items: Sequence[BatchItem],
) -> tuple[int, int, int, bool, bool]:
    if not queue:
        return 0, 0, 0, False, False
    head_index = queue[0]
    head_req = items[head_index].request
    if head_req.opening_frame:
        return (
            head_index,
            0,
            normalize_cost(head_req.cost),
            head_req.is_priority_update,
            True,
        )
    for pos, index in enumerate(queue):
        if items[index].request.is_priority_update:
            return index, pos, normalize_cost(items[index].request.cost), True, True
    return head_index, 0, normalize_cost(head_req.cost), False, True


def remove_queue_entry(queue: Sequence[int], pos: int) -> list:
    if not isinstance(queue, list):
        queue = list(queue)
    if pos < 0 or pos >= len(queue):
        return queue
    del queue[pos]
    return queue


def select_stream_candidate(
        queue: Sequence[int],
        items: Sequence[BatchItem],
        advisory_only: bool,
) -> tuple[int, int, int, bool, bool]:
    req_idx, pos, cost, is_priority_update, ok = peek_stream_candidate(queue, items)
    if not ok or (advisory_only and not is_priority_update):
        return 0, 0, 0, False, False
    return req_idx, pos, cost, is_priority_update, True


def identity_order(n: int) -> tuple[int, ...]:
    return tuple(range(_uint64(n, "n")))


def order_urgent_batch(items: Sequence[BatchItem]) -> tuple[int, ...]:
    ordered: list[int] = []
    for index, item in enumerate(items):
        insert = len(ordered)
        while insert > 0 and _urgent_item_precedes(
                item,
                index,
                items[ordered[insert - 1]],
                ordered[insert - 1],
        ):
            insert -= 1
        ordered.insert(insert, index)
    return tuple(ordered)


def apply_batch_stream_classes(
        state: BatchState,
        prepared: BatchBuildResult,
        hint: SchedulerHint,
        interactive_quantum: int,
        batch_seq: int,
) -> Dict[int, BatchPreparedStream]:
    prepared_streams = prepared_stream_map(state, len(prepared.stream_meta))
    for stream_id, meta in prepared.stream_meta.items():
        previous = state.stream_class.get(stream_id)
        stream_class = classify_stream_class(
            prepared.queued_bytes.get(stream_id, 0),
            meta.priority,
            hint,
            previous=previous,
            has_previous=previous is not None,
            interactive_quantum=interactive_quantum,
        )
        last_seen = state.stream_last_seen_batch.get(stream_id)
        if last_seen is None or batch_seq - last_seen >= 2:
            state.small_burst_disarmed.pop(stream_id, None)
        prepared_streams[stream_id] = BatchPreparedStream(
            meta=meta,
            queued_bytes=prepared.queued_bytes.get(stream_id, 0),
            traffic_class=stream_class,
            small_burst_armed=stream_id not in state.small_burst_disarmed,
        )
    return prepared_streams


def retain_batch_stream_classes(
        state: BatchState,
        prepared_streams: Dict[int, BatchPreparedStream],
        batch_seq: int,
        interactive_streak: int,
        class_selections_since_bulk: int,
) -> None:
    for stream_id, prepared_stream in prepared_streams.items():
        state.stream_class[stream_id] = prepared_stream.traffic_class
        state.stream_last_seen_batch[stream_id] = batch_seq
    state.batch_seq = _uint64(batch_seq, "batch_seq")
    state.interactive_streak = _uint64(interactive_streak, "interactive_streak")
    state.class_selections_since_bulk = _uint64(
        class_selections_since_bulk,
        "class_selections_since_bulk",
    )


def refresh_active_stream_selections(
        state: BatchState,
        prepared: BatchBuildResult,
        items: Sequence[BatchItem],
        cfg: BatchConfig,
        advisory_only: bool,
        selection_epoch: int,
) -> tuple[list, list]:
    interactive_active = active_stream_list(state, False, len(prepared.stream_meta))
    bulk_active = active_stream_list(state, True, len(prepared.stream_meta))
    for group in prepared.groups:
        for stream_id in group.streams:
            prepared_stream = prepared.prepared_streams.get(stream_id)
            if prepared_stream is None:
                continue
            req_idx, pos, cost, is_priority_update, ok = select_stream_candidate(
                group.queues.get(stream_id, []),
                items,
                advisory_only,
            )
            if not ok:
                continue
            prepared_stream.selection = BatchStreamSelection(
                req_idx=req_idx,
                queue_pos=pos,
                cost=cost,
                base_weight=stream_weight(
                    prepared_stream.meta.priority,
                    prepared_stream.queued_bytes,
                    cfg.scheduler_hint,
                    cfg.max_frame_payload,
                ),
                is_priority_update=is_priority_update,
            )
            prepared_stream.selection_epoch = selection_epoch
            if prepared_stream.traffic_class is TrafficClass.BULK:
                bulk_active.append(stream_id)
            else:
                interactive_active.append(stream_id)
    return interactive_active, bulk_active


def top_candidates_for_group_classes(
        cfg: BatchConfig,
        state: BatchState,
        transient: BatchTransientState,
        prepared: BatchBuildResult,
        prefs: BatchTiePrefs,
        group: BatchBuiltGroup,
        group_order: int,
        interactive_quantum: int,
        feedback_window_value: int,
        interactive_active: Sequence[int],
        bulk_active: Sequence[int],
        selection_epoch: int,
        bypass_selections: Dict[int, int],
) -> GroupClassCandidatePair:
    group_virtual = group_virtual_time(state, transient, group.key)
    group_finish_base = group_finish_tag(state, transient, group.key)
    group_lag_value = group_lag(state, group.key)
    group_last_served_value = group_last_served(state, transient, group.key)
    fresh_group = is_fresh_group(state, group.key)
    root_virtual = state.root_virtual_time
    preferred_stream = prefs.streams.get(group.key, 0) if prefs.streams else 0

    interactive_top = WFQStreamCandidate()
    bulk_top = WFQStreamCandidate()
    total_interactive_base = 0
    total_interactive_weight = 0
    total_bulk_base = 0
    total_bulk_weight = 0
    has_interactive_top = False
    has_bulk_top = False

    for stream_order, stream_id in enumerate(group.streams):
        prepared_stream = prepared.prepared_streams.get(stream_id)
        if prepared_stream is None or prepared_stream.selection_epoch != selection_epoch:
            continue
        stream_class = prepared_stream.traffic_class
        selection = prepared_stream.selection
        base_weight = selection.base_weight
        lag_adjusted_weight = adjust_weight_for_lag(
            base_weight,
            stream_lag(state, stream_id),
            feedback_window_value,
            is_fresh_stream(state, stream_id),
        )
        active_class_streams = (
            len(bulk_active)
            if stream_class is TrafficClass.BULK
            else len(interactive_active)
        )
        effective_weight = class_adjusted_weight(
            base_weight,
            lag_adjusted_weight,
            prepared_stream.queued_bytes,
            prepared_stream.small_burst_armed,
            interactive_quantum,
            should_apply_aging(stream_id, active_class_streams, bypass_selections),
        )
        stream_start = max64(stream_finish_tag(state, transient, stream_id), group_virtual)
        stream_finish = saturating_add(
            stream_start,
            service_tag(selection.cost, max64(effective_weight, 1)),
        )
        candidate = WFQStreamCandidate(
            stream_id=stream_id,
            req_idx=selection.req_idx,
            queue_pos=selection.queue_pos,
            cost=selection.cost,
            base_weight=base_weight,
            weight=effective_weight,
            stream_virtual=group_virtual,
            stream_start=stream_start,
            stream_finish=stream_finish,
            stream_last_served=stream_last_served(state, transient, stream_id),
            eligible=stream_start <= group_virtual,
            is_priority_update=selection.is_priority_update,
            stream_order=stream_order,
        )
        if stream_class is TrafficClass.BULK:
            total_bulk_base = saturating_add(total_bulk_base, base_weight)
            total_bulk_weight = saturating_add(total_bulk_weight, effective_weight)
            if not has_bulk_top or better_stream_candidate(preferred_stream, candidate, bulk_top):
                bulk_top = candidate
                has_bulk_top = True
            continue
        total_interactive_base = saturating_add(total_interactive_base, base_weight)
        total_interactive_weight = saturating_add(total_interactive_weight, effective_weight)
        if not has_interactive_top or better_stream_candidate(
                preferred_stream,
                candidate,
                interactive_top,
        ):
            interactive_top = candidate
            has_interactive_top = True

    return GroupClassCandidatePair(
        interactive=build_group_class_candidate_with_group_state(
            cfg,
            group.key,
            group_order,
            TrafficClass.INTERACTIVE,
            interactive_top,
            total_interactive_base,
            total_interactive_weight,
            feedback_window_value,
            root_virtual,
            group_finish_base,
            group_last_served_value,
            group_lag_value,
            fresh_group,
            has_interactive_top,
        ),
        bulk=build_group_class_candidate_with_group_state(
            cfg,
            group.key,
            group_order,
            TrafficClass.BULK,
            bulk_top,
            total_bulk_base,
            total_bulk_weight,
            feedback_window_value,
            root_virtual,
            group_finish_base,
            group_last_served_value,
            group_lag_value,
            fresh_group,
            has_bulk_top,
        ),
        has_interactive=has_interactive_top,
        has_bulk=has_bulk_top,
    )


def build_group_class_candidate_with_group_state(
        cfg: BatchConfig,
        group_key: GroupKey,
        group_order: int,
        traffic_class: TrafficClass,
        top: WFQStreamCandidate,
        total_base_stream_weight: int,
        total_stream_weight: int,
        feedback_window_value: int,
        root_virtual: int,
        group_finish_base: int,
        group_last_served_value: int,
        group_lag_value: int,
        fresh_group: bool,
        has_top: bool,
) -> WFQGroupCandidate:
    fresh_group = _require_bool(fresh_group, "fresh_group")
    has_top = _require_bool(has_top, "has_top")
    if not has_top:
        return WFQGroupCandidate()
    base_group_weight = group_weight(group_key, top.base_weight, cfg.scheduler_hint)
    effective_group_weight = adjust_weight_for_lag(
        base_group_weight,
        group_lag_value,
        feedback_window_value,
        fresh_group,
    )
    group_start = max64(group_finish_base, root_virtual)
    group_finish = saturating_add(
        group_start,
        service_tag(top.cost, max64(effective_group_weight, 1)),
    )
    return WFQGroupCandidate(
        group_key=group_key,
        group_virtual=root_virtual,
        group_start=group_start,
        group_finish=group_finish,
        group_last_served=group_last_served_value,
        eligible=group_start <= root_virtual and top.eligible,
        group_order=group_order,
        traffic_class=traffic_class,
        base_group_weight=max64(base_group_weight, 1),
        group_weight=max64(effective_group_weight, 1),
        total_base_stream_weight=max64(total_base_stream_weight, 1),
        total_stream_weight=max64(total_stream_weight, 1),
        stream=top,
    )


def update_lag_feedback(
        state: Optional[BatchState],
        prepared: BatchBuildResult,
        chosen: WFQGroupCandidate,
        candidates: Sequence[WFQGroupCandidate],
        total_group_weight: int,
        feedback_window_value: int,
        selection_epoch: int,
) -> None:
    if state is None or feedback_window_value <= 0 or chosen.stream.stream_id == 0:
        return
    cost = normalize_cost(chosen.stream.cost)
    for candidate in candidates:
        if candidate.base_group_weight == 0:
            continue
        expected = fair_share(cost, candidate.base_group_weight, max64(total_group_weight, 1))
        actual = cost if candidate.group_key == chosen.group_key else 0
        set_group_lag(
            state,
            candidate.group_key,
            apply_lag_feedback(
                group_lag(state, candidate.group_key),
                expected,
                actual,
                feedback_window_value,
            ),
        )

    if chosen.group_order >= len(prepared.groups):
        return
    for stream_id in prepared.groups[chosen.group_order].streams:
        prepared_stream = prepared.prepared_streams.get(stream_id)
        if (
                prepared_stream is None
                or prepared_stream.selection_epoch != selection_epoch
                or prepared_stream.traffic_class is not chosen.traffic_class
        ):
            continue
        expected = fair_share(
            cost,
            prepared_stream.selection.base_weight,
            max64(chosen.total_base_stream_weight, 1),
        )
        actual = cost if stream_id == chosen.stream.stream_id else 0
        set_stream_lag(
            state,
            stream_id,
            apply_lag_feedback(
                stream_lag(state, stream_id),
                expected,
                actual,
                feedback_window_value,
            ),
        )


def update_bypass_selections(
        active_streams: Sequence[int],
        selected_stream_id: int,
        bypass_selections: Dict[int, int],
) -> None:
    selected_stream_id = _uint64(selected_stream_id, "selected_stream_id")
    for stream_id in active_streams:
        stream_id = _uint64(stream_id, "stream_id")
        if is_synthetic_stream_key(stream_id):
            continue
        if stream_id == selected_stream_id:
            bypass_selections[stream_id] = 0
        else:
            bypass_selections[stream_id] = saturating_add(
                bypass_selections.get(stream_id, 0),
                1,
            )


def consume_queued_bytes(queued_bytes: Dict[int, int], stream_id: int, cost: int) -> None:
    stream_id = _uint64(stream_id, "stream_id")
    delta = normalize_cost(cost)
    if queued_bytes.get(stream_id, 0) <= delta:
        queued_bytes.pop(stream_id, None)
        return
    queued_bytes[stream_id] -= delta


def consume_prepared_queued_bytes(
        queued_bytes: Dict[int, int],
        prepared_streams: Dict[int, BatchPreparedStream],
        stream_id: int,
        cost: int,
) -> None:
    consume_queued_bytes(queued_bytes, stream_id, cost)
    prepared_stream = prepared_streams.get(stream_id)
    if prepared_stream is not None:
        prepared_stream.queued_bytes = queued_bytes.get(stream_id, 0)


def append_remaining_in_input_order(
        ordered: Sequence[int],
        size: int,
) -> tuple[int, ...]:
    size = _uint64(size, "size")
    out = list(ordered)
    if len(out) >= size:
        return tuple(out)
    selected = [False] * size
    for index in out:
        if 0 <= index < size:
            selected[index] = True
    for index in range(size):
        if not selected[index]:
            out.append(index)
    return tuple(out)


def better_stream_candidate(
        preferred: int,
        left: WFQStreamCandidate,
        right: WFQStreamCandidate,
) -> bool:
    preferred = _uint64(preferred, "preferred")
    if left.eligible != right.eligible:
        return left.eligible
    better = better_eligible_window(
        left.eligible,
        left.stream_start,
        left.stream_finish,
        right.stream_start,
        right.stream_finish,
    )
    if better is not None:
        return better
    if preferred != 0:
        left_preferred = left.stream_id == preferred
        right_preferred = right.stream_id == preferred
        if left_preferred != right_preferred:
            return left_preferred
    if left.stream_last_served != right.stream_last_served:
        return left.stream_last_served < right.stream_last_served
    return left.stream_order < right.stream_order


def record_preferred_heads(
        state: Optional[BatchState],
        candidate: WFQGroupCandidate,
        groups: Sequence[BatchBuiltGroup],
        recorded_batch_head: bool,
        recorded_group_head: list,
) -> None:
    if state is None or is_synthetic_stream_key(candidate.stream.stream_id):
        return
    if not recorded_batch_head:
        next_group, ok = next_real_group_head(groups, candidate.group_order)
        if ok:
            state.preferred_group_head = next_group
            state.has_preferred_group_head = True
        else:
            state.preferred_group_head = GroupKey()
            state.has_preferred_group_head = False
    if candidate.group_order < 0 or candidate.group_order >= len(recorded_group_head):
        return
    if recorded_group_head[candidate.group_order]:
        return
    recorded_group_head[candidate.group_order] = True
    next_stream, ok = next_real_stream_head(
        groups[candidate.group_order].streams,
        candidate.stream.stream_order,
    )
    if ok:
        state.preferred_stream_head[candidate.group_key] = next_stream
    else:
        state.preferred_stream_head.pop(candidate.group_key, None)


def snapshot_batch_tie_prefs(state: Optional[BatchState]) -> BatchTiePrefs:
    if state is None:
        return BatchTiePrefs()
    streams = tie_pref_streams_map(state, len(state.preferred_stream_head))
    streams.update(state.preferred_stream_head)
    return BatchTiePrefs(
        has_group=state.has_preferred_group_head,
        group=state.preferred_group_head,
        streams=streams,
    )


def next_real_group_head(
        groups: Sequence[BatchBuiltGroup],
        selected: int,
) -> tuple[GroupKey, bool]:
    if len(groups) < 2 or selected < 0:
        return GroupKey(), False
    for offset in range(1, len(groups)):
        next_group = groups[(selected + offset) % len(groups)].key
        if not is_transient_group_key(next_group):
            return next_group, True
    return GroupKey(), False


def next_real_stream_head(streams: Sequence[int], selected: int) -> tuple[int, bool]:
    if len(streams) < 2 or selected < 0:
        return 0, False
    for offset in range(1, len(streams)):
        next_stream = streams[(selected + offset) % len(streams)]
        if not is_synthetic_stream_key(next_stream):
            return next_stream, True
    return 0, False


def transient_batch_state(state: Optional[BatchState], cap_hint: int = 0) -> BatchTransientState:
    return BatchTransientState(
        stream_finish=transient_stream_finish_map(state, cap_hint),
        stream_last_served=transient_stream_last_served_map(state, cap_hint),
        group_virtual=transient_group_virtual_map(state, cap_hint),
        group_finish=transient_group_finish_map(state, cap_hint),
        group_last_served=transient_group_last_served_map(state, cap_hint),
    )


def _group_retained_value(
        group_key: GroupKey,
        transient_values: Dict[GroupKey, int],
        state_values: Dict[GroupKey, int],
) -> int:
    if is_transient_group_key(group_key):
        return transient_values.get(group_key, 0)
    return state_values.get(group_key, 0)


def _set_group_retained_value(
        group_key: GroupKey,
        value: int,
        transient_values: Dict[GroupKey, int],
        state_values: Dict[GroupKey, int],
) -> None:
    value = _uint64(value, "value")
    if is_transient_group_key(group_key):
        transient_values[group_key] = value
    else:
        state_values[group_key] = value


def _stream_retained_value(
        stream_id: int,
        transient_values: Dict[int, int],
        state_values: Dict[int, int],
) -> int:
    stream_id = _uint64(stream_id, "stream_id")
    if is_synthetic_stream_key(stream_id):
        return transient_values.get(stream_id, 0)
    return state_values.get(stream_id, 0)


def _set_stream_retained_value(
        stream_id: int,
        value: int,
        transient_values: Dict[int, int],
        state_values: Dict[int, int],
) -> None:
    stream_id = _uint64(stream_id, "stream_id")
    value = _uint64(value, "value")
    if is_synthetic_stream_key(stream_id):
        transient_values[stream_id] = value
    else:
        state_values[stream_id] = value


def group_virtual_time(
        state: BatchState,
        transient: BatchTransientState,
        group_key: GroupKey,
) -> int:
    return _group_retained_value(
        group_key,
        transient.group_virtual,
        state.group_virtual_time,
    )


def set_group_virtual_time(
        state: BatchState,
        transient: BatchTransientState,
        group_key: GroupKey,
        value: int,
) -> None:
    _set_group_retained_value(
        group_key,
        value,
        transient.group_virtual,
        state.group_virtual_time,
    )


def group_finish_tag(
        state: BatchState,
        transient: BatchTransientState,
        group_key: GroupKey,
) -> int:
    return _group_retained_value(
        group_key,
        transient.group_finish,
        state.group_finish_tag,
    )


def set_group_finish_tag(
        state: BatchState,
        transient: BatchTransientState,
        group_key: GroupKey,
        value: int,
) -> None:
    _set_group_retained_value(
        group_key,
        value,
        transient.group_finish,
        state.group_finish_tag,
    )


def group_last_served(
        state: BatchState,
        transient: BatchTransientState,
        group_key: GroupKey,
) -> int:
    return _group_retained_value(
        group_key,
        transient.group_last_served,
        state.group_last_service,
    )


def set_group_last_served(
        state: BatchState,
        transient: BatchTransientState,
        group_key: GroupKey,
        value: int,
) -> None:
    _set_group_retained_value(
        group_key,
        value,
        transient.group_last_served,
        state.group_last_service,
    )


def stream_finish_tag(
        state: BatchState,
        transient: BatchTransientState,
        stream_id: int,
) -> int:
    return _stream_retained_value(
        stream_id,
        transient.stream_finish,
        state.stream_finish_tag,
    )


def set_stream_finish_tag(
        state: BatchState,
        transient: BatchTransientState,
        stream_id: int,
        value: int,
) -> None:
    _set_stream_retained_value(
        stream_id,
        value,
        transient.stream_finish,
        state.stream_finish_tag,
    )


def stream_last_served(
        state: BatchState,
        transient: BatchTransientState,
        stream_id: int,
) -> int:
    return _stream_retained_value(
        stream_id,
        transient.stream_last_served,
        state.stream_last_service,
    )


def set_stream_last_served(
        state: BatchState,
        transient: BatchTransientState,
        stream_id: int,
        value: int,
) -> None:
    _set_stream_retained_value(
        stream_id,
        value,
        transient.stream_last_served,
        state.stream_last_service,
    )


def commit_wfq_selection(
        state: BatchState,
        transient: BatchTransientState,
        candidate: WFQGroupCandidate,
        active_group_weight: int,
        active_stream_weight: int,
) -> None:
    state.service_seq = saturating_add(state.service_seq, 1)
    seq = state.service_seq

    root_virtual = max64(state.root_virtual_time, candidate.group_start)
    state.root_virtual_time = saturating_add(
        root_virtual,
        service_tag(candidate.stream.cost, max64(active_group_weight, 1)),
    )

    group_virtual = group_virtual_time(state, transient, candidate.group_key)
    group_virtual = max64(group_virtual, candidate.stream.stream_start)
    set_group_virtual_time(
        state,
        transient,
        candidate.group_key,
        saturating_add(
            group_virtual,
            service_tag(candidate.stream.cost, max64(active_stream_weight, 1)),
        ),
    )
    set_group_finish_tag(state, transient, candidate.group_key, candidate.group_finish)
    set_group_last_served(state, transient, candidate.group_key, seq)
    set_stream_finish_tag(
        state,
        transient,
        candidate.stream.stream_id,
        candidate.stream.stream_finish,
    )
    set_stream_last_served(state, transient, candidate.stream.stream_id, seq)


def maybe_rebase_wfq_state(state: Optional[BatchState]) -> None:
    if state is None or state.root_virtual_time < (1 << 48):
        return
    values = [state.root_virtual_time]
    values.extend(state.group_virtual_time.values())
    values.extend(state.group_finish_tag.values())
    values.extend(state.stream_finish_tag.values())
    floor = min(values) if values else 0
    if floor == 0:
        return
    state.root_virtual_time -= floor
    for key in list(state.group_virtual_time):
        state.group_virtual_time[key] -= floor
    for key in list(state.group_finish_tag):
        state.group_finish_tag[key] -= floor
    for key in list(state.stream_finish_tag):
        state.stream_finish_tag[key] -= floor


def order_batch_indices(
        cfg: BatchConfig,
        state: Optional[BatchState],
        items: Sequence[BatchItem],
) -> tuple[int, ...]:
    cfg = coerce_batch_config(cfg)
    if cfg.urgent:
        return order_urgent_batch(items)

    if state is None:
        state = BatchState()
    else:
        normalize_batch_state(state)
    retained_real_state = has_retained_real_batch_state(state)
    if not retained_real_state:
        scrub_idle_retained_batch_state(state)

    prepared = build_batch_groups(state, items)
    if not prepared.has_real_stream_scoped:
        order = identity_order(len(items))
        if not retained_real_state:
            release_idle_batch_state_storage(state)
        return order

    transient = transient_batch_state(state, len(items))
    tie_prefs = snapshot_batch_tie_prefs(state)
    interactive_quantum = scheduler_quantum(cfg.max_frame_payload)
    feedback_window_value = feedback_window(cfg.scheduler_hint, cfg.max_frame_payload)
    batch_seq = saturating_add(state.batch_seq, 1)
    prepared.prepared_streams = apply_batch_stream_classes(
        state,
        prepared,
        cfg.scheduler_hint,
        interactive_quantum,
        batch_seq,
    )
    ordered = ordered_list(state, len(items))
    advisory_head_armed = True
    seen_real_opportunity = False
    transient_head_used = False
    recorded_batch_head = False
    recorded_group_head = recorded_group_head_list(state, len(prepared.groups))
    interactive_streak = state.interactive_streak
    class_selections_since_bulk = state.class_selections_since_bulk
    bypass_selections = bypass_selections_map(state, len(prepared.stream_meta))
    selection_epoch = 0

    while len(ordered) < len(items):
        if not seen_real_opportunity and not transient_head_used:
            group_index, stream_id, req_idx, rest, ok = pick_next_transient_ordinary_head(
                prepared.groups
            )
            if ok:
                ordered.append(req_idx)
                prepared.groups[group_index].queues[stream_id] = rest
                transient_head_used = True
                continue

        advisory_only = advisory_head_armed and prepared.has_priority_update
        selection_epoch = saturating_add(selection_epoch, 1)
        interactive_active, bulk_active = refresh_active_stream_selections(
            state,
            prepared,
            items,
            cfg,
            advisory_only,
            selection_epoch,
        )
        interactive_candidates = group_candidate_list(state, False, len(prepared.groups))
        bulk_candidates = group_candidate_list(state, True, len(prepared.groups))
        interactive_group_weight = 0
        bulk_group_weight = 0
        interactive_best = WFQGroupCandidate()
        bulk_best = WFQGroupCandidate()

        for group_order, group in enumerate(prepared.groups):
            pair = top_candidates_for_group_classes(
                cfg,
                state,
                transient,
                prepared,
                tie_prefs,
                group,
                group_order,
                interactive_quantum,
                feedback_window_value,
                interactive_active,
                bulk_active,
                selection_epoch,
                bypass_selections,
            )
            if pair.has_interactive:
                interactive_candidates.append(pair.interactive)
                interactive_group_weight = saturating_add(
                    interactive_group_weight,
                    pair.interactive.group_weight,
                )
                if not _candidate_present(interactive_best) or better_group_candidate(
                        tie_prefs,
                        pair.interactive,
                        interactive_best,
                ):
                    interactive_best = pair.interactive
            if pair.has_bulk:
                bulk_candidates.append(pair.bulk)
                bulk_group_weight = saturating_add(bulk_group_weight, pair.bulk.group_weight)
                if not _candidate_present(bulk_best) or better_group_candidate(
                        tie_prefs,
                        pair.bulk,
                        bulk_best,
                ):
                    bulk_best = pair.bulk

        if not interactive_candidates and not bulk_candidates:
            ordered = list(append_remaining_in_input_order(ordered, len(items)))
            break

        selected_class = choose_traffic_class(
            tie_prefs,
            cfg.scheduler_hint,
            interactive_best,
            bulk_best,
            interactive_streak,
            class_selections_since_bulk,
        )
        if selected_class is TrafficClass.BULK:
            if not _candidate_present(bulk_best) and _candidate_present(interactive_best):
                candidate = interactive_best
                candidates = interactive_candidates
                total_group_weight = interactive_group_weight
                active_class_streams = interactive_active
            else:
                candidate = bulk_best
                candidates = bulk_candidates
                total_group_weight = bulk_group_weight
                active_class_streams = bulk_active
        else:
            if not _candidate_present(interactive_best) and _candidate_present(bulk_best):
                candidate = bulk_best
                candidates = bulk_candidates
                total_group_weight = bulk_group_weight
                active_class_streams = bulk_active
            else:
                candidate = interactive_best
                candidates = interactive_candidates
                total_group_weight = interactive_group_weight
                active_class_streams = interactive_active

        if not _candidate_present(candidate):
            ordered = list(append_remaining_in_input_order(ordered, len(items)))
            break

        ordered.append(candidate.stream.req_idx)
        record_preferred_heads(
            state,
            candidate,
            prepared.groups,
            recorded_batch_head,
            recorded_group_head,
        )
        if not recorded_batch_head:
            recorded_batch_head = True
        update_lag_feedback(
            state,
            prepared,
            candidate,
            candidates,
            total_group_weight,
            feedback_window_value,
            selection_epoch,
        )
        update_bypass_selections(
            active_class_streams,
            candidate.stream.stream_id,
            bypass_selections,
        )
        prepared_stream = prepared.prepared_streams.get(candidate.stream.stream_id)
        if (
                prepared_stream is not None
                and prepared_stream.small_burst_armed
                and prepared_stream.queued_bytes <= interactive_quantum
        ):
            prepared_stream.small_burst_armed = False
            state.small_burst_disarmed[candidate.stream.stream_id] = None

        group = prepared.groups[candidate.group_order]
        group.queues[candidate.stream.stream_id] = remove_queue_entry(
            group.queues.get(candidate.stream.stream_id, []),
            candidate.stream.queue_pos,
        )
        consume_prepared_queued_bytes(
            prepared.queued_bytes,
            prepared.prepared_streams,
            candidate.stream.stream_id,
            candidate.stream.cost,
        )
        commit_wfq_selection(
            state,
            transient,
            candidate,
            max64(total_group_weight, 1),
            max64(candidate.total_stream_weight, 1),
        )
        if candidate.stream.is_priority_update:
            advisory_head_armed = False
        if not is_synthetic_stream_key(candidate.stream.stream_id):
            seen_real_opportunity = True
            if candidate.traffic_class is TrafficClass.BULK:
                interactive_streak = 0
                class_selections_since_bulk = 0
            else:
                interactive_streak = min((1 << 32) - 1, interactive_streak + 1)
                if _candidate_present(interactive_best) and _candidate_present(bulk_best):
                    class_selections_since_bulk = min(
                        (1 << 32) - 1,
                        class_selections_since_bulk + 1,
                    )
                else:
                    class_selections_since_bulk = 0

    retain_batch_stream_classes(
        state,
        prepared.prepared_streams,
        batch_seq,
        interactive_streak,
        class_selections_since_bulk,
    )
    maybe_rebase_wfq_state(state)
    return tuple(ordered)


def _urgent_item_key(item: BatchItem, index: int) -> tuple[int, int, int, int]:
    req = item.request
    scoped = 0 if req.stream_scoped else 1
    return req.urgency_rank, scoped, req.stream_id if req.stream_scoped else 0, index


def _urgent_item_precedes(
        candidate: BatchItem,
        candidate_index: int,
        current: BatchItem,
        current_index: int,
) -> bool:
    candidate_req = candidate.request
    current_req = current.request
    same_stream = (
            candidate_req.stream_scoped
            and current_req.stream_scoped
            and candidate_req.stream_id != 0
            and candidate_req.stream_id == current_req.stream_id
    )
    if same_stream and candidate_req.opening_frame != current_req.opening_frame:
        return candidate_req.opening_frame
    return _urgent_item_key(candidate, candidate_index) < _urgent_item_key(
        current,
        current_index,
    )


def _scheduler_hint_bias(
        hint: SchedulerHint, request: RequestMeta, stream: StreamMeta
) -> int:
    if request.is_priority_update:
        return -1
    if hint is SchedulerHint.LATENCY:
        return stream.priority
    if hint is SchedulerHint.BULK_THROUGHPUT:
        return -min(stream.priority, 16)
    return 0


def _candidate_present(candidate: Optional[WFQGroupCandidate]) -> bool:
    return candidate is not None and candidate.stream.stream_id != 0


def _uint64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return min(value, MAX_UINT64)


def uint64(value: int, name: str) -> int:
    return _uint64(value, name)


def _varint62(value: int, name: str) -> int:
    value = _uint64(value, name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % name)
    return value


def varint62(value: int, name: str) -> int:
    return _varint62(value, name)


def _int64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value > MAX_SIGNED_INT64:
        return MAX_SIGNED_INT64
    if value < -MAX_SIGNED_INT64 - 1:
        return -MAX_SIGNED_INT64 - 1
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


def require_bool(value: bool, name: str) -> bool:
    return _require_bool(value, name)


def _saturating_abs_i64(value: int) -> int:
    if value == -MAX_SIGNED_INT64 - 1:
        return MAX_SIGNED_INT64
    return abs(value)


__all__ = (
    "FALLBACK_GROUP_BUCKET",
    "AGING_ROUND_THRESHOLD",
    "BATCH_SCRATCH_RETAIN_FACTOR",
    "BATCH_SCRATCH_RETAIN_MIN_CAP",
    "BULK_ENTRY_MULTIPLIER",
    "BULK_RESERVE_WINDOW",
    "CLASS_SCORE_SCALE",
    "INTERACTIVE_BURST_LIMIT",
    "MAX_EXPLICIT_GROUPS",
    "MAX_SIGNED_INT64",
    "SYNTHETIC_STREAM_KEY_BIT",
    "WFQ_TAG_SCALE",
    "BatchTiePrefs",
    "BatchBuildResult",
    "BatchBuiltGroup",
    "BatchConfig",
    "BatchItem",
    "BatchPreparedStream",
    "BatchScratch",
    "BatchState",
    "BatchStreamSelection",
    "BatchTransientState",
    "GroupClassCandidatePair",
    "GroupKey",
    "RequestMeta",
    "StreamMeta",
    "StreamGroupBinding",
    "TrafficClass",
    "WFQGroupCandidate",
    "WFQStreamCandidate",
    "adjust_weight_for_lag",
    "append_remaining_in_input_order",
    "apply_lag_feedback",
    "apply_batch_stream_classes",
    "banded_weight",
    "batch_scratch_oversized",
    "batch_scratch_retain_limit",
    "batch_stream_meta_map",
    "better_eligible_window",
    "better_class_candidate",
    "better_group_candidate",
    "better_stream_candidate",
    "build_batch_groups",
    "build_group_class_candidate_with_group_state",
    "bypass_count",
    "choose_traffic_class",
    "class_adjusted_weight",
    "class_bias_weight",
    "classify_stream_class",
    "clamp_lag",
    "commit_wfq_selection",
    "coerce_batch_config",
    "coerce_scheduler_hint",
    "coerce_traffic_class",
    "consume_prepared_queued_bytes",
    "consume_queued_bytes",
    "fair_share",
    "feedback_window",
    "active_stream_list",
    "bypass_selections_map",
    "clear_unused_group_queue_maps",
    "group_finish_tag",
    "group_build_list",
    "group_candidate_list",
    "group_lag",
    "group_last_served",
    "group_order_list",
    "group_state_map",
    "group_virtual_time",
    "group_weight",
    "has_retained_real_batch_state",
    "identity_order",
    "is_fresh_group",
    "is_fresh_stream",
    "is_synthetic_stream_key",
    "is_transient_group_key",
    "lag_scaled_weight",
    "maybe_rebase_wfq_state",
    "max64",
    "min64",
    "next_real_group_head",
    "next_real_stream_head",
    "normalize_batch_state",
    "normalize_cost",
    "order_batch_indices",
    "order_urgent_batch",
    "ordered_list",
    "peek_stream_candidate",
    "pick_next_transient_ordinary_head",
    "prepare_batch_scratch_for_build",
    "prepared_stream_map",
    "priority_weight",
    "queued_bytes_map",
    "record_preferred_heads",
    "recorded_group_head_list",
    "refresh_active_stream_selections",
    "release_idle_batch_state_storage",
    "recycle_group_queue_entry_lists",
    "recycle_stream_order_lists",
    "remove_queue_entry",
    "require_bool",
    "retain_batch_stream_classes",
    "scheduler_quantum",
    "scrub_idle_retained_batch_state",
    "select_stream_candidate",
    "selected_list",
    "service_tag",
    "set_group_finish_tag",
    "set_group_lag",
    "set_group_last_served",
    "set_group_virtual_time",
    "set_stream_finish_tag",
    "set_stream_lag",
    "set_stream_last_served",
    "scaled_class_tag",
    "should_apply_aging",
    "snapshot_batch_tie_prefs",
    "stream_lag",
    "stream_finish_tag",
    "stream_last_served",
    "stream_order_map",
    "stream_weight",
    "synthetic_stream_key",
    "tie_pref_streams_map",
    "top_candidates_for_group_classes",
    "transient_batch_state",
    "transient_group_finish_map",
    "transient_group_last_served_map",
    "transient_group_virtual_map",
    "transient_stream_finish_map",
    "transient_stream_last_served_map",
    "uint64",
    "update_bypass_selections",
    "update_lag_feedback",
    "varint62",
    "next_group_queue_entry_list",
    "next_group_queue_map",
    "next_stream_order_list",
)
