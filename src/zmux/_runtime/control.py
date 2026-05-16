"""Pending control/advisory frame coordination helpers.

This module mirrors the bookkeeping shape of Go ``control.go`` without
depending on the not-yet-wired native session object.  The concrete runtime can
compose this state object under its session lock and use the pure helpers for
budgeting, coalescing, and write-batch construction.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, MutableSequence
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Callable, Optional

from .._wire.varint import encode_varint, varint_len
from ..config import Settings, default_settings
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    ProtocolError,
    SessionClosed,
)
from ..frame import Frame
from ..payload import (
    MetadataUpdate,
    StreamMetadata,
    build_priority_update_payload as _build_priority_update_payload,
    parse_priority_update_payload as _parse_priority_update_payload,
)
from ..protocol import ErrorCode, FrameType, MAX_VARINT62

MIN_PENDING_CONTROL_BUDGET = 64 << 10
MIN_PENDING_PRIORITY_BUDGET = 64 << 10
DEFAULT_MAX_WRITE_BATCH_FRAMES = 32
DEFAULT_URGENCY_RANK = 100
MAX_UINT64 = (1 << 64) - 1
_URGENT_TYPE_RANKS = {
    FrameType.CLOSE: 0,
    FrameType.GOAWAY: 1,
    FrameType.ABORT: 2,
    FrameType.RESET: 3,
    FrameType.STOP_SENDING: 4,
    FrameType.MAX_DATA: 5,
    FrameType.BLOCKED: 6,
    FrameType.PONG: 7,
    FrameType.PING: 8,
}


class SessionControlKind(IntEnum):
    """Session-scoped pending control frame kinds."""

    MAX_DATA = 0
    BLOCKED = 1


class StreamControlKind(IntEnum):
    """Stream-scoped pending control frame kinds."""

    MAX_DATA = 0
    BLOCKED = 1


class WriteLane(str, Enum):
    """Runtime write lane used for pending protocol work."""

    URGENT = "urgent"
    ADVISORY = "advisory"
    ORDINARY = "ordinary"


class PendingPriorityQueueStatus(IntEnum):
    """Result status for local PRIORITY_UPDATE queueing."""

    NONE = 0
    ACCEPTED = 1
    DROPPED_BUDGET = 2
    DROPPED_MEMORY = 3
    DROPPED_UNAVAILABLE = 4


@dataclass(frozen=True)
class PriorityUpdatePlan(object):
    """Projected memory state for replacing one pending priority update."""

    next_pending_bytes: int = 0
    projected_tracked: int = 0
    accept: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "next_pending_bytes", _nonnegative_int(self.next_pending_bytes)
        )
        object.__setattr__(
            self, "projected_tracked", _nonnegative_int(self.projected_tracked)
        )
        object.__setattr__(self, "accept", _require_bool(self.accept, "accept"))


@dataclass(frozen=True)
class AdvisoryHandoffPlan(object):
    """Projected tracked memory after moving pending advisory bytes to a queue."""

    projected_tracked: int = 0
    accept: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "projected_tracked", _nonnegative_int(self.projected_tracked)
        )
        object.__setattr__(self, "accept", _require_bool(self.accept, "accept"))


@dataclass(frozen=True)
class PendingControlValue(object):
    """A coalesced varint control value and its presence bit."""

    value: int = 0
    present: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", clamp_varint62(self.value))
        object.__setattr__(self, "present", _require_bool(self.present, "present"))

    def byte_cost(self, stream_id: int = 0) -> int:
        if not self.present:
            return 0
        if stream_id:
            return pending_stream_control_bytes(stream_id, self.value)
        return pending_session_control_bytes(self.value)


@dataclass(frozen=True)
class PendingControlMetrics(object):
    """Small diagnostic counters owned by pending control bookkeeping."""

    coalesced_terminal_signals: int = 0
    superseded_terminal_signals: int = 0
    dropped_local_priority_updates: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "coalesced_terminal_signals",
            _nonnegative_int(self.coalesced_terminal_signals),
        )
        object.__setattr__(
            self,
            "superseded_terminal_signals",
            _nonnegative_int(self.superseded_terminal_signals),
        )
        object.__setattr__(
            self,
            "dropped_local_priority_updates",
            _nonnegative_int(self.dropped_local_priority_updates),
        )


@dataclass(frozen=True)
class WriteRequest(object):
    """A runtime write request assembled from pending control frames."""

    frames: tuple[Frame, ...]
    queued_bytes: int
    lane: WriteLane = WriteLane.ORDINARY
    origin: str = "protocol"
    terminal_policy: str = "reject"
    clone_frames_before_send: bool = False
    urgent_reserved: bool = False
    advisory_reserved: bool = False

    def __post_init__(self) -> None:
        frames = tuple(self.frames)
        object.__setattr__(self, "frames", frames)
        object.__setattr__(self, "queued_bytes", _nonnegative_int(self.queued_bytes))
        object.__setattr__(self, "lane", _coerce_write_lane(self.lane))
        object.__setattr__(
            self,
            "terminal_policy",
            str(self.terminal_policy),
        )
        object.__setattr__(
            self,
            "clone_frames_before_send",
            _require_bool(self.clone_frames_before_send, "clone_frames_before_send"),
        )
        object.__setattr__(self, "urgent_reserved", self.lane is WriteLane.URGENT)
        object.__setattr__(self, "advisory_reserved", self.lane is WriteLane.ADVISORY)


@dataclass(frozen=True)
class PendingWriteRequestResult(object):
    """Result returned by one pending-write take attempt."""

    request: Optional[WriteRequest] = None
    error: Optional[BaseException] = None

    def has_request(self) -> bool:
        return self.request is not None


@dataclass(frozen=True)
class PendingPriorityQueueResult(object):
    """Structured result for local PRIORITY_UPDATE queueing."""

    status: PendingPriorityQueueStatus = PendingPriorityQueueStatus.NONE
    projected_tracked: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "status",
            _coerce_pending_priority_queue_status(self.status),
        )
        object.__setattr__(
            self,
            "projected_tracked",
            _nonnegative_int(self.projected_tracked),
        )

    def accepted(self) -> bool:
        return self.status is PendingPriorityQueueStatus.ACCEPTED

    def structured_error(self) -> Optional[BaseException]:
        if self.status is PendingPriorityQueueStatus.ACCEPTED:
            return None
        if self.status is PendingPriorityQueueStatus.DROPPED_UNAVAILABLE:
            return _session_closed_error()
        if self.status is PendingPriorityQueueStatus.DROPPED_BUDGET:
            return _local_internal_error("pending priority update budget exceeded")
        if self.status is PendingPriorityQueueStatus.DROPPED_MEMORY:
            return _local_internal_error(
                "pending priority update memory cap exceeded: %d"
                % self.projected_tracked
            )
        return _local_internal_error("pending priority update rejected")


@dataclass(frozen=True)
class PreparedPriorityUpdate(object):
    """A pending priority update moved out for stream-local write ordering."""

    stream_id: int = 0
    payload: bytes = b""
    frame_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "stream_id", _nonnegative_int(self.stream_id))
        object.__setattr__(self, "payload", _payload_bytes(self.payload, "payload"))
        object.__setattr__(self, "frame_bytes", _nonnegative_int(self.frame_bytes))

    def has_frame(self) -> bool:
        return self.stream_id != 0 and bool(self.payload) and self.frame_bytes > 0

    def frame(self) -> Optional[Frame]:
        if not self.has_frame():
            return None
        return build_pending_priority_update_frame(self.stream_id, self.payload)


@dataclass(frozen=True)
class PendingControlSnapshot(object):
    """Immutable inspection snapshot for tests and diagnostics."""

    control_bytes: int = 0
    priority_bytes: int = 0
    prepared_priority_bytes: int = 0
    has_session_max_data: bool = False
    session_max_data: int = 0
    has_session_blocked: bool = False
    session_blocked: int = 0
    pending_goaway_bytes: int = 0
    stream_max_data_count: int = 0
    stream_blocked_count: int = 0
    terminal_count: int = 0
    priority_update_count: int = 0
    metrics: PendingControlMetrics = field(default_factory=PendingControlMetrics)


class PendingTxFrameCollector(object):
    """Collect a bounded write batch using Go's first-frame-admission rule."""

    def __init__(
            self,
            frames: Iterable[Frame] = (),
            *,
            max_frames: int = DEFAULT_MAX_WRITE_BATCH_FRAMES,
            max_bytes: int = 0,
    ) -> None:
        self.frames = list(frames)
        self.max_frames = _nonnegative_int(max_frames)
        self.max_bytes = _nonnegative_int(max_bytes)
        self.queued_bytes = 0
        for frame in self.frames:
            self.queued_bytes = _saturating_add(
                self.queued_bytes,
                frame_buffered_bytes(frame),
            )
        self.stopped = False

    def append(self, frame: Frame) -> bool:
        frame_bytes = frame_buffered_bytes(frame)
        if self.frames:
            if self.max_frames and len(self.frames) >= self.max_frames:
                self.stopped = True
                return False
            if self.max_bytes and self.queued_bytes + frame_bytes > self.max_bytes:
                self.stopped = True
                return False
        self.frames.append(frame)
        self.queued_bytes = _saturating_add(self.queued_bytes, frame_bytes)
        if self.max_frames and len(self.frames) >= self.max_frames:
            self.stopped = True
        return True

    def can_append_frames(self, frames: Iterable[Frame]) -> bool:
        frames = tuple(frames)
        if not frames:
            return True
        if self.frames and self.max_frames and len(self.frames) + len(frames) > self.max_frames:
            return False
        if self.frames and self.max_bytes:
            total = self.queued_bytes
            for frame in frames:
                total = _saturating_add(total, frame_buffered_bytes(frame))
            if total > self.max_bytes:
                return False
        return True

    def append_frames(self, frames: Iterable[Frame]) -> bool:
        frames = tuple(frames)
        if not self.can_append_frames(frames):
            self.stopped = True
            return False
        if frames and not self.frames:
            self.frames.extend(frames)
            for frame in frames:
                self.queued_bytes = _saturating_add(
                    self.queued_bytes, frame_buffered_bytes(frame)
                )
            if self.max_frames and len(self.frames) >= self.max_frames:
                self.stopped = True
            return True
        for frame in frames:
            if not self.append(frame):
                return False
        return True

    def empty(self) -> bool:
        return not self.frames

    def as_tuple(self) -> tuple[Frame, ...]:
        return tuple(self.frames)


class PendingControlState(object):
    """Coalesced pending control/advisory state for one session.

    The owning runtime is expected to call methods while holding its session
    lock.  This object does no I/O and keeps all queue operations bounded by
    configured byte/frame budgets.
    """

    def __init__(
            self,
            *,
            local_settings: Optional[Settings] = None,
            peer_settings: Optional[Settings] = None,
            pending_control_budget: int = 0,
            pending_priority_budget: int = 0,
            session_memory_hard_cap: int = 0,
            urgent_lane_cap: int = 0,
            max_write_batch_frames: int = DEFAULT_MAX_WRITE_BATCH_FRAMES,
            allow_non_close_control: bool = True,
    ) -> None:
        self.local_settings = local_settings or default_settings()
        self.peer_settings = peer_settings or default_settings()
        self.pending_control_budget = _nonnegative_int(pending_control_budget)
        self.pending_priority_budget = _nonnegative_int(pending_priority_budget)
        self.session_memory_hard_cap = _nonnegative_int(session_memory_hard_cap)
        self.urgent_lane_cap = _nonnegative_int(urgent_lane_cap)
        self.max_write_batch_frames = _nonnegative_int(max_write_batch_frames)
        self.allow_non_close_control = _require_bool(
            allow_non_close_control,
            "allow_non_close_control",
        )

        self.control_bytes = 0
        self.session_max_data = PendingControlValue()
        self.session_blocked = PendingControlValue()
        self.session_blocked_at = 0
        self.session_blocked_set = False
        self.pending_goaway_payload = b""
        self.has_pending_goaway = False
        self.stream_max_data = OrderedDict()
        self.stream_blocked = OrderedDict()
        self.terminal_frames = OrderedDict()
        self.priority_updates = OrderedDict()
        self.priority_bytes = 0
        self.prepared_priority_bytes = 0
        self.metrics = PendingControlMetrics()

    def pending_control_budget_value(self) -> int:
        if self.pending_control_budget:
            return self.pending_control_budget
        max_payload = self.peer_settings.max_control_payload_bytes
        if not max_payload:
            max_payload = self.local_settings.max_control_payload_bytes
        if not max_payload:
            max_payload = default_settings().max_control_payload_bytes
        return max(MIN_PENDING_CONTROL_BUDGET, _saturating_mul(max_payload, 8))

    def pending_priority_budget_value(self) -> int:
        if self.pending_priority_budget:
            return self.pending_priority_budget
        max_payload = self.peer_settings.max_extension_payload_bytes
        if not max_payload:
            max_payload = self.local_settings.max_extension_payload_bytes
        if not max_payload:
            max_payload = default_settings().max_extension_payload_bytes
        return max(MIN_PENDING_PRIORITY_BUDGET, _saturating_mul(max_payload, 8))

    def session_memory_hard_cap_value(self) -> int:
        return self.session_memory_hard_cap or MAX_UINT64

    def tracked_session_memory(self) -> int:
        return _saturating_add(
            self.control_bytes,
            _saturating_add(self.priority_bytes, self.prepared_priority_bytes),
        )

    def replace_pending_control_bytes(
            self, old_bytes: int, new_bytes: int, *, force: bool = False
    ) -> bool:
        old_bytes = _nonnegative_int(old_bytes)
        new_bytes = _nonnegative_int(new_bytes)
        projected = max(0, self.control_bytes - old_bytes)
        projected = _saturating_add(projected, new_bytes)
        if not force and projected > self.pending_control_budget_value():
            return False
        tracked = self.tracked_session_memory()
        projected_tracked = max(0, tracked - self.control_bytes)
        projected_tracked = _saturating_add(projected_tracked, projected)
        if not force and projected_tracked > self.session_memory_hard_cap_value():
            return False
        self.control_bytes = projected
        return True

    def pending_session_control_value(
            self, kind: SessionControlKind
    ) -> PendingControlValue:
        kind = _coerce_session_control_kind(kind)
        if kind is SessionControlKind.MAX_DATA:
            return self.session_max_data
        return self.session_blocked

    def set_pending_session_control(
            self, kind: SessionControlKind, value: int
    ) -> bool:
        kind = _coerce_session_control_kind(kind)
        value = clamp_varint62(value)
        current = self.pending_session_control_value(kind)
        if not self.replace_pending_control_bytes(
                current.byte_cost(), pending_session_control_bytes(value)
        ):
            return False
        replacement = PendingControlValue(value, True)
        if kind is SessionControlKind.MAX_DATA:
            self.session_max_data = replacement
        else:
            self.session_blocked = replacement
        return True

    def drop_pending_session_control(self, kind: SessionControlKind) -> bool:
        kind = _coerce_session_control_kind(kind)
        current = self.pending_session_control_value(kind)
        if not current.present:
            return False
        self.replace_pending_control_bytes(current.byte_cost(), 0, force=True)
        if kind is SessionControlKind.MAX_DATA:
            self.session_max_data = PendingControlValue()
        else:
            self.session_blocked = PendingControlValue()
        return True

    def queue_pending_session_control(
            self, kind: SessionControlKind, value: int
    ) -> bool:
        if not self.ensure_pending_non_close_control():
            return False
        kind = _coerce_session_control_kind(kind)
        value = clamp_varint62(value)
        current = self.pending_session_control_value(kind)
        if kind is SessionControlKind.MAX_DATA:
            if current.present and value <= current.value:
                return False
        else:
            if current.present and current.value == value:
                return False
            if self.session_blocked_set and self.session_blocked_at == value:
                return False
        if not self.set_pending_session_control(kind, value):
            return False
        if kind is SessionControlKind.BLOCKED:
            self.session_blocked_set = True
            self.session_blocked_at = value
        return True

    def ensure_pending_session_max_data(self, value: int) -> bool:
        if not self.ensure_pending_non_close_control():
            return False
        value = clamp_varint62(value)
        current = self.session_max_data
        if current.present and value <= current.value:
            return True
        return self.set_pending_session_control(SessionControlKind.MAX_DATA, value)

    def clear_session_blocked_state(self) -> None:
        self.session_blocked_set = False
        self.session_blocked_at = 0

    def set_pending_goaway_payload(self, payload: bytes) -> bool:
        payload = _payload_bytes(payload, "payload")
        old_bytes = len(self.pending_goaway_payload) if self.has_pending_goaway else 0
        if not self.replace_pending_control_bytes(old_bytes, len(payload), force=True):
            return False
        self.pending_goaway_payload = payload
        self.has_pending_goaway = True
        return True

    def clear_pending_goaway(self) -> None:
        if not self.has_pending_goaway:
            return
        self.replace_pending_control_bytes(
            len(self.pending_goaway_payload), 0, force=True
        )
        self.pending_goaway_payload = b""
        self.has_pending_goaway = False

    def set_pending_stream_control(
            self, kind: StreamControlKind, stream_id: int, value: int
    ) -> bool:
        kind = _coerce_stream_control_kind(kind)
        stream_id = _require_stream_id(stream_id)
        value = clamp_varint62(value)
        queue = self._stream_queue(kind)
        old_value = queue.get(stream_id)
        old_bytes = (
            pending_stream_control_bytes(stream_id, old_value)
            if old_value is not None
            else 0
        )
        new_bytes = pending_stream_control_bytes(stream_id, value)
        if not self.replace_pending_control_bytes(old_bytes, new_bytes):
            return False
        queue[stream_id] = value
        return True

    def drop_pending_stream_control_entry(
            self, kind: StreamControlKind, stream_id: int
    ) -> bool:
        kind = _coerce_stream_control_kind(kind)
        stream_id = _require_stream_id(stream_id)
        queue = self._stream_queue(kind)
        value = queue.pop(stream_id, None)
        if value is None:
            return False
        self.replace_pending_control_bytes(
            pending_stream_control_bytes(stream_id, value), 0, force=True
        )
        return True

    def queue_stream_max_data(self, stream_id: int, value: int) -> bool:
        if not self.ensure_pending_non_close_control():
            return False
        stream_id = _require_stream_id(stream_id)
        value = clamp_varint62(value)
        current = self.stream_max_data.get(stream_id)
        if current is not None and value <= current:
            return True
        return self.set_pending_stream_control(
            StreamControlKind.MAX_DATA, stream_id, value
        )

    def queue_stream_blocked(self, stream_id: int, value: int) -> bool:
        if not self.ensure_pending_non_close_control():
            return False
        stream_id = _require_stream_id(stream_id)
        value = clamp_varint62(value)
        current = self.stream_blocked.get(stream_id)
        if current is not None and current == value:
            return False
        return self.set_pending_stream_control(
            StreamControlKind.BLOCKED, stream_id, value
        )

    def set_pending_terminal_frames(
            self,
            stream_id: int,
            frames: Iterable[Frame],
            *,
            coalesced: bool = False,
            superseded: bool = False,
    ) -> bool:
        if not self.ensure_pending_non_close_control():
            return False
        stream_id = _require_stream_id(stream_id)
        coalesced = _require_bool(coalesced, "coalesced")
        superseded = _require_bool(superseded, "superseded")
        frames = tuple(frames)
        old_frames = self.terminal_frames.get(stream_id, ())
        old_bytes = sum(frame_buffered_bytes(frame) for frame in old_frames)
        new_bytes = sum(frame_buffered_bytes(frame) for frame in frames)
        if not self.replace_pending_control_bytes(old_bytes, new_bytes):
            return False
        if frames:
            self.terminal_frames[stream_id] = frames
        else:
            self.terminal_frames.pop(stream_id, None)
        self._bump_terminal_metrics(coalesced, superseded)
        return True

    def drop_pending_terminal_control_entry(self, stream_id: int) -> bool:
        stream_id = _require_stream_id(stream_id)
        frames = self.terminal_frames.pop(stream_id, None)
        if not frames:
            return False
        self.replace_pending_control_bytes(
            sum(frame_buffered_bytes(frame) for frame in frames), 0, force=True
        )
        return True

    def queue_priority_update(
            self, stream_id: int, payload: bytes
    ) -> PendingPriorityQueueResult:
        stream_id = _require_stream_id(stream_id)
        payload = _payload_bytes(payload, "payload")
        if not payload:
            return PendingPriorityQueueResult()
        if not self.ensure_pending_non_close_control():
            return PendingPriorityQueueResult(
                PendingPriorityQueueStatus.DROPPED_UNAVAILABLE
            )
        budget = self.pending_priority_budget_value()
        if budget == 0:
            return PendingPriorityQueueResult(PendingPriorityQueueStatus.DROPPED_BUDGET)
        old_len = len(self.priority_updates.get(stream_id, b""))
        plan = plan_pending_priority_update(
            self.tracked_session_memory(),
            self.priority_bytes,
            old_len,
            len(payload),
            budget,
            self.session_memory_hard_cap_value(),
        )
        if plan.next_pending_bytes > budget:
            return PendingPriorityQueueResult(
                PendingPriorityQueueStatus.DROPPED_BUDGET, plan.projected_tracked
            )
        if plan.projected_tracked > self.session_memory_hard_cap_value():
            return PendingPriorityQueueResult(
                PendingPriorityQueueStatus.DROPPED_MEMORY, plan.projected_tracked
            )
        self.priority_updates[stream_id] = payload
        self.priority_bytes = plan.next_pending_bytes
        return PendingPriorityQueueResult(
            PendingPriorityQueueStatus.ACCEPTED, plan.projected_tracked
        )

    def build_and_queue_priority_update(
            self,
            stream_id: int,
            capabilities: int,
            update: MetadataUpdate,
            max_payload: Optional[int] = None,
    ) -> PendingPriorityQueueResult:
        if max_payload is None:
            max_payload = self.peer_settings.max_extension_payload_bytes
        payload = build_priority_update_payload(capabilities, update, max_payload)
        return self.queue_priority_update(stream_id, payload)

    def drop_pending_priority_update_entry(self, stream_id: int) -> bool:
        stream_id = _require_stream_id(stream_id)
        payload = self.priority_updates.pop(stream_id, None)
        if payload is None:
            return False
        self.priority_bytes = max(0, self.priority_bytes - len(payload))
        return True

    def take_pending_priority_update_frame(
            self, stream_id: int
    ) -> PreparedPriorityUpdate:
        if not self.ensure_pending_non_close_control():
            return PreparedPriorityUpdate()
        stream_id = _require_stream_id(stream_id)
        payload = self.priority_updates.get(stream_id)
        if not payload:
            self.drop_pending_priority_update_entry(stream_id)
            return PreparedPriorityUpdate()
        frame = build_pending_priority_update_frame(stream_id, payload)
        frame_bytes = frame_buffered_bytes(frame)
        plan = plan_priority_advisory_handoff(
            self.tracked_session_memory(),
            len(payload),
            frame_bytes,
            self.session_memory_hard_cap_value(),
        )
        if not plan.accept:
            self.drop_pending_priority_update_entry(stream_id)
            return PreparedPriorityUpdate()
        self.drop_pending_priority_update_entry(stream_id)
        self.prepared_priority_bytes = _saturating_add(
            self.prepared_priority_bytes, frame_bytes
        )
        return PreparedPriorityUpdate(stream_id, payload, frame_bytes)

    def release_prepared_priority_bytes(self, count: int) -> None:
        count = _nonnegative_int(count)
        self.prepared_priority_bytes = max(0, self.prepared_priority_bytes - count)

    def restore_prepared_priority_update(self, prepared: PreparedPriorityUpdate) -> bool:
        if not prepared.has_frame():
            return False
        self.release_prepared_priority_bytes(prepared.frame_bytes)
        if not self.allow_non_close_control:
            return False
        result = self.queue_priority_update(prepared.stream_id, prepared.payload)
        return result.accepted()

    def ensure_pending_non_close_control(self) -> bool:
        if self.allow_non_close_control:
            return True
        self.clear_pending_non_close_control_state()
        return False

    def clear_pending_non_close_control_state(self) -> None:
        keep_control_bytes = (
            len(self.pending_goaway_payload) if self.has_pending_goaway else 0
        )
        self.session_max_data = PendingControlValue()
        self.session_blocked = PendingControlValue()
        self.stream_max_data.clear()
        self.stream_blocked.clear()
        self.terminal_frames.clear()
        self.priority_updates.clear()
        self.priority_bytes = 0
        self.prepared_priority_bytes = 0
        self.control_bytes = keep_control_bytes
        self.clear_session_blocked_state()

    def has_pending_control_work(self) -> bool:
        return (
                bool(self.terminal_frames)
                or self.session_max_data.present
                or bool(self.stream_max_data)
                or self.session_blocked.present
                or bool(self.stream_blocked)
                or bool(self.priority_updates)
        )

    def drain_pending_urgent_control_frames(self) -> tuple[Frame, ...]:
        collector = PendingTxFrameCollector(max_frames=0, max_bytes=0)
        self._visit_pending_urgent_control_frames(collector)
        return collector.as_tuple()

    def take_pending_control_write_request(self) -> PendingWriteRequestResult:
        if not self.ensure_pending_non_close_control():
            return PendingWriteRequestResult()
        result = self.take_pending_urgent_control_request()
        if result.has_request() or result.error is not None:
            return result
        return self.take_pending_priority_update_request()

    def take_pending_urgent_control_request(self) -> PendingWriteRequestResult:
        if not (
                self.terminal_frames
                or self.session_max_data.present
                or self.stream_max_data
                or self.session_blocked.present
                or self.stream_blocked
        ):
            return PendingWriteRequestResult()
        collector = PendingTxFrameCollector(
            max_frames=self.max_write_batch_frames,
            max_bytes=self.urgent_lane_cap,
        )
        self._visit_pending_urgent_control_frames(collector)
        if collector.empty():
            return PendingWriteRequestResult()
        projected = _saturating_add(self.tracked_session_memory(), collector.queued_bytes)
        hard_cap = self.session_memory_hard_cap_value()
        if projected > hard_cap:
            return PendingWriteRequestResult(
                error=_session_memory_cap_error(
                    "queue urgent control", projected, hard_cap
                )
            )
        request = build_pending_control_write_request(
            collector.as_tuple(), collector.queued_bytes, WriteLane.URGENT
        )
        return PendingWriteRequestResult(request=request)

    def take_pending_priority_update_request(self) -> PendingWriteRequestResult:
        while self.priority_updates:
            collector = PendingTxFrameCollector(max_frames=self.max_write_batch_frames)
            accepted_ids = []
            removed_pending_bytes = 0
            for stream_id, payload in list(self.priority_updates.items()):
                if collector.stopped:
                    break
                frame = build_pending_priority_update_frame(stream_id, payload)
                if not collector.append(frame):
                    break
                accepted_ids.append(stream_id)
                removed_pending_bytes = _saturating_add(
                    removed_pending_bytes, len(payload)
                )
            if not accepted_ids:
                return PendingWriteRequestResult()
            plan = plan_priority_advisory_handoff(
                self.tracked_session_memory(),
                removed_pending_bytes,
                collector.queued_bytes,
                self.session_memory_hard_cap_value(),
            )
            if not plan.accept:
                for stream_id in accepted_ids:
                    self.drop_pending_priority_update_entry(stream_id)
                continue
            for stream_id in accepted_ids:
                self.drop_pending_priority_update_entry(stream_id)
            request = build_pending_control_write_request(
                collector.as_tuple(), collector.queued_bytes, WriteLane.ADVISORY
            )
            return PendingWriteRequestResult(request=request)
        return PendingWriteRequestResult()

    def snapshot(self) -> PendingControlSnapshot:
        return PendingControlSnapshot(
            control_bytes=self.control_bytes,
            priority_bytes=self.priority_bytes,
            prepared_priority_bytes=self.prepared_priority_bytes,
            has_session_max_data=self.session_max_data.present,
            session_max_data=self.session_max_data.value,
            has_session_blocked=self.session_blocked.present,
            session_blocked=self.session_blocked.value,
            pending_goaway_bytes=(
                len(self.pending_goaway_payload) if self.has_pending_goaway else 0
            ),
            stream_max_data_count=len(self.stream_max_data),
            stream_blocked_count=len(self.stream_blocked),
            terminal_count=len(self.terminal_frames),
            priority_update_count=len(self.priority_updates),
            metrics=self.metrics,
        )

    def recompute_control_bytes(self) -> int:
        total = 0
        total = _saturating_add(total, self.session_max_data.byte_cost())
        total = _saturating_add(total, self.session_blocked.byte_cost())
        if self.has_pending_goaway:
            total = _saturating_add(total, len(self.pending_goaway_payload))
        for stream_id, value in self.stream_max_data.items():
            total = _saturating_add(
                total, pending_stream_control_bytes(stream_id, value)
            )
        for stream_id, value in self.stream_blocked.items():
            total = _saturating_add(
                total, pending_stream_control_bytes(stream_id, value)
            )
        for frames in self.terminal_frames.values():
            total = _saturating_add(
                total, sum(frame_buffered_bytes(frame) for frame in frames)
            )
        self.control_bytes = total
        return total

    def recompute_priority_bytes(self) -> int:
        total = 0
        for payload in self.priority_updates.values():
            total = _saturating_add(total, len(payload))
        self.priority_bytes = total
        return self.priority_bytes

    def _visit_pending_urgent_control_frames(
            self, collector: PendingTxFrameCollector
    ) -> None:
        self._visit_terminal_frames(collector)
        self._visit_session_control(SessionControlKind.MAX_DATA, collector)
        self._visit_stream_control(StreamControlKind.MAX_DATA, collector)
        self._visit_session_control(SessionControlKind.BLOCKED, collector)
        self._visit_stream_control(StreamControlKind.BLOCKED, collector)

    def _visit_terminal_frames(self, collector: PendingTxFrameCollector) -> None:
        for stream_id, frames in list(self.terminal_frames.items()):
            if collector.stopped:
                break
            if not collector.append_frames(frames):
                break
            self.drop_pending_terminal_control_entry(stream_id)

    def _visit_session_control(
            self, kind: SessionControlKind, collector: PendingTxFrameCollector
    ) -> None:
        if collector.stopped:
            return
        current = self.pending_session_control_value(kind)
        if not current.present:
            return
        frame = make_pending_varint_control_frame(
            session_control_frame_type(kind), 0, current.value
        )
        if not collector.append(frame):
            return
        self.drop_pending_session_control(kind)

    def _visit_stream_control(
            self, kind: StreamControlKind, collector: PendingTxFrameCollector
    ) -> None:
        queue = self._stream_queue(kind)
        for stream_id in sorted(queue):
            if collector.stopped:
                break
            value = queue[stream_id]
            frame = make_pending_varint_control_frame(
                stream_control_frame_type(kind), stream_id, value
            )
            if not collector.append(frame):
                break
            self.drop_pending_stream_control_entry(kind, stream_id)

    def _stream_queue(self, kind: StreamControlKind) -> OrderedDict:
        kind = _coerce_stream_control_kind(kind)
        if kind is StreamControlKind.MAX_DATA:
            return self.stream_max_data
        return self.stream_blocked

    def _bump_terminal_metrics(self, coalesced: bool, superseded: bool) -> None:
        if not coalesced and not superseded:
            return
        self.metrics = PendingControlMetrics(
            coalesced_terminal_signals=(
                    self.metrics.coalesced_terminal_signals + int(coalesced)
            ),
            superseded_terminal_signals=(
                    self.metrics.superseded_terminal_signals + int(superseded)
            ),
            dropped_local_priority_updates=self.metrics.dropped_local_priority_updates,
        )


def store_pending_control_payload(existing: bytes, payload: bytes) -> bytes:
    """Return an owned copy of a pending control payload."""

    existing = _payload_bytes(existing, "existing")
    payload = _payload_bytes(payload, "payload")
    return existing if existing == payload else payload


def is_urgent_type(frame_type: FrameType) -> bool:
    """Return whether ``frame_type`` belongs on the urgent control lane."""

    return _coerce_frame_type(frame_type) in _URGENT_TYPE_RANKS


def urgency_rank(frame_type: FrameType) -> int:
    """Return Go's stable urgent-lane ordering rank for a frame type."""

    return _URGENT_TYPE_RANKS.get(_coerce_frame_type(frame_type), DEFAULT_URGENCY_RANK)


def project_tracked_memory_delta(tracked: int, removed: int, added: int) -> int:
    """Project tracked memory after removing one bucket and adding another."""

    tracked = _nonnegative_int(tracked)
    removed = _nonnegative_int(removed)
    added = _nonnegative_int(added)
    tracked = 0 if removed >= tracked else tracked - removed
    return _saturating_add(tracked, added)


def plan_pending_priority_update(
        tracked: int,
        current_pending: int,
        previous_entry: int,
        next_entry: int,
        budget: int,
        hard_cap: int,
) -> PriorityUpdatePlan:
    """Plan whether replacing one pending priority update fits the budgets."""

    tracked = _nonnegative_int(tracked)
    current_pending = _nonnegative_int(current_pending)
    previous_entry = _nonnegative_int(previous_entry)
    next_entry = _nonnegative_int(next_entry)
    budget = _nonnegative_int(budget)
    hard_cap = _nonnegative_int(hard_cap)
    next_pending = project_tracked_memory_delta(
        current_pending, previous_entry, next_entry
    )
    projected = project_tracked_memory_delta(tracked, current_pending, next_pending)
    return PriorityUpdatePlan(
        next_pending,
        projected,
        next_pending <= budget and projected <= hard_cap,
    )


def plan_priority_advisory_handoff(
        tracked: int, removed_pending: int, advisory_bytes: int, hard_cap: int
) -> AdvisoryHandoffPlan:
    """Plan whether pending advisory bytes can be handed off to the queue."""

    tracked = _nonnegative_int(tracked)
    removed_pending = _nonnegative_int(removed_pending)
    advisory_bytes = _nonnegative_int(advisory_bytes)
    hard_cap = _nonnegative_int(hard_cap)
    projected = project_tracked_memory_delta(tracked, removed_pending, advisory_bytes)
    return AdvisoryHandoffPlan(projected, projected <= hard_cap)


def pending_control_varint_bytes(value: int) -> int:
    return varint_len(clamp_varint62(value))


def pending_session_control_bytes(value: int) -> int:
    return pending_control_varint_bytes(value)


def pending_stream_control_bytes(stream_id: int, value: int) -> int:
    return pending_control_varint_bytes(stream_id) + pending_control_varint_bytes(value)


def session_control_frame_type(kind: SessionControlKind) -> FrameType:
    kind = _coerce_session_control_kind(kind)
    if kind is SessionControlKind.MAX_DATA:
        return FrameType.MAX_DATA
    return FrameType.BLOCKED


def stream_control_frame_type(kind: StreamControlKind) -> FrameType:
    kind = _coerce_stream_control_kind(kind)
    if kind is StreamControlKind.MAX_DATA:
        return FrameType.MAX_DATA
    return FrameType.BLOCKED


def make_pending_varint_control_frame(
        frame_type: FrameType, stream_id: int, value: int
) -> Frame:
    return Frame(
        frame_type,
        _nonnegative_int(stream_id),
        0,
        encode_varint(clamp_varint62(value)),
    )


def build_pending_priority_update_frame(stream_id: int, payload: bytes) -> Frame:
    return Frame(
        FrameType.EXT,
        _require_stream_id(stream_id),
        0,
        _payload_bytes(payload, "payload"),
    )


def build_priority_update_payload(
        capabilities: int, update: MetadataUpdate, max_payload: int = 4096
) -> bytes:
    return _build_priority_update_payload(capabilities, update, max_payload)


def append_priority_update_payload(
        dst: MutableSequence[int],
        capabilities: int,
        update: MetadataUpdate,
        max_payload: int = 4096,
) -> bytes:
    payload = build_priority_update_payload(capabilities, update, max_payload)
    dst.extend(payload)
    return payload


def parse_priority_update_payload(payload: bytes) -> tuple[StreamMetadata, bool]:
    return _parse_priority_update_payload(_payload_bytes(payload, "payload"))


def frame_buffered_bytes(frame: Frame) -> int:
    # Go's txFrameBufferedBytes/txFrameQueueCost and the Java/Rust queues use
    # a coarse retained cost: frame type plus payload bytes. Stream-id and
    # varint envelope lengths are encoded later and do not drive queue pressure.
    return _saturating_add(1, len(frame.payload))


def build_pending_control_write_request(
        frames: Iterable[Frame], queued_bytes: int, lane: WriteLane
) -> WriteRequest:
    return WriteRequest(tuple(frames), queued_bytes, _coerce_write_lane(lane))


def collect_pending_write_requests(
        take: Callable[[], PendingWriteRequestResult]
) -> tuple[WriteRequest, ...]:
    requests = []
    while True:
        result = take()
        if result.error is not None:
            raise result.error
        if not result.has_request():
            return tuple(requests)
        requests.append(result.request)


def clamp_varint62(value: int) -> int:
    value = _nonnegative_int(value)
    return min(value, MAX_VARINT62)


def _coerce_session_control_kind(kind: SessionControlKind) -> SessionControlKind:
    if isinstance(kind, SessionControlKind):
        return kind
    if isinstance(kind, bool):
        raise TypeError("kind must be a SessionControlKind or integer")
    return SessionControlKind(int(kind))


def _coerce_stream_control_kind(kind: StreamControlKind) -> StreamControlKind:
    if isinstance(kind, StreamControlKind):
        return kind
    if isinstance(kind, bool):
        raise TypeError("kind must be a StreamControlKind or integer")
    return StreamControlKind(int(kind))


def _coerce_write_lane(lane: WriteLane) -> WriteLane:
    if isinstance(lane, WriteLane):
        return lane
    if not isinstance(lane, str):
        raise TypeError("lane must be a WriteLane or string")
    return WriteLane(str(lane))


def _coerce_frame_type(frame_type: FrameType) -> FrameType:
    if isinstance(frame_type, FrameType):
        return frame_type
    if isinstance(frame_type, bool):
        raise TypeError("frame_type must be a FrameType or integer")
    return FrameType(int(frame_type))


def _coerce_pending_priority_queue_status(
        status: PendingPriorityQueueStatus,
) -> PendingPriorityQueueStatus:
    if isinstance(status, PendingPriorityQueueStatus):
        return status
    if isinstance(status, bool):
        raise TypeError("status must be a PendingPriorityQueueStatus or integer")
    return PendingPriorityQueueStatus(int(status))


def _require_stream_id(stream_id: int) -> int:
    stream_id = _nonnegative_int(stream_id)
    if stream_id == 0:
        raise ValueError("stream_id must be non-zero")
    return stream_id


def _nonnegative_int(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an integer")
    if value < 0:
        raise ValueError("value must be >= 0")
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a bool" % name)
    return value


def _payload_bytes(value: bytes, name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    try:
        return memoryview(value).tobytes()
    except TypeError:
        pass
    raise TypeError("%s must be bytes-like" % name)


def _saturating_add(left: int, right: int) -> int:
    return min(MAX_UINT64, left + right)


def _saturating_mul(left: int, right: int) -> int:
    return min(MAX_UINT64, left * right)


def _session_closed_error() -> SessionClosed:
    return SessionClosed(
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.WRITE,
    )


def _local_internal_error(message: str) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.INTERNAL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.WRITE,
    )


def _session_memory_cap_error(operation: str, tracked: int, hard_cap: int) -> ProtocolError:
    return _local_internal_error(
        "%s: session memory cap exceeded: tracked=%d cap=%d"
        % (operation, tracked, hard_cap)
    )


__all__ = (
    "DEFAULT_URGENCY_RANK",
    "DEFAULT_MAX_WRITE_BATCH_FRAMES",
    "AdvisoryHandoffPlan",
    "MIN_PENDING_CONTROL_BUDGET",
    "MIN_PENDING_PRIORITY_BUDGET",
    "PendingControlMetrics",
    "PendingControlSnapshot",
    "PendingControlState",
    "PendingControlValue",
    "PendingPriorityQueueResult",
    "PendingPriorityQueueStatus",
    "PendingTxFrameCollector",
    "PendingWriteRequestResult",
    "PriorityUpdatePlan",
    "PreparedPriorityUpdate",
    "SessionControlKind",
    "StreamControlKind",
    "WriteLane",
    "WriteRequest",
    "append_priority_update_payload",
    "build_pending_control_write_request",
    "build_pending_priority_update_frame",
    "build_priority_update_payload",
    "clamp_varint62",
    "collect_pending_write_requests",
    "frame_buffered_bytes",
    "is_urgent_type",
    "make_pending_varint_control_frame",
    "parse_priority_update_payload",
    "pending_control_varint_bytes",
    "pending_session_control_bytes",
    "pending_stream_control_bytes",
    "plan_pending_priority_update",
    "plan_priority_advisory_handoff",
    "project_tracked_memory_delta",
    "session_control_frame_type",
    "store_pending_control_payload",
    "stream_control_frame_type",
    "urgency_rank",
)
