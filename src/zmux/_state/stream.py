"""Stream-local state machines for the native zmux runtime.

This module mirrors the large Go ``stream_state.go`` file as small Python
objects: metadata/visibility, lifecycle flags, half-state terminal errors,
per-stream accounting, pending control frames, and DATA frame construction.
Concrete session objects own locks and I/O; these classes only mutate local
state and return deterministic plans.
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Optional, Tuple

from .half import _coerce_enum, _require_bool
from .tombstone import (
    LateDataAction,
    LateDataCause,
    StreamTombstone,
    build_stream_tombstone,
    should_compact_terminal,
)
from .visibility import (
    LocalOpenPhase,
    LocalOpenVisibility,
    should_enqueue_accepted,
    should_finalize_peer_active,
    should_flush_priority_update,
    should_flush_stream_blocked,
    should_flush_stream_max_data,
    should_reclaim_unseen_local_stream,
)
from .._runtime.read_loop import saturating_add
from .._runtime.stream import (
    RecvHalfState,
    SendHalfState,
    StreamHalfState,
    StreamReadBuffer,
    TerminalErrorChoice,
    fully_terminal,
    read_error_choice,
    terminal_error_priority,
)
from ..config import OpenOptions
from ..errors import (
    ApplicationError,
    EmptyMetadataUpdate,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    PriorityUpdateUnavailable,
    ProtocolError,
    ReadClosed,
    StreamNotWritable,
    TerminationKind,
    WriteClosed,
    ZmuxError,
    error_code,
    error_reason,
)
from ..frame import Frame
from ..payload import (
    MetadataUpdate,
    StreamMetadata,
    build_open_metadata_prefix,
    build_priority_update_payload,
    parse_priority_update_payload,
)
from ..protocol import (
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    MAX_VARINT62,
    Capability,
    ErrorCode,
    FrameType,
    capabilities_can_carry_group_in_update,
    capabilities_can_carry_group_on_open,
    capabilities_can_carry_open_info,
    capabilities_can_carry_priority_in_update,
    capabilities_can_carry_priority_on_open,
)
from ..streams import ReadableBuffer

INVALID_STREAM_QUEUE_INDEX = -1
MAX_UINT64 = (1 << 64) - 1
_DEFAULT_METADATA_CAPABILITIES = int(
    Capability.OPEN_METADATA | Capability.PRIORITY_HINTS | Capability.STREAM_GROUPS
)


class MetadataUpdateRoute(IntEnum):
    """Where a local metadata update should be carried."""

    PRIORITY_FRAME = 0
    OPEN_METADATA = 1

    def uses_open_metadata(self) -> bool:
        return self is MetadataUpdateRoute.OPEN_METADATA


class ReceivedMetadataCarriage(IntEnum):
    """Wire carriage used by peer metadata."""

    UPDATE = 0
    OPEN = 1

    def allows_open_info(self) -> bool:
        return self is ReceivedMetadataCarriage.OPEN


class PendingStreamFlag(IntFlag):
    """Bitset matching Go's streamPending* flags."""

    NONE = 0
    MAX_DATA = 1
    BLOCKED = 2
    PRIORITY_UPDATE = 4
    TERMINAL_STOP = 8
    TERMINAL_RESET = 16
    TERMINAL_ABORT = 32


_TERMINAL_CONTROL_FLAGS = (
        PendingStreamFlag.TERMINAL_STOP
        | PendingStreamFlag.TERMINAL_RESET
        | PendingStreamFlag.TERMINAL_ABORT
)
_SUPERSEDED_TERMINAL_FLAGS = (
        PendingStreamFlag.TERMINAL_STOP | PendingStreamFlag.TERMINAL_RESET
)


class PendingStreamControlKind(IntEnum):
    MAX_DATA = 0
    BLOCKED = 1


class PendingStreamQueueKind(IntEnum):
    MAX_DATA = 0
    BLOCKED = 1
    PRIORITY = 2
    TERMINAL = 3


class TerminalAbortSource(IntEnum):
    LOCAL = 0
    PEER = 1


class TerminalResetSource(IntEnum):
    DIRECT = 0
    FROM_STOP_SENDING = 1


class DataFrameTraits(IntFlag):
    NONE = 0
    FIN = 1
    OPEN_METADATA = 2

    def sends_fin(self) -> bool:
        return bool(self & DataFrameTraits.FIN)

    def includes_open_metadata(self) -> bool:
        return bool(self & DataFrameTraits.OPEN_METADATA)


@dataclass(frozen=True)
class MetadataChange:
    """Result of replacing a stream metadata snapshot."""

    previous_open_info_len: int = 0
    next_open_info_len: int = 0
    previous_group: Optional[int] = None
    next_group: Optional[int] = None
    changed: bool = False

    def open_info_changed(self) -> bool:
        return self.previous_open_info_len != self.next_open_info_len

    def group_changed(self) -> bool:
        return self.previous_group != self.next_group


@dataclass(frozen=True)
class ReceivedMetadataPolicy:
    allow_priority: bool = False
    allow_group: bool = False
    allow_open_info_payload: bool = False


@dataclass
class StreamMetadataState:
    """Peer-visible metadata and local-open visibility bookkeeping."""

    metadata: StreamMetadata = field(default_factory=StreamMetadata)
    opened_on_wire: bool = False
    peer_visible: bool = False
    opening_frame_pending: bool = False
    pending_priority_update_priority: Optional[int] = None
    pending_priority_update_group: Optional[int] = None
    pending_priority_update_payload: bytes = b""
    pending_priority_update: bool = False
    priority_update_queued: bool = False

    @classmethod
    def from_open_options(
            cls, open_options: Optional[OpenOptions] = None
    ) -> "StreamMetadataState":
        options = open_options or OpenOptions()
        metadata = StreamMetadata(
            options.initial_priority,
            _normalize_group(options.initial_group),
            options.open_info,
        )
        if metadata.is_empty():
            metadata = StreamMetadata()
        return cls(metadata=metadata)

    def open_info(self) -> bytes:
        return self.metadata.open_info

    def open_info_len(self) -> int:
        return len(self.metadata.open_info)

    def local_open_phase(self, opened_locally: bool) -> LocalOpenPhase:
        opened_locally = _require_bool(opened_locally, "opened_locally")
        return LocalOpenVisibility(
            opened_locally,
            self.opened_on_wire,
            self.peer_visible,
            self.opening_frame_pending,
        ).phase()

    def mark_opened_on_wire(self) -> None:
        self.opened_on_wire = True

    def should_mark_peer_visible(self, opened_locally: bool, id_assigned: bool) -> bool:
        id_assigned = _require_bool(id_assigned, "id_assigned")
        return id_assigned and self.local_open_phase(opened_locally).should_mark_peer_visible()

    def mark_peer_visible(self) -> None:
        self.peer_visible = True

    def mark_opening_frame_pending(self) -> None:
        if not self.peer_visible:
            self.opening_frame_pending = True

    def clear_opening_frame_pending(self) -> None:
        self.opening_frame_pending = False

    def awaiting_peer_visibility(
            self, opened_locally: bool, id_assigned: bool, fully_terminal_value: bool
    ) -> bool:
        id_assigned = _require_bool(id_assigned, "id_assigned")
        fully_terminal_value = _require_bool(
            fully_terminal_value, "fully_terminal_value"
        )
        return (
                id_assigned
                and not fully_terminal_value
                and self.local_open_phase(opened_locally).awaiting_peer_visibility()
        )

    def can_take_pending_priority_update(self, opened_locally: bool) -> bool:
        opened_locally = _require_bool(opened_locally, "opened_locally")
        return self.local_open_phase(opened_locally).can_take_pending_priority_update()

    def build_opening_prefix(
            self, capabilities: int, max_frame_payload: int = 16384
    ) -> bytes:
        return build_open_metadata_prefix(
            capabilities,
            _priority_on_open(self.metadata.priority),
            self.metadata.group,
            self.metadata.open_info,
            max_frame_payload,
        )

    def validate_metadata_update_as_open(
            self,
            update: MetadataUpdate,
            capabilities: int,
            max_frame_payload: int = 16384,
    ) -> None:
        validate_open_metadata_update_capability(capabilities, update)
        next_metadata = self._next_metadata_for_update(update)
        build_open_metadata_prefix(
            capabilities,
            _priority_on_open(next_metadata.priority),
            next_metadata.group,
            next_metadata.open_info,
            max_frame_payload,
        )

    def apply_metadata_update(
            self,
            update: MetadataUpdate,
            capabilities: int,
            max_frame_payload: int = 16384,
    ) -> MetadataChange:
        next_metadata = self._next_metadata_for_update(update)
        if not self.opened_on_wire:
            validate_open_metadata_update_capability(capabilities, update)
            build_open_metadata_prefix(
                capabilities,
                _priority_on_open(next_metadata.priority),
                next_metadata.group,
                next_metadata.open_info,
                max_frame_payload,
            )
        return self.replace_metadata(next_metadata)

    def apply_open_metadata(
            self,
            capabilities: int,
            priority: Optional[int] = None,
            group: Optional[int] = None,
            open_info: bytes = b"",
    ) -> MetadataChange:
        next_priority = (
            _normalize_optional_varint(priority, "priority")
            if priority is not None and capabilities_can_carry_priority_on_open(capabilities)
            else self.metadata.priority
        )
        next_group = (
            _normalize_group(group)
            if group is not None and capabilities_can_carry_group_on_open(capabilities)
            else self.metadata.group
        )
        next_open_info = (
            _payload_bytes(open_info, "open_info")
            if capabilities_can_carry_open_info(capabilities)
            else self.metadata.open_info
        )
        return self.replace_metadata(
            StreamMetadata(next_priority, next_group, next_open_info)
        )

    def apply_priority_update(
            self, capabilities: int, metadata: StreamMetadata, valid: bool = True
    ) -> MetadataChange:
        valid = _require_bool(valid, "valid")
        if not valid:
            return MetadataChange()
        next_priority = (
            metadata.priority
            if metadata.priority is not None
               and capabilities_can_carry_priority_in_update(capabilities)
            else self.metadata.priority
        )
        next_group = (
            _normalize_group(metadata.group)
            if metadata.group is not None
               and capabilities_can_carry_group_in_update(capabilities)
            else self.metadata.group
        )
        if next_priority == self.metadata.priority and next_group == self.metadata.group:
            return MetadataChange()
        return self.replace_metadata(
            StreamMetadata(next_priority, next_group, self.metadata.open_info)
        )

    def apply_received_metadata(
            self,
            metadata: StreamMetadata,
            capabilities: int,
            carriage: ReceivedMetadataCarriage,
    ) -> MetadataChange:
        policy = received_metadata_policy(capabilities, carriage)
        next_priority = (
            metadata.priority
            if policy.allow_priority and metadata.priority is not None
            else self.metadata.priority
        )
        next_group = (
            _normalize_group(metadata.group)
            if policy.allow_group and metadata.group is not None
            else self.metadata.group
        )
        next_open_info = (
            metadata.open_info
            if policy.allow_open_info_payload
            else self.metadata.open_info
        )
        return self.replace_metadata(
            StreamMetadata(next_priority, next_group, next_open_info)
        )

    def clear_retained_open_info(self) -> MetadataChange:
        if not self.metadata.open_info:
            return MetadataChange()
        return self.replace_metadata(
            StreamMetadata(self.metadata.priority, self.metadata.group, b"")
        )

    def replace_metadata(self, next_metadata: StreamMetadata) -> MetadataChange:
        next_metadata = next_metadata or StreamMetadata()
        previous = self.metadata
        self.metadata = StreamMetadata(
            next_metadata.priority,
            _normalize_group(next_metadata.group),
            next_metadata.open_info,
        )
        return MetadataChange(
            len(previous.open_info),
            len(self.metadata.open_info),
            previous.group,
            self.metadata.group,
            previous != self.metadata,
        )

    def stage_priority_update(
            self,
            priority: Optional[int] = None,
            group: Optional[int] = None,
            payload: bytes = b"",
            *,
            group_present: bool = False,
    ) -> None:
        group_present = _require_bool(group_present, "group_present")
        if priority is not None:
            self.pending_priority_update_priority = _normalize_optional_varint(
                priority, "priority"
            )
        if group_present or group is not None or self.pending_priority_update_group is None:
            self.pending_priority_update_group = _normalize_group(group)
        self.pending_priority_update_payload = _payload_bytes(payload, "payload")
        self.pending_priority_update = True

    def has_pending_priority_update(self) -> bool:
        return self.pending_priority_update

    def mark_priority_update_queued(self) -> None:
        self.priority_update_queued = True

    def clear_priority_update_queued(self) -> None:
        self.priority_update_queued = False

    def clear_pending_priority_update(self) -> None:
        self.pending_priority_update = False
        self.pending_priority_update_priority = None
        self.pending_priority_update_group = None
        self.pending_priority_update_payload = b""
        self.priority_update_queued = False

    def _next_metadata_for_update(self, update: MetadataUpdate) -> StreamMetadata:
        if update.is_empty():
            raise ValueError("metadata update has no fields")
        return StreamMetadata(
            self.metadata.priority if update.priority is None else update.priority,
            self.metadata.group if update.group is None else _normalize_group(update.group),
            self.metadata.open_info,
        )


@dataclass
class StreamLifecycleState:
    """Visibility, accept, event, and active-count flags."""

    application_visible: bool = False
    id_assigned: bool = False
    accept_queued: bool = False
    accepted: bool = False
    opened_event_sent: bool = False
    accepted_event_sent: bool = False
    churn_counted: bool = False
    active_counted: bool = False
    provisional_tracked: bool = False
    unseen_local_tracked: bool = False
    provisional_created_at: Optional[float] = None
    stream_id: int = 0
    visibility_sequence: int = 0

    def visible_stream_id(self, opened_on_wire: bool) -> int:
        opened_on_wire = _require_bool(opened_on_wire, "opened_on_wire")
        return self.stream_id if opened_on_wire else 0

    def assign_stream_id(self, stream_id: int) -> None:
        self.stream_id = _require_varint62(stream_id, "stream_id")
        self.id_assigned = True

    def mark_accepted(self) -> None:
        self.accepted = True

    def mark_application_visible(self) -> None:
        self.application_visible = True

    def mark_churn_counted(self) -> None:
        self.churn_counted = True

    def mark_active_counted(self) -> None:
        self.active_counted = True

    def clear_active_counted(self) -> None:
        self.active_counted = False

    def mark_opened_event_sent(self) -> None:
        self.opened_event_sent = True

    def mark_accepted_event_sent(self) -> None:
        self.accepted_event_sent = True

    def clear_pending_tracking(self) -> None:
        self.provisional_tracked = False
        self.provisional_created_at = None
        self.unseen_local_tracked = False


@dataclass
class StreamAdvisoryState:
    """Retained peer reasons and scheduling-advisory state."""

    send_stop_reason_bytes: int = 0
    recv_reset_reason_bytes: int = 0
    recv_abort_reason_bytes: int = 0
    stop_sending_graceful_deadline: Optional[float] = None
    scheduling_group_tracked: bool = False
    tracked_scheduling_group: int = 0

    def record_send_stop_reason_bytes(self, reason_bytes: int) -> None:
        self.send_stop_reason_bytes = _nonnegative_int(reason_bytes, "reason_bytes")

    def record_recv_reset_reason_bytes(self, reason_bytes: int) -> None:
        self.recv_reset_reason_bytes = _nonnegative_int(reason_bytes, "reason_bytes")

    def record_recv_abort_reason_bytes(self, reason_bytes: int) -> None:
        self.recv_abort_reason_bytes = _nonnegative_int(reason_bytes, "reason_bytes")

    def retained_peer_reason_bytes(self) -> int:
        total = saturating_add(self.send_stop_reason_bytes, self.recv_reset_reason_bytes)
        return saturating_add(total, self.recv_abort_reason_bytes)

    def clear_retained_peer_reason_bytes(self) -> None:
        self.send_stop_reason_bytes = 0
        self.recv_reset_reason_bytes = 0
        self.recv_abort_reason_bytes = 0

    def arm_stop_sending_graceful_drain(
            self, deadline: Optional[float], send_terminal: bool
    ) -> None:
        if deadline is None or deadline <= 0 or send_terminal:
            self.clear_stop_sending_graceful_drain()
            return
        self.stop_sending_graceful_deadline = float(deadline)

    def clear_stop_sending_graceful_drain(self) -> None:
        self.stop_sending_graceful_deadline = None

    def stop_sending_graceful_expired(self, now: float) -> bool:
        return (
                self.stop_sending_graceful_deadline is not None
                and float(now) >= self.stop_sending_graceful_deadline
        )

    def mark_scheduling_group_tracked(self, bucket: int) -> None:
        bucket = _nonnegative_int(bucket, "bucket")
        self.scheduling_group_tracked = bucket != 0
        self.tracked_scheduling_group = bucket

    def clear_scheduling_group_tracked(self) -> None:
        self.scheduling_group_tracked = False
        self.tracked_scheduling_group = 0


@dataclass
class StreamSendAccountingState:
    local_send_started: bool = False
    peer_send_limit: int = 0
    reserved_send_bytes: int = 0
    queued_data_bytes: int = 0
    inflight_queued_bytes: int = 0
    blocked_at: int = 0
    blocked_queued: bool = False
    sent_bytes: int = 0

    def mark_local_send_started(self) -> None:
        self.local_send_started = True

    def initialize_peer_send_limit(self, value: int) -> None:
        self.peer_send_limit = _nonnegative_int(value, "value")

    def raise_peer_send_limit(self, value: int) -> None:
        self.peer_send_limit = max(self.peer_send_limit, _nonnegative_int(value, "value"))
        self.clear_blocked()

    def reserve_send_bytes(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.reserved_send_bytes = saturating_add(self.reserved_send_bytes, value)

    def release_reserved_send_bytes(self, value: int) -> None:
        self.reserved_send_bytes = max(
            0, self.reserved_send_bytes - _nonnegative_int(value, "value")
        )

    def reserve_queued_data_bytes(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.queued_data_bytes = saturating_add(self.queued_data_bytes, value)

    def release_queued_data_bytes(self, value: int) -> None:
        self.queued_data_bytes = max(
            0, self.queued_data_bytes - _nonnegative_int(value, "value")
        )

    def reserve_inflight_queued_bytes(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.inflight_queued_bytes = saturating_add(self.inflight_queued_bytes, value)

    def release_inflight_queued_bytes(self, value: int) -> None:
        self.inflight_queued_bytes = max(
            0, self.inflight_queued_bytes - _nonnegative_int(value, "value")
        )

    def mark_blocked_queued(self, value: int) -> None:
        self.blocked_queued = True
        self.blocked_at = _require_varint62(value, "value")

    def clear_blocked(self) -> None:
        self.blocked_queued = False
        self.blocked_at = 0

    def commit_reserved_send_bytes(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.reserved_send_bytes = max(0, self.reserved_send_bytes - value)
        self.sent_bytes = saturating_add(self.sent_bytes, value)
        self.clear_blocked()

    def clear_pending_buffered_state(self) -> None:
        self.reserved_send_bytes = 0
        self.queued_data_bytes = 0
        self.inflight_queued_bytes = 0
        self.clear_blocked()


@dataclass
class StreamReceiveAccountingState:
    recv_pending: int = 0
    recv_buffer: int = 0
    late_data_received: int = 0

    def add_recv_pending(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.recv_pending = saturating_add(self.recv_pending, value)

    def account_received(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.recv_buffer = saturating_add(self.recv_buffer, value)

    def release_budget(self, value: int) -> int:
        value = min(_nonnegative_int(value, "value"), self.recv_buffer)
        self.recv_buffer -= value
        return value

    def clear_recv_pending(self) -> None:
        self.recv_pending = 0

    def clear(self) -> None:
        self.recv_pending = 0
        self.recv_buffer = 0

    def record_late_data_received(self, value: int) -> None:
        value = _nonnegative_int(value, "value")
        self.late_data_received = saturating_add(self.late_data_received, value)


@dataclass
class StreamReceiveWindowState:
    recv_advertised_limit: int = 0
    initial_receive_window: int = 0
    recv_received_bytes: int = 0

    def initialize(self, recv_advertised_limit: int) -> None:
        normalized = _nonnegative_int(recv_advertised_limit, "recv_advertised_limit")
        self.recv_advertised_limit = normalized
        self.initial_receive_window = normalized

    def record_received_bytes(self, length: int) -> None:
        length = _nonnegative_int(length, "length")
        self.recv_received_bytes = saturating_add(self.recv_received_bytes, length)

    def raise_recv_advertised_limit(self, value: int) -> None:
        self.recv_advertised_limit = max(
            self.recv_advertised_limit, _nonnegative_int(value, "value")
        )


@dataclass
class StreamQueueMembershipState:
    provisional_index: int = INVALID_STREAM_QUEUE_INDEX
    accept_index: int = INVALID_STREAM_QUEUE_INDEX
    unseen_local_index: int = INVALID_STREAM_QUEUE_INDEX
    enqueued: bool = False

    def clear(self) -> None:
        self.provisional_index = INVALID_STREAM_QUEUE_INDEX
        self.accept_index = INVALID_STREAM_QUEUE_INDEX
        self.unseen_local_index = INVALID_STREAM_QUEUE_INDEX
        self.enqueued = False


@dataclass(frozen=True)
class PendingStreamControlValue:
    value: int = 0
    present: bool = False


@dataclass(frozen=True)
class PendingTerminalResult:
    changed: bool = False
    coalesced: bool = False
    superseded: bool = False


@dataclass
class PendingStreamTerminalState:
    opener: Optional[Frame] = None
    stop_payload: bytes = b""
    reset_payload: bytes = b""
    abort_payload: bytes = b""
    buffered_bytes: int = 0

    @property
    def opener_set(self) -> bool:
        return self.opener is not None

    def clear(self) -> None:
        self.opener = None
        self.stop_payload = b""
        self.reset_payload = b""
        self.abort_payload = b""
        self.buffered_bytes = 0


@dataclass
class PendingStreamState:
    """Per-stream pending control/advisory queue state."""

    priority: bytes = b""
    control: dict = field(default_factory=dict)
    terminal: PendingStreamTerminalState = field(default_factory=PendingStreamTerminalState)
    queue_index: dict = field(default_factory=dict)
    flags: PendingStreamFlag = PendingStreamFlag.NONE

    def __post_init__(self) -> None:
        if not self.queue_index:
            self.queue_index = {
                kind: INVALID_STREAM_QUEUE_INDEX for kind in PendingStreamQueueKind
            }
        if not self.control:
            self.control = {kind: 0 for kind in PendingStreamControlKind}

    def pending_control_value(
            self, kind: PendingStreamControlKind
    ) -> PendingStreamControlValue:
        kind = _coerce_pending_control_kind(kind)
        flag = pending_stream_control_flag(kind)
        if not (self.flags & flag):
            return PendingStreamControlValue()
        return PendingStreamControlValue(self.control.get(kind, 0), True)

    def set_pending_control_value(
            self, kind: PendingStreamControlKind, value: int
    ) -> None:
        kind = _coerce_pending_control_kind(kind)
        self.control[kind] = _require_varint62(value, "value")
        self.flags |= pending_stream_control_flag(kind)

    def clear_pending_control_value(self, kind: PendingStreamControlKind) -> None:
        kind = _coerce_pending_control_kind(kind)
        self.control[kind] = 0
        self.flags &= ~pending_stream_control_flag(kind)

    def skip_pending_control_queue(
            self,
            kind: PendingStreamControlKind,
            value: int,
            *,
            blocked_queued: bool = False,
            blocked_at: int = 0,
    ) -> bool:
        kind = _coerce_pending_control_kind(kind)
        value = _require_varint62(value, "value")
        blocked_queued = _require_bool(blocked_queued, "blocked_queued")
        blocked_at = _require_varint62(blocked_at, "blocked_at")
        pending = self.pending_control_value(kind)
        if kind is PendingStreamControlKind.MAX_DATA:
            return pending.present and value <= pending.value
        if kind is PendingStreamControlKind.BLOCKED:
            return (pending.present and pending.value == value) or (
                    blocked_queued and blocked_at == value
            )
        return True

    @staticmethod
    def pending_control_flush_state(
            kind: PendingStreamControlKind,
            *,
            id_assigned: bool,
            local_send: bool,
            local_receive: bool,
            phase: LocalOpenPhase,
            read_stopped: bool,
            recv_terminal_value: bool,
            send_half: SendHalfState,
    ) -> Tuple[bool, bool]:
        kind = _coerce_pending_control_kind(kind)
        id_assigned = _require_bool(id_assigned, "id_assigned")
        local_send = _require_bool(local_send, "local_send")
        local_receive = _require_bool(local_receive, "local_receive")
        read_stopped = _require_bool(read_stopped, "read_stopped")
        recv_terminal_value = _require_bool(
            recv_terminal_value, "recv_terminal_value"
        )
        if kind is PendingStreamControlKind.MAX_DATA:
            return should_flush_stream_max_data(
                id_assigned, local_receive, phase, read_stopped, recv_terminal_value
            )
        if kind is PendingStreamControlKind.BLOCKED:
            return should_flush_stream_blocked(id_assigned, local_send, phase, send_half)
        return False, False

    def set_pending_priority_update(self, payload: bytes) -> None:
        self.priority = _payload_bytes(payload, "payload")
        if self.priority:
            self.flags |= PendingStreamFlag.PRIORITY_UPDATE
        else:
            self.flags &= ~PendingStreamFlag.PRIORITY_UPDATE

    def has_pending_priority_update(self) -> bool:
        return bool(self.flags & PendingStreamFlag.PRIORITY_UPDATE and self.priority)

    def clear_pending_priority_update(self) -> None:
        self.set_pending_priority_update(b"")

    @staticmethod
    def pending_priority_flush_state(
            phase: LocalOpenPhase, send_half: SendHalfState
    ) -> Tuple[bool, bool]:
        return should_flush_priority_update(phase, send_half)

    def pending_queue_index(self, kind: PendingStreamQueueKind) -> int:
        return self.queue_index.get(_coerce_pending_queue_kind(kind), INVALID_STREAM_QUEUE_INDEX)

    def set_pending_queue_index(self, kind: PendingStreamQueueKind, index: int) -> None:
        self.queue_index[_coerce_pending_queue_kind(kind)] = int(index)

    def in_pending_queue(self, kind: PendingStreamQueueKind) -> bool:
        kind = _coerce_pending_queue_kind(kind)
        if kind is PendingStreamQueueKind.MAX_DATA:
            return bool(self.flags & PendingStreamFlag.MAX_DATA)
        if kind is PendingStreamQueueKind.BLOCKED:
            return bool(self.flags & PendingStreamFlag.BLOCKED)
        if kind is PendingStreamQueueKind.PRIORITY:
            return self.has_pending_priority_update()
        if kind is PendingStreamQueueKind.TERMINAL:
            return self.has_pending_terminal_control()
        return False

    def has_pending_terminal_control(self) -> bool:
        return bool(self.flags & _TERMINAL_CONTROL_FLAGS)

    def set_terminal_opener(self, frame: Optional[Frame], stream_id: int = 0) -> None:
        self.terminal.opener = frame
        if stream_id > 0:
            self.recompute_pending_terminal_control_bytes(stream_id)
        elif not self.has_pending_terminal_control():
            self.terminal.buffered_bytes = 0

    def set_terminal_stop(self, payload: bytes, stream_id: int = 0) -> PendingTerminalResult:
        return self._set_non_abort_terminal(
            PendingStreamFlag.TERMINAL_STOP,
            "stop_payload",
            payload,
            stream_id,
        )

    def set_terminal_reset(self, payload: bytes, stream_id: int = 0) -> PendingTerminalResult:
        return self._set_non_abort_terminal(
            PendingStreamFlag.TERMINAL_RESET,
            "reset_payload",
            payload,
            stream_id,
        )

    def _set_non_abort_terminal(
            self,
            flag: PendingStreamFlag,
            payload_attr: str,
            payload: bytes,
            stream_id: int,
    ) -> PendingTerminalResult:
        payload = _payload_bytes(payload, "payload")
        if self.flags & PendingStreamFlag.TERMINAL_ABORT:
            return PendingTerminalResult(coalesced=True)
        if self.flags & flag and getattr(self.terminal, payload_attr) == payload:
            return PendingTerminalResult(coalesced=True)
        setattr(self.terminal, payload_attr, payload)
        self.flags |= flag
        self.recompute_pending_terminal_control_bytes(stream_id)
        return PendingTerminalResult(changed=True)

    def set_terminal_abort(self, payload: bytes, stream_id: int = 0) -> PendingTerminalResult:
        payload = _payload_bytes(payload, "payload")
        if self.flags & PendingStreamFlag.TERMINAL_ABORT and self.terminal.abort_payload == payload:
            return PendingTerminalResult(coalesced=True)
        superseded = bool(
            self.flags & _SUPERSEDED_TERMINAL_FLAGS
            or self.terminal.opener is not None
        )
        self.terminal.opener = None
        self.terminal.stop_payload = b""
        self.terminal.reset_payload = b""
        self.flags &= ~_SUPERSEDED_TERMINAL_FLAGS
        self.terminal.abort_payload = payload
        self.flags |= PendingStreamFlag.TERMINAL_ABORT
        self.recompute_pending_terminal_control_bytes(stream_id)
        return PendingTerminalResult(changed=True, superseded=superseded)

    def pending_terminal_frames(self, stream_id: int) -> Tuple[Frame, ...]:
        stream_id = _require_stream_id(stream_id, "stream_id")
        if not self.has_pending_terminal_control():
            return ()
        frames = []
        if self.terminal.opener is not None:
            frames.append(self.terminal.opener)
        if self.flags & PendingStreamFlag.TERMINAL_ABORT:
            frames.append(Frame(FrameType.ABORT, stream_id, 0, self.terminal.abort_payload))
            return tuple(frames)
        if self.flags & PendingStreamFlag.TERMINAL_STOP:
            frames.append(
                Frame(FrameType.STOP_SENDING, stream_id, 0, self.terminal.stop_payload)
            )
        if self.flags & PendingStreamFlag.TERMINAL_RESET:
            frames.append(Frame(FrameType.RESET, stream_id, 0, self.terminal.reset_payload))
        return tuple(frames)

    def pending_terminal_flush_state(self) -> Tuple[bool, bool]:
        return self.has_pending_terminal_control(), False

    def pending_terminal_control_bytes(self) -> int:
        return self.terminal.buffered_bytes

    def recompute_pending_terminal_control_bytes(self, stream_id: int) -> int:
        if stream_id <= 0 or not self.has_pending_terminal_control():
            self.terminal.buffered_bytes = 0
            return 0
        self.terminal.buffered_bytes = sum(
            frame_buffered_bytes(frame) for frame in self.pending_terminal_frames(stream_id)
        )
        return self.terminal.buffered_bytes

    def clear_pending_terminal_control(self) -> None:
        self.terminal.clear()
        self.flags &= ~_TERMINAL_CONTROL_FLAGS


@dataclass
class StreamTerminalState:
    """Terminal error details and public surface-error selection."""

    terminal_code: int = 0
    terminal_reason: str = ""
    local_error: Optional[BaseException] = None
    send_close_error: Optional[BaseException] = None
    recv_close_error: Optional[BaseException] = None
    send_stop_error: Optional[ApplicationError] = None
    recv_reset_error: Optional[ApplicationError] = None
    recv_abort_error: Optional[ApplicationError] = None

    def local_abort(self) -> bool:
        return (
                isinstance(self.local_error, ApplicationError)
                and self.local_error.source is ErrorSource.LOCAL
                and self.local_error.termination_kind is TerminationKind.ABORT
        )

    def record_local_write_reset(self, code: int, reason: str = "") -> None:
        self.send_close_error = _application_error(
            code,
            reason,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.WRITE,
            kind=TerminationKind.RESET,
        )
        self._set_terminal(code, reason)

    def record_local_read_stop(self, code: int, reason: str = "") -> None:
        self._set_terminal(code, reason)

    def record_peer_stop_sending(self, code: int, reason: str = "") -> None:
        self.send_stop_error = _application_error(
            code,
            reason,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.WRITE,
            kind=TerminationKind.STOPPED,
        )
        self._set_terminal(code, reason)

    def record_peer_reset(self, code: int, reason: str = "") -> None:
        self.recv_reset_error = _application_error(
            code,
            reason,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.READ,
            kind=TerminationKind.RESET,
        )
        self._set_terminal(code, reason)

    def record_peer_abort(self, code: int, reason: str = "") -> None:
        self.recv_abort_error = _application_error(
            code,
            reason,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.BOTH,
            kind=TerminationKind.ABORT,
        )
        self._set_terminal(code, reason)

    def record_local_abort(self, code: int, reason: str = "") -> None:
        self.local_error = _application_error(
            code,
            reason,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            kind=TerminationKind.ABORT,
        )
        self._set_terminal(code, reason)

    def record_local_failure(self, error: Optional[BaseException]) -> None:
        self.local_error = error or ZmuxError(
            "zmux: stream failed locally",
            code=int(ErrorCode.INTERNAL),
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.UNKNOWN,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.ABORT,
        )
        if isinstance(self.local_error, ApplicationError):
            self._set_terminal(
                self.local_error.application_code or 0, self.local_error.reason
            )
            return
        self._set_terminal(
            error_code(self.local_error, int(ErrorCode.INTERNAL)) or int(ErrorCode.INTERNAL),
            error_reason(self.local_error),
        )

    def record_session_close(
            self,
            error: Optional[ApplicationError],
            *,
            close_write_half: bool,
            close_read_half: bool,
    ) -> None:
        close_write_half = _require_bool(close_write_half, "close_write_half")
        close_read_half = _require_bool(close_read_half, "close_read_half")
        if error is None:
            return
        if close_write_half:
            self.send_close_error = session_close_half_error(error, ErrorDirection.WRITE)
        if close_read_half:
            self.recv_close_error = session_close_half_error(error, ErrorDirection.READ)
        self._set_terminal(error.application_code or 0, error.reason)

    @staticmethod
    def peer_stop_write_closed() -> WriteClosed:
        return _write_closed(ErrorSource.REMOTE, TerminationKind.STOPPED)

    def operation_error(self, half_state: StreamHalfState) -> BaseException:
        if self.local_error is not None:
            return self.local_error
        if self.send_close_error is not None:
            return self.send_close_error
        if self.recv_close_error is not None:
            return self.recv_close_error
        choice = half_state.terminal_error_priority()
        if choice is TerminalErrorChoice.SEND_ABORT:
            return self._local_error_or_fallback()
        if choice is TerminalErrorChoice.RECV_ABORT:
            return self.recv_abort_error or self._generic_closed_error()
        if choice is TerminalErrorChoice.SEND_RESET:
            if half_state.send_reset_from_stop and self.send_stop_error is not None:
                return self.peer_stop_write_closed()
            return self._local_write_reset_error()
        if choice is TerminalErrorChoice.RECV_RESET:
            return self.recv_reset_error or self._generic_closed_error()
        if choice is TerminalErrorChoice.SEND_CLOSED:
            return self._send_closed_error(half_state)
        if choice is TerminalErrorChoice.RECV_CLOSED:
            return self._recv_closed_error(half_state)
        return self._generic_closed_error()

    def read_error(
            self,
            *,
            local_receive: bool,
            local_read_stop: bool,
            recv_half: RecvHalfState,
    ) -> Optional[BaseException]:
        local_receive = _require_bool(local_receive, "local_receive")
        local_read_stop = _require_bool(local_read_stop, "local_read_stop")
        choice = read_error_choice(local_receive, local_read_stop, recv_half)
        if choice is TerminalErrorChoice.NONE:
            return None
        temp_half = StreamHalfState(True, local_receive, SendHalfState.OPEN, recv_half)
        temp_half.local_read_stop = local_read_stop
        return self.operation_error(temp_half)

    def terminal_code_for_tombstone(
            self, send_half: SendHalfState, recv_half: RecvHalfState
    ) -> Tuple[int, bool]:
        choice = terminal_error_priority(send_half, recv_half)
        if choice is TerminalErrorChoice.SEND_ABORT:
            if isinstance(self.local_error, ApplicationError):
                return self.local_error.application_code or 0, True
            if self.recv_abort_error is not None:
                return self.recv_abort_error.application_code or 0, True
        if choice is TerminalErrorChoice.RECV_ABORT and self.recv_abort_error is not None:
            return self.recv_abort_error.application_code or 0, True
        if choice is TerminalErrorChoice.SEND_RESET and isinstance(
                self.send_close_error, ApplicationError
        ):
            return self.send_close_error.application_code or 0, True
        if choice is TerminalErrorChoice.RECV_RESET and self.recv_reset_error is not None:
            return self.recv_reset_error.application_code or 0, True
        return 0, False

    def _local_error_or_fallback(self) -> BaseException:
        if self.local_error is not None:
            return self.local_error
        if self.recv_abort_error is not None:
            return self.recv_abort_error
        return self._generic_closed_error()

    def _send_closed_error(self, half_state: StreamHalfState) -> WriteClosed:
        if (
                half_state.remote_write_stop
                or half_state.effective_send_half() is SendHalfState.STOP_SEEN
        ):
            return self.peer_stop_write_closed()
        return _write_closed(ErrorSource.LOCAL, TerminationKind.GRACEFUL)

    def _recv_closed_error(self, half_state: StreamHalfState) -> BaseException:
        recv_half = half_state.effective_recv_half()
        if recv_half is RecvHalfState.FIN:
            return _read_closed(ErrorSource.REMOTE, TerminationKind.GRACEFUL)
        if recv_half is RecvHalfState.STOP_SENT:
            return self._local_read_stopped_error()
        if self.terminal_code or self.terminal_reason:
            return self._local_read_stopped_error()
        return _read_closed(ErrorSource.LOCAL, TerminationKind.UNKNOWN)

    def _generic_closed_error(self) -> BaseException:
        if self.terminal_code or self.terminal_reason:
            return _application_error(
                self.terminal_code,
                self.terminal_reason,
                source=ErrorSource.LOCAL,
                direction=ErrorDirection.BOTH,
                kind=TerminationKind.UNKNOWN,
            )
        return ZmuxError(
            "zmux: stream is closed",
            code=int(ErrorCode.INTERNAL),
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.UNKNOWN,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.UNKNOWN,
        )

    def _local_read_stopped_error(self) -> ApplicationError:
        return _application_error(
            self.terminal_code,
            self.terminal_reason,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.READ,
            kind=TerminationKind.STOPPED,
        )

    def _local_write_reset_error(self) -> ApplicationError:
        return _application_error(
            self.terminal_code,
            self.terminal_reason,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.WRITE,
            kind=TerminationKind.RESET,
        )

    def _set_terminal(self, code: int, reason: str = "") -> None:
        self.terminal_code = _require_varint62(code, "code")
        self.terminal_reason = "" if reason is None else str(reason)


@dataclass
class StreamState:
    """Aggregate stream state shaped after Go ``nativeStream``."""

    stream_id: int = 0
    id_assigned: bool = False
    bidirectional: bool = True
    opened_locally: bool = False
    local_send: Optional[bool] = None
    local_receive: Optional[bool] = None
    lifecycle: StreamLifecycleState = field(default_factory=StreamLifecycleState)
    metadata_state: StreamMetadataState = field(default_factory=StreamMetadataState)
    advisory: StreamAdvisoryState = field(default_factory=StreamAdvisoryState)
    send: StreamSendAccountingState = field(default_factory=StreamSendAccountingState)
    receive: StreamReceiveAccountingState = field(default_factory=StreamReceiveAccountingState)
    receive_window: StreamReceiveWindowState = field(default_factory=StreamReceiveWindowState)
    terminal: StreamTerminalState = field(default_factory=StreamTerminalState)
    pending: PendingStreamState = field(default_factory=PendingStreamState)
    queue: StreamQueueMembershipState = field(default_factory=StreamQueueMembershipState)
    read_buffer: StreamReadBuffer = field(default_factory=StreamReadBuffer)
    half: StreamHalfState = field(init=False)

    def __post_init__(self) -> None:
        self.stream_id = _nonnegative_int(self.stream_id, "stream_id")
        self.id_assigned = _require_bool(self.id_assigned, "id_assigned")
        self.bidirectional = _require_bool(self.bidirectional, "bidirectional")
        self.opened_locally = _require_bool(self.opened_locally, "opened_locally")
        if self.stream_id:
            self.lifecycle.assign_stream_id(self.stream_id)
            self.id_assigned = True
        elif self.id_assigned:
            self.lifecycle.id_assigned = True
        if self.local_send is None:
            self.local_send = self.opened_locally or self.bidirectional
        else:
            self.local_send = _require_bool(self.local_send, "local_send")
        if self.local_receive is None:
            self.local_receive = self.bidirectional or not self.opened_locally
        else:
            self.local_receive = _require_bool(self.local_receive, "local_receive")
        self.half = StreamHalfState(self.local_send, self.local_receive)
        if self.lifecycle.stream_id == 0 and self.stream_id:
            self.lifecycle.assign_stream_id(self.stream_id)

    @property
    def metadata(self) -> StreamMetadata:
        meta = self.metadata_state.metadata
        return StreamMetadata(meta.priority, meta.group, meta.open_info)

    @property
    def open_info(self) -> bytes:
        return self.metadata_state.open_info()

    def open_info_len(self) -> int:
        return self.metadata_state.open_info_len()

    def update_metadata(
            self,
            update: MetadataUpdate,
            capabilities: int,
            *,
            max_frame_payload: int = 16384,
            max_priority_payload: int = 4096,
    ) -> MetadataUpdateRoute:
        if update.is_empty():
            raise EmptyMetadataUpdate()
        self.ensure_metadata_update_allowed()
        route = metadata_update_route(self.visibility_phase(), capabilities, update)
        if route.uses_open_metadata():
            self.apply_open_metadata_update(
                update,
                capabilities,
                max_frame_payload=max_frame_payload,
            )
            return route
        self.queue_pending_metadata_update(
            update,
            capabilities,
            max_payload=max_priority_payload,
        )
        return route

    def ensure_metadata_update_allowed(self) -> None:
        if not self.local_send:
            raise StreamNotWritable()
        if self.half.effective_send_half() is not SendHalfState.OPEN:
            raise self.terminal.operation_error(self.half)
        if self.fully_terminal():
            raise self.terminal.operation_error(self.half)

    def apply_open_metadata_update(
            self,
            update: MetadataUpdate,
            capabilities: int,
            *,
            max_frame_payload: int = 16384,
    ) -> MetadataChange:
        return self.metadata_state.apply_metadata_update(
            update,
            capabilities,
            max_frame_payload,
        )

    def queue_pending_metadata_update(
            self,
            update: MetadataUpdate,
            capabilities: int,
            *,
            max_payload: int = 4096,
    ) -> bytes:
        pending_payload = (
            self.pending.priority if self.pending.has_pending_priority_update() else b""
        )
        payload = build_merged_priority_update_payload(
            capabilities,
            update,
            pending_payload,
            max_payload,
        )
        self.pending.set_pending_priority_update(payload)
        self.metadata_state.stage_priority_update(
            update.priority,
            update.group,
            payload,
            group_present=update.group is not None,
        )
        if update.priority is not None or update.group is not None:
            current = self.metadata_state.metadata
            self.metadata_state.replace_metadata(
                StreamMetadata(
                    current.priority if update.priority is None else update.priority,
                    current.group if update.group is None else _normalize_group(update.group),
                    current.open_info,
                )
            )
        return payload

    def local_open_visibility(self) -> LocalOpenVisibility:
        return LocalOpenVisibility(
            self.opened_locally,
            self.metadata_state.opened_on_wire,
            self.metadata_state.peer_visible,
            self.metadata_state.opening_frame_pending,
        )

    def visibility_phase(self) -> LocalOpenPhase:
        return self.local_open_visibility().phase()

    def clear_opening_barrier(self) -> None:
        if self.metadata_state.opening_frame_pending:
            self.metadata_state.clear_opening_frame_pending()

    def is_local_opened(self) -> bool:
        return self.visibility_phase().is_local()

    def is_send_committed(self) -> bool:
        return self.metadata_state.opened_on_wire

    def is_peer_visible(self) -> bool:
        return self.visibility_phase() is LocalOpenPhase.PEER_VISIBLE

    def mark_send_committed(self) -> None:
        self.metadata_state.opened_on_wire = True

    def mark_opener_queued(self) -> None:
        self.metadata_state.mark_opening_frame_pending()

    def set_peer_visible(self) -> None:
        self.metadata_state.mark_peer_visible()
        self.metadata_state.clear_opening_frame_pending()

    def awaiting_peer_visibility(self) -> bool:
        return self.metadata_state.awaiting_peer_visibility(
            self.opened_locally,
            self.id_assigned or self.lifecycle.id_assigned,
            self.fully_terminal(),
        )

    def should_emit_opener_frame(self) -> bool:
        return self.visibility_phase().should_emit_opener_frame()

    def should_mark_peer_visible(self) -> bool:
        return self.metadata_state.should_mark_peer_visible(
            self.opened_locally,
            self.id_assigned or self.lifecycle.id_assigned,
        )

    def should_queue_stream_blocked(self, available_stream: int) -> bool:
        return self.visibility_phase().should_queue_stream_blocked(
            _nonnegative_int(available_stream, "available_stream")
        )

    def fully_terminal(self) -> bool:
        return fully_terminal(
            bool(self.local_send),
            bool(self.local_receive),
            self.half.effective_send_half(),
            self.half.effective_recv_half(),
        )

    def blocks_graceful_session_close(self) -> bool:
        if self.fully_terminal():
            return False
        if self.is_local_opened():
            return True
        if not self.local_send:
            return False
        if (
                self.send.sent_bytes == 0
                and self.send.queued_data_bytes == 0
                and self.send.inflight_queued_bytes == 0
                and not self.pending.has_pending_terminal_control()
        ):
            return False
        return self.half.effective_send_half() is SendHalfState.OPEN

    def should_reclaim_unseen_local(self, peer_goaway_bidi: int, peer_goaway_uni: int) -> bool:
        return should_reclaim_unseen_local_stream(
            self.visibility_phase(),
            self.id_assigned or self.lifecycle.id_assigned,
            self.bidirectional,
            self.stream_id,
            _nonnegative_int(peer_goaway_bidi, "peer_goaway_bidi"),
            _nonnegative_int(peer_goaway_uni, "peer_goaway_uni"),
            bool(self.local_send),
            bool(self.local_receive),
            self.half.effective_send_half(),
            self.half.effective_recv_half(),
        )

    def should_finalize_peer_active(self) -> bool:
        return should_finalize_peer_active(
            self.lifecycle.active_counted,
            self.is_local_opened(),
            bool(self.local_send),
            bool(self.local_receive),
            self.half.effective_send_half(),
            self.half.effective_recv_half(),
        )

    def should_finalize_local_active(self) -> bool:
        return (
                self.lifecycle.active_counted
                and self.is_local_opened()
                and self.fully_terminal()
        )

    def should_compact_terminal(self, still_tracked: bool) -> bool:
        still_tracked = _require_bool(still_tracked, "still_tracked")
        if self.queue.enqueued and self.open_info_len() > 0:
            return False
        if self.send.queued_data_bytes or self.send.inflight_queued_bytes:
            return False
        return should_compact_terminal(
            self.id_assigned or self.lifecycle.id_assigned,
            self.fully_terminal(),
            self.receive.recv_buffer,
            len(self.read_buffer),
            still_tracked,
        )

    def tombstone_state(self) -> StreamTombstone:
        send_code, has_send_code = self.terminal.terminal_code_for_tombstone(
            self.half.effective_send_half(), self.half.effective_recv_half()
        )
        return build_stream_tombstone(
            bool(self.local_receive),
            self.half.effective_send_half(),
            self.half.effective_recv_half(),
            send_reset_code=send_code if has_send_code else None,
            send_abort_code=send_code if has_send_code else None,
            recv_reset_code=send_code if has_send_code else None,
            recv_abort_code=send_code if has_send_code else None,
        )

    def tombstone_late_data_action(self) -> LateDataAction:
        return self.tombstone_state().data_action

    def late_data_cause(self) -> LateDataCause:
        recv_half = self.half.effective_recv_half()
        if recv_half is RecvHalfState.STOP_SENT:
            return LateDataCause.CLOSE_READ
        if recv_half is RecvHalfState.RESET:
            return LateDataCause.RESET
        if recv_half is RecvHalfState.ABORTED:
            return LateDataCause.ABORT
        return LateDataCause.NONE

    def enqueue_accepted(self) -> bool:
        if not should_enqueue_accepted(
                self.lifecycle.application_visible,
                self.lifecycle.accepted,
                self.queue.enqueued,
        ):
            return False
        self.queue.enqueued = True
        self.lifecycle.accept_queued = True
        return True

    def append_read_data(self, data: ReadableBuffer, *, retained_bytes: int = 0) -> int:
        view = _readonly_view(data)
        retained = self.read_buffer.append(view, retained_bytes=retained_bytes)
        self.receive.account_received(len(view))
        self.receive_window.record_received_bytes(len(view))
        return retained

    def read(self, max_bytes: int = -1) -> bytes:
        data = self.read_buffer.read(max_bytes)
        if data:
            self._release_receive_budget(len(data))
        return data

    def readinto(self, dst: MutableSequence[int]):
        result = self.read_buffer.readinto(dst)
        if result.bytes_read:
            self._release_receive_budget(result.bytes_read)
        return result

    def clear_read_buffer(self) -> int:
        cleared = self.read_buffer.clear()
        self._release_receive_budget(cleared.bytes)
        return cleared.bytes

    def _release_receive_budget(self, value: int) -> int:
        released = self.receive.release_budget(value)
        if (
                released
                and self.local_receive
                and self.half.effective_recv_half() is RecvHalfState.OPEN
        ):
            self.receive.add_recv_pending(released)
        return released

    def set_send_stop_seen(self, code: int, reason: str = "") -> None:
        self.terminal.record_peer_stop_sending(code, reason)
        self.half.mark_send_stop_seen()
        self._clear_send_pending_runtime_state()

    def set_send_fin(self) -> None:
        self.half.send_half = SendHalfState.FIN
        self.half.send_reset_from_stop = False
        self._clear_send_pending_runtime_state()
        self.advisory.clear_scheduling_group_tracked()

    def clear_send_fin(self) -> None:
        self.half.send_reset_from_stop = False
        if self.terminal.send_stop_error is not None:
            self.half.send_half = SendHalfState.STOP_SEEN
            return
        self.half.send_half = (
            SendHalfState.OPEN if bool(self.local_send) else SendHalfState.ABSENT
        )

    def set_send_reset_with_source(
            self,
            code: int,
            reason: str = "",
            source: TerminalResetSource = TerminalResetSource.DIRECT,
    ) -> None:
        source = _coerce_enum(source, TerminalResetSource, "source")
        self.terminal.record_local_write_reset(code, reason)
        self.half.mark_send_reset(from_stop=source is TerminalResetSource.FROM_STOP_SENDING)
        self._clear_send_pending_runtime_state()
        self.advisory.clear_scheduling_group_tracked()

    def set_send_abort_with_source(
            self,
            code: int,
            reason: str = "",
            source: TerminalAbortSource = TerminalAbortSource.LOCAL,
    ) -> None:
        self._record_abort_source(code, reason, source)
        if self.half.send_half is not SendHalfState.ABSENT:
            self.half.send_half = SendHalfState.ABORTED
        self.half.send_reset_from_stop = False
        self._clear_send_pending_runtime_state()
        self.advisory.clear_scheduling_group_tracked()

    def _clear_send_pending_runtime_state(self) -> None:
        self.send.clear_pending_buffered_state()
        self.pending.clear_pending_control_value(PendingStreamControlKind.BLOCKED)
        self.pending.clear_pending_priority_update()

    def set_recv_stop_sent(self, code: int = int(ErrorCode.CANCELLED)) -> None:
        self.half.mark_local_read_stop()
        self.terminal.record_local_read_stop(code)
        self.clear_read_buffer()
        self.receive.clear_recv_pending()
        self.pending.clear_pending_control_value(PendingStreamControlKind.MAX_DATA)

    def set_recv_fin(self) -> None:
        self.half.mark_recv_fin()
        self.receive.clear_recv_pending()
        self.pending.clear_pending_control_value(PendingStreamControlKind.MAX_DATA)

    def set_recv_reset(self, code: int, reason: str = "") -> None:
        self.terminal.record_peer_reset(code, reason)
        self.half.mark_recv_reset()
        self.clear_read_buffer()
        self.receive.clear_recv_pending()
        self.pending.clear_pending_control_value(PendingStreamControlKind.MAX_DATA)

    def set_recv_abort_with_source(
            self,
            code: int,
            reason: str = "",
            source: TerminalAbortSource = TerminalAbortSource.LOCAL,
    ) -> None:
        self._record_abort_source(code, reason, source)
        if self.half.recv_half is not RecvHalfState.ABSENT:
            self.half.recv_half = RecvHalfState.ABORTED
        self.clear_read_buffer()
        self.receive.clear_recv_pending()
        self.pending.clear_pending_control_value(PendingStreamControlKind.MAX_DATA)

    def set_aborted_with_source(
            self,
            code: int,
            reason: str = "",
            source: TerminalAbortSource = TerminalAbortSource.LOCAL,
    ) -> None:
        self.set_send_abort_with_source(code, reason, source)
        self.set_recv_abort_with_source(code, reason, source)

    def _record_abort_source(
            self,
            code: int,
            reason: str,
            source: TerminalAbortSource,
    ) -> TerminalAbortSource:
        source = _coerce_enum(source, TerminalAbortSource, "source")
        if source is TerminalAbortSource.PEER:
            self.terminal.record_peer_abort(code, reason)
        else:
            self.terminal.record_local_abort(code, reason)
        return source

    def data_frame(
            self,
            app: ReadableBuffer = b"",
            traits: DataFrameTraits = DataFrameTraits.NONE,
            *,
            capabilities: int = _DEFAULT_METADATA_CAPABILITIES,
            max_frame_payload: int = 16384,
    ) -> Frame:
        traits = _coerce_data_frame_traits(traits)
        prefix = (
            self.metadata_state.build_opening_prefix(capabilities, max_frame_payload)
            if traits.includes_open_metadata()
            else b""
        )
        return data_frame(
            self.stream_id,
            prefix,
            app,
            traits,
        )

    def data_frame_from_parts(
            self,
            parts: Sequence[ReadableBuffer],
            index: int,
            offset: int,
            length: int,
            traits: DataFrameTraits = DataFrameTraits.NONE,
            *,
            capabilities: int = _DEFAULT_METADATA_CAPABILITIES,
            max_frame_payload: int = 16384,
    ) -> Frame:
        traits = _coerce_data_frame_traits(traits)
        prefix = (
            self.metadata_state.build_opening_prefix(capabilities, max_frame_payload)
            if traits.includes_open_metadata()
            else b""
        )
        return data_frame_from_parts(
            self.stream_id,
            prefix,
            parts,
            index,
            offset,
            length,
            traits,
        )


def metadata_update_can_carry_on_open(capabilities: int, update: MetadataUpdate) -> bool:
    return (
            (update.priority is None or capabilities_can_carry_priority_on_open(capabilities))
            and (update.group is None or capabilities_can_carry_group_on_open(capabilities))
    )


def validate_open_metadata_update_capability(
        capabilities: int, update: MetadataUpdate
) -> None:
    if not metadata_update_can_carry_on_open(capabilities, update):
        raise PriorityUpdateUnavailable()


def metadata_update_route(
        phase: LocalOpenPhase, capabilities: int, update: MetadataUpdate
) -> MetadataUpdateRoute:
    phase = _coerce_enum(phase, LocalOpenPhase, "phase")
    if phase.needs_local_opener():
        validate_open_metadata_update_capability(capabilities, update)
        return MetadataUpdateRoute.OPEN_METADATA
    if phase.should_emit_opener_frame() and metadata_update_can_carry_on_open(
            capabilities, update
    ):
        return MetadataUpdateRoute.OPEN_METADATA
    return MetadataUpdateRoute.PRIORITY_FRAME


def merge_pending_metadata_update(
        update: MetadataUpdate, pending_payload: bytes = b""
) -> MetadataUpdate:
    if not pending_payload:
        return update
    pending, valid = parse_priority_update_payload(pending_payload)
    if not valid:
        raise ProtocolError(
            "invalid pending priority update payload",
            code=int(ErrorCode.INTERNAL),
            scope=ErrorScope.SESSION,
            operation=ErrorOperation.WRITE,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.WRITE,
        )
    return MetadataUpdate(
        update.priority if update.priority is not None else pending.priority,
        update.group if update.group is not None else pending.group,
    )


def build_merged_priority_update_payload(
        capabilities: int,
        update: MetadataUpdate,
        pending_payload: bytes = b"",
        max_payload: int = 4096,
) -> bytes:
    return build_priority_update_payload(
        capabilities,
        merge_pending_metadata_update(update, pending_payload),
        max_payload,
    )


def received_metadata_policy(
        capabilities: int, carriage: ReceivedMetadataCarriage
) -> ReceivedMetadataPolicy:
    carriage = _coerce_enum(carriage, ReceivedMetadataCarriage, "carriage")
    if carriage.allows_open_info():
        return ReceivedMetadataPolicy(
            capabilities_can_carry_priority_on_open(capabilities),
            capabilities_can_carry_group_on_open(capabilities),
            capabilities_can_carry_open_info(capabilities),
        )
    return ReceivedMetadataPolicy(
        capabilities_can_carry_priority_in_update(capabilities),
        capabilities_can_carry_group_in_update(capabilities),
        False,
    )


def pending_stream_control_flag(
        kind: PendingStreamControlKind,
) -> PendingStreamFlag:
    kind = _coerce_pending_control_kind(kind)
    if kind is PendingStreamControlKind.MAX_DATA:
        return PendingStreamFlag.MAX_DATA
    return PendingStreamFlag.BLOCKED


def data_frame(
        stream_id: int,
        open_metadata_prefix: bytes = b"",
        app: ReadableBuffer = b"",
        traits: DataFrameTraits = DataFrameTraits.NONE,
) -> Frame:
    traits = _coerce_data_frame_traits(traits)
    flags = FRAME_FLAG_FIN if traits.sends_fin() else 0
    app_view = _readonly_view(app)
    payload = app_view.tobytes()
    if traits.includes_open_metadata() and open_metadata_prefix:
        flags |= FRAME_FLAG_OPEN_METADATA
        payload = _payload_bytes(open_metadata_prefix, "open_metadata_prefix") + payload
    return Frame(FrameType.DATA, _require_stream_id(stream_id, "stream_id"), flags, payload)


def data_frame_from_parts(
        stream_id: int,
        open_metadata_prefix: bytes,
        parts: Sequence[ReadableBuffer],
        index: int,
        offset: int,
        length: int,
        traits: DataFrameTraits = DataFrameTraits.NONE,
) -> Frame:
    traits = _coerce_data_frame_traits(traits)
    length = _nonnegative_int(length, "length")
    flags = FRAME_FLAG_FIN if traits.sends_fin() else 0
    prefix = _payload_bytes(open_metadata_prefix, "open_metadata_prefix")
    if traits.includes_open_metadata() and prefix:
        flags |= FRAME_FLAG_OPEN_METADATA
        payload = prefix + _slice_parts_to_bytes(parts, index, offset, length)
    else:
        view, ok = single_part_payload_view(parts, index, offset, length)
        payload = view.tobytes() if ok else _slice_parts_to_bytes(parts, index, offset, length)
    return Frame(FrameType.DATA, _require_stream_id(stream_id, "stream_id"), flags, payload)


def single_part_payload_view(
        parts: Sequence[ReadableBuffer], index: int, offset: int, length: int
) -> Tuple[memoryview, bool]:
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 0:
        return memoryview(b""), False
    index = _nonnegative_int(index, "index")
    offset = _nonnegative_int(offset, "offset")
    while index < len(parts):
        part = _readonly_view(parts[index])
        if offset >= len(part):
            index += 1
            offset = 0
            continue
        available = len(part) - offset
        if length > available:
            return memoryview(b""), False
        return part[offset: offset + length], True
    return memoryview(b""), length == 0


def frame_buffered_bytes(frame: Frame) -> int:
    return saturating_add(1, len(frame.payload))


def stream_matches_id(stream: Optional[StreamState], stream_id: int) -> bool:
    return stream is not None and stream.id_assigned and stream.stream_id == stream_id


def session_close_half_error(
        error: ApplicationError, direction: ErrorDirection
) -> ApplicationError:
    source = error.source if error.source is not ErrorSource.UNKNOWN else ErrorSource.LOCAL
    return _application_error(
        error.application_code or 0,
        error.reason,
        source=source,
        direction=direction,
        kind=TerminationKind.SESSION_TERMINATION,
    )


def _slice_parts_to_bytes(
        parts: Sequence[ReadableBuffer], index: int, offset: int, length: int
) -> bytes:
    length = _nonnegative_int(length, "length")
    if length == 0:
        return b""
    out = bytearray(length)
    written = 0
    index = _nonnegative_int(index, "index")
    offset = _nonnegative_int(offset, "offset")
    while written < length and index < len(parts):
        part = _readonly_view(parts[index])
        if offset >= len(part):
            index += 1
            offset = 0
            continue
        n = min(length - written, len(part) - offset)
        out[written: written + n] = part[offset: offset + n]
        written += n
        index += 1
        offset = 0
    if written != length:
        raise ValueError("parts do not contain requested payload length")
    return bytes(out)


def _application_error(
        code: int,
        reason: str = "",
        *,
        source: ErrorSource,
        direction: ErrorDirection,
        kind: TerminationKind,
) -> ApplicationError:
    err = ApplicationError(_require_varint62(code, "code"), "" if reason is None else str(reason))
    err.with_scope(ErrorScope.STREAM)
    err.with_source(source)
    err.with_direction(direction)
    err.with_termination_kind(kind)
    return err


def _write_closed(source: ErrorSource, kind: TerminationKind) -> WriteClosed:
    err = WriteClosed()
    err.with_source(source)
    err.with_termination_kind(kind)
    return err


def _read_closed(source: ErrorSource, kind: TerminationKind) -> ReadClosed:
    err = ReadClosed()
    err.with_source(source)
    err.with_termination_kind(kind)
    return err


def _priority_on_open(priority: Optional[int]) -> Optional[int]:
    if priority is None or priority == 0:
        return None
    return priority


def _normalize_group(group: Optional[int]) -> Optional[int]:
    if group is None:
        return None
    value = _normalize_optional_varint(group, "group")
    return None if value == 0 else value


def _normalize_optional_varint(value: int, name: str) -> int:
    return _require_varint62(value, name)


def _payload_bytes(value, name: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bool, int, str)):
        raise TypeError("%s must be bytes-like" % name)
    try:
        return bytes(value)
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % name) from exc


def _readonly_view(data: ReadableBuffer) -> memoryview:
    view = memoryview(data)
    if (
            view.ndim == 1
            and view.itemsize == 1
            and view.format in ("B", "b", "c")
            and view.contiguous
    ):
        return view if view.readonly else memoryview(view.tobytes())
    try:
        view = view.cast("B")
    except (TypeError, ValueError):
        view = memoryview(view.tobytes())
    return view if view.readonly else memoryview(view.tobytes())


def _coerce_pending_control_kind(
        kind: PendingStreamControlKind,
) -> PendingStreamControlKind:
    if isinstance(kind, PendingStreamControlKind):
        return kind
    if isinstance(kind, bool):
        raise TypeError("pending control kind must be a PendingStreamControlKind or integer")
    return PendingStreamControlKind(int(kind))


def _coerce_pending_queue_kind(kind: PendingStreamQueueKind) -> PendingStreamQueueKind:
    if isinstance(kind, PendingStreamQueueKind):
        return kind
    if isinstance(kind, bool):
        raise TypeError("pending queue kind must be a PendingStreamQueueKind or integer")
    return PendingStreamQueueKind(int(kind))


def _coerce_data_frame_traits(traits: DataFrameTraits) -> DataFrameTraits:
    if isinstance(traits, DataFrameTraits):
        return traits
    if isinstance(traits, bool):
        raise TypeError("data frame traits must be a DataFrameTraits or integer")
    return DataFrameTraits(traits)


def _require_stream_id(value: int, name: str) -> int:
    value = _require_varint62(value, name)
    if value == 0:
        raise ValueError("%s must be non-zero" % name)
    return value


def _require_varint62(value: int, name: str) -> int:
    value = _nonnegative_int(value, name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % name)
    return value


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


__all__ = (
    "INVALID_STREAM_QUEUE_INDEX",
    "MAX_UINT64",
    "DataFrameTraits",
    "LateDataCause",
    "MetadataChange",
    "MetadataUpdateRoute",
    "PendingStreamControlKind",
    "PendingStreamControlValue",
    "PendingStreamFlag",
    "PendingStreamQueueKind",
    "PendingStreamState",
    "PendingStreamTerminalState",
    "PendingTerminalResult",
    "ReceivedMetadataCarriage",
    "ReceivedMetadataPolicy",
    "StreamAdvisoryState",
    "StreamLifecycleState",
    "StreamMetadataState",
    "StreamQueueMembershipState",
    "StreamReceiveAccountingState",
    "StreamReceiveWindowState",
    "StreamSendAccountingState",
    "StreamState",
    "StreamTerminalState",
    "TerminalAbortSource",
    "TerminalResetSource",
    "build_merged_priority_update_payload",
    "data_frame",
    "data_frame_from_parts",
    "frame_buffered_bytes",
    "merge_pending_metadata_update",
    "metadata_update_can_carry_on_open",
    "metadata_update_route",
    "pending_stream_control_flag",
    "received_metadata_policy",
    "session_close_half_error",
    "single_part_payload_view",
    "stream_matches_id",
    "validate_open_metadata_update_capability",
)
