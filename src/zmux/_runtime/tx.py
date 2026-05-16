"""Transmit frame, write request, and writer-queue helper algorithms.

This module owns the transport-independent data model used by the writer:
``TxFrame`` payload views, ``WriteJob`` requests, queue-cost accounting,
coalescing/classification helpers, and small deadline utilities.  The mutable
blocking queue state lives in ``write_queue`` so the high-churn admission logic
stays separate from the value objects and pure helpers.
"""

from __future__ import annotations

import queue as _stdlib_queue
import sys
import threading
import time
from collections.abc import Iterable, MutableSequence, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum, IntEnum
from typing import Callable, Dict, List, Optional, Protocol, Tuple

from .._validation import (
    require_bool as _require_bool,
    require_nonnegative_duration as _nonnegative_duration,
    require_nonnegative_int as _nonnegative_int,
    require_stream_id as _require_stream_id,
    require_varint62 as _require_varint62,
)
from .flow import queue_would_block as _flow_queue_would_block
from .stream import SendHalfState, effective_deadline
from .write_plan import OpenerVisibilityMark
from .._wire.frame import normalize_limits, validate_frame
from .._wire.varint import append_varint, parse_varint, varint_len
from ..config import DEFAULT_WRITE_BATCH_MAX_FRAMES, Limits
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    ProtocolError,
    StreamNotWritable,
    WriteTimeout,
)
from ..frame import Frame
from ..payload import (
    MetadataUpdate,
    build_priority_update_payload,
    parse_data_payload_metadata_offset,
    parse_priority_update_payload,
)
from ..protocol import (
    EXT_PRIORITY_UPDATE,
    FRAME_FLAG_FIN,
    METADATA_STREAM_GROUP,
    METADATA_STREAM_PRIORITY,
    ErrorCode,
    FrameType,
)
from ..streams import ReadableBuffer

MAX_UINT64 = (1 << 64) - 1
MAX_REQUEST_COST = (1 << 63) - 1
MAX_WRITE_BATCH_FRAMES = DEFAULT_WRITE_BATCH_MAX_FRAMES
FRAME_QUEUE_OVERHEAD_BYTES = 1
MAX_INITIAL_QUEUE_SCRATCH_RESERVE = 64
MAX_TX_PAYLOAD_PREALLOC_BYTES = MAX_WRITE_BATCH_FRAMES * Limits().max_frame_payload
PriorityUpdateFields = Tuple[Optional[int], Optional[int]]

WRITER_QUEUE_FULL_MESSAGE = "zmux: writer queue full"
URGENT_WRITER_QUEUE_FULL_MESSAGE = "zmux: urgent writer queue full"
PENDING_CONTROL_BUDGET_MESSAGE = "zmux: pending control budget exceeded"
PENDING_PRIORITY_BUDGET_MESSAGE = "zmux: pending priority budget exceeded"
QUEUED_DATA_HWM_MESSAGE = "zmux: queued data high watermark exceeded"
QUEUED_WRITE_DISCARDED_MESSAGE = "zmux: queued write was discarded"

DEFAULT_URGENCY_RANK = 100
_POLL_WAIT_CAP_SECONDS = 3600.0
POLL_WAIT_CAP_SECONDS = _POLL_WAIT_CAP_SECONDS
class BatchOrder(Protocol):
    def __call__(self, batch: List[object]) -> Iterable[object]:
        ...


class TxPayloadKind(IntEnum):
    FLAT = 0
    PREFIX_FLAT = 1
    PARTS = 2
    PREFIX_PARTS = 3


class TerminalWritePolicy(IntEnum):
    REJECT = 0
    ALLOW = 1

    def allows_terminal(self) -> bool:
        return self is TerminalWritePolicy.ALLOW


class FrameOwnership(IntEnum):
    BORROWED = 0
    IMMUTABLE = 1
    OWNED = 2

    def requires_clone(self) -> bool:
        return self is FrameOwnership.BORROWED

    def owns_frames(self) -> bool:
        return not self.requires_clone()


class WriteRequestOrigin(IntEnum):
    PROTOCOL = 0
    STREAM = 1

    def is_stream_generated(self) -> bool:
        return self is WriteRequestOrigin.STREAM


class QueueLane(IntEnum):
    ORDINARY = 0
    ADVISORY = 1
    URGENT = 2

    def is_urgent(self) -> bool:
        return self is QueueLane.URGENT

    def is_advisory(self) -> bool:
        return self is QueueLane.ADVISORY


_QUEUE_LANES = (QueueLane.URGENT, QueueLane.ADVISORY, QueueLane.ORDINARY)


class WriteUrgencyProfile(IntEnum):
    MIXED = 0
    ALL_URGENT = 1

    def all_urgent(self) -> bool:
        return self is WriteUrgencyProfile.ALL_URGENT


class QueueReservationState(IntEnum):
    NONE = 0
    BLOCKED = 1


class WriteJobKind(Enum):
    FRAME = "frame"
    FRAMES = "frames"
    TRACKED_FRAMES = "tracked_frames"
    GRACEFUL_CLOSE = "graceful_close"
    SHUTDOWN = "shutdown"
    DRAIN_SHUTDOWN = "drain_shutdown"


class CoalesceKind(Enum):
    PRIORITY_UPDATE = "priority_update"
    MAX_DATA = "max_data"
    BLOCKED = "blocked"
    GOAWAY = "goaway"


class WriteQueuePopStatus(IntEnum):
    BATCH = 0
    TIMED_OUT = 1
    CLOSED = 2


@dataclass(frozen=True)
class ChunkSpan(object):
    start: int
    end: int

    def __post_init__(self) -> None:
        start = _nonnegative_int(self.start, "start")
        end = _nonnegative_int(self.end, "end")
        if end < start:
            raise ValueError("end must be >= start")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)


def frame_buffered_bytes(frame: Frame) -> int:
    return _saturating_add(FRAME_QUEUE_OVERHEAD_BYTES, len(frame.payload))


def frames_buffered_bytes(frames: Iterable[Frame]) -> int:
    total = 0
    for frame in frames:
        total = _saturating_add(total, frame_buffered_bytes(frame))
    return total


def frame_chunk_spans(
        frames: Sequence[Frame], max_frames: int = 0, max_bytes: int = 0
) -> tuple[ChunkSpan, ...]:
    if not frames:
        return ()
    max_frames = _chunk_frame_limit(max_frames, len(frames))
    max_bytes = _nonnegative_int(max_bytes, "max_bytes")
    spans: list[ChunkSpan] = []
    start = 0
    chunk_bytes = 0
    for index, frame in enumerate(frames):
        frame_bytes = frame_buffered_bytes(frame)
        if _chunk_over_limit(index, start, chunk_bytes, frame_bytes, max_frames, max_bytes):
            spans.append(ChunkSpan(start, index))
            start = index
            chunk_bytes = 0
        chunk_bytes = _saturating_add(chunk_bytes, frame_bytes)
    spans.append(ChunkSpan(start, len(frames)))
    return tuple(spans)


def send_by_deadline(
        deadline: Optional[float],
        closed: Optional[object],
        lane: object,
        value: object,
) -> bool:
    if lane is None or _event_is_set(closed):
        return False
    deadline = _normalize_deadline(deadline)
    if deadline is not None and time.monotonic() >= deadline:
        return False
    append = getattr(lane, "append", None)
    if append is not None:
        append(value)
        return True
    put = getattr(lane, "put", None)
    if put is None:
        return False
    while True:
        if _event_is_set(closed):
            return False
        remaining = _deadline_remaining(deadline)
        if remaining is not None and remaining <= 0:
            return False
        if closed is None and deadline is None:
            put(value)
            return True
        timeout = _poll_wait_timeout(remaining)
        try:
            put(value, block=True, timeout=timeout)
            return True
        except _stdlib_queue.Full:
            continue
        except TypeError:
            put(value)
            return True


def wait_by_deadline(
        deadline: Optional[float],
        closed: Optional[object],
        done: Optional[object],
) -> None:
    deadline = _normalize_deadline(deadline)
    if deadline is None and closed is None and done is None:
        return
    while True:
        if _event_is_set(closed) or _event_is_set(done):
            return
        remaining = _deadline_remaining(deadline)
        if remaining is not None and remaining <= 0:
            return
        timeout = _poll_wait_timeout(remaining)
        if _event_wait(closed, timeout) or _event_is_set(done):
            return
        if _event_wait(done, 0.0):
            return
        if closed is None and done is None and timeout > 0:
            time.sleep(timeout)


def collect_ready_batch_into(
        batch: Iterable[object],
        lane: object,
        max_items: int,
        order: Optional[BatchOrder] = None,
) -> List[object]:
    out = batch if isinstance(batch, list) else list(batch)
    max_items = _nonnegative_int(max_items, "max_items")
    while len(out) < max_items:
        ok, value = _try_recv_ready(lane)
        if not ok:
            return _ordered_batch(out, order)
        out.append(value)
    return _ordered_batch(out, order)


def write_all(writer: object, data: ReadableBuffer) -> None:
    view = _byte_view(data)
    total = len(view)
    if total == 0:
        return
    if writer is None:
        raise StreamNotWritable()
    method = getattr(writer, "write_all", None)
    if method is not None:
        method(view)
        return
    method = getattr(writer, "write", None)
    if method is None:
        raise StreamNotWritable()
    offset = 0
    while offset < total:
        written = method(view[offset:])
        if written is None:
            return
        if isinstance(written, bool) or not isinstance(written, int):
            raise OSError("zmux: write reported invalid progress")
        written = int(written)
        if written <= 0 or written > total - offset:
            raise OSError("zmux: write reported invalid progress")
        offset += written


@dataclass(frozen=True)
class CoalesceKey(object):
    kind: CoalesceKind
    stream_id: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _coerce_enum(self.kind, CoalesceKind, "kind"))
        object.__setattr__(
            self,
            "stream_id",
            _require_varint62(self.stream_id, "stream_id"),
        )


@dataclass
class TxFrame(object):
    frame_type: FrameType
    flags: int = 0
    stream_id: int = 0
    payload: bytes = b""
    stream_id_len: int = 0
    payload_kind: TxPayloadKind = TxPayloadKind.FLAT
    payload_prefix: bytes = b""
    payload_parts: Tuple[memoryview, ...] = ()
    payload_part_idx: int = 0
    payload_part_off: int = 0
    payload_part_len: int = 0
    payload_len: int = 0

    def __post_init__(self) -> None:
        self.frame_type = _coerce_frame_type(self.frame_type)
        self.flags = _byte(self.flags, "flags")
        self.stream_id = _require_varint62(self.stream_id, "stream_id")
        self.payload_kind = _coerce_enum(self.payload_kind, TxPayloadKind, "payload_kind")
        if self.stream_id_len == 0:
            self.stream_id_len = varint_len(self.stream_id)
        else:
            self.stream_id_len = _nonnegative_int(self.stream_id_len, "stream_id_len")
        if self.payload_len == 0 and self.payload_kind is TxPayloadKind.FLAT:
            self.payload = _bytes_or_empty(self.payload, "payload")
            self.payload_len = len(self.payload)
        else:
            self.payload = _bytes_or_empty(self.payload, "payload")
            self.payload_prefix = _bytes_or_empty(self.payload_prefix, "payload_prefix")
            self.payload_parts = tuple(_byte_view(part) for part in self.payload_parts)
            self.payload_len = checked_tx_payload_length(self.payload_len)

    def code(self) -> int:
        return int(self.frame_type) | self.flags

    def has_payload_prefix(self) -> bool:
        kind = self.payload_kind
        return kind is TxPayloadKind.PREFIX_FLAT or kind is TxPayloadKind.PREFIX_PARTS

    def has_payload_parts(self) -> bool:
        kind = self.payload_kind
        return kind is TxPayloadKind.PARTS or kind is TxPayloadKind.PREFIX_PARTS

    def payload_length(self) -> int:
        return checked_tx_payload_length(self.payload_len)

    def append_payload(self, dst: MutableSequence[int]) -> MutableSequence[int]:
        if self.has_payload_prefix():
            dst.extend(self.payload_prefix)
        if self.has_payload_parts():
            idx = self.payload_part_idx
            off = self.payload_part_off
            remaining = self.payload_part_len
            parts = self.payload_parts
            parts_len = len(parts)
            while remaining > 0 and idx < parts_len:
                part = parts[idx]
                if off >= len(part):
                    idx += 1
                    off = 0
                    continue
                take = min(len(part) - off, remaining)
                dst.extend(part[off: off + take])
                remaining -= take
                off += take
                if off >= len(part):
                    idx += 1
                    off = 0
            return dst
        dst.extend(self.payload)
        return dst

    def cloned_payload(self) -> bytes:
        payload_len = self.payload_length()
        if payload_len == 0:
            return b""
        if not self.has_payload_parts():
            if self.has_payload_prefix():
                return self.payload_prefix + self.payload
            return bytes(self.payload)
        if payload_len > MAX_TX_PAYLOAD_PREALLOC_BYTES:
            out = bytearray()
            self.append_payload(out)
            return bytes(out)
        out = bytearray(payload_len)
        view = memoryview(out)
        offset = 0
        if self.has_payload_prefix():
            prefix = self.payload_prefix
            view[: len(prefix)] = prefix
            offset = len(prefix)
        if self.has_payload_parts():
            idx = self.payload_part_idx
            off = self.payload_part_off
            remaining = self.payload_part_len
            parts = self.payload_parts
            parts_len = len(parts)
            while remaining > 0 and idx < parts_len:
                part = parts[idx]
                if off >= len(part):
                    idx += 1
                    off = 0
                    continue
                take = min(len(part) - off, remaining)
                view[offset: offset + take] = part[off: off + take]
                offset += take
                remaining -= take
                off += take
                if off >= len(part):
                    idx += 1
                    off = 0
            return bytes(out[:offset])
        payload = self.payload
        view[offset: offset + len(payload)] = payload
        return bytes(out)

    def payload_for_validation(self) -> bytes:
        if self.has_payload_prefix():
            return self.payload_prefix
        return self.payload

    def reset_payload_view(self) -> None:
        self.payload = b""
        self.payload_prefix = b""
        self.payload_parts = ()
        self.payload_part_idx = 0
        self.payload_part_off = 0
        self.payload_part_len = 0
        self.payload_kind = TxPayloadKind.FLAT
        self.payload_len = 0

    def set_flat_payload(self, payload: ReadableBuffer) -> None:
        self.reset_payload_view()
        self.payload = _bytes_or_empty(payload, "payload")
        self.payload_len = len(self.payload)

    def set_prefixed_flat_payload(
            self, prefix: ReadableBuffer, payload: ReadableBuffer
    ) -> None:
        prefix_bytes = _bytes_or_empty(prefix, "prefix")
        payload_bytes = _bytes_or_empty(payload, "payload")
        if not payload_bytes:
            self.set_flat_payload(prefix_bytes)
            return
        self.reset_payload_view()
        self.payload_kind = TxPayloadKind.PREFIX_FLAT
        self.payload_prefix = prefix_bytes
        self.payload = payload_bytes
        self.payload_len = add_tx_payload_lengths(len(prefix_bytes), len(payload_bytes))

    def _set_parts_payload_view(
            self,
            kind: TxPayloadKind,
            parts: Sequence[ReadableBuffer],
            idx: int,
            off: int,
            length: int,
            prefix: bytes = b"",
    ) -> None:
        trimmed, idx, off = trim_tx_payload_parts(parts, idx, off, length)
        self.reset_payload_view()
        self.payload_kind = kind
        self.payload_prefix = prefix
        self.payload_parts = trimmed
        self.payload_part_idx = idx
        self.payload_part_off = off
        self.payload_part_len = length

    def set_parts_payload(
            self,
            parts: Sequence[ReadableBuffer],
            idx: int = 0,
            off: int = 0,
            length: int = 0,
    ) -> None:
        length = checked_tx_payload_length(length)
        self._set_parts_payload_view(TxPayloadKind.PARTS, parts, idx, off, length)
        self.payload_len = length

    def set_prefixed_parts_payload(
            self,
            prefix: ReadableBuffer,
            parts: Sequence[ReadableBuffer],
            idx: int = 0,
            off: int = 0,
            length: int = 0,
    ) -> None:
        length = checked_tx_payload_length(length)
        prefix_bytes = _bytes_or_empty(prefix, "prefix")
        self._set_parts_payload_view(
            TxPayloadKind.PREFIX_PARTS,
            parts,
            idx,
            off,
            length,
            prefix=prefix_bytes,
        )
        self.payload_len = add_tx_payload_lengths(len(prefix_bytes), length)

    def to_frame(self) -> Frame:
        return Frame(self.frame_type, self.stream_id, self.flags, self.cloned_payload())


@dataclass(frozen=True)
class PreparedPriorityUpdate(object):
    frame: Optional[TxFrame] = None
    stream_id: int = 0
    payload: bytes = b""
    frame_bytes: int = 0

    def __post_init__(self) -> None:
        stream_id = _require_varint62(self.stream_id, "stream_id")
        payload = _bytes_or_empty(self.payload, "payload")
        frame_bytes = _nonnegative_int(self.frame_bytes, "frame_bytes")
        if self.frame is not None and frame_bytes == 0:
            frame_bytes = tx_frame_buffered_bytes(self.frame)
        object.__setattr__(self, "stream_id", stream_id)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "frame_bytes", frame_bytes)

    def has_frame(self) -> bool:
        return self.stream_id != 0 and bool(self.payload) and self.frame_bytes > 0

    def append_to(self, frames: Sequence[TxFrame]) -> Tuple[TxFrame, ...]:
        if not self.has_frame() or self.frame is None:
            return tuple(frames)
        return tuple(frames) + (self.frame,)


@dataclass
class QueuedWriteRequest(object):
    frames: Tuple[TxFrame, ...] = ()
    origin: WriteRequestOrigin = WriteRequestOrigin.PROTOCOL
    terminal_policy: TerminalWritePolicy = TerminalWritePolicy.REJECT
    clone_frames_before_send: bool = False
    queue_reserved: bool = False
    queued_bytes: int = 0
    reserved_stream: object = None
    urgent_reserved: bool = False
    advisory_reserved: bool = False
    request_meta_ready: bool = False
    request_stream_id: int = 0
    request_stream_id_known: bool = False
    request_stream_scoped: bool = False
    request_urgency_rank: int = 0
    request_cost: int = 0
    request_buffered_bytes: int = 0
    request_is_priority_update: bool = False
    request_all_urgent: bool = False
    terminal_data_priority: bool = False
    terminal_reset_only: bool = False
    terminal_abort_only: bool = False
    terminal_has_fin: bool = False
    prepared_send_bytes: int = 0
    prepared_send_fin: bool = False
    prepared_opener_visibility: OpenerVisibilityMark = OpenerVisibilityMark.UNCHANGED
    prepared_priority_stream_id: int = 0
    prepared_priority_payload: bytes = b""
    prepared_priority_bytes: int = 0
    prepared_priority_queued: bool = False

    def __post_init__(self) -> None:
        self.frames = tuple(self.frames)
        self.origin = _coerce_enum(self.origin, WriteRequestOrigin, "origin")
        self.terminal_policy = _coerce_enum(
            self.terminal_policy, TerminalWritePolicy, "terminal_policy"
        )
        self.prepared_opener_visibility = _coerce_enum(
            self.prepared_opener_visibility,
            OpenerVisibilityMark,
            "prepared_opener_visibility",
        )
        for name in (
                "clone_frames_before_send",
                "queue_reserved",
                "urgent_reserved",
                "advisory_reserved",
                "request_meta_ready",
                "request_stream_id_known",
                "request_stream_scoped",
                "request_is_priority_update",
                "request_all_urgent",
                "terminal_data_priority",
                "terminal_reset_only",
                "terminal_abort_only",
                "terminal_has_fin",
                "prepared_send_fin",
                "prepared_priority_queued",
        ):
            setattr(self, name, _require_bool(getattr(self, name), name))
        self.queued_bytes = _nonnegative_int(self.queued_bytes, "queued_bytes")
        for name in ("request_stream_id", "prepared_priority_stream_id"):
            setattr(self, name, _require_varint62(getattr(self, name), name))
        for name in (
                "request_urgency_rank",
                "request_cost",
                "request_buffered_bytes",
                "prepared_send_bytes",
                "prepared_priority_bytes",
        ):
            setattr(self, name, _nonnegative_int(getattr(self, name), name))
        self.prepared_priority_payload = _bytes_or_empty(
            self.prepared_priority_payload,
            "prepared_priority_payload",
        )

    def prepared_priority_update(self) -> PreparedPriorityUpdate:
        return PreparedPriorityUpdate(
            stream_id=self.prepared_priority_stream_id,
            payload=self.prepared_priority_payload,
            frame_bytes=self.prepared_priority_bytes,
        )

    def set_prepared_priority_update(self, priority: PreparedPriorityUpdate) -> None:
        self.prepared_priority_stream_id = priority.stream_id
        self.prepared_priority_payload = priority.payload
        self.prepared_priority_bytes = priority.frame_bytes

    def clear_retained_refs(self) -> None:
        self.frames = ()
        self.queue_reserved = False
        self.queued_bytes = 0
        self.reserved_stream = None
        self.urgent_reserved = False
        self.advisory_reserved = False
        self.clone_frames_before_send = False
        self.clear_prepared_state()
        clear_write_request_classification(self)

    def clear_prepared_state(self) -> None:
        self.prepared_send_bytes = 0
        self.prepared_send_fin = False
        self.prepared_opener_visibility = OpenerVisibilityMark.UNCHANGED
        self.set_prepared_priority_update(PreparedPriorityUpdate())
        self.prepared_priority_queued = False

    def targets_stream_id(self, stream_id: int) -> bool:
        classify_write_request(self)
        if not self.request_stream_id_known:
            return False
        return stream_id == 0 or self.request_stream_id == stream_id

    def allows_terminal_send_half(
            self, send_half: SendHalfState, stream_id: int = 0
    ) -> bool:
        if not self.targets_stream_id(stream_id):
            return False
        send_half = _coerce_enum(send_half, SendHalfState, "send_half")
        if send_half in (SendHalfState.FIN, SendHalfState.STOP_SEEN):
            if not self.terminal_data_priority:
                return False
            return send_half is not SendHalfState.FIN or self.terminal_has_fin
        if send_half is SendHalfState.RESET:
            return self.terminal_reset_only
        if send_half is SendHalfState.ABORTED:
            return self.terminal_abort_only
        return False

    def allows_queued_graceful_fin_drain_for_stream(self, stream_id: int) -> bool:
        return (
                self.queue_reserved
                and self.targets_stream_id(stream_id)
                and self.terminal_data_priority
                and self.terminal_has_fin
                and not self.terminal_reset_only
                and not self.terminal_abort_only
        )


@dataclass(frozen=True)
class QueuedWriteResult(object):
    admitted: bool = False
    completed: bool = False
    error: Optional[BaseException] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "admitted", _require_bool(self.admitted, "admitted"))
        object.__setattr__(
            self,
            "completed",
            _require_bool(self.completed, "completed"),
        )

    def pending_completion(self) -> bool:
        return self.admitted and not self.completed


@dataclass
class QueueReservationResult(object):
    state: QueueReservationState = QueueReservationState.NONE
    memory_error: Optional[BaseException] = None

    def __post_init__(self) -> None:
        self.state = _coerce_enum(self.state, QueueReservationState, "state")

    def blocked(self) -> bool:
        return self.state is QueueReservationState.BLOCKED


@dataclass
class DataCosts(object):
    total: int = 0
    by_stream: Dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.total = _nonnegative_int(self.total, "total")
        self.by_stream = {
            _require_stream_id(stream_id): _nonnegative_int(count, "count")
            for stream_id, count in self.by_stream.items()
            if _nonnegative_int(count, "count") != 0
        }

    def is_empty(self) -> bool:
        return self.total == 0

    def add(self, stream_id: int, count: int) -> None:
        stream_id = _require_stream_id(stream_id)
        count = _nonnegative_int(count, "count")
        if count == 0:
            return
        self.total = _saturating_add(self.total, count)
        self.by_stream[stream_id] = _saturating_add(
            self.by_stream.get(stream_id, 0), count
        )

    def get(self, stream_id: int) -> int:
        return self.by_stream.get(stream_id, 0)

    def items(self):
        return self.by_stream.items()


@dataclass(frozen=True)
class QueueCost(object):
    queued: int = 0
    urgent: int = 0
    advisory: int = 0
    data: DataCosts = field(default_factory=DataCosts)
    pending_control: int = 0
    pending_priority: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "queued", _nonnegative_int(self.queued, "queued"))
        object.__setattr__(self, "urgent", _nonnegative_int(self.urgent, "urgent"))
        object.__setattr__(
            self,
            "advisory",
            _nonnegative_int(self.advisory, "advisory"),
        )
        if not isinstance(self.data, DataCosts):
            raise TypeError("data must be a DataCosts")
        object.__setattr__(
            self,
            "pending_control",
            _nonnegative_int(self.pending_control, "pending_control"),
        )
        object.__setattr__(
            self,
            "pending_priority",
            _nonnegative_int(self.pending_priority, "pending_priority"),
        )


@dataclass(frozen=True)
class StreamDiscardStats(object):
    removed_frames: int = 0
    data_frames: int = 0
    data_bytes: int = 0
    terminal_frames: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "removed_frames",
            _nonnegative_int(self.removed_frames, "removed_frames"),
        )
        object.__setattr__(
            self,
            "data_frames",
            _nonnegative_int(self.data_frames, "data_frames"),
        )
        object.__setattr__(
            self,
            "data_bytes",
            _nonnegative_int(self.data_bytes, "data_bytes"),
        )
        object.__setattr__(
            self,
            "terminal_frames",
            _nonnegative_int(self.terminal_frames, "terminal_frames"),
        )

    def add_frame(self, frame: Frame) -> "StreamDiscardStats":
        data_frames = 1 if frame.frame_type is FrameType.DATA else 0
        data_bytes = frame_data_app_bytes(frame) if data_frames else 0
        terminal_frames = 1 if frame_has_terminal_control(frame) else 0
        return StreamDiscardStats(
            _saturating_add(self.removed_frames, 1),
            _saturating_add(self.data_frames, data_frames),
            _saturating_add(self.data_bytes, data_bytes),
            _saturating_add(self.terminal_frames, terminal_frames),
        )

    def add(self, other: "StreamDiscardStats") -> "StreamDiscardStats":
        return StreamDiscardStats(
            _saturating_add(self.removed_frames, other.removed_frames),
            _saturating_add(self.data_frames, other.data_frames),
            _saturating_add(self.data_bytes, other.data_bytes),
            _saturating_add(self.terminal_frames, other.terminal_frames),
        )

    def removed_any(self) -> bool:
        return self.removed_frames != 0


@dataclass(frozen=True)
class WriteQueueLimits(object):
    max_bytes: int = 1
    urgent_max_bytes: int = 1
    session_data_max_bytes: int = 1
    per_stream_data_max_bytes: int = 1
    pending_control_max_bytes: int = 1
    pending_priority_max_bytes: int = 1
    max_batch_bytes: int = 1
    max_batch_frames: int = MAX_WRITE_BATCH_FRAMES

    def __post_init__(self) -> None:
        for name in (
                "max_bytes",
                "urgent_max_bytes",
                "session_data_max_bytes",
                "per_stream_data_max_bytes",
                "pending_control_max_bytes",
                "pending_priority_max_bytes",
                "max_batch_bytes",
        ):
            object.__setattr__(self, name, max(1, _nonnegative_int(getattr(self, name), name)))
        frames = max(1, _nonnegative_int(self.max_batch_frames, "max_batch_frames"))
        object.__setattr__(self, "max_batch_frames", min(frames, MAX_WRITE_BATCH_FRAMES))


@dataclass(frozen=True)
class WriterQueueStats(object):
    urgent_jobs: int = 0
    advisory_jobs: int = 0
    ordinary_jobs: int = 0
    queued_bytes: int = 0
    max_bytes: int = 0
    urgent_queued_bytes: int = 0
    urgent_max_bytes: int = 0
    advisory_queued_bytes: int = 0
    data_queued_bytes: int = 0
    session_data_high_watermark: int = 0
    per_stream_data_high_watermark: int = 0
    pending_control_bytes: int = 0
    pending_control_bytes_budget: int = 0
    pending_priority_bytes: int = 0
    pending_priority_bytes_budget: int = 0
    max_batch_frames: int = 0

    def __post_init__(self) -> None:
        for name in (
                "urgent_jobs",
                "advisory_jobs",
                "ordinary_jobs",
                "queued_bytes",
                "max_bytes",
                "urgent_queued_bytes",
                "urgent_max_bytes",
                "advisory_queued_bytes",
                "data_queued_bytes",
                "session_data_high_watermark",
                "per_stream_data_high_watermark",
                "pending_control_bytes",
                "pending_control_bytes_budget",
                "pending_priority_bytes",
                "pending_priority_bytes_budget",
                "max_batch_frames",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))


@dataclass(frozen=True)
class WriteCompletionResult(object):
    """Completed tracked-write result.

    ``None`` from ``try_result()`` means still pending; a result with
    ``error is None`` means completed successfully.
    """

    error: Optional[BaseException] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def raise_if_failed(self) -> None:
        if self.error is not None:
            raise self.error


class WriteCompletion(object):
    """Thread-safe completion token for queued tracked writes."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._done = False
        self._result: Optional[WriteCompletionResult] = None
        self._generation = 0

    def same(self, other: object) -> bool:
        return self is other

    @property
    def generation(self) -> int:
        with self._cond:
            generation = self._generation
        return generation

    def done(self) -> bool:
        with self._cond:
            done = self._done
        return done

    def try_result(self) -> Optional[WriteCompletionResult]:
        with self._cond:
            result = self._result
        return result

    def complete_success(self) -> None:
        self._complete(WriteCompletionResult())

    def complete_error(self, error: BaseException) -> None:
        self._complete(WriteCompletionResult(error))

    def notify_waiters(self) -> None:
        with self._cond:
            self._generation = _next_generation(self._generation)
            self._cond.notify_all()

    def wait_for_change_since(self, generation: int, timeout: float) -> None:
        timeout = max(0.0, float(timeout))
        if timeout == 0.0:
            return
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._result is None and self._generation == generation:
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    return
                self._cond.wait(min(remaining, _POLL_WAIT_CAP_SECONDS))

    def wait(self, timeout: Optional[float] = None) -> Optional[BaseException]:
        deadline = (
            None
            if timeout is None
            else time.monotonic() + _nonnegative_duration(timeout, "timeout")
        )
        with self._cond:
            while self._result is None:
                if deadline is None:
                    self._cond.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    raise WriteTimeout()
                self._cond.wait(min(remaining, _POLL_WAIT_CAP_SECONDS))
            error = self._result.error
        return error

    def _complete(self, result: WriteCompletionResult) -> None:
        with self._cond:
            if self._done:
                return
            self._result = result
            self._done = True
            self._generation = _next_generation(self._generation)
            self._cond.notify_all()


@dataclass(frozen=True)
class TrackedWriteJob(object):
    frames: Tuple[Frame, ...]
    completion: WriteCompletion

    def __post_init__(self) -> None:
        object.__setattr__(self, "frames", tuple(self.frames))


@dataclass(frozen=True)
class WriteJob(object):
    kind: WriteJobKind
    frame: Optional[Frame] = None
    frames: Tuple[Frame, ...] = ()
    tracked: Optional[TrackedWriteJob] = None

    @classmethod
    def frame_job(cls, frame: Frame) -> "WriteJob":
        return cls(WriteJobKind.FRAME, frame=frame)

    @classmethod
    def frames_job(cls, frames: Iterable[Frame]) -> "WriteJob":
        return cls(WriteJobKind.FRAMES, frames=tuple(frames))

    @classmethod
    def tracked_frames(cls, frames: Iterable[Frame], completion: WriteCompletion) -> "WriteJob":
        return cls(
            WriteJobKind.TRACKED_FRAMES,
            tracked=TrackedWriteJob(tuple(frames), completion),
        )

    @classmethod
    def graceful_close(cls, frame: Frame) -> "WriteJob":
        return cls(WriteJobKind.GRACEFUL_CLOSE, frame=frame)

    @classmethod
    def shutdown(cls) -> "WriteJob":
        return cls(WriteJobKind.SHUTDOWN)

    @classmethod
    def drain_shutdown(cls) -> "WriteJob":
        return cls(WriteJobKind.DRAIN_SHUTDOWN)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _coerce_enum(self.kind, WriteJobKind, "kind"))
        object.__setattr__(self, "frames", tuple(self.frames))

    def all_frames(self) -> Tuple[Frame, ...]:
        if self.kind in (WriteJobKind.FRAME, WriteJobKind.GRACEFUL_CLOSE):
            return () if self.frame is None else (self.frame,)
        if self.kind is WriteJobKind.FRAMES:
            return self.frames
        if self.kind is WriteJobKind.TRACKED_FRAMES and self.tracked is not None:
            return self.tracked.frames
        return ()

    def cost_bytes(self) -> int:
        return retained_frames_queue_cost(self.all_frames())

    def is_urgent(self) -> bool:
        if self.kind is WriteJobKind.SHUTDOWN:
            return True
        if self.kind in (WriteJobKind.DRAIN_SHUTDOWN, WriteJobKind.GRACEFUL_CLOSE):
            return False
        return frames_are_all_urgent(self.all_frames())

    def bypasses_capacity(self) -> bool:
        if self.kind in (WriteJobKind.SHUTDOWN, WriteJobKind.DRAIN_SHUTDOWN):
            return True
        if self.kind is WriteJobKind.GRACEFUL_CLOSE:
            return False
        return frames_bypass_capacity(self.all_frames())

    def bypasses_urgent_capacity(self) -> bool:
        if self.kind in (WriteJobKind.SHUTDOWN, WriteJobKind.DRAIN_SHUTDOWN):
            return True
        return frames_bypass_urgent_capacity(self.all_frames())

    def projected_data_queue_cost_bytes(self) -> int:
        return self.cost_bytes() if self.contains_data_frame() else 0

    def contains_data_frame(self) -> bool:
        return frames_contain_data_frame(self.all_frames())

    def urgent_stream_id(self) -> Optional[int]:
        if self.kind in (WriteJobKind.FRAME, WriteJobKind.GRACEFUL_CLOSE):
            if self.frame is not None and frame_is_urgent(self.frame) and self.frame.stream_id:
                return self.frame.stream_id
            return None
        if self.kind in (WriteJobKind.FRAMES, WriteJobKind.TRACKED_FRAMES):
            return urgent_frames_stream_id(self.all_frames())
        return None

    def coalesce_key(self) -> Optional[CoalesceKey]:
        if self.kind is not WriteJobKind.FRAME or self.frame is None:
            return None
        frame = self.frame
        if frame.frame_type is FrameType.EXT:
            if _frame_is_priority_update(frame):
                return CoalesceKey(CoalesceKind.PRIORITY_UPDATE, frame.stream_id)
            return None
        if frame.frame_type is FrameType.MAX_DATA and _payload_is_exact_varint(frame.payload):
            return CoalesceKey(CoalesceKind.MAX_DATA, frame.stream_id)
        if frame.frame_type is FrameType.BLOCKED and _payload_is_exact_varint(frame.payload):
            return CoalesceKey(CoalesceKind.BLOCKED, frame.stream_id)
        if frame.frame_type is FrameType.GOAWAY:
            return CoalesceKey(CoalesceKind.GOAWAY, 0)
        return None

    def tracks_completion(self, completion: WriteCompletion) -> bool:
        return (
                self.kind is WriteJobKind.TRACKED_FRAMES
                and self.tracked is not None
                and self.tracked.completion.same(completion)
        )

    def with_frames(self, frames: Iterable[Frame]) -> Optional["WriteJob"]:
        frames = tuple(frames)
        if self.kind is WriteJobKind.FRAME:
            return (
                WriteJob.frame_job(frames[0])
                if len(frames) == 1
                else WriteJob.frames_job(frames)
            )
        if self.kind is WriteJobKind.GRACEFUL_CLOSE:
            return (
                WriteJob.graceful_close(frames[0])
                if len(frames) == 1
                else WriteJob.frames_job(frames)
            )
        if self.kind is WriteJobKind.FRAMES:
            return WriteJob.frames_job(frames)
        if self.kind is WriteJobKind.TRACKED_FRAMES and self.tracked is not None:
            if not frames:
                return None
            return WriteJob.tracked_frames(frames, self.tracked.completion)
        return self


def make_tx_frame(frame_type: FrameType, flags: int = 0, stream_id: int = 0) -> TxFrame:
    return TxFrame(frame_type, flags, stream_id)


def flat_tx_frame(frame: Frame) -> TxFrame:
    tx = make_tx_frame(frame.frame_type, frame.flags, frame.stream_id)
    tx.set_flat_payload(frame.payload)
    return tx


def max_tx_payload_length() -> int:
    return sys.maxsize


def checked_tx_payload_length(count: int) -> int:
    count = _nonnegative_int(count, "count")
    if count > max_tx_payload_length():
        raise OverflowError("count exceeds platform payload length")
    return count


def add_tx_payload_lengths(left: int, right: int) -> int:
    left = _nonnegative_int(left, "left")
    right = _nonnegative_int(right, "right")
    return min(left + right, max_tx_payload_length())


def trim_tx_payload_parts(
        parts: Sequence[ReadableBuffer],
        idx: int,
        off: int,
        length: int,
) -> Tuple[Tuple[memoryview, ...], int, int]:
    length = checked_tx_payload_length(length)
    if length <= 0 or not parts:
        return (), 0, 0
    views = tuple(_byte_view(part) for part in parts)
    idx = _nonnegative_int(idx, "idx")
    off = _nonnegative_int(off, "off")
    while idx < len(views) and off >= len(views[idx]):
        idx += 1
        off = 0
    if idx >= len(views):
        return (), 0, 0
    start = idx
    start_off = off
    remaining = length
    while idx < len(views) and remaining > 0:
        part = views[idx]
        if off >= len(part):
            idx += 1
            off = 0
            continue
        take = min(len(part) - off, remaining)
        remaining -= take
        off += take
        if off >= len(part):
            idx += 1
            off = 0
    end = idx
    if remaining == 0 and off > 0 and idx < len(views):
        end = idx + 1
    if end < start:
        end = start
    return views[start:end], 0, start_off


def tx_frame_queue_cost(frame: TxFrame) -> int:
    return _saturating_add(FRAME_QUEUE_OVERHEAD_BYTES, frame.payload_length())


def tx_frame_buffered_bytes(frame: TxFrame) -> int:
    return tx_frame_queue_cost(frame)


def tx_frames_queue_cost(frames: Iterable[TxFrame]) -> int:
    total = 0
    for frame in frames:
        total = _saturating_add(total, tx_frame_queue_cost(frame))
    return total


def tx_frames_buffered_bytes(frames: Iterable[TxFrame]) -> int:
    return tx_frames_queue_cost(frames)


def request_cost_from_bytes(count: int) -> int:
    return min(MAX_REQUEST_COST, _nonnegative_int(count, "count"))


def add_request_cost(cost: int, count: int) -> int:
    cost = _nonnegative_int(cost, "cost")
    if cost >= MAX_REQUEST_COST:
        return MAX_REQUEST_COST
    delta = request_cost_from_bytes(count)
    return min(MAX_REQUEST_COST, cost + delta)


def tx_frame_encoded_bytes(frame: TxFrame) -> int:
    stream_len = frame.stream_id_len or varint_len(frame.stream_id)
    body_len = 1 + stream_len + frame.payload_length()
    return varint_len(body_len) + body_len


def clone_tx_frames_if_needed(
        frames: Sequence[TxFrame], clone: bool
) -> Tuple[Tuple[TxFrame, ...], bool]:
    if not clone:
        return tuple(frames), False
    cloned = []
    for frame in frames:
        replacement = make_tx_frame(frame.frame_type, frame.flags, frame.stream_id)
        replacement.set_flat_payload(frame.cloned_payload())
        cloned.append(replacement)
    return tuple(cloned), False


def make_prepared_priority_update(stream_id: int, payload: bytes) -> PreparedPriorityUpdate:
    payload = _bytes_or_empty(payload, "payload")
    if stream_id == 0 or not payload:
        return PreparedPriorityUpdate()
    frame = build_pending_priority_update_tx_frame(stream_id, payload)
    return PreparedPriorityUpdate(
        frame=frame,
        stream_id=stream_id,
        payload=payload,
        frame_bytes=tx_frame_buffered_bytes(frame),
    )


def build_pending_priority_update_tx_frame(stream_id: int, payload: bytes) -> TxFrame:
    frame = make_tx_frame(FrameType.EXT, 0, _require_stream_id(stream_id))
    frame.set_flat_payload(payload)
    return frame


def prepared_priority_update_from_frames(
        frames: Sequence[TxFrame],
) -> PreparedPriorityUpdate:
    if len(frames) < 2:
        return PreparedPriorityUpdate()
    first = frames[0]
    if (
            first.frame_type is not FrameType.EXT
            or first.stream_id == 0
            or not first.payload
            or not frame_is_priority_update_tx(first)
    ):
        return PreparedPriorityUpdate()
    for frame in frames[1:]:
        if frame.frame_type is not FrameType.DATA or frame.stream_id != first.stream_id:
            return PreparedPriorityUpdate()
    return PreparedPriorityUpdate(
        frame=first,
        stream_id=first.stream_id,
        payload=first.payload,
        frame_bytes=tx_frame_buffered_bytes(first),
    )


def write_urgency_profile_from(all_urgent: bool) -> WriteUrgencyProfile:
    return WriteUrgencyProfile.ALL_URGENT if all_urgent else WriteUrgencyProfile.MIXED


def promote_lane(lane: QueueLane, profile: WriteUrgencyProfile) -> QueueLane:
    lane = _coerce_enum(lane, QueueLane, "lane")
    profile = _coerce_enum(profile, WriteUrgencyProfile, "profile")
    if lane is QueueLane.ORDINARY and profile.all_urgent():
        return QueueLane.URGENT
    return lane


def clear_write_request_classification(req: Optional[QueuedWriteRequest]) -> None:
    if req is None:
        return
    req.request_meta_ready = False
    req.request_stream_id = 0
    req.request_stream_id_known = False
    req.request_stream_scoped = False
    req.request_urgency_rank = 0
    req.request_cost = 0
    req.request_buffered_bytes = 0
    req.request_is_priority_update = False
    req.request_all_urgent = False
    clear_terminal_classification_and_fin(req)


def init_terminal_classification(req: QueuedWriteRequest) -> None:
    req.terminal_data_priority = True
    req.terminal_reset_only = True
    req.terminal_abort_only = True
    req.terminal_has_fin = False


def clear_terminal_classification(req: QueuedWriteRequest) -> None:
    req.terminal_data_priority = False
    req.terminal_reset_only = False
    req.terminal_abort_only = False


def clear_terminal_classification_and_fin(req: QueuedWriteRequest) -> None:
    clear_terminal_classification(req)
    req.terminal_has_fin = False


def set_request_stream_scope(req: QueuedWriteRequest, stream_id: int) -> None:
    req.request_stream_id = stream_id
    req.request_stream_id_known = True
    req.request_stream_scoped = True


def clear_request_stream_scope(req: QueuedWriteRequest) -> None:
    req.request_stream_id_known = False
    req.request_stream_scoped = False


def ensure_minimum_request_cost(req: QueuedWriteRequest) -> None:
    if req.request_cost <= 0:
        req.request_cost = 1


def frame_is_priority_update_tx(frame: TxFrame) -> bool:
    if frame.frame_type is not FrameType.EXT:
        return False
    return _payload_is_priority_update(frame.payload)


def classify_terminal_frame(
        req: QueuedWriteRequest, frame: TxFrame, fin_seen: bool
) -> bool:
    if frame.frame_type is FrameType.DATA:
        if fin_seen:
            req.terminal_data_priority = False
        if frame.flags & FRAME_FLAG_FIN:
            fin_seen = True
            req.terminal_has_fin = True
        req.terminal_reset_only = False
        req.terminal_abort_only = False
    elif frame.frame_type is FrameType.EXT:
        if fin_seen or not frame_is_priority_update_tx(frame):
            req.terminal_data_priority = False
        req.terminal_reset_only = False
        req.terminal_abort_only = False
    elif frame.frame_type is FrameType.RESET:
        req.terminal_data_priority = False
        req.terminal_abort_only = False
    elif frame.frame_type is FrameType.ABORT:
        req.terminal_data_priority = False
        req.terminal_reset_only = False
    else:
        clear_terminal_classification(req)
    return fin_seen


def classify_write_request(req: Optional[QueuedWriteRequest]) -> None:
    if req is None or req.request_meta_ready:
        return
    clear_write_request_classification(req)
    req.request_meta_ready = True
    if len(req.frames) == 1:
        classify_single_frame_write_request(req, req.frames[0])
        return
    req.request_all_urgent = bool(req.frames)
    req.request_urgency_rank = DEFAULT_URGENCY_RANK
    init_terminal_classification(req)

    seen = False
    mixed = False
    fin_seen = False
    for frame in req.frames:
        if not is_urgent_type(frame.frame_type):
            req.request_all_urgent = False
        req.request_urgency_rank = min(req.request_urgency_rank, urgency_rank(frame.frame_type))
        frame_bytes = tx_frame_buffered_bytes(frame)
        req.request_buffered_bytes = _saturating_add(req.request_buffered_bytes, frame_bytes)
        req.request_cost = add_request_cost(req.request_cost, frame_bytes)
        if not batch_frame_is_stream_scoped(frame):
            continue
        if not seen:
            req.request_stream_id = frame.stream_id
            seen = True
        elif frame.stream_id != req.request_stream_id:
            mixed = True
        if mixed:
            clear_terminal_classification_and_fin(req)
            continue
        fin_seen = classify_terminal_frame(req, frame, fin_seen)

    ensure_minimum_request_cost(req)
    if seen and not mixed:
        set_request_stream_scope(req, req.request_stream_id)
    if not seen:
        clear_request_stream_scope(req)
        clear_terminal_classification_and_fin(req)


def classify_single_frame_write_request(req: QueuedWriteRequest, frame: TxFrame) -> None:
    clear_write_request_classification(req)
    req.request_meta_ready = True
    req.request_all_urgent = is_urgent_type(frame.frame_type)
    req.request_urgency_rank = urgency_rank(frame.frame_type)
    req.request_buffered_bytes = tx_frame_buffered_bytes(frame)
    req.request_cost = request_cost_from_bytes(req.request_buffered_bytes)
    init_terminal_classification(req)
    req.request_is_priority_update = frame_is_priority_update_tx(frame)
    if not batch_frame_is_stream_scoped(frame):
        clear_request_stream_scope(req)
        clear_terminal_classification_and_fin(req)
        ensure_minimum_request_cost(req)
        return
    set_request_stream_scope(req, frame.stream_id)
    classify_terminal_frame(req, frame, False)
    ensure_minimum_request_cost(req)


def batch_stream_id(req: QueuedWriteRequest) -> Tuple[int, bool]:
    classify_write_request(req)
    return req.request_stream_id, req.request_stream_id_known


def batch_frame_is_stream_scoped(frame: TxFrame) -> bool:
    if frame.stream_id == 0:
        return False
    return frame.frame_type in (
        FrameType.DATA,
        FrameType.MAX_DATA,
        FrameType.STOP_SENDING,
        FrameType.BLOCKED,
        FrameType.RESET,
        FrameType.ABORT,
        FrameType.EXT,
    )


def tx_frame_chunk_spans(
        frames: Sequence[TxFrame], max_frames: int = 0, max_bytes: int = 0
) -> Tuple[ChunkSpan, ...]:
    if not frames:
        return ()
    max_frames = _chunk_frame_limit(max_frames, len(frames))
    max_bytes = _nonnegative_int(max_bytes, "max_bytes")
    spans = []
    start = 0
    chunk_bytes = 0
    for index, frame in enumerate(frames):
        frame_bytes = tx_frame_buffered_bytes(frame)
        if _chunk_over_limit(index, start, chunk_bytes, frame_bytes, max_frames, max_bytes):
            spans.append(ChunkSpan(start, index))
            start = index
            chunk_bytes = 0
        chunk_bytes = _saturating_add(chunk_bytes, frame_bytes)
    spans.append(ChunkSpan(start, len(frames)))
    return tuple(spans)


def validate_outbound_tx_frames_with_limits(
        frames: Iterable[TxFrame],
        local_limits: Optional[Limits] = None,
        peer_limits: Optional[Limits] = None,
) -> None:
    local = normalize_limits(local_limits)
    peer = normalize_limits(peer_limits)
    for frame in frames:
        validate_outbound_tx_frame_with_limits(frame, local, peer)


def validate_outbound_tx_frame_with_limits(
        frame: TxFrame, local_limits: Limits, peer_limits: Limits
) -> None:
    validation = Frame(
        frame.frame_type,
        frame.stream_id,
        frame.flags,
        frame.payload_for_validation(),
    )
    validate_frame(validation, normalize_limits(None), False)
    if frame.frame_type is FrameType.DATA:
        limit = peer_limits.max_frame_payload
        op = "send DATA payload"
    elif frame.frame_type in (
            FrameType.MAX_DATA,
            FrameType.BLOCKED,
            FrameType.PONG,
            FrameType.ABORT,
            FrameType.GOAWAY,
            FrameType.CLOSE,
    ):
        limit = peer_limits.max_control_payload_bytes
        op = "send control payload"
    elif frame.frame_type is FrameType.PING:
        limit = min(local_limits.max_control_payload_bytes, peer_limits.max_control_payload_bytes)
        op = "send PING payload"
    elif frame.frame_type is FrameType.EXT:
        limit = peer_limits.max_extension_payload_bytes
        op = "send EXT payload"
    else:
        return
    if frame.payload_length() > limit:
        raise ProtocolError(
            "%s too large" % op,
            code=int(ErrorCode.FRAME_SIZE),
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.WRITE,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.WRITE,
        )


def build_tx_lane_request(
        frames: Iterable[TxFrame],
        origin: WriteRequestOrigin = WriteRequestOrigin.PROTOCOL,
        terminal_policy: TerminalWritePolicy = TerminalWritePolicy.REJECT,
        local_limits: Optional[Limits] = None,
        peer_limits: Optional[Limits] = None,
) -> QueuedWriteRequest:
    frames = tuple(frames)
    if not frames:
        return QueuedWriteRequest()
    validate_outbound_tx_frames_with_limits(frames, local_limits, peer_limits)
    req = QueuedWriteRequest(
        frames=frames,
        origin=origin,
        terminal_policy=terminal_policy,
    )
    if req.origin.is_stream_generated():
        classify_write_request(req)
        req.queued_bytes = req.request_buffered_bytes
    else:
        req.queued_bytes = tx_frames_buffered_bytes(req.frames)
    return req


def ensure_request_queued_bytes(req: Optional[QueuedWriteRequest]) -> int:
    if req is None:
        return 0
    if req.queued_bytes == 0:
        classify_write_request(req)
        req.queued_bytes = req.request_buffered_bytes
    return req.queued_bytes


def request_buffered_bytes(req: Optional[QueuedWriteRequest]) -> int:
    if req is None:
        return 0
    classify_write_request(req)
    return req.request_buffered_bytes


def queue_would_block(
        memory_blocked: bool,
        session_queued: int,
        stream_queued: int,
        requested: int,
        session_high_watermark: int,
        stream_high_watermark: int,
) -> bool:
    return _flow_queue_would_block(
        memory_blocked,
        session_queued,
        stream_queued,
        requested,
        session_high_watermark,
        stream_high_watermark,
    )


def replacement_would_exceed_limit(
        current: int, old_cost: int, new_cost: int, limit: int
) -> bool:
    current = _nonnegative_int(current, "current")
    old_cost = _nonnegative_int(old_cost, "old_cost")
    new_cost = _nonnegative_int(new_cost, "new_cost")
    limit = _nonnegative_int(limit, "limit")
    return new_cost > old_cost and new_cost > max(0, limit - max(0, current - old_cost))


def queue_cost_for(lane: QueueLane, job: WriteJob, queued: int) -> QueueCost:
    lane = _coerce_enum(lane, QueueLane, "lane")
    queued = _nonnegative_int(queued, "queued")
    urgent = (
        queued
        if lane is QueueLane.URGENT and job.is_urgent() and not job.bypasses_urgent_capacity()
        else 0
    )
    advisory = queued if lane is QueueLane.ADVISORY else 0
    key = job.coalesce_key()
    if key is not None and key.kind is CoalesceKind.PRIORITY_UPDATE:
        pending_control = 0
        pending_priority = pending_priority_frame_bytes(job.frame)
    elif key is not None and key.kind in (CoalesceKind.MAX_DATA, CoalesceKind.BLOCKED):
        pending_control = pending_control_frame_bytes(job.frame)
        pending_priority = 0
    elif key is not None and key.kind is CoalesceKind.GOAWAY:
        pending_control = 0
        pending_priority = 0
    else:
        pending_control = terminal_control_bytes(job)
        pending_priority = 0
    return QueueCost(
        queued=queued,
        urgent=urgent,
        advisory=advisory,
        data=data_costs(job),
        pending_control=pending_control,
        pending_priority=pending_priority,
    )


def data_costs(job: WriteJob) -> DataCosts:
    costs = DataCosts()
    for frame in job.all_frames():
        add_frame_data_cost(costs, frame)
    return costs


def terminal_control_bytes(job: WriteJob) -> int:
    total = 0
    for frame in job.all_frames():
        total = _saturating_add(total, frame_terminal_control_bytes(frame))
    return total


def frame_terminal_control_bytes(frame: Frame) -> int:
    if frame.frame_type not in (
            FrameType.ABORT,
            FrameType.RESET,
            FrameType.STOP_SENDING,
    ):
        return 0
    return retained_frame_queue_cost(frame)


def add_frame_data_cost(costs: DataCosts, frame: Frame) -> None:
    if frame.frame_type is not FrameType.DATA:
        return
    costs.add(frame.stream_id, retained_frame_queue_cost(frame))


def pending_control_frame_bytes(frame: Optional[Frame]) -> int:
    if frame is None or frame.frame_type not in (FrameType.MAX_DATA, FrameType.BLOCKED):
        return 0
    try:
        value, consumed = parse_varint(frame.payload)
    except Exception:
        return retained_frame_queue_cost(frame)
    if consumed != len(frame.payload):
        return retained_frame_queue_cost(frame)
    total = varint_len(value)
    if frame.stream_id != 0:
        total = _saturating_add(total, varint_len(frame.stream_id))
    return total


def pending_priority_frame_bytes(frame: Optional[Frame]) -> int:
    if frame is None or not _frame_is_priority_update(frame):
        return 0
    return len(frame.payload)


def frame_has_terminal_control(frame: Frame) -> bool:
    return frame.frame_type in (
        FrameType.ABORT,
        FrameType.RESET,
        FrameType.STOP_SENDING,
    )


def frame_has_terminal_control_for_stream(frame: Frame, stream_id: int) -> bool:
    return frame.stream_id == stream_id and frame_has_terminal_control(frame)


def job_has_terminal_control_for_stream(job: WriteJob, stream_id: int) -> bool:
    return any(
        frame_has_terminal_control_for_stream(frame, stream_id)
        for frame in job.all_frames()
    )


def jobs_have_terminal_control_for_stream(
        jobs: Iterable[WriteJob], stream_id: int
) -> bool:
    return any(job_has_terminal_control_for_stream(job, stream_id) for job in jobs)


def frame_data_app_bytes(frame: Frame) -> int:
    if frame.frame_type is not FrameType.DATA:
        return 0
    if frame.flags & FRAME_FLAG_FIN and len(frame.payload) == 0:
        return 0
    if frame.flags == 0:
        return len(frame.payload)
    try:
        _, _, offset = parse_data_payload_metadata_offset(frame.payload, frame.flags)
    except Exception:
        offset = 0
    return max(0, len(frame.payload) - offset)


def remove_stream_frames(
        job: WriteJob,
        stream_id: int,
        remove: Callable[[Frame, int], bool],
) -> Tuple[Optional[WriteJob], StreamDiscardStats]:
    frames = job.all_frames()
    if not frames:
        return job, StreamDiscardStats()
    kept = []
    stats = StreamDiscardStats()
    for frame in frames:
        if remove(frame, stream_id):
            stats = stats.add_frame(frame)
        else:
            kept.append(frame)
    if not stats.removed_any():
        return job, stats
    if job.kind is WriteJobKind.TRACKED_FRAMES and job.tracked is not None:
        job.tracked.completion.complete_error(
            _internal_queue_error(QUEUED_WRITE_DISCARDED_MESSAGE)
        )
    if not kept:
        return None, stats
    return job.with_frames(kept), stats


def job_has_removable_stream_frame(
        job: WriteJob, stream_id: int, remove: Callable[[Frame, int], bool]
) -> bool:
    return any(remove(frame, stream_id) for frame in job.all_frames())


def jobs_have_removable_stream_frame(
        jobs: Iterable[WriteJob], stream_id: int, remove: Callable[[Frame, int], bool]
) -> bool:
    return any(job_has_removable_stream_frame(job, stream_id, remove) for job in jobs)


def frame_belongs_to_stream(frame: Frame, stream_id: int) -> bool:
    return stream_id != 0 and frame.stream_id == stream_id


def frame_is_send_tail_for_stream(frame: Frame, stream_id: int) -> bool:
    return frame_belongs_to_stream(frame, stream_id) and frame.frame_type in (
        FrameType.DATA,
        FrameType.BLOCKED,
        FrameType.EXT,
    )


def complete_job_error(job: WriteJob, error: BaseException) -> None:
    if job.kind is WriteJobKind.TRACKED_FRAMES and job.tracked is not None:
        job.tracked.completion.complete_error(error)


def merge_coalesced_priority_update(old: WriteJob, new: WriteJob) -> WriteJob:
    if old.kind is not WriteJobKind.FRAME or new.kind is not WriteJobKind.FRAME:
        return new
    if old.frame is None or new.frame is None:
        return new
    if (
            old.frame.frame_type is not FrameType.EXT
            or new.frame.frame_type is not FrameType.EXT
            or old.frame.stream_id != new.frame.stream_id
    ):
        return new
    merged = merged_priority_update_payload(old.frame.payload, new.frame.payload)
    if merged is None:
        return new
    return WriteJob.frame_job(replace(new.frame, payload=merged))


def merged_priority_update_payload(old_payload: bytes, new_payload: bytes) -> Optional[bytes]:
    old_fields = priority_update_fields(old_payload)
    new_fields = priority_update_fields(new_payload)
    if old_fields is None or new_fields is None:
        return None
    old_priority, old_group = old_fields
    new_priority, new_group = new_fields
    priority = new_priority if new_priority is not None else old_priority
    group = new_group if new_group is not None else old_group
    if priority is None and group is None:
        return None
    out = bytearray()
    append_varint(out, EXT_PRIORITY_UPDATE)
    if priority is not None:
        append_metadata_varint(out, METADATA_STREAM_PRIORITY, priority)
    if group is not None:
        append_metadata_varint(out, METADATA_STREAM_GROUP, group)
    return bytes(out)


# noinspection PyTypeHints
def priority_update_fields(
        payload: bytes
) -> Optional[PriorityUpdateFields]:
    try:
        metadata, valid = parse_priority_update_payload(payload)
    except Exception:
        return None
    if not valid:
        return None
    return metadata.priority, metadata.group


def append_metadata_varint(dst: MutableSequence[int], typ: int, value: int) -> None:
    value = _require_varint62(value, "metadata value")
    append_varint(dst, typ)
    append_varint(dst, varint_len(value))
    append_varint(dst, value)


def retained_frame_queue_cost(frame: Frame) -> int:
    return _saturating_add(FRAME_QUEUE_OVERHEAD_BYTES, len(frame.payload))


def retained_frames_queue_cost(frames: Iterable[Frame]) -> int:
    total = 0
    for frame in frames:
        total = _saturating_add(total, retained_frame_queue_cost(frame))
    return total


def frame_is_urgent(frame: Frame) -> bool:
    return is_urgent_type(frame.frame_type)


def is_urgent_type(frame_type: FrameType) -> bool:
    frame_type = _coerce_frame_type(frame_type)
    return frame_type in (
        FrameType.CLOSE,
        FrameType.GOAWAY,
        FrameType.ABORT,
        FrameType.RESET,
        FrameType.STOP_SENDING,
        FrameType.MAX_DATA,
        FrameType.BLOCKED,
        FrameType.PONG,
        FrameType.PING,
    )


def urgency_rank(frame_type: FrameType) -> int:
    frame_type = _coerce_frame_type(frame_type)
    ranks = {
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
    return ranks.get(frame_type, DEFAULT_URGENCY_RANK)


def frame_bypasses_capacity(frame: Frame) -> bool:
    return frame_is_urgent(frame)


def frame_bypasses_urgent_capacity(_frame: Frame) -> bool:
    return False


def frames_are_all_urgent(frames: Iterable[Frame]) -> bool:
    return all(frame_is_urgent(frame) for frame in frames)


def frames_bypass_capacity(frames: Iterable[Frame]) -> bool:
    return all(frame_bypasses_capacity(frame) for frame in frames)


def frames_bypass_urgent_capacity(frames: Iterable[Frame]) -> bool:
    return all(frame_bypasses_urgent_capacity(frame) for frame in frames)


def frames_contain_data_frame(frames: Iterable[Frame]) -> bool:
    return any(frame.frame_type is FrameType.DATA for frame in frames)


def urgent_frames_stream_id(frames: Iterable[Frame]) -> Optional[int]:
    stream_id = None
    for frame in frames:
        if not frame_is_urgent(frame) or frame.stream_id == 0:
            return None
        if stream_id is None:
            stream_id = frame.stream_id
        elif stream_id != frame.stream_id:
            return None
    return stream_id


def frame_queue_cost(frame: Frame) -> int:
    return retained_frame_queue_cost(frame)


def frames_queue_cost(frames: Iterable[Frame]) -> int:
    return retained_frames_queue_cost(frames)


def build_priority_update_frame(
        stream_id: int,
        metadata: MetadataUpdate,
        capabilities: int,
        max_payload: int = 4096,
) -> Frame:
    payload = build_priority_update_payload(capabilities, metadata, max_payload)
    return Frame(FrameType.EXT, _require_stream_id(stream_id), 0, payload)


def _order_urgent_jobs_in_place(batch: MutableSequence[WriteJob]) -> None:
    if len(batch) < 2:
        return
    ordered = sorted(batch, key=_urgent_job_key)
    batch.clear()
    batch.extend(ordered)


def _urgent_job_key(job: WriteJob) -> tuple[int, int, int]:
    rank = DEFAULT_URGENCY_RANK + 1
    stream_id = 0
    for frame in job.all_frames():
        rank = min(rank, urgency_rank(frame.frame_type))
        if stream_id == 0 and frame.stream_id != 0:
            stream_id = frame.stream_id
    if job.kind is WriteJobKind.SHUTDOWN:
        rank = DEFAULT_URGENCY_RANK + 2
    scoped = 0 if stream_id != 0 else 1
    return rank, scoped, stream_id


def _payload_is_priority_update(payload: bytes) -> bool:
    try:
        subtype, _ = parse_varint(payload)
    except Exception:
        return False
    return subtype == EXT_PRIORITY_UPDATE


def _frame_is_priority_update(frame: Frame) -> bool:
    return frame.frame_type is FrameType.EXT and _payload_is_priority_update(frame.payload)


def _payload_is_exact_varint(payload: bytes) -> bool:
    try:
        _, consumed = parse_varint(payload)
    except Exception:
        return False
    return consumed == len(payload)


def _normalize_deadline(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    deadline = _nonnegative_duration(deadline, "deadline")
    if deadline <= 0:
        return None
    return deadline


def _deadline_remaining(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def _poll_wait_timeout(remaining: Optional[float]) -> float:
    if remaining is None:
        return min(_POLL_WAIT_CAP_SECONDS, 0.050)
    return max(0.0, min(remaining, 0.050, _POLL_WAIT_CAP_SECONDS))


def _event_is_set(event: Optional[object]) -> bool:
    if event is None:
        return False
    is_set = getattr(event, "is_set", None)
    if is_set is not None:
        return bool(is_set())
    done = getattr(event, "done", None)
    if done is not None:
        return bool(done())
    return bool(event)


def _event_wait(event: Optional[object], timeout: float) -> bool:
    if event is None:
        return False
    wait = getattr(event, "wait", None)
    if wait is None:
        return _event_is_set(event)
    return bool(wait(max(0.0, timeout)))


def _try_recv_ready(lane: object) -> tuple[bool, object]:
    if lane is None:
        return False, None
    popleft = getattr(lane, "popleft", None)
    if popleft is not None:
        try:
            return True, popleft()
        except IndexError:
            return False, None
    if isinstance(lane, list):
        if not lane:
            return False, None
        return True, lane.pop(0)
    get_nowait = getattr(lane, "get_nowait", None)
    if get_nowait is not None:
        try:
            return True, get_nowait()
        except _stdlib_queue.Empty:
            return False, None
    get = getattr(lane, "get", None)
    if get is not None:
        try:
            return True, get(block=False)
        except _stdlib_queue.Empty:
            return False, None
        except TypeError:
            return False, None
    return False, None


def _ordered_batch(
        batch: List[object],
        order: Optional[BatchOrder],
) -> List[object]:
    if order is None:
        return batch
    ordered = order(batch)
    return ordered if isinstance(ordered, list) else list(ordered)


def _coerce_frame_type(value: FrameType) -> FrameType:
    if isinstance(value, FrameType):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("frame_type must be a FrameType or integer")
    return FrameType.from_code(value)


def _byte(value: int, name: str) -> int:
    value = _nonnegative_int(value, name)
    if value > 0xFF:
        raise ValueError("%s must fit in one byte" % name)
    return value


def _saturating_add(left: int, right: int) -> int:
    left = _nonnegative_int(left, "left")
    right = _nonnegative_int(right, "right")
    return min(MAX_UINT64, left + right)


def _next_generation(current: int) -> int:
    value = (_nonnegative_int(current, "current") + 1) & MAX_UINT64
    return 1 if value == 0 else value


def _chunk_frame_limit(max_frames: int, frame_count: int) -> int:
    frame_count = _nonnegative_int(frame_count, "frame_count")
    if isinstance(max_frames, bool) or not isinstance(max_frames, int):
        raise TypeError("max_frames must be an integer")
    if max_frames <= 0:
        return max(1, frame_count)
    return max_frames


def _chunk_over_limit(
        index: int,
        start: int,
        chunk_bytes: int,
        frame_bytes: int,
        max_frames: int,
        max_bytes: int,
) -> bool:
    return index - start >= max_frames or (
            index > start
            and 0 < max_bytes < _saturating_add(chunk_bytes, frame_bytes)
    )


def _coerce_enum(value, enum_type, name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        return enum_type(value)
    if isinstance(value, bool):
        raise TypeError("%s must be a %s or integer" % (name, enum_type.__name__))
    return enum_type(value)


def _byte_view(data: ReadableBuffer) -> memoryview:
    view = memoryview(data)
    if view.ndim != 1 or view.format not in ("B", "b", "c"):
        try:
            view = view.cast("B")
        except TypeError:
            view = memoryview(view.tobytes())
    return view


def _bytes_or_empty(data: ReadableBuffer, name: str) -> bytes:
    if data is None:
        return b""
    try:
        return _byte_view(data).tobytes()
    except (TypeError, ValueError) as exc:
        raise TypeError("%s must be bytes-like" % name) from exc


def _internal_queue_error(message: str) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.INTERNAL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.WRITE,
    )


internal_queue_error = _internal_queue_error
nonnegative_duration = _nonnegative_duration
order_urgent_jobs_in_place = _order_urgent_jobs_in_place
saturating_add = _saturating_add


__all__ = (
    "DEFAULT_URGENCY_RANK",
    "FRAME_QUEUE_OVERHEAD_BYTES",
    "MAX_REQUEST_COST",
    "POLL_WAIT_CAP_SECONDS",
    "MAX_UINT64",
    "MAX_WRITE_BATCH_FRAMES",
    "PENDING_CONTROL_BUDGET_MESSAGE",
    "PENDING_PRIORITY_BUDGET_MESSAGE",
    "QUEUED_DATA_HWM_MESSAGE",
    "QUEUED_WRITE_DISCARDED_MESSAGE",
    "URGENT_WRITER_QUEUE_FULL_MESSAGE",
    "WRITER_QUEUE_FULL_MESSAGE",
    "ChunkSpan",
    "CoalesceKey",
    "CoalesceKind",
    "DataCosts",
    "FrameOwnership",
    "PreparedPriorityUpdate",
    "QueueCost",
    "QueueLane",
    "QueueReservationResult",
    "QueueReservationState",
    "QueuedWriteRequest",
    "QueuedWriteResult",
    "OpenerVisibilityMark",
    "StreamDiscardStats",
    "TerminalWritePolicy",
    "TrackedWriteJob",
    "TxFrame",
    "TxPayloadKind",
    "WriteCompletion",
    "WriteCompletionResult",
    "WriteJob",
    "WriteJobKind",
    "WriteQueueLimits",
    "WriteQueuePopStatus",
    "WriteRequestOrigin",
    "WriteUrgencyProfile",
    "WriterQueueStats",
    "add_request_cost",
    "add_tx_payload_lengths",
    "batch_frame_is_stream_scoped",
    "batch_stream_id",
    "build_priority_update_frame",
    "build_tx_lane_request",
    "checked_tx_payload_length",
    "classify_write_request",
    "clone_tx_frames_if_needed",
    "collect_ready_batch_into",
    "complete_job_error",
    "effective_deadline",
    "frame_buffered_bytes",
    "frame_chunk_spans",
    "frames_buffered_bytes",
    "ensure_request_queued_bytes",
    "frame_belongs_to_stream",
    "frame_data_app_bytes",
    "frame_is_send_tail_for_stream",
    "frame_is_urgent",
    "frame_queue_cost",
    "frames_queue_cost",
    "internal_queue_error",
    "is_urgent_type",
    "jobs_have_removable_stream_frame",
    "make_prepared_priority_update",
    "make_tx_frame",
    "max_tx_payload_length",
    "merge_coalesced_priority_update",
    "nonnegative_duration",
    "order_urgent_jobs_in_place",
    "prepared_priority_update_from_frames",
    "promote_lane",
    "queue_cost_for",
    "queue_would_block",
    "remove_stream_frames",
    "replacement_would_exceed_limit",
    "request_buffered_bytes",
    "request_cost_from_bytes",
    "retained_frame_queue_cost",
    "retained_frames_queue_cost",
    "saturating_add",
    "trim_tx_payload_parts",
    "tx_frame_buffered_bytes",
    "tx_frame_chunk_spans",
    "tx_frame_encoded_bytes",
    "tx_frame_queue_cost",
    "tx_frames_buffered_bytes",
    "send_by_deadline",
    "tx_frames_queue_cost",
    "urgency_rank",
    "validate_outbound_tx_frame_with_limits",
    "validate_outbound_tx_frames_with_limits",
    "wait_by_deadline",
    "write_all",
    "write_urgency_profile_from",
)
