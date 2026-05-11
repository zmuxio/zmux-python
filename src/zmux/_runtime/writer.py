"""Writer batch encoding, ordering, and transport-write helpers.

The Go writer owns the single serialized transmit path.  Python keeps the
transport-independent pieces here: bounded batch accounting, trusted TxFrame
encoding, vectored writes for large payload batches, and deterministic batch
ordering metadata.  Session-owned locking and stream-state suppression remain
with the future concrete session writer.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Iterable, MutableSequence, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Protocol, Tuple

from .queue import (
    MAX_UINT64,
    MAX_WRITE_BATCH_FRAMES,
    QueueLane,
    QueuedWriteRequest,
    TxFrame,
    WriteJob,
    WriteJobKind,
    classify_write_request,
    make_tx_frame,
    tx_frame_encoded_bytes,
    tx_frame_queue_cost,
    tx_frames_queue_cost,
    write_all,
)
from .batch_scheduler import BatchScheduler
from .sched_core import (
    FALLBACK_GROUP_BUCKET,
    MAX_EXPLICIT_GROUPS,
    BatchConfig,
    BatchItem,
    GroupKey,
    RequestMeta,
    StreamMeta,
    coerce_batch_config as _coerce_batch_config,
    coerce_scheduler_hint as _coerce_scheduler_hint,
    order_batch_indices,
)
from .write_plan import rate_limited_fragment_cap, saturating_add
from .._wire.frame import append_frame_header_trusted, normalize_limits
from .._wire.varint import parse_varint
from ..config import Settings, default_settings
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    ProtocolError,
    TerminationKind,
    TransportError,
    ZmuxError,
)
from ..frame import Frame
from ..protocol import (
    EXT_PRIORITY_UPDATE,
    FRAME_FLAG_OPEN_METADATA,
    ErrorCode,
    FrameType,
    SchedulerHint,
)
from ..streams import ReadableBuffer

MAX_CONTROL_BATCHES_PER_WAKE = 4
MAX_ENCODED_FRAME_OVERHEAD = 17
_DEFAULT_SETTINGS = default_settings()
_DEFAULT_MAX_FRAME_PAYLOAD = _DEFAULT_SETTINGS.max_frame_payload
MAX_RETAINED_WRITE_BATCH_BYTES = MAX_WRITE_BATCH_FRAMES * _DEFAULT_MAX_FRAME_PAYLOAD
MIN_VECTORED_PAYLOAD_BYTES = 16 << 10
MAX_VECTORED_SEGMENTS = 64
MIN_VECTORED_PAYLOAD_BYTES_PER_SEGMENT = 1024
MIN_RETAINED_ENCODED_BUFFER_BYTES = 64 << 10
MAX_RETAINED_ENCODED_BUFFER_BYTES = 512 << 10
MIN_RETAINED_BATCH_FRAMES = 64
MAX_RETAINED_ACCOUNTING_ENTRIES = 4096
SCRATCH_RETAIN_FACTOR = 4

LATENCY_BATCH_COST_MULTIPLIER = 2
DEFAULT_BATCH_COST_MULTIPLIER = 4
BULK_BATCH_COST_MULTIPLIER = 8
LATENCY_SPARSE_COALESCE_SECONDS = 0.001
DEFAULT_SPARSE_COALESCE_SECONDS = 0.001
BULK_SPARSE_COALESCE_SECONDS = 0.002
LATENCY_HOT_COALESCE_SECONDS = 0.002
DEFAULT_HOT_COALESCE_SECONDS = 0.003
BULK_HOT_COALESCE_SECONDS = 0.004


class DequeuedWriteWorkKind(IntEnum):
    REQUEST = 1
    CONTROL = 2
    CLOSED = 3


@dataclass(frozen=True)
class DequeuedWriteWork:
    request: Optional[QueuedWriteRequest] = None
    lane: QueueLane = QueueLane.ORDINARY
    kind: DequeuedWriteWorkKind = DequeuedWriteWorkKind.REQUEST

    def __post_init__(self) -> None:
        if self.request is not None and not isinstance(self.request, QueuedWriteRequest):
            raise TypeError("request must be QueuedWriteRequest or None")
        object.__setattr__(self, "lane", _coerce_enum(self.lane, QueueLane, "lane"))
        object.__setattr__(
            self,
            "kind",
            _coerce_enum(self.kind, DequeuedWriteWorkKind, "kind"),
        )


@dataclass(frozen=True)
class RejectedWriteRequest:
    request: QueuedWriteRequest
    error: BaseException

    def __post_init__(self) -> None:
        if not isinstance(self.request, QueuedWriteRequest):
            raise TypeError("request must be QueuedWriteRequest")
        if not isinstance(self.error, BaseException):
            raise TypeError("error must be BaseException")


@dataclass(frozen=True)
class WriteBatchSize:
    encoded_bytes: int = 0
    payload_bytes: int = 0
    frame_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "encoded_bytes",
            _nonnegative_int(self.encoded_bytes, "encoded_bytes"),
        )
        object.__setattr__(
            self,
            "payload_bytes",
            _nonnegative_int(self.payload_bytes, "payload_bytes"),
        )
        object.__setattr__(
            self,
            "frame_count",
            _nonnegative_int(self.frame_count, "frame_count"),
        )

    def empty(self) -> bool:
        return self.frame_count == 0


@dataclass
class StreamValueAccumulator:
    """Small-map accumulator mirroring Go's single-stream fast path."""

    cap_hint: int = 0
    _single_stream: object = None
    _single_value: int = 0
    _values: Optional[Dict[int, Tuple[object, int]]] = None
    _order: List[int] = field(default_factory=list)

    def promote(self) -> None:
        if self._values is not None:
            return
        self._values = {}
        if self._single_stream is not None and self._single_value > 0:
            key = id(self._single_stream)
            self._values[key] = (self._single_stream, self._single_value)
            self._order.append(key)
        self._single_stream = None
        self._single_value = 0

    def add(self, stream: object, value: int) -> None:
        if stream is None:
            return
        value = _nonnegative_int(value, "value")
        if value == 0:
            return
        if self._values is not None:
            self._add_to_map(stream, value)
            return
        if self._single_stream is None:
            self._single_stream = stream
            self._single_value = value
            return
        if self._single_stream is stream:
            self._single_value = _saturating_add(self._single_value, value)
            return
        self.promote()
        self._add_to_map(stream, value)

    def remember_first(self, stream: object, value: int) -> None:
        if stream is None:
            return
        value = _nonnegative_int(value, "value")
        if value == 0:
            return
        if self._values is not None:
            key = id(stream)
            if key not in self._values:
                self._values[key] = (stream, value)
                self._order.append(key)
            return
        if self._single_stream is None:
            self._single_stream = stream
            self._single_value = value
            return
        if self._single_stream is stream:
            return
        self.promote()
        key = id(stream)
        if key not in self._values:
            self._values[key] = (stream, value)
            self._order.append(key)

    def items(self) -> Tuple[Tuple[object, int], ...]:
        if self._values is None:
            if self._single_stream is not None and self._single_value > 0:
                return ((self._single_stream, self._single_value),)
            return ()
        return tuple(self._values[key] for key in self._order)

    def clear(self) -> None:
        self._single_stream = None
        self._single_value = 0
        if self._values is not None:
            self._values.clear()
        self._order.clear()

    def _add_to_map(self, stream: object, value: int) -> None:
        assert self._values is not None
        key = id(stream)
        if key not in self._values:
            self._order.append(key)
            self._values[key] = (stream, value)
            return
        existing, current = self._values[key]
        self._values[key] = (existing, _saturating_add(current, value))


@dataclass
class WriteBatchScratch:
    """Reusable batch-local lists without retaining frame payload references."""

    batch: List[QueuedWriteRequest] = field(default_factory=list)
    items: List[BatchItem] = field(default_factory=list)
    ordered: List[QueuedWriteRequest] = field(default_factory=list)
    rejected: List[RejectedWriteRequest] = field(default_factory=list)
    encoded: bytearray = field(default_factory=bytearray)
    explicit_groups: Dict[int, None] = field(default_factory=dict)
    explicit_group_ids: List[int] = field(default_factory=list)
    queued_by_stream: Dict[int, int] = field(default_factory=dict)
    queued_streams: List[object] = field(default_factory=list)

    def batch_slice(self, n: int, cap_hint: int = 0) -> List[QueuedWriteRequest]:
        del cap_hint
        self.batch.clear()
        self.batch.extend(QueuedWriteRequest() for _ in range(_nonnegative_int(n, "n")))
        return self.batch

    def item_slice(self, n: int) -> List[BatchItem]:
        self.items.clear()
        self.items.extend(BatchItem() for _ in range(_nonnegative_int(n, "n")))
        return self.items

    def ordered_slice(self, n: int) -> List[QueuedWriteRequest]:
        self.ordered.clear()
        self.ordered.extend(QueuedWriteRequest() for _ in range(_nonnegative_int(n, "n")))
        return self.ordered

    def rejected_slice(self, cap_hint: int = 0) -> List[RejectedWriteRequest]:
        del cap_hint
        self.rejected.clear()
        return self.rejected

    def encoded_buffer(self, expected: int) -> bytearray:
        expected = _nonnegative_int(expected, "expected")
        self.encoded.clear()
        if expected > MAX_RETAINED_ENCODED_BUFFER_BYTES:
            self.encoded = bytearray()
        return self.encoded

    def release_encoded_buffer(self, buf: Optional[bytearray] = None) -> None:
        if buf is not None and buf is not self.encoded:
            return
        if len(self.encoded) > MAX_RETAINED_ENCODED_BUFFER_BYTES:
            self.encoded = bytearray()
        else:
            self.encoded.clear()

    def data_scratch(self, n: int) -> Tuple[List[BatchItem], Dict[int, None]]:
        items = self.item_slice(n)
        for group_id in self.explicit_group_ids:
            self.explicit_groups.pop(group_id, None)
        self.explicit_group_ids.clear()
        return items, self.explicit_groups

    def add_explicit_group(self, group_id: int) -> None:
        group_id = _nonnegative_int(group_id, "group_id")
        if group_id in self.explicit_groups:
            return
        self.explicit_groups[group_id] = None
        self.explicit_group_ids.append(group_id)

    def clear_retained_batch_refs(self) -> None:
        self.batch.clear()
        self.ordered.clear()
        self.rejected.clear()
        self.clear_queued_stream_refs()

    def reset(self) -> None:
        self.batch.clear()
        self.items.clear()
        self.ordered.clear()
        self.rejected.clear()
        self.encoded.clear()
        self.explicit_groups.clear()
        self.explicit_group_ids.clear()
        self.queued_by_stream.clear()
        self.queued_streams.clear()

    def queued_stream_scratch(self, cap_hint: int = 0) -> Dict[int, int]:
        del cap_hint
        self.clear_queued_stream_refs()
        return self.queued_by_stream

    def clear_queued_stream_refs(self) -> None:
        for stream in self.queued_streams:
            self.queued_by_stream.pop(id(stream), None)
        self.queued_streams.clear()

    def add_queued_stream(self, stream: object, queued: int) -> None:
        if stream is None:
            return
        queued = _nonnegative_int(queued, "queued")
        if queued == 0:
            return
        key = id(stream)
        if key not in self.queued_by_stream:
            self.queued_streams.append(stream)
        self.queued_by_stream[key] = _saturating_add(
            self.queued_by_stream.get(key, 0),
            queued,
        )

    def queued_stream_items(self) -> Tuple[Tuple[object, int], ...]:
        return tuple(
            (stream, self.queued_by_stream[id(stream)])
            for stream in self.queued_streams
            if id(stream) in self.queued_by_stream
        )

    def stream_value_accumulator(self, cap_hint: int = 0) -> StreamValueAccumulator:
        return StreamValueAccumulator(cap_hint=_nonnegative_int(cap_hint, "cap_hint"))


@dataclass(frozen=True)
class EncodedFrame:
    header: bytes
    payload_parts: Tuple[memoryview, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "header", _payload_bytes(self.header, "header"))
        object.__setattr__(
            self,
            "payload_parts",
            _payload_view_tuple(self.payload_parts, "payload_parts"),
        )

    @property
    def payload_bytes(self) -> int:
        return sum(len(part) for part in self.payload_parts)

    @property
    def encoded_bytes(self) -> int:
        return len(self.header) + self.payload_bytes

    @property
    def segment_count(self) -> int:
        return 1 + sum(1 for part in self.payload_parts if len(part) != 0)

    def parts(self) -> Tuple[memoryview, ...]:
        return (_byte_view(self.header),) + self.payload_parts


@dataclass
class EncodedBatchStats:
    frame_count: int = 0
    close_frames: int = 0
    encoded_bytes: int = 0
    payload_bytes: int = 0
    data_bytes: int = 0
    segments: int = 0
    data_cost_by_stream: Dict[int, int] = field(default_factory=dict)
    data_frame_count_by_stream: Dict[int, int] = field(default_factory=dict)
    terminal_frame_count_by_stream: Dict[int, int] = field(default_factory=dict)
    opened_stream_ids: Tuple[int, ...] = ()

    def __post_init__(self) -> None:
        for name in (
                "frame_count",
                "close_frames",
                "encoded_bytes",
                "payload_bytes",
                "data_bytes",
                "segments",
        ):
            setattr(self, name, _nonnegative_int(getattr(self, name), name))
        for name in (
                "data_cost_by_stream",
                "data_frame_count_by_stream",
                "terminal_frame_count_by_stream",
        ):
            setattr(self, name, _stream_stat_dict(getattr(self, name), name))
        self.opened_stream_ids = tuple(
            _positive_int(stream_id, "opened_stream_id")
            for stream_id in self.opened_stream_ids
        )

    def clear(self) -> None:
        self.frame_count = 0
        self.close_frames = 0
        self.encoded_bytes = 0
        self.payload_bytes = 0
        self.data_bytes = 0
        self.segments = 0
        self.data_cost_by_stream.clear()
        self.data_frame_count_by_stream.clear()
        self.terminal_frame_count_by_stream.clear()
        self.opened_stream_ids = ()


@dataclass(frozen=True)
class EncodedBatch:
    frames: Tuple[EncodedFrame, ...]
    stats: EncodedBatchStats

    def __post_init__(self) -> None:
        object.__setattr__(self, "frames", _encoded_frame_tuple(self.frames, "frames"))
        if not isinstance(self.stats, EncodedBatchStats):
            raise TypeError("stats must be EncodedBatchStats")

    def append_to(self, dst: MutableSequence[int]) -> None:
        for frame in self.frames:
            dst.extend(frame.header)
            for part in frame.payload_parts:
                dst.extend(part)

    def to_bytes(self) -> bytes:
        return append_encoded_frames(self.frames, self.stats.encoded_bytes)


class SupportsWriteVectored(Protocol):
    def write_vectored(self, parts: Iterable[ReadableBuffer]) -> int:
        ...


def prepare_write_batch_size(batch: Sequence[QueuedWriteRequest]) -> WriteBatchSize:
    batch = _request_tuple(batch, "batch")
    max_int = sys.maxsize
    encoded_total = 0
    payload_total = 0
    frame_count = 0

    for req in batch:
        classify_write_request(req)
        if len(req.frames) > max_int - frame_count:
            raise _frame_size_write("send batch too large")
        frame_count += len(req.frames)
        if frame_count > max_int // MAX_ENCODED_FRAME_OVERHEAD:
            raise _frame_size_write("send batch too large")
        for frame in req.frames:
            encoded = tx_frame_encoded_bytes(frame)
            if encoded > max_int or encoded_total > max_int - encoded:
                raise _frame_size_write("send batch too large")
            encoded_total += encoded
            payload_len = frame.payload_length()
            if payload_total > max_int - payload_len:
                raise _frame_size_write("send batch too large")
            payload_total += payload_len

    return WriteBatchSize(encoded_total, payload_total, frame_count)


def append_frame_binary_trusted(dst: MutableSequence[int], frame: TxFrame) -> MutableSequence[int]:
    append_frame_header_trusted(
        dst,
        frame.code(),
        frame.stream_id,
        frame.payload_length(),
    )
    frame.append_payload(dst)
    return dst


def encode_tx_frame(frame: TxFrame) -> EncodedFrame:
    _require_tx_frame(frame, "frame")
    header = bytearray()
    append_frame_header_trusted(
        header,
        frame.code(),
        frame.stream_id,
        frame.payload_length(),
    )
    return EncodedFrame(bytes(header), tx_frame_payload_views(frame))


def tx_frame_payload_views(frame: TxFrame) -> Tuple[memoryview, ...]:
    _require_tx_frame(frame, "frame")
    views: List[memoryview] = []
    if frame.has_payload_prefix() and frame.payload_prefix:
        views.append(_byte_view(frame.payload_prefix))
    if frame.has_payload_parts():
        views.extend(_tx_part_views(frame))
    elif frame.payload:
        views.append(_byte_view(frame.payload))
    return tuple(view for view in views if len(view) != 0)


def encode_write_batch(
        batch: Sequence[QueuedWriteRequest],
        *,
        validate_limits: object = None,
) -> EncodedBatch:
    batch = _request_tuple(batch, "batch")
    size = prepare_write_batch_size(batch)
    encoded_frames: List[EncodedFrame] = []
    stats = EncodedBatchStats()
    opened_streams: List[int] = []
    opened_seen = set()
    limits = normalize_limits(validate_limits) if validate_limits is not None else None

    for req in batch:
        for frame in req.frames:
            if limits is not None:
                from .queue import validate_outbound_tx_frame_with_limits

                validate_outbound_tx_frame_with_limits(frame, limits, limits)
            encoded = encode_tx_frame(frame)
            encoded_frames.append(encoded)
            _account_encoded_frame(stats, frame, encoded)
            if frame_opens_local_stream(frame) and frame.stream_id not in opened_seen:
                opened_seen.add(frame.stream_id)
                opened_streams.append(frame.stream_id)

    if stats.encoded_bytes != size.encoded_bytes:
        raise _local_internal_error("encoded write batch length mismatch")
    _coalesce_stream_accounting(stats)
    stats.opened_stream_ids = tuple(opened_streams)
    return EncodedBatch(tuple(encoded_frames), stats)


def encode_write_jobs(
        jobs: Sequence[WriteJob],
        *,
        validate_limits: object = None,
) -> EncodedBatch:
    return encode_write_batch(
        queued_requests_from_jobs(jobs),
        validate_limits=validate_limits,
    )


def queued_request_from_job(job: WriteJob) -> QueuedWriteRequest:
    if not isinstance(job, WriteJob):
        raise TypeError("job must be WriteJob")
    frames = tuple(tx_frame_from_frame(frame) for frame in job.all_frames())
    return request_from_frames(frames)


def queued_requests_from_jobs(jobs: Sequence[WriteJob]) -> Tuple[QueuedWriteRequest, ...]:
    requests = []
    for job in jobs:
        if job.kind in (WriteJobKind.SHUTDOWN, WriteJobKind.DRAIN_SHUTDOWN):
            continue
        requests.append(queued_request_from_job(job))
    return tuple(requests)


def tx_frame_from_frame(frame: Frame) -> TxFrame:
    if not isinstance(frame, Frame):
        raise TypeError("frame must be Frame")
    tx = make_tx_frame(frame.frame_type, frame.flags, frame.stream_id)
    tx.set_flat_payload(frame.payload)
    return tx


def append_encoded_frames(frames: Sequence[EncodedFrame], encoded_bytes: int = 0) -> bytes:
    frames = _encoded_frame_tuple(frames, "frames")
    expected = _nonnegative_int(encoded_bytes, "encoded_bytes")
    if expected == 0:
        expected = sum(frame.encoded_bytes for frame in frames)
    out = bytearray(expected)
    view = memoryview(out)
    offset = 0
    for frame in frames:
        header = frame.header
        view[offset: offset + len(header)] = header
        offset += len(header)
        for part in frame.payload_parts:
            part_len = len(part)
            view[offset: offset + part_len] = part
            offset += part_len
    if offset != expected:
        raise _local_internal_error("encoded write batch length mismatch")
    return bytes(out)


def should_use_vectored_batch(stats: EncodedBatchStats) -> bool:
    if not isinstance(stats, EncodedBatchStats):
        raise TypeError("stats must be EncodedBatchStats")
    return (
            stats.payload_bytes >= MIN_VECTORED_PAYLOAD_BYTES
            and 0 < stats.segments <= MAX_VECTORED_SEGMENTS
            and stats.payload_bytes // stats.segments >= MIN_VECTORED_PAYLOAD_BYTES_PER_SEGMENT
    )


def write_encoded_batch(
        writer: object,
        batch: EncodedBatch,
        *,
        prefer_vectored: bool = True,
        flush: bool = True,
) -> int:
    if not isinstance(batch, EncodedBatch):
        raise TypeError("batch must be EncodedBatch")
    prefer_vectored = _require_bool(prefer_vectored, "prefer_vectored")
    flush = _require_bool(flush, "flush")
    if not batch.frames:
        return 0
    use_vectored = (
            prefer_vectored
            and should_use_vectored_batch(batch.stats)
            and getattr(writer, "write_vectored", None) is not None
    )
    try:
        if use_vectored:
            write_vectored_all(writer, encoded_batch_parts(batch))
        else:
            write_all(writer, batch.to_bytes())
        if flush:
            _flush(writer)
    except OSError as exc:
        raise _transport_write_failure(exc) from exc
    return batch.stats.encoded_bytes


def write_batch(
        writer: object,
        batch: Sequence[QueuedWriteRequest],
        *,
        validate_limits: object = None,
        prefer_vectored: bool = True,
        flush: bool = True,
) -> EncodedBatchStats:
    prefer_vectored = _require_bool(prefer_vectored, "prefer_vectored")
    flush = _require_bool(flush, "flush")
    encoded = encode_write_batch(batch, validate_limits=validate_limits)
    write_encoded_batch(writer, encoded, prefer_vectored=prefer_vectored, flush=flush)
    return encoded.stats


def write_job_batch(
        writer: object,
        jobs: Sequence[WriteJob],
        *,
        validate_limits: object = None,
        prefer_vectored: bool = True,
        flush: bool = True,
) -> EncodedBatchStats:
    prefer_vectored = _require_bool(prefer_vectored, "prefer_vectored")
    flush = _require_bool(flush, "flush")
    encoded = encode_write_jobs(jobs, validate_limits=validate_limits)
    write_encoded_batch(writer, encoded, prefer_vectored=prefer_vectored, flush=flush)
    return encoded.stats


def encoded_batch_parts(batch: EncodedBatch) -> Tuple[memoryview, ...]:
    if not isinstance(batch, EncodedBatch):
        raise TypeError("batch must be EncodedBatch")
    parts: List[memoryview] = []
    for frame in batch.frames:
        parts.append(_byte_view(frame.header))
        parts.extend(frame.payload_parts)
    return tuple(part for part in parts if len(part) != 0)


def write_vectored_all(writer: object, parts: Iterable[ReadableBuffer]) -> None:
    method = getattr(writer, "write_vectored", None)
    if method is None:
        for part in parts:
            view = _byte_view(part)
            if len(view) != 0:
                write_all(writer, view)
        return

    iterator = iter(parts)
    window: List[memoryview] = []
    exhausted = False
    while True:
        while len(window) < MAX_VECTORED_SEGMENTS and not exhausted:
            try:
                view = _byte_view(next(iterator))
            except StopIteration:
                exhausted = True
                break
            if len(view) != 0:
                window.append(view)
        if not window:
            return
        offered = 0
        for view in window:
            offered += len(view)
        written = _write_count(method(tuple(window)))
        if written <= 0:
            raise OSError("zmux: vectored write reported no progress")
        if written > offered:
            raise OSError("zmux: vectored write reported invalid progress")
        index, offset = _advance_vectored_position(window, 0, 0, written)
        if index >= len(window):
            window.clear()
        elif offset == 0:
            del window[:index]
        else:
            window = [window[index][offset:]] + window[index + 1:]


def collect_ready_batch(
        first: QueuedWriteRequest,
        ready: Iterable[QueuedWriteRequest],
        lane: QueueLane,
        *,
        max_frames: int = MAX_WRITE_BATCH_FRAMES,
        scheduler: Optional[BatchScheduler] = None,
        config: Optional[BatchConfig] = None,
        stream_meta: Optional[Dict[int, StreamMeta]] = None,
) -> Tuple[QueuedWriteRequest, ...]:
    max_frames = max(1, _nonnegative_int(max_frames, "max_frames"))
    batch = [first]
    for req in ready:
        if len(batch) >= max_frames:
            break
        batch.append(req)
    return order_write_batch(
        batch,
        lane,
        scheduler=scheduler,
        config=config,
        stream_meta=stream_meta,
    )


def order_write_batch(
        batch: Sequence[QueuedWriteRequest],
        lane: QueueLane,
        *,
        scheduler: Optional[BatchScheduler] = None,
        config: Optional[BatchConfig] = None,
        stream_meta: Optional[Dict[int, StreamMeta]] = None,
) -> Tuple[QueuedWriteRequest, ...]:
    lane = _coerce_enum(lane, QueueLane, "lane")
    batch = _request_tuple(batch, "batch")
    if len(batch) < 2:
        return batch
    if same_stream_burst_keeps_order(batch, lane):
        return batch
    order = batch_order(
        batch,
        lane,
        scheduler=scheduler,
        config=config,
        stream_meta=stream_meta,
    )
    if len(order) != len(batch) or batch_order_is_identity(order):
        return batch
    if any(idx < 0 or idx >= len(batch) for idx in order):
        return batch
    return tuple(batch[idx] for idx in order)


def batch_order(
        batch: Sequence[QueuedWriteRequest],
        lane: QueueLane,
        *,
        scheduler: Optional[BatchScheduler] = None,
        config: Optional[BatchConfig] = None,
        stream_meta: Optional[Dict[int, StreamMeta]] = None,
) -> Tuple[int, ...]:
    lane = _coerce_enum(lane, QueueLane, "lane")
    batch = _request_tuple(batch, "batch")
    if lane is QueueLane.URGENT:
        return order_batch_indices(
            BatchConfig(urgent=True) if config is None else config,
            None,
            urgent_batch_items(batch),
        )
    if lane in (QueueLane.ORDINARY, QueueLane.ADVISORY):
        cfg = BatchConfig() if config is None else config
        cfg = BatchConfig(
            urgent=False,
            group_fair=cfg.group_fair,
            scheduler_hint=cfg.scheduler_hint,
            max_frame_payload=cfg.max_frame_payload,
        )
        if scheduler is None:
            scheduler = BatchScheduler()
        return scheduler.order(
            cfg,
            data_batch_items(batch, cfg, stream_meta or {}, scheduler=scheduler),
        )
    return tuple(range(len(batch)))


def same_stream_burst_keeps_order(
        batch: Sequence[QueuedWriteRequest], lane: QueueLane = QueueLane.ORDINARY
) -> bool:
    lane = _coerce_enum(lane, QueueLane, "lane")
    batch = _request_tuple(batch, "batch")
    if lane not in (QueueLane.ORDINARY, QueueLane.ADVISORY) or not batch:
        return False
    first = batch[0]
    classify_write_request(first)
    if not first.request_stream_scoped or first.request_is_priority_update:
        return False
    stream_id = first.request_stream_id
    for req in batch[1:]:
        classify_write_request(req)
        if (
                not req.request_stream_scoped
                or req.request_is_priority_update
                or req.request_stream_id != stream_id
        ):
            return False
    return True


def batch_order_is_identity(order: Sequence[int]) -> bool:
    order = tuple(_nonnegative_int(value, "order index") for value in order)
    return all(index == value for index, value in enumerate(order))


def urgent_batch_items(batch: Sequence[QueuedWriteRequest]) -> Tuple[BatchItem, ...]:
    items = []
    for index, req in enumerate(_request_tuple(batch, "batch")):
        classify_write_request(req)
        items.append(
            BatchItem(
                RequestMeta(
                    group_key=GroupKey.transient(index),
                    stream_id=req.request_stream_id,
                    stream_scoped=req.request_stream_scoped,
                    opening_frame=(
                            req.request_stream_scoped
                            and req.prepared_opener_visibility.marks_peer_visible()
                    ),
                    urgency_rank=req.request_urgency_rank,
                    cost=max(1, req.request_cost),
                )
            )
        )
    return tuple(items)


def data_batch_items(
        batch: Sequence[QueuedWriteRequest],
        config: BatchConfig,
        stream_meta: Dict[int, StreamMeta],
        *,
        scheduler: Optional[BatchScheduler] = None,
) -> Tuple[BatchItem, ...]:
    batch = _request_tuple(batch, "batch")
    config = _coerce_batch_config(config)
    if not isinstance(stream_meta, dict):
        raise TypeError("stream_meta must be a dict")
    if scheduler is not None and not isinstance(scheduler, BatchScheduler):
        raise TypeError("scheduler must be BatchScheduler or None")
    items = []
    explicit_groups: Dict[int, None] = {}
    for index, req in enumerate(batch):
        classify_write_request(req)
        meta = stream_meta.get(req.request_stream_id, StreamMeta())
        group_key = GroupKey.transient(index)
        if req.request_stream_scoped:
            if scheduler is not None or config.group_fair:
                group_key = _batch_group_key(
                    req.request_stream_id,
                    meta.group,
                    config.group_fair,
                    scheduler,
                    explicit_groups,
                )
            else:
                group_key = GroupKey.stream(req.request_stream_id)
        items.append(
            BatchItem(
                RequestMeta(
                    group_key=group_key,
                    stream_id=req.request_stream_id,
                    stream_scoped=req.request_stream_scoped,
                    is_priority_update=(
                            req.request_stream_scoped and req.request_is_priority_update
                    ),
                    opening_frame=(
                            req.request_stream_scoped
                            and req.prepared_opener_visibility.marks_peer_visible()
                    ),
                    cost=max(1, req.request_cost),
                    urgency_rank=req.request_urgency_rank,
                ),
                meta,
            )
        )
    return tuple(items)


def _batch_group_key(
        stream_id: int,
        group: int,
        group_fair: bool,
        scheduler: Optional[BatchScheduler],
        explicit_groups: Dict[int, None],
) -> GroupKey:
    if scheduler is not None:
        return scheduler.group_key_for_stream(stream_id, group, group_fair)
    if stream_id == 0 or not group_fair or group == 0:
        return GroupKey.stream(stream_id)
    if group in explicit_groups:
        return GroupKey.explicit(group)
    if len(explicit_groups) < MAX_EXPLICIT_GROUPS:
        explicit_groups[group] = None
        return GroupKey.explicit(group)
    return GroupKey.explicit(FALLBACK_GROUP_BUCKET)


def ordinary_batch_cost_limit(
        peer_settings: Optional[Settings] = None,
        send_rate_estimate: int = 0,
        max_batch_frames: int = MAX_WRITE_BATCH_FRAMES,
) -> int:
    settings = peer_settings or _DEFAULT_SETTINGS
    if not isinstance(settings, Settings):
        raise TypeError("peer_settings must be Settings or None")
    send_rate_estimate = max(0, _signed_int(send_rate_estimate, "send_rate_estimate"))
    max_batch_frames = max(1, _signed_int(max_batch_frames, "max_batch_frames"))
    hint = _coerce_scheduler_hint(settings.scheduler_hints)
    max_payload = settings.max_frame_payload or _DEFAULT_MAX_FRAME_PAYLOAD
    multiplier = DEFAULT_BATCH_COST_MULTIPLIER
    if hint is SchedulerHint.LATENCY:
        multiplier = LATENCY_BATCH_COST_MULTIPLIER
    elif hint is SchedulerHint.BULK_THROUGHPUT:
        multiplier = BULK_BATCH_COST_MULTIPLIER
    base = _saturating_mul(saturating_add(max_payload, 1), multiplier)
    effective = rate_limited_fragment_cap(base, send_rate_estimate, 0, hint)
    frame_cap = _saturating_mul(saturating_add(max_payload, 1), max_batch_frames)
    return max(1, min(frame_cap, effective))


def ordinary_batch_coalesce_seconds(
        batch: Sequence[QueuedWriteRequest],
        batch_cost: int,
        cost_limit: int,
        *,
        urgent_queued: bool = False,
        discard_staged: bool = False,
        peer_settings: Optional[Settings] = None,
        max_batch_frames: int = MAX_WRITE_BATCH_FRAMES,
) -> float:
    batch = _request_tuple(batch, "batch")
    batch_cost = _nonnegative_int(batch_cost, "batch_cost")
    cost_limit = _nonnegative_int(cost_limit, "cost_limit")
    urgent_queued = _require_bool(urgent_queued, "urgent_queued")
    discard_staged = _require_bool(discard_staged, "discard_staged")
    max_batch_frames = max(1, _signed_int(max_batch_frames, "max_batch_frames"))
    if (
            not batch
            or len(batch) >= max_batch_frames
            or batch_cost >= cost_limit
            or urgent_queued
            or discard_staged
    ):
        return 0.0
    settings = peer_settings or _DEFAULT_SETTINGS
    if not isinstance(settings, Settings):
        raise TypeError("peer_settings must be Settings or None")
    hint = _coerce_scheduler_hint(settings.scheduler_hints)
    max_payload = settings.max_frame_payload or _DEFAULT_MAX_FRAME_PAYLOAD
    sparse_threshold = max(4, max_payload // 2 + 1)
    sparse = len(batch) == 1 and batch_cost <= sparse_threshold
    if hint is SchedulerHint.LATENCY:
        return LATENCY_SPARSE_COALESCE_SECONDS if sparse else LATENCY_HOT_COALESCE_SECONDS
    if hint is SchedulerHint.BULK_THROUGHPUT:
        return BULK_SPARSE_COALESCE_SECONDS if sparse else BULK_HOT_COALESCE_SECONDS
    return DEFAULT_SPARSE_COALESCE_SECONDS if sparse else DEFAULT_HOT_COALESCE_SECONDS


def frame_opens_local_stream(frame: TxFrame) -> bool:
    _require_tx_frame(frame, "frame")
    return frame.stream_id != 0 and frame.frame_type in (FrameType.DATA, FrameType.ABORT)


def frame_data_bytes_tx(frame: TxFrame) -> int:
    _require_tx_frame(frame, "frame")
    if frame.frame_type is not FrameType.DATA:
        return 0
    if frame.flags & FRAME_FLAG_OPEN_METADATA:
        return _open_metadata_app_bytes(frame)
    return frame.payload_length()


def frame_is_priority_update_tx(frame: TxFrame) -> bool:
    _require_tx_frame(frame, "frame")
    if frame.frame_type is not FrameType.EXT or frame.stream_id == 0:
        return False
    try:
        extension_id, _ = parse_varint(_payload_head_bytes(frame, 8))
    except Exception:
        return False
    return extension_id == EXT_PRIORITY_UPDATE


def request_from_frames(frames: Iterable[TxFrame]) -> QueuedWriteRequest:
    req = QueuedWriteRequest(frames=_tx_frame_tuple(frames, "frames"))
    classify_write_request(req)
    req.queued_bytes = tx_frames_queue_cost(req.frames)
    return req


def now_seconds() -> float:
    return time.monotonic()


def _account_encoded_frame(
        stats: EncodedBatchStats, frame: TxFrame, encoded: EncodedFrame
) -> None:
    stats.frame_count = _saturating_add(stats.frame_count, 1)
    if frame.frame_type is FrameType.CLOSE:
        stats.close_frames = _saturating_add(stats.close_frames, 1)
    stats.encoded_bytes = _saturating_add(stats.encoded_bytes, encoded.encoded_bytes)
    stats.payload_bytes = _saturating_add(stats.payload_bytes, encoded.payload_bytes)
    stats.segments = _saturating_add(stats.segments, encoded.segment_count)
    data_bytes = frame_data_bytes_tx(frame)
    stats.data_bytes = _saturating_add(stats.data_bytes, data_bytes)
    if frame.frame_type is FrameType.DATA:
        _dict_saturating_add(
            stats.data_cost_by_stream,
            frame.stream_id,
            tx_frame_queue_cost(frame),
        )
        _dict_saturating_add(stats.data_frame_count_by_stream, frame.stream_id, 1)
    if frame.stream_id and frame.frame_type in (
            FrameType.ABORT,
            FrameType.RESET,
            FrameType.STOP_SENDING,
    ):
        _dict_saturating_add(stats.terminal_frame_count_by_stream, frame.stream_id, 1)


def _tx_part_views(frame: TxFrame) -> Tuple[memoryview, ...]:
    if frame.payload_part_len <= 0:
        return ()
    out: List[memoryview] = []
    idx = frame.payload_part_idx
    off = frame.payload_part_off
    remaining = frame.payload_part_len
    while remaining > 0 and idx < len(frame.payload_parts):
        part = _byte_view(frame.payload_parts[idx])
        if off >= len(part):
            idx += 1
            off = 0
            continue
        take = min(len(part) - off, remaining)
        out.append(part[off: off + take])
        remaining -= take
        idx += 1
        off = 0
    return tuple(out)


def _open_metadata_app_bytes(frame: TxFrame) -> int:
    payload_len = frame.payload_length()
    if payload_len == 0:
        return 0
    head = _payload_head_bytes(frame, min(8, payload_len))
    try:
        metadata_len, consumed = parse_varint(head)
    except Exception:
        return 0
    if metadata_len > payload_len - consumed:
        return 0
    return payload_len - consumed - metadata_len


def _payload_head_bytes(frame: TxFrame, limit: int) -> bytes:
    if limit <= 0:
        return b""
    out = bytearray()
    for part in tx_frame_payload_views(frame):
        remaining = limit - len(out)
        if remaining <= 0:
            break
        out.extend(part[:remaining])
        if len(out) >= limit:
            break
    return bytes(out)


def _advance_vectored_position(
        vectors: Sequence[memoryview], index: int, offset: int, written: int
) -> Tuple[int, int]:
    while index < len(vectors) and written > 0:
        remaining = len(vectors[index]) - offset
        if written < remaining:
            return index, offset + written
        written -= remaining
        index += 1
        offset = 0
    while index < len(vectors) and len(vectors[index]) == 0:
        index += 1
    return index, offset


def _dict_saturating_add(values: Dict[int, int], key: int, delta: int) -> None:
    if delta <= 0:
        return
    values[key] = _saturating_add(values.get(key, 0), delta)


def _coalesce_stream_accounting(stats: EncodedBatchStats) -> None:
    stats.data_cost_by_stream = _stream_stat_dict(
        stats.data_cost_by_stream,
        "data_cost_by_stream",
    )
    stats.data_frame_count_by_stream = _stream_stat_dict(
        stats.data_frame_count_by_stream,
        "data_frame_count_by_stream",
    )
    stats.terminal_frame_count_by_stream = _stream_stat_dict(
        stats.terminal_frame_count_by_stream,
        "terminal_frame_count_by_stream",
    )


def _stream_stat_dict(values: Dict[int, int], name: str) -> Dict[int, int]:
    if not isinstance(values, dict):
        raise TypeError("%s must be a dict" % name)
    normalized: Dict[int, int] = {}
    for stream_id, value in values.items():
        stream_id = _nonnegative_int(stream_id, "%s stream id" % name)
        value = _nonnegative_int(value, "%s value" % name)
        if value == 0:
            continue
        normalized[stream_id] = _saturating_add(normalized.get(stream_id, 0), value)
    return dict(sorted(normalized.items()))


def _flush(writer: object) -> None:
    method = getattr(writer, "flush", None)
    if method is not None:
        method()


def _transport_write_failure(error: OSError) -> BaseException:
    if isinstance(error, ZmuxError):
        return error
    return TransportError(
        error,
        "zmux: transport write failed",
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        direction=ErrorDirection.BOTH,
        termination_kind=TerminationKind.SESSION_TERMINATION,
    )


def _payload_bytes(payload: ReadableBuffer, name: str) -> bytes:
    if isinstance(payload, int):
        raise TypeError("%s must be bytes-like" % name)
    try:
        return bytes(_byte_view(payload))
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % name) from exc


def _payload_view_tuple(parts: Iterable[ReadableBuffer], name: str) -> Tuple[memoryview, ...]:
    if isinstance(parts, (bytes, bytearray, memoryview)):
        raise TypeError("%s must be an iterable of bytes-like objects" % name)
    try:
        return tuple(_byte_view(part) for part in parts)
    except TypeError as exc:
        raise TypeError("%s must be an iterable of bytes-like objects" % name) from exc


def _encoded_frame_tuple(frames: Iterable[EncodedFrame], name: str) -> Tuple[EncodedFrame, ...]:
    if isinstance(frames, EncodedFrame):
        raise TypeError("%s must be a sequence of EncodedFrame objects" % name)
    try:
        values = tuple(frames)
    except TypeError as exc:
        raise TypeError("%s must be a sequence of EncodedFrame objects" % name) from exc
    for frame in values:
        if not isinstance(frame, EncodedFrame):
            raise TypeError("%s must contain only EncodedFrame objects" % name)
    return values


def _request_tuple(
        requests: Iterable[QueuedWriteRequest],
        name: str,
) -> Tuple[QueuedWriteRequest, ...]:
    if isinstance(requests, QueuedWriteRequest):
        raise TypeError("%s must be a sequence of QueuedWriteRequest objects" % name)
    try:
        values = tuple(requests)
    except TypeError as exc:
        raise TypeError("%s must be a sequence of QueuedWriteRequest objects" % name) from exc
    for request in values:
        if not isinstance(request, QueuedWriteRequest):
            raise TypeError("%s must contain only QueuedWriteRequest objects" % name)
    return values


def _tx_frame_tuple(frames: Iterable[TxFrame], name: str) -> Tuple[TxFrame, ...]:
    if isinstance(frames, TxFrame):
        raise TypeError("%s must be a sequence of TxFrame objects" % name)
    try:
        values = tuple(frames)
    except TypeError as exc:
        raise TypeError("%s must be a sequence of TxFrame objects" % name) from exc
    for frame in values:
        _require_tx_frame(frame, name)
    return values


def _require_tx_frame(frame: TxFrame, name: str) -> TxFrame:
    if not isinstance(frame, TxFrame):
        raise TypeError("%s must be TxFrame" % name)
    return frame


def _write_count(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OSError("zmux: vectored write returned a non-integer byte count")
    return value


def _coerce_enum(value, enum_type, name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be a %s or integer" % (name, enum_type.__name__))
    return enum_type(value)


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


def _positive_int(value: int, name: str) -> int:
    value = _nonnegative_int(value, name)
    if value == 0:
        raise ValueError("%s must be > 0" % name)
    return value


def _saturating_add(left: int, right: int) -> int:
    return min(
        MAX_UINT64,
        max(0, _signed_int(left, "left")) + max(0, _signed_int(right, "right")),
    )


def _saturating_mul(left: int, right: int) -> int:
    left = max(0, _signed_int(left, "left"))
    right = max(0, _signed_int(right, "right"))
    if left == 0 or right == 0:
        return 0
    return min(MAX_UINT64, left * right)


def _byte_view(data: ReadableBuffer) -> memoryview:
    view = memoryview(data)
    if view.ndim != 1 or view.format not in ("B", "b", "c"):
        try:
            view = view.cast("B")
        except (TypeError, ValueError):
            view = memoryview(view.tobytes())
    return view


def _signed_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


def _frame_size_write(message: str) -> FrameSizeError:
    return FrameSizeError(
        message,
        code=int(ErrorCode.FRAME_SIZE),
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


__all__ = (
    "BULK_HOT_COALESCE_SECONDS",
    "BULK_SPARSE_COALESCE_SECONDS",
    "DEFAULT_HOT_COALESCE_SECONDS",
    "DEFAULT_SPARSE_COALESCE_SECONDS",
    "FALLBACK_GROUP_BUCKET",
    "LATENCY_HOT_COALESCE_SECONDS",
    "LATENCY_SPARSE_COALESCE_SECONDS",
    "MAX_CONTROL_BATCHES_PER_WAKE",
    "MAX_ENCODED_FRAME_OVERHEAD",
    "MAX_EXPLICIT_GROUPS",
    "MAX_RETAINED_WRITE_BATCH_BYTES",
    "MAX_VECTORED_SEGMENTS",
    "MIN_VECTORED_PAYLOAD_BYTES",
    "BatchConfig",
    "BatchItem",
    "BatchScheduler",
    "DequeuedWriteWork",
    "DequeuedWriteWorkKind",
    "EncodedBatch",
    "EncodedBatchStats",
    "EncodedFrame",
    "GroupKey",
    "RejectedWriteRequest",
    "RequestMeta",
    "StreamMeta",
    "StreamValueAccumulator",
    "WriteBatchScratch",
    "WriteBatchSize",
    "append_encoded_frames",
    "append_frame_binary_trusted",
    "batch_order",
    "batch_order_is_identity",
    "collect_ready_batch",
    "data_batch_items",
    "encode_tx_frame",
    "encode_write_batch",
    "encode_write_jobs",
    "encoded_batch_parts",
    "frame_data_bytes_tx",
    "frame_is_priority_update_tx",
    "frame_opens_local_stream",
    "now_seconds",
    "order_batch_indices",
    "order_write_batch",
    "ordinary_batch_coalesce_seconds",
    "ordinary_batch_cost_limit",
    "prepare_write_batch_size",
    "queued_request_from_job",
    "queued_requests_from_jobs",
    "request_from_frames",
    "same_stream_burst_keeps_order",
    "should_use_vectored_batch",
    "tx_frame_from_frame",
    "tx_frame_payload_views",
    "urgent_batch_items",
    "write_all",
    "write_batch",
    "write_encoded_batch",
    "write_job_batch",
    "write_vectored_all",
)
