"""Pure write-planning helpers for stream DATA emission.

The Go ``write_plan.go`` file mixes pure admission math with native stream
locking and writer-queue I/O.  Python keeps the deterministic part here:
vectored-buffer accounting, fragment sizing, write-window admission, and burst
batch state.  Concrete stream/session objects can compose these helpers without
duplicating the edge-case arithmetic.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, List, Optional, Tuple

from .flow import MAX_UINT64, saturating_add, saturating_mul_div_floor
from .write_policy import (
    DEFAULT_FRAGMENT_TIME_BUDGET,
    DEFAULT_FRAGMENT_TIME_BUDGET_NANOS,
    DEFAULT_WRITE_BURST_FRAMES,
    MILD_FRAGMENT_TIME_BUDGET,
    MILD_FRAGMENT_TIME_BUDGET_NANOS,
    MILD_WRITE_BURST_FRAMES,
    SATURATED_FRAGMENT_TIME_BUDGET,
    SATURATED_FRAGMENT_TIME_BUDGET_NANOS,
    SATURATED_WRITE_BURST_FRAMES,
    STRONG_FRAGMENT_TIME_BUDGET,
    STRONG_FRAGMENT_TIME_BUDGET_NANOS,
    STRONG_WRITE_BURST_FRAMES,
    fragment_cap,
    fragment_time_budget,
    fragment_time_budget_nanos,
    rate_limited_fragment_cap,
    scaled_fragment_cap,
    tx_fragment_cap,
    write_burst_limit,
)
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    WriteTimeout,
)
from ..frame import Frame
from ..protocol import (
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    ErrorCode,
    MAX_VARINT62,
    SchedulerHint,
)
from ..streams import ReadableBuffer

FrameBuffer = List[Frame]

class OpenerVisibilityMark(IntEnum):
    UNCHANGED = 0
    PEER_VISIBLE = 1

    def marks_peer_visible(self) -> bool:
        return self is OpenerVisibilityMark.PEER_VISIBLE


class WriteDeadlinePolicy(IntEnum):
    USE_STREAM = 0
    OVERRIDE_ONLY = 1

    def uses_stream_deadline(self) -> bool:
        return self is not WriteDeadlinePolicy.OVERRIDE_ONLY


class LocalOpenerPrepareStatus(IntEnum):
    READY = 0
    RETRY = 1


class WritePrepareWindowMode(IntEnum):
    STEP = 0
    BURST = 1


class WritePrepareOutcome(IntEnum):
    READY = 0
    RETRY = 1
    BURST_FALLBACK = 2


class WriteChunkMode(IntEnum):
    STREAMING = 0
    FINAL = 1

    def is_final(self) -> bool:
        return self is WriteChunkMode.FINAL


class WriteFinReservation(IntEnum):
    DEFER = 0
    RESERVE = 1

    def reserves_fin(self) -> bool:
        return self is WriteFinReservation.RESERVE


class WriteBurstFinalState(IntEnum):
    NOT_FINALIZED = 0
    FINALIZED = 1

    def finalized(self) -> bool:
        return self is WriteBurstFinalState.FINALIZED


class WriteBurstFlushMode(IntEnum):
    PREPARED = 0
    ACCUMULATED_ERROR = 1
    READY = 2


@dataclass(frozen=True)
class WritePrepareWindow(object):
    opener_visibility: OpenerVisibilityMark = OpenerVisibilityMark.UNCHANGED
    prefix_len: int = 0
    available_session: int = 0
    available_stream: int = 0
    frame_cap: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "opener_visibility",
            _coerce_enum(self.opener_visibility, OpenerVisibilityMark, "opener_visibility"),
        )
        object.__setattr__(self, "prefix_len", _nonnegative_int(self.prefix_len, "prefix_len"))
        object.__setattr__(
            self,
            "available_session",
            _nonnegative_int(self.available_session, "available_session"),
        )
        object.__setattr__(
            self,
            "available_stream",
            _nonnegative_int(self.available_stream, "available_stream"),
        )
        object.__setattr__(self, "frame_cap", _nonnegative_int(self.frame_cap, "frame_cap"))

    def blocked(self) -> bool:
        return write_prepare_blocked(self)


@dataclass(frozen=True)
class LocalOpenerPrepareResult(object):
    visibility: OpenerVisibilityMark = OpenerVisibilityMark.UNCHANGED
    status: LocalOpenerPrepareStatus = LocalOpenerPrepareStatus.READY
    wait: object = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "visibility",
            _coerce_enum(self.visibility, OpenerVisibilityMark, "visibility"),
        )
        object.__setattr__(
            self,
            "status",
            _coerce_enum(self.status, LocalOpenerPrepareStatus, "status"),
        )

    def should_retry(self) -> bool:
        return self.status is LocalOpenerPrepareStatus.RETRY


@dataclass(frozen=True)
class WritePrepareAttempt(object):
    window: WritePrepareWindow = field(default_factory=WritePrepareWindow)
    outcome: WritePrepareOutcome = WritePrepareOutcome.READY

    def __post_init__(self) -> None:
        if not isinstance(self.window, WritePrepareWindow):
            raise TypeError("window must be WritePrepareWindow")
        object.__setattr__(
            self,
            "outcome",
            _coerce_enum(self.outcome, WritePrepareOutcome, "outcome"),
        )


@dataclass(frozen=True)
class WriteStep(object):
    frame: Frame
    app_n: int = 0
    opener_visibility: OpenerVisibilityMark = OpenerVisibilityMark.UNCHANGED

    def __post_init__(self) -> None:
        if not isinstance(self.frame, Frame):
            raise TypeError("frame must be Frame")
        object.__setattr__(self, "app_n", _nonnegative_int(self.app_n, "app_n"))
        object.__setattr__(
            self,
            "opener_visibility",
            _coerce_enum(self.opener_visibility, OpenerVisibilityMark, "opener_visibility"),
        )


@dataclass(frozen=True)
class PreparedWriteStepBuild(object):
    step: Optional[WriteStep] = None
    ready: bool = False
    chunk: int = 0
    fin_reservation: WriteFinReservation = WriteFinReservation.DEFER

    def __post_init__(self) -> None:
        if self.step is not None and not isinstance(self.step, WriteStep):
            raise TypeError("step must be WriteStep or None")
        object.__setattr__(self, "ready", _require_bool(self.ready, "ready"))
        object.__setattr__(self, "chunk", _nonnegative_int(self.chunk, "chunk"))
        object.__setattr__(
            self,
            "fin_reservation",
            _coerce_enum(self.fin_reservation, WriteFinReservation, "fin_reservation"),
        )

    def has_step(self) -> bool:
        return self.ready and self.step is not None


@dataclass(frozen=True)
class PreparedPriorityFrame(object):
    frame: Optional[Frame] = None
    frame_bytes: int = 0

    def __post_init__(self) -> None:
        if self.frame is not None and not isinstance(self.frame, Frame):
            raise TypeError("frame must be Frame or None")
        frame_bytes = _nonnegative_int(self.frame_bytes, "frame_bytes")
        if self.frame is None:
            frame_bytes = 0
        elif frame_bytes == 0:
            frame_bytes = frame_buffered_bytes(self.frame)
        object.__setattr__(self, "frame_bytes", frame_bytes)

    def has_frame(self) -> bool:
        return (
                self.frame is not None
                and self.frame.stream_id != 0
                and bool(self.frame.payload)
                and self.frame_bytes > 0
        )


@dataclass(frozen=True)
class WriteBatchStart(object):
    burst_limit: int = DEFAULT_WRITE_BURST_FRAMES
    priority: PreparedPriorityFrame = field(default_factory=PreparedPriorityFrame)
    queue_byte_cap: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.priority, PreparedPriorityFrame):
            raise TypeError("priority must be PreparedPriorityFrame")
        object.__setattr__(self, "burst_limit", _nonnegative_int(self.burst_limit, "burst_limit"))
        object.__setattr__(
            self,
            "queue_byte_cap",
            _nonnegative_int(self.queue_byte_cap, "queue_byte_cap"),
        )

    def allows_next_queued_frame(self, current_queued: int, next_frame_bytes: int) -> bool:
        current_queued = _nonnegative_int(current_queued, "current_queued")
        next_frame_bytes = _nonnegative_int(next_frame_bytes, "next_frame_bytes")
        if self.queue_byte_cap <= 0 or current_queued == 0:
            return True
        return saturating_add(current_queued, next_frame_bytes) <= self.queue_byte_cap


@dataclass
class QueuedWriteCommit(object):
    progress: int = 0
    opener_visibility: OpenerVisibilityMark = OpenerVisibilityMark.UNCHANGED
    finalize: bool = False

    def __post_init__(self) -> None:
        self.progress = _nonnegative_int(self.progress, "progress")
        self.opener_visibility = _coerce_enum(
            self.opener_visibility,
            OpenerVisibilityMark,
            "opener_visibility",
        )
        self.finalize = _require_bool(self.finalize, "finalize")

    def empty(self) -> bool:
        return (
                self.progress <= 0
                and not self.opener_visibility.marks_peer_visible()
                and not self.finalize
        )

    def burst_final_state(self) -> WriteBurstFinalState:
        if self.finalize:
            return WriteBurstFinalState.FINALIZED
        return WriteBurstFinalState.NOT_FINALIZED


@dataclass
class WriteBurstState(object):
    frames: FrameBuffer = field(default_factory=list)
    queued_bytes: int = 0
    commit: QueuedWriteCommit = field(default_factory=QueuedWriteCommit)
    data_frames: int = 0

    def __post_init__(self) -> None:
        self.frames = list(_frame_tuple(self.frames, "frames"))
        self.queued_bytes = _nonnegative_int(self.queued_bytes, "queued_bytes")
        if not isinstance(self.commit, QueuedWriteCommit):
            raise TypeError("commit must be QueuedWriteCommit")
        self.data_frames = _nonnegative_int(self.data_frames, "data_frames")

    # noinspection PyTypeHints
    def init_frame_buffer(
            self, start: WriteBatchStart, frames: Optional[FrameBuffer] = None
    ) -> None:
        self.frames = [] if frames is None else list(_frame_tuple(frames, "frames"))
        self.frames.clear()
        self.queued_bytes = 0
        self.commit = QueuedWriteCommit()
        self.data_frames = 0
        if start.priority.has_frame():
            self.frames.append(start.priority.frame)
            self.queued_bytes = start.priority.frame_bytes

    def append_prepared(
            self,
            frames: Iterable[Frame],
            queued_bytes: int,
            progress: int,
            final_state: WriteBurstFinalState,
    ) -> None:
        prepared = _frame_tuple(frames, "frames")
        if prepared:
            self.frames.extend(prepared)
        if queued_bytes == 0 and prepared:
            queued_bytes = sum(frame_buffered_bytes(frame) for frame in prepared)
        self.queued_bytes = saturating_add(
            self.queued_bytes,
            _nonnegative_int(queued_bytes, "queued_bytes"),
        )
        self.commit.progress = _nonnegative_int(progress, "progress")
        final_state = _coerce_enum(final_state, WriteBurstFinalState, "final_state")
        self.commit.finalize = final_state.finalized()

    def append_step(self, step: WriteStep) -> None:
        if not isinstance(step, WriteStep):
            raise TypeError("step must be WriteStep")
        self.frames.append(step.frame)
        self.queued_bytes = saturating_add(self.queued_bytes, frame_buffered_bytes(step.frame))
        self.commit.progress = saturating_add(self.commit.progress, step.app_n)
        self.data_frames += 1
        if step.opener_visibility.marks_peer_visible():
            self.commit.opener_visibility = step.opener_visibility
        if step.frame.flags & FRAME_FLAG_FIN:
            self.commit.finalize = True

    def has_frames(self) -> bool:
        return bool(self.frames)


@dataclass(frozen=True)
class WriteBurstBatchPreparation(object):
    start: WriteBatchStart = field(default_factory=WriteBatchStart)
    frames: Tuple[Frame, ...] = ()
    queued_bytes: int = 0
    progress: int = 0
    final_state: WriteBurstFinalState = WriteBurstFinalState.NOT_FINALIZED
    error: Optional[BaseException] = None
    handled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.start, WriteBatchStart):
            raise TypeError("start must be WriteBatchStart")
        object.__setattr__(self, "frames", _frame_tuple(self.frames, "frames"))
        object.__setattr__(
            self,
            "queued_bytes",
            _nonnegative_int(self.queued_bytes, "queued_bytes"),
        )
        object.__setattr__(self, "progress", _nonnegative_int(self.progress, "progress"))
        object.__setattr__(
            self,
            "final_state",
            _coerce_enum(self.final_state, WriteBurstFinalState, "final_state"),
        )
        object.__setattr__(self, "handled", _require_bool(self.handled, "handled"))


@dataclass(frozen=True)
class WriteBurstResult(object):
    progress: int = 0
    final_state: WriteBurstFinalState = WriteBurstFinalState.NOT_FINALIZED
    stop: bool = False
    error: Optional[BaseException] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "progress", _nonnegative_int(self.progress, "progress"))
        object.__setattr__(
            self,
            "final_state",
            _coerce_enum(self.final_state, WriteBurstFinalState, "final_state"),
        )
        object.__setattr__(self, "stop", _require_bool(self.stop, "stop"))


def total_part_len(parts: Iterable[ReadableBuffer]) -> Tuple[int, bool]:
    return total_part_len_within(parts, sys.maxsize)


def total_part_len_within(
        parts: Iterable[ReadableBuffer], limit: int
) -> Tuple[int, bool]:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if limit < 0:
        return 0, False
    total = 0
    for part in parts:
        length = _buffer_byte_len(part)
        if length > limit - total:
            return 0, False
        total += length
    return total, True


def checked_total_part_len(
        parts: Iterable[ReadableBuffer],
        limit: int = MAX_VARINT62,
) -> int:
    limit = _nonnegative_int(limit, "limit")
    total, ok = total_part_len_within(parts, limit)
    if ok:
        return total
    raise FrameSizeError(
        "send DATA payload too large",
        code=int(ErrorCode.FRAME_SIZE),
        scope=ErrorScope.STREAM,
        operation=ErrorOperation.WRITE,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.WRITE,
    )


def advance_parts(
        parts: Sequence[ReadableBuffer],
        index: int,
        offset: int,
        amount: int,
) -> Tuple[int, int]:
    index = max(0, _signed_int(index, "index"))
    offset = max(0, _signed_int(offset, "offset"))
    amount = _nonnegative_int(amount, "amount")
    while amount > 0 and index < len(parts):
        part_len = _buffer_byte_len(parts[index])
        remain = part_len - offset
        if remain <= 0:
            index += 1
            offset = 0
            continue
        if amount < remain:
            return index, offset + amount
        amount -= remain
        index += 1
        offset = 0
    while index < len(parts) and offset >= _buffer_byte_len(parts[index]):
        index += 1
        offset = 0
    return index, offset


def write_deadline_policy_after_error(error: Optional[BaseException]) -> WriteDeadlinePolicy:
    if isinstance(error, (TimeoutError, WriteTimeout)):
        return WriteDeadlinePolicy.OVERRIDE_ONLY
    return WriteDeadlinePolicy.USE_STREAM


def bounded_write_chunk(
        remaining: int,
        available_session: int,
        available_stream: int,
        frame_cap: int,
) -> int:
    return min(
        _nonnegative_int(remaining, "remaining"),
        _nonnegative_int(available_session, "available_session"),
        _nonnegative_int(available_stream, "available_stream"),
        _nonnegative_int(frame_cap, "frame_cap"),
    )


def write_prepare_blocked(window: WritePrepareWindow) -> bool:
    return window.available_session == 0 or window.available_stream == 0 or window.frame_cap == 0


def writable_data_bytes(
        frame_payload_room: int,
        session_available: int,
        stream_available: int,
        remaining: int,
) -> int:
    return bounded_write_chunk(remaining, session_available, stream_available, frame_payload_room)


FrameBuilder = Callable[[int, int], Frame]


def build_prepared_write_step(
        total_remaining: int,
        mode: WriteChunkMode,
        window: WritePrepareWindow,
        build_frame: FrameBuilder,
) -> PreparedWriteStepBuild:
    total_remaining = _nonnegative_int(total_remaining, "total_remaining")
    mode = _coerce_enum(mode, WriteChunkMode, "mode")
    opener = window.opener_visibility.marks_peer_visible()
    if opener and mode.is_final() and total_remaining == 0:
        flags = FRAME_FLAG_FIN
        flags |= FRAME_FLAG_OPEN_METADATA
        frame = build_frame(0, flags)
        return PreparedWriteStepBuild(
            WriteStep(frame, 0, window.opener_visibility),
            True,
            0,
            WriteFinReservation.DEFER,
        )
    if opener and write_prepare_blocked(window):
        frame = build_frame(0, FRAME_FLAG_OPEN_METADATA)
        return PreparedWriteStepBuild(
            WriteStep(frame, 0, window.opener_visibility),
            True,
            0,
            WriteFinReservation.DEFER,
        )

    chunk = bounded_write_chunk(
        total_remaining,
        window.available_session,
        window.available_stream,
        window.frame_cap,
    )
    if chunk == 0:
        return PreparedWriteStepBuild()
    finalized = mode.is_final() and chunk == total_remaining
    flags = 0
    if finalized:
        flags |= FRAME_FLAG_FIN
    if opener:
        flags |= FRAME_FLAG_OPEN_METADATA
    frame = build_frame(chunk, flags)
    reservation = WriteFinReservation.RESERVE if finalized else WriteFinReservation.DEFER
    return PreparedWriteStepBuild(
        WriteStep(frame, chunk, window.opener_visibility),
        True,
        chunk,
        reservation,
    )


def frame_buffered_bytes(frame: Frame) -> int:
    # Go's txFrameBufferedBytes/txFrameQueueCost intentionally tracks only the
    # frame type byte plus payload bytes for stable queue-pressure accounting.
    if not isinstance(frame, Frame):
        raise TypeError("frame must be Frame")
    return saturating_add(1, len(frame.payload))


def _buffer_byte_len(data: ReadableBuffer) -> int:
    view = memoryview(data)
    if view.ndim != 1 or view.format != "B":
        try:
            view = view.cast("B")
        except (TypeError, ValueError):
            view = memoryview(view.tobytes())
    return len(view)


def _frame_tuple(frames: Iterable[Frame], name: str) -> Tuple[Frame, ...]:
    if isinstance(frames, Frame):
        raise TypeError("%s must be a sequence of Frame objects" % name)
    try:
        values = tuple(frames)
    except TypeError as exc:
        raise TypeError("%s must be a sequence of Frame objects" % name) from exc
    for frame in values:
        if not isinstance(frame, Frame):
            raise TypeError("%s must contain only Frame objects" % name)
    return values


def _coerce_scheduler_hint(hint: SchedulerHint) -> SchedulerHint:
    if isinstance(hint, SchedulerHint):
        return hint
    if isinstance(hint, bool) or not isinstance(hint, int):
        raise TypeError("hint must be a SchedulerHint or integer")
    return SchedulerHint.from_code(hint)


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


def _signed_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


__all__ = (
    "DEFAULT_FRAGMENT_TIME_BUDGET",
    "DEFAULT_FRAGMENT_TIME_BUDGET_NANOS",
    "DEFAULT_WRITE_BURST_FRAMES",
    "MAX_UINT64",
    "MILD_FRAGMENT_TIME_BUDGET",
    "MILD_FRAGMENT_TIME_BUDGET_NANOS",
    "MILD_WRITE_BURST_FRAMES",
    "SATURATED_FRAGMENT_TIME_BUDGET",
    "SATURATED_FRAGMENT_TIME_BUDGET_NANOS",
    "SATURATED_WRITE_BURST_FRAMES",
    "STRONG_FRAGMENT_TIME_BUDGET",
    "STRONG_FRAGMENT_TIME_BUDGET_NANOS",
    "STRONG_WRITE_BURST_FRAMES",
    "LocalOpenerPrepareResult",
    "LocalOpenerPrepareStatus",
    "OpenerVisibilityMark",
    "PreparedPriorityFrame",
    "PreparedWriteStepBuild",
    "QueuedWriteCommit",
    "WriteBatchStart",
    "WriteBurstBatchPreparation",
    "WriteBurstFinalState",
    "WriteBurstFlushMode",
    "WriteBurstResult",
    "WriteBurstState",
    "WriteChunkMode",
    "WriteDeadlinePolicy",
    "WriteFinReservation",
    "WritePrepareAttempt",
    "WritePrepareOutcome",
    "WritePrepareWindow",
    "WritePrepareWindowMode",
    "WriteStep",
    "advance_parts",
    "bounded_write_chunk",
    "build_prepared_write_step",
    "checked_total_part_len",
    "fragment_cap",
    "fragment_time_budget",
    "fragment_time_budget_nanos",
    "frame_buffered_bytes",
    "rate_limited_fragment_cap",
    "saturating_add",
    "saturating_mul_div_floor",
    "scaled_fragment_cap",
    "total_part_len",
    "total_part_len_within",
    "tx_fragment_cap",
    "writable_data_bytes",
    "write_burst_limit",
    "write_deadline_policy_after_error",
    "write_prepare_blocked",
)
