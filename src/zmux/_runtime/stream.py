"""Stream runtime helpers for the native zmux implementation.

The concrete session/writer objects own locks and transport I/O.  This module
keeps the stream-local pieces deterministic and cheap to test: half-state
transitions, local-open visibility predicates, receive-buffer retention,
deadline math, read/write action admission, and terminal frame planning.
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import MutableSequence, Sequence
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Optional

from .read_loop import saturating_add
from .write_plan import advance_parts, checked_total_part_len
from .._state.flow import (
    PeerStreamControlAction,
    ignore_late_non_opening_control,
    peer_blocked_action,
    peer_max_data_action,
    should_advertise_blocked,
    should_advertise_max_data,
)
from .._state.half import (
    RecvHalfState,
    SendHalfState,
    base_recv_half_state,
    base_send_half_state,
    fully_terminal,
    normalize_recv_half_state,
    normalize_send_half_state,
    read_stopped,
    recv_terminal,
    send_terminal,
)
from .._state.terminal import (
    LocalAbortAction,
    LocalRecvAction,
    LocalSendAction,
    PeerAbortPlan,
    PeerDataOutcome,
    PeerDataPlan,
    PeerResetPlan,
    PeerStopSendingPlan,
    SessionClosePlan,
    StopSendingOutcome,
    TerminalErrorChoice,
    ignore_peer_abort,
    ignore_peer_reset,
    ignore_peer_stop_sending,
    local_abort_action_for_stream,
    local_close_read_action,
    local_close_write_action,
    local_reset_action,
    peer_data_transition,
    peer_stop_sending_outcome,
    plan_peer_abort,
    plan_peer_reset,
    plan_peer_stop_sending,
    read_error_choice,
    session_close_transition,
    terminal_error_priority,
)
from .._state.tombstone import (
    LateDataAction,
    StreamTombstone,
    TerminalLateDataResult,
    TerminalKind,
    build_stream_tombstone,
    should_compact_terminal,
    tombstone_late_data_action,
    tombstone_terminal_code,
    tombstone_terminal_kind,
)
from .._state.visibility import (
    LocalOpenPhase,
    LocalOpenVisibility,
    should_enqueue_accepted,
    should_finalize_peer_active,
    should_flush_priority_update,
    should_flush_stream_blocked,
    should_flush_stream_max_data,
    should_reclaim_unseen_local_stream,
)
from ..errors import (
    ApplicationError,
    ErrorDirection,
    ErrorOperation,
    ErrorSource,
    ProtocolError,
    ReadClosed,
    ReadTimeout,
    StreamNotReadable,
    StreamNotWritable,
    TerminationKind,
    WriteClosed,
    WriteTimeout,
    ZmuxError,
)
from ..frame import Frame
from ..payload import (
    MetadataUpdate,
    StreamMetadata,
    build_error_payload,
    build_open_metadata_prefix,
    build_priority_update_payload,
    parse_priority_update_payload,
)
from ..protocol import (
    ErrorCode,
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    FrameType,
    MAX_VARINT62,
)
from ..streams import ReadableBuffer

MAX_UINT64 = (1 << 64) - 1
READ_BUF_SHRINK_MIN_CAP = 256 << 10
READ_BUF_SHRINK_MAX_TAIL = 64 << 10
RELEASE_EMPTY_CHUNK_DEQUE_MIN_CAPACITY = 1024


class StreamReceiveReleaseMode(IntEnum):
    RETAIN = 0
    CLEAR_READ_BUF_ONLY = 1
    RELEASE_BUDGET = 2
    RELEASE_AND_CLEAR_READ_BUF = 3

    def releases_budget(self) -> bool:
        return (
                self is StreamReceiveReleaseMode.RELEASE_BUDGET
                or self is StreamReceiveReleaseMode.RELEASE_AND_CLEAR_READ_BUF
        )

    def clears_read_buf(self) -> bool:
        return (
                self is StreamReceiveReleaseMode.CLEAR_READ_BUF_ONLY
                or self is StreamReceiveReleaseMode.RELEASE_AND_CLEAR_READ_BUF
        )


class StreamReceiveReleaseTraits(IntFlag):
    NONE = 0
    BUDGET = 1
    CLEAR_READ_BUF = 2

    def release_mode(self) -> StreamReceiveReleaseMode:
        if (
                self & StreamReceiveReleaseTraits.BUDGET
                and self & StreamReceiveReleaseTraits.CLEAR_READ_BUF
        ):
            return StreamReceiveReleaseMode.RELEASE_AND_CLEAR_READ_BUF
        if self & StreamReceiveReleaseTraits.BUDGET:
            return StreamReceiveReleaseMode.RELEASE_BUDGET
        if self & StreamReceiveReleaseTraits.CLEAR_READ_BUF:
            return StreamReceiveReleaseMode.CLEAR_READ_BUF_ONLY
        return StreamReceiveReleaseMode.RETAIN


class TerminalSignalKind(IntEnum):
    RESET = 0
    ABORT = 1


class TerminalOpenerPolicy(IntEnum):
    ALLOW = 0
    REJECT_UNOPENED = 1


class TerminalResetSource(IntEnum):
    DIRECT = 0
    FROM_STOP_SENDING = 1


class TerminalDataIntent(IntEnum):
    CLOSE_READ = 0
    CLOSE_WRITE = 1

    def requires_local_send(self) -> bool:
        return self is TerminalDataIntent.CLOSE_READ

    def includes_priority(self) -> bool:
        return self is TerminalDataIntent.CLOSE_WRITE

    def sends_fin(self) -> bool:
        return self is TerminalDataIntent.CLOSE_WRITE


class OpenerVisibility(IntEnum):
    NONE = 0
    PEER_VISIBLE = 1

    def marks_peer_visible(self) -> bool:
        return self is OpenerVisibility.PEER_VISIBLE


class TerminalPlanStatus(IntEnum):
    READY = 0
    RETRY = 1


class TerminalSignalDisposition(IntEnum):
    PENDING = 0
    FINISHED = 1


class TerminalWriteWakePolicy(IntEnum):
    SKIP = 0
    NOTIFY = 1


class TerminalFrameRollbackKind(IntEnum):
    NONE = 0
    CLOSE_WRITE = 1


class StreamNotifyMask(IntFlag):
    NONE = 0
    READ = 1
    WRITE = 2
    BOTH = READ | WRITE

    def includes_read(self) -> bool:
        return bool(self & StreamNotifyMask.READ)

    def includes_write(self) -> bool:
        return bool(self & StreamNotifyMask.WRITE)


class PendingTerminalKind(IntFlag):
    NONE = 0
    STOP = 1
    RESET = 2
    ABORT = 4
    OPENER = 8


@dataclass(frozen=True)
class StreamAddr:
    """Fallback address object for stream-local address reporting."""

    endpoint: str
    stream_id: int = 0
    stream_id_set: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str):
            raise TypeError("endpoint must be a string")
        object.__setattr__(
            self,
            "stream_id",
            _nonnegative_int(self.stream_id, "stream_id"),
        )
        object.__setattr__(
            self,
            "stream_id_set",
            _require_bool(self.stream_id_set, "stream_id_set"),
        )
        if self.stream_id_set and self.stream_id == 0:
            raise ValueError("stream_id must be non-zero when stream_id_set is true")

    @staticmethod
    def network() -> str:
        return "zmux"

    def __str__(self) -> str:
        if self.stream_id_set:
            return "%s/stream/%d" % (self.endpoint, self.stream_id)
        return "%s/stream/pending" % self.endpoint


@dataclass(frozen=True)
class StreamReadResult:
    bytes_read: int = 0
    released_retained_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "bytes_read",
            _nonnegative_int(self.bytes_read, "bytes_read"),
        )
        object.__setattr__(
            self,
            "released_retained_bytes",
            _nonnegative_int(self.released_retained_bytes, "released_retained_bytes"),
        )


@dataclass(frozen=True)
class StreamBufferClearResult:
    bytes: int = 0
    released_retained_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "bytes", _nonnegative_int(self.bytes, "bytes"))
        object.__setattr__(
            self,
            "released_retained_bytes",
            _nonnegative_int(self.released_retained_bytes, "released_retained_bytes"),
        )


@dataclass
class _ReadChunk:
    data: memoryview
    offset: int = 0
    retained_bytes: int = 0

    def __post_init__(self) -> None:
        self.data = memoryview(self.data)
        self.offset = min(_nonnegative_int(self.offset, "offset"), len(self.data))
        self.retained_bytes = _nonnegative_int(self.retained_bytes, "retained_bytes")
        if self.retained_bytes <= 0:
            self.retained_bytes = _retained_bytes_for_view(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def consumed(self) -> bool:
        return self.offset >= len(self.data)

    def tail_view(self) -> memoryview:
        return self.data[self.offset:]

    def tighten_after_consume(self) -> int:
        tail_len = self.remaining()
        if not should_tighten_read_buf_after_consume(tail_len, self.retained_bytes):
            return 0
        old = self.retained_bytes
        tail = self.tail_view().tobytes()
        self.data = memoryview(tail)
        self.offset = 0
        self.retained_bytes = len(tail)
        return max(0, old - self.retained_bytes)


@dataclass
class StreamReadBuffer:
    """Chunked receive buffer with retained-storage accounting.

    Python cannot observe list/deque capacity like Go/Rust can, so retained
    bytes are tracked from the backing object length.  Large partially-consumed
    chunks are copied down to their small tail using the same threshold policy
    as Go and Rust, avoiding long-lived references to large frame buffers.
    """

    _chunks: deque = field(default_factory=deque)
    _len: int = 0
    _retained_bytes: int = 0
    _removed_chunks_since_reset: int = 0

    def __len__(self) -> int:
        return self._len

    def __bool__(self) -> bool:
        return self._len != 0

    @property
    def retained_bytes(self) -> int:
        return self._retained_bytes

    def is_empty(self) -> bool:
        return self._len == 0

    def append(self, data: ReadableBuffer, *, offset: int = 0, retained_bytes: int = 0) -> int:
        return self.push_chunk(data, offset=offset, retained_bytes=retained_bytes)

    def push_chunk(
            self, data: ReadableBuffer, *, offset: int = 0, retained_bytes: int = 0
    ) -> int:
        view = _readonly_view(data)
        if len(view) == 0:
            return 0
        offset = min(_nonnegative_int(offset, "offset"), len(view))
        retained_bytes = _nonnegative_int(retained_bytes, "retained_bytes")
        if offset == len(view):
            return 0
        chunk = _ReadChunk(view, offset, retained_bytes)
        if offset:
            chunk.tighten_after_consume()
        readable = chunk.remaining()
        retained = max(readable, chunk.retained_bytes)
        chunk.retained_bytes = retained
        self._chunks.append(chunk)
        self._len = saturating_add(self._len, readable)
        self._retained_bytes = saturating_add(self._retained_bytes, retained)
        return retained

    def read(self, max_bytes: int = -1) -> bytes:
        if max_bytes is None:
            max_bytes = self._len
        else:
            max_bytes = _signed_int(max_bytes, "max_bytes")
            if max_bytes < 0:
                max_bytes = self._len
        max_bytes = min(max_bytes, self._len)
        if max_bytes == 0:
            return b""
        out = bytearray(max_bytes)
        result = self.readinto(out)
        if result.bytes_read == max_bytes:
            return bytes(out)
        return bytes(out[: result.bytes_read])

    def readinto(self, dst: MutableSequence[int]) -> StreamReadResult:
        dst_view = _writable_byte_view(dst)
        if dst_view.readonly:
            raise TypeError("dst must be writable")
        copied = 0
        released_retained = 0
        while copied < len(dst_view) and self._chunks:
            chunk = self._chunks[0]
            n = min(len(dst_view) - copied, chunk.remaining())
            dst_view[copied: copied + n] = chunk.data[chunk.offset: chunk.offset + n]
            copied += n
            chunk.offset += n
            self._len = max(0, self._len - n)

            if chunk.consumed():
                released_retained = saturating_add(
                    released_retained, self._release_front_chunk()
                )
            else:
                released = chunk.tighten_after_consume()
                if released:
                    self._retained_bytes = max(0, self._retained_bytes - released)
                    released_retained = saturating_add(released_retained, released)
        return StreamReadResult(copied, released_retained)

    def readv_into(self, dsts: Sequence[MutableSequence[int]]) -> StreamReadResult:
        copied = 0
        released = 0
        for dst in dsts:
            dst_len = _buffer_byte_len(dst)
            if dst_len == 0:
                continue
            result = self.readinto(dst)
            copied = saturating_add(copied, result.bytes_read)
            released = saturating_add(released, result.released_retained_bytes)
            if result.bytes_read < dst_len or self.is_empty():
                break
        return StreamReadResult(copied, released)

    def clear(self) -> StreamBufferClearResult:
        result = StreamBufferClearResult(self._len, self._retained_bytes)
        removed = len(self._chunks)
        self._chunks.clear()
        self._len = 0
        self._retained_bytes = 0
        self._release_empty_chunk_storage(removed)
        return result

    def _release_front_chunk(self) -> int:
        chunk = self._chunks.popleft()
        released = chunk.retained_bytes
        self._retained_bytes = max(0, self._retained_bytes - released)
        if not self._chunks:
            self._len = 0
            self._retained_bytes = 0
        self._release_empty_chunk_storage(1)
        return released

    def _release_empty_chunk_storage(self, removed_chunks: int) -> None:
        self._removed_chunks_since_reset = saturating_add(
            self._removed_chunks_since_reset, max(0, removed_chunks)
        )
        if (
                not self._chunks
                and self._removed_chunks_since_reset >= RELEASE_EMPTY_CHUNK_DEQUE_MIN_CAPACITY
        ):
            self._chunks = deque()
            self._removed_chunks_since_reset = 0


@dataclass
class StreamReceiveAccountingState:
    recv_pending: int = 0
    recv_buffer: int = 0

    def __post_init__(self) -> None:
        self.recv_pending = _nonnegative_int(self.recv_pending, "recv_pending")
        self.recv_buffer = _nonnegative_int(self.recv_buffer, "recv_buffer")

    def account_received(self, amount: int) -> None:
        amount = _nonnegative_int(amount, "amount")
        self.recv_buffer = saturating_add(self.recv_buffer, amount)

    def release_budget(self, amount: int) -> int:
        amount = min(_nonnegative_int(amount, "amount"), self.recv_buffer)
        self.recv_buffer -= amount
        return amount

    def clear(self) -> None:
        self.recv_pending = 0
        self.recv_buffer = 0


@dataclass(frozen=True)
class ReceiveReleaseResult:
    released_budget_bytes: int = 0
    cleared_read_bytes: int = 0
    released_retained_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "released_budget_bytes",
            _nonnegative_int(self.released_budget_bytes, "released_budget_bytes"),
        )
        object.__setattr__(
            self,
            "cleared_read_bytes",
            _nonnegative_int(self.cleared_read_bytes, "cleared_read_bytes"),
        )
        object.__setattr__(
            self,
            "released_retained_bytes",
            _nonnegative_int(self.released_retained_bytes, "released_retained_bytes"),
        )


@dataclass
class StreamWaitState:
    read_deadline: Optional[float] = None
    write_deadline: Optional[float] = None
    read_waiters: int = 0
    write_waiters: int = 0

    def __post_init__(self) -> None:
        self.read_deadline = normalize_deadline(self.read_deadline)
        self.write_deadline = normalize_deadline(self.write_deadline)
        self.read_waiters = _nonnegative_int(self.read_waiters, "read_waiters")
        self.write_waiters = _nonnegative_int(self.write_waiters, "write_waiters")

    def set_deadline(self, deadline: Optional[float]) -> None:
        self.set_read_deadline(deadline)
        self.set_write_deadline(deadline)

    def set_read_deadline(self, deadline: Optional[float]) -> None:
        self.read_deadline = normalize_deadline(deadline)

    def set_write_deadline(self, deadline: Optional[float]) -> None:
        self.write_deadline = normalize_deadline(deadline)

    def set_timeout(self, timeout_seconds: Optional[float], now: Optional[float] = None) -> None:
        deadline = timeout_to_deadline(timeout_seconds, now)
        self.set_deadline(deadline)

    def set_read_timeout(
            self, timeout_seconds: Optional[float], now: Optional[float] = None
    ) -> None:
        self.set_read_deadline(timeout_to_deadline(timeout_seconds, now))

    def set_write_timeout(
            self, timeout_seconds: Optional[float], now: Optional[float] = None
    ) -> None:
        self.set_write_deadline(timeout_to_deadline(timeout_seconds, now))

    def remaining_read(
            self,
            operation_deadline: Optional[float] = None,
            now: Optional[float] = None,
    ) -> Optional[float]:
        return deadline_remaining(
            effective_deadline(self.read_deadline, operation_deadline),
            now,
        )

    def remaining_write(
            self,
            operation_deadline: Optional[float] = None,
            now: Optional[float] = None,
    ) -> Optional[float]:
        return deadline_remaining(
            effective_deadline(self.write_deadline, operation_deadline),
            now,
        )

    def check_read(
            self,
            operation_deadline: Optional[float] = None,
            now: Optional[float] = None,
    ) -> None:
        if deadline_expired(effective_deadline(self.read_deadline, operation_deadline), now):
            raise ReadTimeout()

    def check_write(
            self,
            operation_deadline: Optional[float] = None,
            now: Optional[float] = None,
    ) -> None:
        if deadline_expired(effective_deadline(self.write_deadline, operation_deadline), now):
            raise WriteTimeout()

    def begin_read_wait(self) -> None:
        self.read_waiters = saturating_add(self.read_waiters, 1)

    def end_read_wait(self) -> None:
        self.read_waiters = max(0, self.read_waiters - 1)

    def begin_write_wait(self) -> None:
        self.write_waiters = saturating_add(self.write_waiters, 1)

    def end_write_wait(self) -> None:
        self.write_waiters = max(0, self.write_waiters - 1)


@dataclass
class StreamHalfState:
    """Mutable stream half-state with Java/Rust-style convenience methods."""

    local_send: bool
    local_receive: bool
    send_half: SendHalfState = SendHalfState.UNKNOWN
    recv_half: RecvHalfState = RecvHalfState.UNKNOWN
    local_read_stop: bool = False
    local_read_signal_pending: bool = False
    remote_write_stop: bool = False
    send_reset_from_stop: bool = False

    def __post_init__(self) -> None:
        self.local_send = _require_bool(self.local_send, "local_send")
        self.local_receive = _require_bool(self.local_receive, "local_receive")
        self.local_read_stop = _require_bool(self.local_read_stop, "local_read_stop")
        self.local_read_signal_pending = _require_bool(
            self.local_read_signal_pending,
            "local_read_signal_pending",
        )
        self.remote_write_stop = _require_bool(self.remote_write_stop, "remote_write_stop")
        self.send_reset_from_stop = _require_bool(
            self.send_reset_from_stop,
            "send_reset_from_stop",
        )
        self.send_half = normalize_send_half_state(self.local_send, self.send_half)
        self.recv_half = normalize_recv_half_state(self.local_receive, self.recv_half)

    def effective_send_half(self) -> SendHalfState:
        if self.send_half is SendHalfState.OPEN and self.remote_write_stop:
            return SendHalfState.STOP_SEEN
        return self.send_half

    def effective_recv_half(self) -> RecvHalfState:
        if self.local_read_stop:
            if self.recv_half is RecvHalfState.ABSENT:
                return RecvHalfState.ABSENT
            return RecvHalfState.STOP_SENT
        return self.recv_half

    def read_closed(self) -> bool:
        return (not self.local_receive) or self.effective_recv_half() is not RecvHalfState.OPEN

    def write_closed(self) -> bool:
        return self.effective_send_half() is not SendHalfState.OPEN

    def send_terminal(self) -> bool:
        return send_terminal(self.send_half)

    def recv_terminal(self) -> bool:
        return recv_terminal(self.recv_half)

    def fully_terminal(self) -> bool:
        return fully_terminal(self.local_send, self.local_receive, self.send_half, self.recv_half)

    def effectively_fully_terminal(self) -> bool:
        send_half = self.effective_send_half()
        recv_half = self.effective_recv_half()
        if send_half is SendHalfState.ABORTED or recv_half is RecvHalfState.ABORTED:
            return True
        send_term = (not self.local_send) or send_terminal(send_half)
        recv_term = (not self.local_receive) or recv_terminal(recv_half)
        return send_term and recv_term

    def receive_graceful(self) -> bool:
        return self.effective_recv_half() is RecvHalfState.FIN

    def mark_fin_queued_if_open(self) -> SendHalfState:
        previous = self.send_half
        if self.send_half is SendHalfState.OPEN:
            self.send_half = SendHalfState.FIN
        return previous

    def mark_send_fin(self) -> SendHalfState:
        previous = self.send_half
        if self.send_half in (SendHalfState.OPEN, SendHalfState.STOP_SEEN):
            self.send_half = SendHalfState.FIN
        return previous

    def clear_send_fin_if_queued(
            self,
            previous: SendHalfState = SendHalfState.OPEN,
    ) -> SendHalfState:
        old = self.send_half
        if self.send_half is SendHalfState.FIN:
            self.send_half = previous
        return old

    def mark_send_reset(self, from_stop: bool = False) -> SendHalfState:
        from_stop = _require_bool(from_stop, "from_stop")
        previous = self.send_half
        if self.send_half is not SendHalfState.ABSENT:
            self.send_half = SendHalfState.RESET
            self.send_reset_from_stop = from_stop
        return previous

    def mark_send_stop_seen(self) -> None:
        self.remote_write_stop = True
        if self.send_half is SendHalfState.OPEN:
            self.send_half = SendHalfState.STOP_SEEN

    def conclude_stop_sending_with_reset(self) -> SendHalfState:
        previous = self.send_half
        if self.send_half in (SendHalfState.OPEN, SendHalfState.STOP_SEEN):
            self.send_half = SendHalfState.RESET
            self.send_reset_from_stop = self.remote_write_stop
        return previous

    def mark_recv_fin(self) -> None:
        if self.recv_half in (RecvHalfState.OPEN, RecvHalfState.STOP_SENT):
            self.recv_half = RecvHalfState.FIN

    def mark_recv_reset(self) -> None:
        if self.recv_half is not RecvHalfState.ABSENT:
            self.recv_half = RecvHalfState.RESET

    def mark_local_read_stop(self) -> None:
        if self.recv_half is not RecvHalfState.ABSENT:
            self.local_read_stop = True
            self.local_read_signal_pending = True
            self.recv_half = RecvHalfState.STOP_SENT

    def clear_local_read_signal_pending(self) -> None:
        self.local_read_signal_pending = False

    def abort_both(self) -> SendHalfState:
        previous = self.send_half
        if self.send_half is not SendHalfState.ABSENT:
            self.send_half = SendHalfState.ABORTED
        if self.recv_half is not RecvHalfState.ABSENT:
            self.recv_half = RecvHalfState.ABORTED
        self.send_reset_from_stop = False
        return previous

    def close_for_session(self, graceful: bool) -> None:
        graceful = _require_bool(graceful, "graceful")
        if graceful:
            if self.local_send and not self.send_terminal():
                self.send_half = SendHalfState.FIN
                self.send_reset_from_stop = False
            if self.local_receive and not self.recv_terminal():
                self.recv_half = RecvHalfState.FIN
            return
        if self.local_send and not self.send_terminal():
            self.send_half = SendHalfState.ABORTED
            self.send_reset_from_stop = False
        if self.local_receive and not self.recv_terminal():
            self.recv_half = RecvHalfState.ABORTED

    def peer_data_plan(self, fin: bool = False) -> PeerDataPlan:
        fin = _require_bool(fin, "fin")
        recv_half = self.effective_recv_half()
        if self.local_read_stop and recv_half is RecvHalfState.FIN:
            recv_half = RecvHalfState.STOP_SENT
        return peer_data_transition(
            self.local_send,
            self.local_receive,
            self.effective_send_half(),
            recv_half,
            fin,
        )

    def terminal_error_priority(self) -> TerminalErrorChoice:
        return terminal_error_priority(self.effective_send_half(), self.effective_recv_half())


@dataclass
class StreamTerminalState:
    send_reset_error: Optional[ApplicationError] = None
    send_stop_error: Optional[ApplicationError] = None
    recv_reset_error: Optional[ApplicationError] = None
    send_abort_error: Optional[ApplicationError] = None
    recv_abort_error: Optional[ApplicationError] = None
    local_error: Optional[BaseException] = None
    local_read_stop_code: Optional[int] = None
    abort_source: ErrorSource = ErrorSource.UNKNOWN
    send_reset_from_stop: bool = False

    def __post_init__(self) -> None:
        self.abort_source = _coerce_enum(self.abort_source, ErrorSource, "abort_source")
        self.send_reset_from_stop = _require_bool(
            self.send_reset_from_stop,
            "send_reset_from_stop",
        )

    def record_local_read_stop(self, code: int) -> None:
        self.local_read_stop_code = _require_varint62(code, "code")

    def record_send_reset(self, code: int, reason: str = "", *, from_stop: bool = False) -> None:
        from_stop = _require_bool(from_stop, "from_stop")
        self.send_reset_error = application_error(
            code,
            reason,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.WRITE,
            termination_kind=TerminationKind.RESET,
        )
        self.send_reset_from_stop = from_stop

    def record_peer_stop_sending(self, code: int, reason: str = "") -> None:
        self.send_stop_error = application_error(
            code,
            reason,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.WRITE,
            termination_kind=TerminationKind.STOPPED,
        )

    def record_peer_reset(self, code: int, reason: str = "") -> None:
        self.recv_reset_error = application_error(
            code,
            reason,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.READ,
            termination_kind=TerminationKind.RESET,
        )

    def record_local_abort(self, code: int, reason: str = "") -> None:
        app = application_error(
            code,
            reason,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.ABORT,
        )
        self.send_abort_error = app
        self.recv_abort_error = app.clone()
        self.recv_abort_error.with_source(ErrorSource.LOCAL)
        self.abort_source = ErrorSource.LOCAL

    def record_peer_abort(self, code: int, reason: str = "") -> None:
        app = application_error(
            code,
            reason,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.ABORT,
        )
        self.send_abort_error = app
        self.recv_abort_error = app.clone()
        self.recv_abort_error.with_source(ErrorSource.REMOTE)
        self.abort_source = ErrorSource.REMOTE

    def record_local_failure(self, error: BaseException) -> None:
        self.local_error = error

    def error_for_choice(self, choice: TerminalErrorChoice) -> Optional[BaseException]:
        if self.local_error is not None:
            return self.local_error
        if choice is TerminalErrorChoice.SEND_ABORT:
            return self.send_abort_error
        if choice is TerminalErrorChoice.RECV_ABORT:
            return self.recv_abort_error
        if choice is TerminalErrorChoice.SEND_RESET:
            if self.send_reset_from_stop and self.send_stop_error is not None:
                return self.peer_stop_write_closed()
            return self.send_reset_error
        if choice is TerminalErrorChoice.RECV_RESET:
            return self.recv_reset_error
        if choice is TerminalErrorChoice.SEND_CLOSED:
            return WriteClosed(termination_kind=TerminationKind.GRACEFUL)
        if choice is TerminalErrorChoice.RECV_CLOSED:
            return ReadClosed()
        return None

    def read_error(
            self,
            *,
            local_receive: bool,
            local_read_stop: bool,
            recv_half: RecvHalfState,
    ) -> Optional[BaseException]:
        local_receive = _require_bool(local_receive, "local_receive")
        local_read_stop = _require_bool(local_read_stop, "local_read_stop")
        recv_half = normalize_recv_half_state(local_receive, recv_half)
        choice = read_error_choice(local_receive, local_read_stop, recv_half)
        if choice is TerminalErrorChoice.NONE:
            return None
        if choice is TerminalErrorChoice.RECV_CLOSED:
            return self._recv_closed_error(local_read_stop, recv_half)
        return self.error_for_choice(choice)

    def operation_error(self, half: StreamHalfState) -> Optional[BaseException]:
        if not isinstance(half, StreamHalfState):
            raise TypeError("half must be StreamHalfState")
        choice = half.terminal_error_priority()
        if choice is TerminalErrorChoice.SEND_CLOSED and (
                half.remote_write_stop or half.effective_send_half() is SendHalfState.STOP_SEEN
        ):
            return self.peer_stop_write_closed()
        if (
                choice is TerminalErrorChoice.SEND_RESET
                and half.send_reset_from_stop
                and self.send_stop_error is not None
        ):
            return self.peer_stop_write_closed()
        if choice is TerminalErrorChoice.RECV_CLOSED:
            return self._recv_closed_error(
                half.local_read_stop,
                half.effective_recv_half(),
            )
        return self.error_for_choice(choice)

    @staticmethod
    def peer_stop_write_closed() -> WriteClosed:
        return WriteClosed(
            source=ErrorSource.REMOTE,
            termination_kind=TerminationKind.STOPPED,
        )

    @staticmethod
    def _recv_closed_error(
            local_read_stop: bool,
            recv_half: RecvHalfState,
    ) -> ReadClosed:
        if local_read_stop or recv_half is RecvHalfState.STOP_SENT:
            return ReadClosed(
                source=ErrorSource.LOCAL,
                termination_kind=TerminationKind.STOPPED,
            )
        if recv_half is RecvHalfState.FIN:
            return ReadClosed(
                source=ErrorSource.REMOTE,
                termination_kind=TerminationKind.GRACEFUL,
            )
        return ReadClosed()

    def terminal_code_for_tombstone(
            self, send_half: SendHalfState, recv_half: RecvHalfState
    ) -> tuple[int, bool]:
        choice = terminal_error_priority(send_half, recv_half)
        if choice is TerminalErrorChoice.SEND_ABORT and self.send_abort_error is not None:
            return self.send_abort_error.application_code or 0, True
        if choice is TerminalErrorChoice.RECV_ABORT and self.recv_abort_error is not None:
            return self.recv_abort_error.application_code or 0, True
        if choice is TerminalErrorChoice.SEND_RESET and self.send_reset_error is not None:
            return self.send_reset_error.application_code or 0, True
        if choice is TerminalErrorChoice.RECV_RESET and self.recv_reset_error is not None:
            return self.recv_reset_error.application_code or 0, True
        return 0, False


@dataclass(frozen=True)
class TerminalLocalOpenerResult:
    visibility: OpenerVisibility = OpenerVisibility.NONE
    finished: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "visibility",
            _coerce_enum(self.visibility, OpenerVisibility, "visibility"),
        )
        object.__setattr__(self, "finished", _require_bool(self.finished, "finished"))


@dataclass(frozen=True)
class TerminalFramePlan:
    frames: tuple[Frame, ...] = ()
    opener_visibility: OpenerVisibility = OpenerVisibility.NONE
    status: TerminalPlanStatus = TerminalPlanStatus.READY
    wait_reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "frames", _frame_tuple(self.frames, "frames"))
        object.__setattr__(
            self,
            "opener_visibility",
            _coerce_enum(self.opener_visibility, OpenerVisibility, "opener_visibility"),
        )
        object.__setattr__(
            self,
            "status",
            _coerce_enum(self.status, TerminalPlanStatus, "status"),
        )
        if not isinstance(self.wait_reason, str):
            raise TypeError("wait_reason must be a string")

    def should_retry(self) -> bool:
        return self.status is TerminalPlanStatus.RETRY


@dataclass(frozen=True)
class TerminalSignalPlan:
    frame_type: Optional[FrameType] = None
    payload: bytes = b""
    opener_visibility: OpenerVisibility = OpenerVisibility.NONE
    disposition: TerminalSignalDisposition = TerminalSignalDisposition.PENDING
    write_wake: TerminalWriteWakePolicy = TerminalWriteWakePolicy.SKIP

    def __post_init__(self) -> None:
        if self.frame_type is not None:
            object.__setattr__(
                self,
                "frame_type",
                _coerce_enum(self.frame_type, FrameType, "frame_type"),
            )
        object.__setattr__(self, "payload", _payload_bytes(self.payload, "payload"))
        object.__setattr__(
            self,
            "opener_visibility",
            _coerce_enum(self.opener_visibility, OpenerVisibility, "opener_visibility"),
        )
        object.__setattr__(
            self,
            "disposition",
            _coerce_enum(self.disposition, TerminalSignalDisposition, "disposition"),
        )
        object.__setattr__(
            self,
            "write_wake",
            _coerce_enum(self.write_wake, TerminalWriteWakePolicy, "write_wake"),
        )

    def finished(self) -> bool:
        return self.disposition is TerminalSignalDisposition.FINISHED

    def should_notify_write(self) -> bool:
        return self.write_wake is TerminalWriteWakePolicy.NOTIFY

    def frame(self, stream_id: int) -> Optional[Frame]:
        if self.finished() or self.frame_type is None:
            return None
        return Frame(self.frame_type, _require_stream_id(stream_id), 0, self.payload)


@dataclass(frozen=True)
class CloseReadPlan:
    opener: TerminalFramePlan = field(default_factory=TerminalFramePlan)
    stop_frame: Optional[Frame] = None

    def __post_init__(self) -> None:
        if not isinstance(self.opener, TerminalFramePlan):
            raise TypeError("opener must be a TerminalFramePlan")
        if self.stop_frame is not None and not isinstance(self.stop_frame, Frame):
            raise TypeError("stop_frame must be a Frame or None")

    def should_retry(self) -> bool:
        return self.opener.should_retry()

    def frames(self) -> tuple[Frame, ...]:
        frames = list(self.opener.frames)
        if self.stop_frame is not None:
            frames.append(self.stop_frame)
        return tuple(frames)


@dataclass(frozen=True)
class PendingTerminalResult:
    accepted: bool = True
    changed: bool = False
    coalesced: bool = False
    superseded: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "accepted", _require_bool(self.accepted, "accepted"))
        object.__setattr__(self, "changed", _require_bool(self.changed, "changed"))
        object.__setattr__(self, "coalesced", _require_bool(self.coalesced, "coalesced"))
        object.__setattr__(self, "superseded", _require_bool(self.superseded, "superseded"))


@dataclass
class PendingTerminalState:
    flags: PendingTerminalKind = PendingTerminalKind.NONE
    opener: Optional[Frame] = None
    stop_payload: bytes = b""
    reset_payload: bytes = b""
    abort_payload: bytes = b""

    def __post_init__(self) -> None:
        self.flags = _coerce_enum(self.flags, PendingTerminalKind, "flags")
        if self.opener is not None and not isinstance(self.opener, Frame):
            raise TypeError("opener must be a Frame or None")
        self.stop_payload = _payload_bytes(self.stop_payload, "stop_payload")
        self.reset_payload = _payload_bytes(self.reset_payload, "reset_payload")
        self.abort_payload = _payload_bytes(self.abort_payload, "abort_payload")

    def clear(self) -> None:
        self.flags = PendingTerminalKind.NONE
        self.opener = None
        self.stop_payload = b""
        self.reset_payload = b""
        self.abort_payload = b""

    def set_stop(self, payload: bytes) -> PendingTerminalResult:
        return self._set_non_abort_terminal(
            PendingTerminalKind.STOP,
            "stop_payload",
            payload,
        )

    def set_reset(self, payload: bytes) -> PendingTerminalResult:
        return self._set_non_abort_terminal(
            PendingTerminalKind.RESET,
            "reset_payload",
            payload,
        )

    def _set_non_abort_terminal(
            self,
            kind: PendingTerminalKind,
            payload_attr: str,
            payload: bytes,
    ) -> PendingTerminalResult:
        payload = _payload_bytes(payload, "payload")
        if self.flags & PendingTerminalKind.ABORT:
            return PendingTerminalResult(changed=False, coalesced=True)
        if self.flags & kind and getattr(self, payload_attr) == payload:
            return PendingTerminalResult(changed=False, coalesced=True)
        setattr(self, payload_attr, payload)
        self.flags |= kind
        return PendingTerminalResult(changed=True)

    def set_abort(self, payload: bytes) -> PendingTerminalResult:
        payload = _payload_bytes(payload, "payload")
        if self.flags & PendingTerminalKind.ABORT and self.abort_payload == payload:
            return PendingTerminalResult(changed=False, coalesced=True)
        superseded = bool(
            self.flags
            & (
                    PendingTerminalKind.STOP
                    | PendingTerminalKind.RESET
                    | PendingTerminalKind.OPENER
            )
        )
        self.opener = None
        self.stop_payload = b""
        self.reset_payload = b""
        self.flags &= ~(
                PendingTerminalKind.STOP
                | PendingTerminalKind.RESET
                | PendingTerminalKind.OPENER
        )
        self.abort_payload = payload
        self.flags |= PendingTerminalKind.ABORT
        return PendingTerminalResult(changed=True, superseded=superseded)


@dataclass
class StreamRuntimeState:
    """Pure stream-local runtime state used by future native sessions."""

    stream_id: int = 0
    id_set: bool = False
    opened_locally: bool = False
    bidirectional: bool = True
    local_send: Optional[bool] = None
    local_receive: Optional[bool] = None
    metadata: StreamMetadata = field(default_factory=StreamMetadata)
    send_committed: bool = False
    peer_visible: bool = False
    opener_queued: bool = False
    read_buffer: StreamReadBuffer = field(default_factory=StreamReadBuffer)
    receive: StreamReceiveAccountingState = field(default_factory=StreamReceiveAccountingState)
    wait_state: StreamWaitState = field(default_factory=StreamWaitState)
    terminal: StreamTerminalState = field(default_factory=StreamTerminalState)
    pending_terminal: PendingTerminalState = field(default_factory=PendingTerminalState)
    pending_priority_update_payload: bytes = b""
    half: StreamHalfState = field(init=False)

    def __post_init__(self) -> None:
        self.stream_id = _nonnegative_int(self.stream_id, "stream_id")
        self.id_set = _require_bool(self.id_set, "id_set")
        if self.id_set and self.stream_id == 0:
            raise ValueError("stream_id must be non-zero when id_set is true")
        self.opened_locally = _require_bool(self.opened_locally, "opened_locally")
        self.bidirectional = _require_bool(self.bidirectional, "bidirectional")
        if self.local_send is None:
            self.local_send = self.opened_locally or self.bidirectional
        else:
            self.local_send = _require_bool(self.local_send, "local_send")
        if self.local_receive is None:
            self.local_receive = self.bidirectional or not self.opened_locally
        else:
            self.local_receive = _require_bool(self.local_receive, "local_receive")
        if not isinstance(self.metadata, StreamMetadata):
            raise TypeError("metadata must be StreamMetadata")
        self.send_committed = _require_bool(self.send_committed, "send_committed")
        self.peer_visible = _require_bool(self.peer_visible, "peer_visible")
        self.opener_queued = _require_bool(self.opener_queued, "opener_queued")
        if not isinstance(self.read_buffer, StreamReadBuffer):
            raise TypeError("read_buffer must be StreamReadBuffer")
        if not isinstance(self.receive, StreamReceiveAccountingState):
            raise TypeError("receive must be StreamReceiveAccountingState")
        if not isinstance(self.wait_state, StreamWaitState):
            raise TypeError("wait_state must be StreamWaitState")
        if not isinstance(self.terminal, StreamTerminalState):
            raise TypeError("terminal must be StreamTerminalState")
        if not isinstance(self.pending_terminal, PendingTerminalState):
            raise TypeError("pending_terminal must be PendingTerminalState")
        self.pending_priority_update_payload = _payload_bytes(
            self.pending_priority_update_payload,
            "pending_priority_update_payload",
        )
        self.half = StreamHalfState(
            self.local_send,
            self.local_receive,
        )

    def local_open_visibility(self) -> LocalOpenVisibility:
        return LocalOpenVisibility(
            self.opened_locally,
            self.send_committed,
            self.peer_visible,
            self.opener_queued,
        )

    def local_open_phase(self) -> LocalOpenPhase:
        return self.local_open_visibility().phase()

    def stream_addr(self, endpoint: str) -> StreamAddr:
        return StreamAddr(endpoint, self.stream_id, self.id_set)

    def has_pending_priority_update(self) -> bool:
        return bool(self.pending_priority_update_payload)

    def set_pending_priority_update_payload(self, payload: bytes) -> None:
        self.pending_priority_update_payload = _payload_bytes(payload, "payload")

    def stage_priority_update(
            self,
            update: MetadataUpdate,
            *,
            capabilities: int,
            max_payload: int = 4096,
    ) -> bytes:
        if not isinstance(update, MetadataUpdate):
            raise TypeError("update must be MetadataUpdate")
        capabilities = _nonnegative_int(capabilities, "capabilities")
        max_payload = _nonnegative_int(max_payload, "max_payload")
        update = merge_pending_priority_update(update, self.pending_priority_update_payload)
        payload = build_priority_update_payload(capabilities, update, max_payload)
        self.pending_priority_update_payload = payload
        self.metadata = StreamMetadata(
            self.metadata.priority if update.priority is None else update.priority,
            self.metadata.group if update.group is None else update.group,
            self.metadata.open_info,
        )
        return payload

    def _pending_priority_update_frame(self) -> Optional[Frame]:
        if not self.pending_priority_update_payload:
            return None
        return Frame(
            FrameType.EXT,
            _require_stream_id(self.stream_id),
            0,
            self.pending_priority_update_payload,
        )

    def read_closed(self) -> bool:
        return self.half.read_closed()

    def write_closed(self) -> bool:
        return self.half.write_closed()

    def buffered_read_len(self) -> int:
        return len(self.read_buffer)

    def peer_data_plan(self, fin: bool = False) -> PeerDataPlan:
        return self.half.peer_data_plan(fin)

    def append_read_data(self, data: ReadableBuffer, *, retained_bytes: int = 0) -> int:
        view = _readonly_view(data)
        retained = self.read_buffer.append(view, retained_bytes=retained_bytes)
        amount = len(view)
        self.receive.account_received(amount)
        return retained

    def read(self, max_bytes: int = -1) -> bytes:
        data = self.read_buffer.read(max_bytes)
        if data:
            self.consume_receive(len(data))
        return data

    def readinto(self, dst: MutableSequence[int]) -> StreamReadResult:
        result = self.read_buffer.readinto(dst)
        if result.bytes_read:
            self.consume_receive(result.bytes_read)
        return result

    def consume_receive(self, amount: int) -> int:
        released = self.receive.release_budget(amount)
        if (
                released
                and self.local_receive
                and self.half.effective_recv_half() is RecvHalfState.OPEN
        ):
            self.receive.recv_pending = saturating_add(
                self.receive.recv_pending,
                released,
            )
        return released

    def apply_receive_release(self, mode: StreamReceiveReleaseMode) -> ReceiveReleaseResult:
        mode = _coerce_enum(mode, StreamReceiveReleaseMode, "mode")
        released_budget = 0
        clear = StreamBufferClearResult()
        if mode.releases_budget():
            released_budget = self.receive.recv_buffer
            self.receive.clear()
        if mode.clears_read_buf():
            clear = self.read_buffer.clear()
        return ReceiveReleaseResult(released_budget, clear.bytes, clear.released_retained_bytes)

    def commit_local_read_stop(self, code: int) -> ReceiveReleaseResult:
        self.half.mark_local_read_stop()
        self.terminal.record_local_read_stop(code)
        return self.apply_receive_release(StreamReceiveReleaseMode.RELEASE_AND_CLEAR_READ_BUF)

    def prepare_terminal_local_opener(
            self,
            _app_error: Optional[ApplicationError],
            policy: TerminalOpenerPolicy,
    ) -> TerminalLocalOpenerResult:
        policy = _coerce_enum(policy, TerminalOpenerPolicy, "policy")
        if not self.local_open_phase().needs_local_opener():
            return TerminalLocalOpenerResult()
        if not self.id_set:
            return TerminalLocalOpenerResult(finished=True)
        if policy is TerminalOpenerPolicy.REJECT_UNOPENED:
            self.half.abort_both()
            return TerminalLocalOpenerResult(finished=True)
        self.mark_send_committed(OpenerVisibility.PEER_VISIBLE)
        return TerminalLocalOpenerResult(visibility=OpenerVisibility.PEER_VISIBLE)

    def mark_send_committed(self, visibility: OpenerVisibility = OpenerVisibility.NONE) -> None:
        visibility = _coerce_enum(visibility, OpenerVisibility, "visibility")
        self.send_committed = True
        if visibility.marks_peer_visible():
            self.peer_visible = True

    def apply_peer_stop_sending(self, code: int, reason: str = "") -> bool:
        if not self.local_send:
            raise StreamNotWritable()
        plan = plan_peer_stop_sending(
            self.local_send,
            self.local_receive,
            self.half.effective_send_half(),
            self.half.effective_recv_half(),
        )
        if plan.ignore:
            return False
        if self.id_set:
            self.peer_visible = True
        self.terminal.record_peer_stop_sending(code, reason)
        self.half.mark_send_stop_seen()
        self.pending_priority_update_payload = b""
        return plan.outcome is StopSendingOutcome.FINISH

    def conclude_stop_sending_with_reset(self) -> SendHalfState:
        previous = self.half.conclude_stop_sending_with_reset()
        self.pending_priority_update_payload = b""
        return previous

    def prepare_data_frame_plan(
            self,
            intent: TerminalDataIntent,
            *,
            capabilities: int = 0,
            max_frame_payload: int = 16384,
    ) -> TerminalFramePlan:
        intent = _coerce_enum(intent, TerminalDataIntent, "intent")
        capabilities = _nonnegative_int(capabilities, "capabilities")
        max_frame_payload = _nonnegative_int(max_frame_payload, "max_frame_payload")
        if intent.requires_local_send() and not self.local_send:
            return TerminalFramePlan()
        opener_visibility = OpenerVisibility.NONE
        commit_visibility = False
        phase = self.local_open_phase()
        if phase.needs_local_opener():
            if not self.id_set:
                return TerminalFramePlan(
                    status=TerminalPlanStatus.RETRY,
                    wait_reason="stream id not assigned",
                )
            opener_visibility = OpenerVisibility.PEER_VISIBLE
            commit_visibility = True
        elif phase.should_emit_opener_frame():
            opener_visibility = OpenerVisibility.PEER_VISIBLE
            commit_visibility = True
        if (
                intent.requires_local_send()
                and not opener_visibility.marks_peer_visible()
        ):
            return TerminalFramePlan()

        flags = 0
        payload = b""
        if intent.sends_fin():
            flags |= FRAME_FLAG_FIN
        if opener_visibility.marks_peer_visible():
            prefix = build_open_metadata_prefix(
                capabilities,
                self.metadata.priority,
                self.metadata.group,
                self.metadata.open_info,
                max_frame_payload,
            )
            if prefix:
                flags |= FRAME_FLAG_OPEN_METADATA
                payload = prefix
        frame = Frame(FrameType.DATA, _require_stream_id(self.stream_id), flags, payload)
        priority_frame = None
        if intent.includes_priority() and not opener_visibility.marks_peer_visible():
            priority_frame = self._pending_priority_update_frame()
        if commit_visibility:
            self.mark_send_committed(opener_visibility)
        if intent.sends_fin():
            self.half.mark_send_fin()
        if priority_frame is not None:
            self.pending_priority_update_payload = b""
            return TerminalFramePlan((priority_frame, frame), opener_visibility)
        return TerminalFramePlan((frame,), opener_visibility)

    def prepare_close_read_plan(
            self,
            code: int = int(ErrorCode.CANCELLED),
            *,
            max_control_payload: int = 0,
            capabilities: int = 0,
            max_frame_payload: int = 16384,
    ) -> CloseReadPlan:
        code = _require_varint62(code, "code")
        max_control_payload = _nonnegative_int(max_control_payload, "max_control_payload")
        capabilities = _nonnegative_int(capabilities, "capabilities")
        max_frame_payload = _nonnegative_int(max_frame_payload, "max_frame_payload")
        action = local_close_read_action(self.local_receive, self.half.effective_recv_half())
        if action is LocalRecvAction.NOT_READABLE:
            raise StreamNotReadable()
        if action is LocalRecvAction.CLOSED:
            raise ReadClosed()
        error = self.terminal.read_error(
            local_receive=self.local_receive,
            local_read_stop=self.half.local_read_stop,
            recv_half=self.half.effective_recv_half(),
        )
        if action is LocalRecvAction.TERMINAL and error is not None:
            raise error
        self.commit_local_read_stop(code)
        opener = self.prepare_data_frame_plan(
            TerminalDataIntent.CLOSE_READ,
            capabilities=capabilities,
            max_frame_payload=max_frame_payload,
        )
        if opener.should_retry():
            return CloseReadPlan(opener)
        stop = build_stop_sending_frame(
            self.stream_id,
            code,
            max_control_payload=max_control_payload,
        )
        self.pending_terminal.set_stop(stop.payload)
        return CloseReadPlan(opener, stop)

    def prepare_close_write_plan(
            self,
            *,
            capabilities: int = 0,
            max_frame_payload: int = 16384,
    ) -> TerminalFramePlan:
        capabilities = _nonnegative_int(capabilities, "capabilities")
        max_frame_payload = _nonnegative_int(max_frame_payload, "max_frame_payload")
        if self.allows_close_write_noop_after_stop_reset():
            return TerminalFramePlan()
        action = local_close_write_action(self.local_send, self.half.effective_send_half())
        if action is LocalSendAction.NOT_WRITABLE:
            raise StreamNotWritable()
        if action is LocalSendAction.CLOSED:
            raise WriteClosed(termination_kind=TerminationKind.GRACEFUL)
        if action is LocalSendAction.TERMINAL:
            error = self.terminal.operation_error(self.half)
            if error is not None:
                raise error
            raise WriteClosed()
        return self.prepare_data_frame_plan(
            TerminalDataIntent.CLOSE_WRITE,
            capabilities=capabilities,
            max_frame_payload=max_frame_payload,
        )

    def allows_close_write_noop_after_stop_reset(self) -> bool:
        send_half = self.half.effective_send_half()
        if send_half is SendHalfState.FIN and self.terminal.send_stop_error is not None:
            return True
        return (
                send_half is SendHalfState.RESET
                and self.half.send_reset_from_stop
                and self.terminal.send_stop_error is not None
        )

    def prepare_terminal_signal_plan(
            self,
            kind: TerminalSignalKind,
            code: int,
            reason: str = "",
            *,
            max_control_payload: int = 0,
            opener_policy: TerminalOpenerPolicy = TerminalOpenerPolicy.ALLOW,
            reset_source: TerminalResetSource = TerminalResetSource.DIRECT,
    ) -> TerminalSignalPlan:
        kind = _coerce_enum(kind, TerminalSignalKind, "kind")
        code = _require_varint62(code, "code")
        max_control_payload = _nonnegative_int(max_control_payload, "max_control_payload")
        opener_policy = _coerce_enum(
            opener_policy,
            TerminalOpenerPolicy,
            "opener_policy",
        )
        reset_source = _coerce_enum(reset_source, TerminalResetSource, "reset_source")
        payload = build_error_payload(code, reason, max_control_payload)
        app_error = application_error(code, reason)
        opener_result = TerminalLocalOpenerResult()
        if self.local_open_phase().needs_local_opener():
            opener_result = self.prepare_terminal_local_opener(app_error, opener_policy)
        if opener_result.finished:
            return TerminalSignalPlan(
                payload=payload,
                opener_visibility=opener_result.visibility,
                disposition=TerminalSignalDisposition.FINISHED,
            )
        if kind is TerminalSignalKind.RESET:
            self.half.mark_send_reset(
                from_stop=reset_source is TerminalResetSource.FROM_STOP_SENDING,
            )
            self.terminal.record_send_reset(
                code,
                reason,
                from_stop=reset_source is TerminalResetSource.FROM_STOP_SENDING,
            )
            return TerminalSignalPlan(
                FrameType.RESET,
                payload,
                opener_result.visibility,
                write_wake=TerminalWriteWakePolicy.NOTIFY,
            )
        self.half.abort_both()
        self.terminal.record_local_abort(code, reason)
        self.apply_receive_release(StreamReceiveReleaseMode.RELEASE_AND_CLEAR_READ_BUF)
        return TerminalSignalPlan(FrameType.ABORT, payload, opener_result.visibility)

    def execute_terminal_signal(
            self,
            kind: TerminalSignalKind,
            code: int,
            reason: str = "",
            *,
            max_control_payload: int = 0,
            opener_policy: TerminalOpenerPolicy = TerminalOpenerPolicy.ALLOW,
            reset_source: TerminalResetSource = TerminalResetSource.DIRECT,
    ) -> TerminalSignalPlan:
        kind = _coerce_enum(kind, TerminalSignalKind, "kind")
        code = _require_varint62(code, "code")
        max_control_payload = _nonnegative_int(max_control_payload, "max_control_payload")
        opener_policy = _coerce_enum(
            opener_policy,
            TerminalOpenerPolicy,
            "opener_policy",
        )
        reset_source = _coerce_enum(reset_source, TerminalResetSource, "reset_source")
        if (
                kind is TerminalSignalKind.RESET
                and self.local_open_phase().needs_local_opener()
                and self.id_set
        ):
            kind = TerminalSignalKind.ABORT
            opener_policy = TerminalOpenerPolicy.ALLOW
            reset_source = TerminalResetSource.DIRECT
        if kind is TerminalSignalKind.RESET:
            action = local_reset_action(self.local_send, self.half.effective_send_half())
            if action is LocalSendAction.NOT_WRITABLE:
                raise StreamNotWritable()
            if action is LocalSendAction.CLOSED:
                raise WriteClosed()
            if action is LocalSendAction.TERMINAL:
                error = self.terminal.operation_error(self.half)
                if error is not None:
                    raise error
                raise WriteClosed()
        elif local_abort_action_for_stream(
                self.half.effective_send_half(),
                self.half.effective_recv_half(),
        ) is LocalAbortAction.NO_OP:
            return TerminalSignalPlan(disposition=TerminalSignalDisposition.FINISHED)
        plan = self.prepare_terminal_signal_plan(
            kind,
            code,
            reason,
            max_control_payload=max_control_payload,
            opener_policy=opener_policy,
            reset_source=reset_source,
        )
        self.enqueue_terminal_signal(plan)
        return plan

    def enqueue_terminal_signal(self, plan: TerminalSignalPlan) -> PendingTerminalResult:
        if plan.finished() or plan.frame_type is None:
            return PendingTerminalResult()
        if plan.opener_visibility.marks_peer_visible():
            self.peer_visible = True
        if plan.frame_type is FrameType.RESET:
            return self.pending_terminal.set_reset(plan.payload)
        if plan.frame_type is FrameType.ABORT:
            return self.pending_terminal.set_abort(plan.payload)
        return PendingTerminalResult()


def should_tighten_read_buf_after_consume(tail_len: int, retained_bytes: int) -> bool:
    tail_len = _nonnegative_int(tail_len, "tail_len")
    retained_bytes = _nonnegative_int(retained_bytes, "retained_bytes")
    if tail_len == 0:
        return True
    if retained_bytes < READ_BUF_SHRINK_MIN_CAP:
        return False
    if tail_len > READ_BUF_SHRINK_MAX_TAIL:
        return False
    return tail_len <= retained_bytes // 4


def read_chunk_overhead_bytes(retained: int, data_len: int) -> int:
    retained = _nonnegative_int(retained, "retained")
    data_len = _nonnegative_int(data_len, "data_len")
    return 0 if retained <= data_len else retained - data_len


def normalize_deadline(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise TypeError("deadline must be a timestamp or None")
    value = float(deadline)
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def timeout_to_deadline(
        timeout_seconds: Optional[float], now: Optional[float] = None
) -> Optional[float]:
    if timeout_seconds is None:
        return None
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise TypeError("timeout must be a number or None")
    timeout_seconds = float(timeout_seconds)
    if math.isnan(timeout_seconds) or math.isinf(timeout_seconds):
        return None
    if timeout_seconds < 0.0:
        timeout_seconds = 0.0
    return _monotonic_now(now) + timeout_seconds


def effective_deadline(
        stream_deadline: Optional[float], operation_deadline: Optional[float]
) -> Optional[float]:
    stream_deadline = normalize_deadline(stream_deadline)
    operation_deadline = normalize_deadline(operation_deadline)
    if stream_deadline is None:
        return operation_deadline
    if operation_deadline is None:
        return stream_deadline
    return min(stream_deadline, operation_deadline)


def deadline_remaining(
        deadline: Optional[float], now: Optional[float] = None
) -> Optional[float]:
    deadline = normalize_deadline(deadline)
    if deadline is None:
        return None
    return max(0.0, deadline - _monotonic_now(now))


def deadline_expired(deadline: Optional[float], now: Optional[float] = None) -> bool:
    deadline = normalize_deadline(deadline)
    return deadline is not None and _monotonic_now(now) >= deadline


def build_stop_sending_frame(
        stream_id: int, code: int, reason: str = "", max_control_payload: int = 0
) -> Frame:
    return Frame(
        FrameType.STOP_SENDING,
        _require_stream_id(stream_id),
        0,
        build_error_payload(code, reason, max_control_payload),
    )


def build_reset_frame(
        stream_id: int, code: int, reason: str = "", max_control_payload: int = 0
) -> Frame:
    return Frame(
        FrameType.RESET,
        _require_stream_id(stream_id),
        0,
        build_error_payload(code, reason, max_control_payload),
    )


def build_abort_frame(
        stream_id: int, code: int, reason: str = "", max_control_payload: int = 0
) -> Frame:
    return Frame(
        FrameType.ABORT,
        _require_stream_id(stream_id),
        0,
        build_error_payload(code, reason, max_control_payload),
    )


def merge_pending_priority_update(
        update: MetadataUpdate, pending_payload: bytes = b""
) -> MetadataUpdate:
    if not isinstance(update, MetadataUpdate):
        raise TypeError("update must be MetadataUpdate")
    pending_payload = _payload_bytes(pending_payload, "pending_payload")
    if not pending_payload:
        return update
    pending, valid = parse_priority_update_payload(pending_payload)
    if not valid:
        raise ProtocolError("invalid pending priority update payload")
    return MetadataUpdate(
        update.priority if update.priority is not None else pending.priority,
        update.group if update.group is not None else pending.group,
    )


def application_error(
        code: int,
        reason: str = "",
        *,
        source: ErrorSource = ErrorSource.UNKNOWN,
        direction: ErrorDirection = ErrorDirection.BOTH,
        termination_kind: TerminationKind = TerminationKind.UNKNOWN,
) -> ApplicationError:
    err = ApplicationError(code, reason)
    if source is not ErrorSource.UNKNOWN:
        err.with_source(source)
    if direction is not ErrorDirection.UNKNOWN:
        err.with_direction(direction)
    if termination_kind is not TerminationKind.UNKNOWN:
        err.with_termination_kind(termination_kind)
    return err


def stream_error_context(
        error: BaseException,
        operation: ErrorOperation,
        direction: ErrorDirection,
) -> BaseException:
    if isinstance(error, ZmuxError):
        return error.with_stream_context(operation, direction)
    return error


def _readonly_view(data: ReadableBuffer) -> memoryview:
    view = _byte_view(data)
    if not view.readonly:
        return memoryview(view.tobytes())
    return view


def _byte_view(data: ReadableBuffer) -> memoryview:
    view = memoryview(data)
    if view.ndim == 1 and view.format == "B":
        return view
    try:
        return view.cast("B")
    except (TypeError, ValueError):
        return memoryview(view.tobytes())


def _writable_byte_view(data: MutableSequence[int]) -> memoryview:
    view = memoryview(data)
    if view.ndim == 1 and view.format in ("B", "b", "c"):
        return view
    if view.ndim != 1 or view.format != "B":
        view = view.cast("B")
    return view


def _retained_bytes_for_view(view: memoryview) -> int:
    obj = view.obj
    if isinstance(obj, (bytes, bytearray)):
        return len(obj)
    return len(view)


def _buffer_byte_len(data: ReadableBuffer) -> int:
    return len(_byte_view(data))


def _payload_bytes(payload: ReadableBuffer, name: str) -> bytes:
    if isinstance(payload, int):
        raise TypeError("%s must be bytes-like" % name)
    try:
        return bytes(_byte_view(payload))
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % name) from exc


def _frame_tuple(frames: Sequence[Frame], name: str) -> tuple[Frame, ...]:
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


def _require_stream_id(stream_id: int) -> int:
    stream_id = _require_varint62(stream_id, "stream_id")
    if stream_id == 0:
        raise ValueError("stream_id must be non-zero")
    return stream_id


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


def _signed_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


def _monotonic_now(now: Optional[float]) -> float:
    if now is None:
        return time.monotonic()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise TypeError("now must be a timestamp")
    return float(now)


def _coerce_enum(value, enum_type, name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be a %s or integer" % (name, enum_type.__name__))
    return enum_type(value)


__all__ = (
    "MAX_UINT64",
    "READ_BUF_SHRINK_MAX_TAIL",
    "READ_BUF_SHRINK_MIN_CAP",
    "CloseReadPlan",
    "LateDataAction",
    "LocalAbortAction",
    "LocalOpenPhase",
    "LocalOpenVisibility",
    "LocalRecvAction",
    "LocalSendAction",
    "OpenerVisibility",
    "PeerAbortPlan",
    "PeerDataOutcome",
    "PeerDataPlan",
    "PeerResetPlan",
    "PeerStopSendingPlan",
    "PeerStreamControlAction",
    "PendingTerminalKind",
    "PendingTerminalResult",
    "PendingTerminalState",
    "RecvHalfState",
    "ReceiveReleaseResult",
    "SendHalfState",
    "SessionClosePlan",
    "StopSendingOutcome",
    "StreamAddr",
    "StreamBufferClearResult",
    "StreamHalfState",
    "StreamNotifyMask",
    "StreamReadBuffer",
    "StreamReadResult",
    "StreamReceiveAccountingState",
    "StreamReceiveReleaseMode",
    "StreamReceiveReleaseTraits",
    "StreamRuntimeState",
    "StreamTerminalState",
    "StreamTombstone",
    "StreamWaitState",
    "TerminalDataIntent",
    "TerminalErrorChoice",
    "TerminalFramePlan",
    "TerminalFrameRollbackKind",
    "TerminalLateDataResult",
    "TerminalKind",
    "TerminalLocalOpenerResult",
    "TerminalOpenerPolicy",
    "TerminalPlanStatus",
    "TerminalResetSource",
    "TerminalSignalDisposition",
    "TerminalSignalKind",
    "TerminalSignalPlan",
    "TerminalWriteWakePolicy",
    "advance_parts",
    "application_error",
    "base_recv_half_state",
    "base_send_half_state",
    "build_abort_frame",
    "build_reset_frame",
    "build_stop_sending_frame",
    "build_stream_tombstone",
    "checked_total_part_len",
    "deadline_expired",
    "deadline_remaining",
    "effective_deadline",
    "fully_terminal",
    "ignore_late_non_opening_control",
    "ignore_peer_abort",
    "ignore_peer_reset",
    "ignore_peer_stop_sending",
    "local_abort_action_for_stream",
    "local_close_read_action",
    "local_close_write_action",
    "local_reset_action",
    "merge_pending_priority_update",
    "normalize_deadline",
    "normalize_recv_half_state",
    "normalize_send_half_state",
    "peer_blocked_action",
    "peer_data_transition",
    "peer_max_data_action",
    "peer_stop_sending_outcome",
    "plan_peer_abort",
    "plan_peer_reset",
    "plan_peer_stop_sending",
    "read_chunk_overhead_bytes",
    "read_error_choice",
    "read_stopped",
    "recv_terminal",
    "send_terminal",
    "session_close_transition",
    "should_advertise_blocked",
    "should_advertise_max_data",
    "should_compact_terminal",
    "should_enqueue_accepted",
    "should_finalize_peer_active",
    "should_flush_priority_update",
    "should_flush_stream_blocked",
    "should_flush_stream_max_data",
    "should_reclaim_unseen_local_stream",
    "should_tighten_read_buf_after_consume",
    "stream_error_context",
    "terminal_error_priority",
    "timeout_to_deadline",
    "tombstone_late_data_action",
    "tombstone_terminal_code",
    "tombstone_terminal_kind",
)
