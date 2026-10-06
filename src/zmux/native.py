"""Native synchronous ZMux session implementation."""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from functools import partial
from types import TracebackType
from typing import Callable, Deque, Iterable, Optional, Tuple, TypeVar

from ._buffers import byte_view
from ._runtime.keepalive import (
    build_padded_ping_echo,
    build_ping_payload,
    effective_keepalive_timeout,
    init_keepalive_jitter_state,
    init_session_nonce_state,
    keepalive_lead_jittered_delay,
    next_session_nonce,
    ping_payload_len,
    ping_payload_limit,
    pong_payload_for_ping,
    pong_payload_matches_ping,
    session_liveness_seed,
)
from ._runtime.flow import (
    late_data_per_stream_cap,
    negotiated_frame_payload,
    next_credit_limit,
    receive_window_exceeded,
    replenish_min_pending,
    session_emergency_threshold,
    session_window_target,
    should_replenish_pending_window,
    standing_growth_allowed,
    stream_emergency_threshold,
    stream_window_target,
    window_remaining,
)
from ._runtime.read_loop import (
    InboundBudgetTracker,
    LateDataCause,
    ParsedFrameKind,
    classify_inbound_frame,
    normalize_stream_group,
    validate_go_away_watermark_creator,
    validate_go_away_watermark_for_direction,
)
from ._runtime.session import (
    ESTABLISHMENT_FAILURE_WRITE_WAIT,
    ESTABLISHMENT_SUCCESS_WRITE_WAIT,
    EventDispatcher,
    RuntimePolicy,
    StreamArity,
    _uncoded_close_code,
    build_close_payload,
    build_establishment_close_frame,
    close_frame_send_timeout,
    establishment_close_drain_delay,
    go_away_drain_interval,
    graceful_close_drain_timeout,
    max_peer_go_away_watermark,
    provisional_open_max_age,
    session_memory_hard_cap,
    session_memory_high_threshold,
)
from ._runtime.stream import StreamReadBuffer
from ._runtime.write_policy import fragment_cap
from ._state.open import (
    initial_local_opened_send_window,
    initial_send_window,
    projected_local_open_id,
    provisional_available_count,
)
from ._state.session import LocalOpenOutcome, ignore_peer_non_close_frame, plan_local_open
from ._state.stream import validate_open_metadata_update_capability
from ._state.stream_id import (
    first_local_stream_id,
    first_peer_stream_id,
    stream_is_bidi,
    stream_is_local,
    stream_kind_for_local,
)
from ._state.tombstone import (
    LateDataAction,
    StreamTombstone,
    StreamTombstoneRecord,
    TerminalBookkeepingState,
    TerminalDataDisposition,
    TerminalKind,
)
from ._wire.errors import ERR_PAYLOAD_TOO_LARGE, frame_size_error, wrap_error
from ._wire.frame import (
    append_frame_header_trusted,
    inbound_payload_limit,
    normalize_limits,
    read_session_frame,
    validate_frame,
)
from .config import (
    DEFAULT_ESTABLISHMENT_TIMEOUT,
    Config,
    Limits,
    OpenOptions,
    clone_config,
)
from .errors import (
    AcceptTimeout,
    ApplicationError,
    EmptyMetadataUpdate,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FlowControlError,
    FrameSizeError,
    GracefulCloseTimeout,
    KeepaliveTimeout,
    NilConnection,
    OpenExpired,
    OpenInfoUnavailable,
    OpenLimited,
    OpenMetadataTooLarge,
    PingTimeout,
    ProtocolError,
    ReadClosed,
    ReadTimeout,
    SessionClosed,
    SessionWaitTimeout,
    StreamNotReadable,
    StreamNotWritable,
    TerminationKind,
    TransportError,
    WriteClosed,
    WriteTimeout,
    error_termination_kind,
    open_info_unavailable,
    open_metadata_too_large,
)
from .events import Event, EventType, StreamEventInfo
from .frame import Frame
from .frame import _write_all as _frame_write_all
from .payload import (
    MetadataUpdate,
    StreamMetadata,
    build_error_payload,
    build_go_away_payload,
    build_open_metadata_prefix,
    build_priority_update_payload,
    parse_data_payload_view,
    parse_error_payload,
)
from .preface import Negotiated, Preface, negotiate_prefaces, read_preface
from .protocol import (
    ErrorCode,
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    MAX_VARINT62,
    Role,
    FrameType,
)
from .session import (
    AcceptBacklogStats,
    ActiveStreamStats,
    AbuseStats,
    DiagnosticStats,
    HiddenStats,
    LivenessStats,
    PressureStats,
    ProgressStats,
    ProvisionalStats,
    ReasonStats,
    SessionState,
    SessionStats,
)
from .streams import ReadableBuffer, WritableBuffer, maybe_timeout
from .transports import (
    DEFAULT_READ_CHUNK,
    BasicDuplexTransport,
    SocketTransport,
    ZmuxSocketAddress,
    deadline_after,
)
from .varint import encode_varint, parse_varint


@dataclass
class _PingState(object):
    ping_padding: bool
    ping_padding_min: int
    ping_padding_max: int
    ping_nonce_state: int
    keepalive_jitter_state: int
    last_ping_padding_len: int = 0

    @classmethod
    def from_config(cls, config: Config) -> "_PingState":
        # An integer ``seed`` on the nonce source is a deterministic test hook.
        # Otherwise each session draws independent seeds from the nonce source
        # (or the CSPRNG), so sessions in different processes never share
        # keepalive jitter or PING tokens (DESIGN D11).
        seed = getattr(config.nonce_source, "seed", 0)
        if not isinstance(seed, int) or isinstance(seed, bool):
            seed = 0
        if seed:
            ping_seed = jitter_seed = seed
        else:
            ping_seed = session_liveness_seed(config.nonce_source)
            jitter_seed = session_liveness_seed(config.nonce_source)
        return cls(
            ping_padding=config.ping_padding,
            ping_padding_min=config.ping_padding_min_bytes,
            ping_padding_max=config.ping_padding_max_bytes,
            ping_nonce_state=init_session_nonce_state(ping_seed),
            keepalive_jitter_state=init_keepalive_jitter_state(jitter_seed),
        )


@dataclass
class _PendingPing(object):
    done: threading.Event
    started_at: float
    rtt_holder: list[float]
    allows_padded_pong: bool
    error_holder: Optional[list[Optional[BaseException]]] = None


# Upper bound on bytes the writer hands to one transport write; the first
# queued request is always taken even when it is larger.
_WRITER_BATCH_MAX_BYTES = 256 * 1024
_WRITER_BATCH_MAX_FRAMES = 32
# Extra time a terminating thread waits for another closer to finish.
_CLOSE_COMPLETION_GRACE = 1.0
_KEEPALIVE_CLOSE_DRAIN_DELAY = 0.100
_ERROR_CLOSE_DRAIN_DELAY = 0.010
_LOCAL_STREAM_IDS_EXHAUSTED_MESSAGE = "zmux: local stream ID space exhausted"

_T = TypeVar("_T")


class _WriteRequest(object):
    """One encoded frame owned by the session writer thread.

    Requests are queued by application threads, the reader thread and the
    keepalive thread; only the writer thread ever touches the transport.
    ``done``/``error`` are guarded by ``Conn._write_cond``.
    """

    __slots__ = (
        "data",
        "data_lane",
        "done",
        "droppable",
        "error",
        "final",
        "frame",
        "started",
    )

    def __init__(
        self,
        frame: Frame,
        data: bytes,
        *,
        droppable: bool = False,
        final: bool = False,
    ) -> None:
        self.frame = frame
        self.data = data
        self.droppable = droppable
        self.final = final
        self.data_lane = False
        self.started = False
        self.done = False
        self.error: Optional[BaseException] = None


class _BackgroundCall(object):
    """Run one blocking call on a daemon thread and wait for it with a bound."""

    __slots__ = ("_done", "_error", "_notify", "_result")

    def __init__(
        self,
        name: str,
        target,
        notify: Optional[threading.Event] = None,
    ) -> None:
        self._done = threading.Event()
        self._notify = notify
        self._result = None
        self._error: Optional[BaseException] = None
        threading.Thread(target=self._run, args=(target,), name=name, daemon=True).start()

    def _run(self, target) -> None:
        try:
            self._result = target()
        except BaseException as exc:
            self._error = exc
        finally:
            self._done.set()
            if self._notify is not None:
                self._notify.set()

    def wait(self, timeout: Optional[float]) -> bool:
        return self._done.wait(timeout)

    def done(self) -> bool:
        return self._done.is_set()

    def failed(self) -> bool:
        return self._done.is_set() and self._error is not None

    def succeeded(self) -> bool:
        return self._done.is_set() and self._error is None

    def result(self):
        if self._error is not None:
            raise self._error
        return self._result


def open(transport: object, config: Optional[Config] = None) -> "Conn":
    """Establish a native ZMux session on a reliable ordered byte stream."""

    return Conn.establish(_coerce_transport(transport), clone_config(config))


def client(transport: object, config: Optional[Config] = None) -> "Conn":
    """Establish a native initiator-role ZMux session."""

    cfg = replace(clone_config(config), role=Role.INITIATOR, tie_breaker_nonce=0)
    return Conn.establish(_coerce_transport(transport), cfg)


def server(transport: object, config: Optional[Config] = None) -> "Conn":
    """Establish a native responder-role ZMux session."""

    cfg = replace(clone_config(config), role=Role.RESPONDER, tie_breaker_nonce=0)
    return Conn.establish(_coerce_transport(transport), cfg)


def open_io(reader: object, writer: object, config: Optional[Config] = None) -> "Conn":
    """Establish a native ZMux session on separate reliable I/O halves."""

    return open(BasicDuplexTransport(reader, writer), config)


def client_io(reader: object, writer: object, config: Optional[Config] = None) -> "Conn":
    """Establish a native initiator session on separate reliable I/O halves."""

    return client(BasicDuplexTransport(reader, writer), config)


def server_io(reader: object, writer: object, config: Optional[Config] = None) -> "Conn":
    """Establish a native responder session on separate reliable I/O halves."""

    return server(BasicDuplexTransport(reader, writer), config)


class Conn(object):
    """Native synchronous ZMux session.

    ``Conn`` is the core package's concrete implementation of
    :class:`zmux.Session`.  It runs over any reliable ordered full-duplex byte
    stream accepted by :func:`open`, :func:`client`, or :func:`server`.
    """

    __slots__ = (
        "_transport",
        "_io",
        "_config",
        "_local_preface",
        "_peer_preface",
        "_negotiated",
        "_runtime_policy",
        "_inbound_budget",
        "_event_dispatcher",
        "_local_limits",
        "_peer_limits",
        "_local_role",
        "_next_bidi",
        "_next_uni",
        "_next_peer_bidi",
        "_next_peer_uni",
        "_last_accepted_peer_bidi",
        "_last_accepted_peer_uni",
        "_streams",
        "_accept_bidi",
        "_accept_uni",
        "_provisional_bidi",
        "_provisional_uni",
        "_provisional_limited",
        "_provisional_expired",
        "_accept_visibility",
        "_next_visibility_sequence",
        "_visible_accept_refused",
        "_terminal_state",
        "_terminal_streams",
        "_terminal_stream_causes",
        "_terminal_stream_order",
        "_lock",
        "_write_cond",
        "_urgent_writes",
        "_data_writes",
        "_inflight_writes",
        "_queued_data_bytes",
        "_queued_data_by_stream",
        "_queued_droppable_bytes",
        "_pending_max_data",
        "_writer_closed",
        "_writer_stop",
        "_closed_event",
        "_state",
        "_close_error",
        "_peer_go_away_error",
        "_peer_close_error",
        "_local_go_away_bidi",
        "_local_go_away_uni",
        "_peer_go_away_bidi",
        "_peer_go_away_uni",
        "_go_away_refused_peer_bidi",
        "_go_away_refused_peer_uni",
        "_local_ids_exhausted",
        "_graceful_close_active",
        "_graceful_close_timeouts",
        "_sent_frames",
        "_received_frames",
        "_sent_data_bytes",
        "_received_data_bytes",
        "_live_late_data_retained",
        "_late_data_after_close_read",
        "_late_data_after_reset",
        "_late_data_after_abort",
        "_hidden_unread_bytes_discarded",
        "_send_session_max",
        "_send_session_used",
        "_session_blocked_sent_at",
        "_recv_session_received",
        "_recv_session_advertised",
        "_recv_session_buffered",
        "_recv_session_pending",
        "_peer_session_blocked_at",
        "_peer_session_blocked_floor",
        "_open_streams",
        "_accepted_streams",
        "_reset_reasons",
        "_abort_reasons",
        "_reset_overflow",
        "_abort_overflow",
        "_pings",
        "_ping_state",
        "_last_ping_rtt",
        "_last_ping_sent_at",
        "_last_pong_at",
        "_last_inbound_frame_at",
        "_last_transport_write_at",
        "_read_idle_ping_due_at",
        "_write_idle_ping_due_at",
        "_max_ping_due_at",
        "_reader_thread",
        "_keepalive_thread",
        "_writer_thread",
    )

    def __init__(
        self,
        transport: object,
        io: "_FrameIO",
        config: Config,
        local_preface: Preface,
        peer_preface: Preface,
        negotiated: Negotiated,
    ) -> None:
        self._transport = transport
        self._io = io
        self._config = config
        self._local_preface = local_preface
        self._peer_preface = peer_preface
        self._negotiated = negotiated
        self._runtime_policy = RuntimePolicy.from_config(
            config,
            local_preface,
            peer_preface,
            negotiated,
        )
        self._inbound_budget = InboundBudgetTracker.from_config(config)
        self._event_dispatcher = EventDispatcher(config.event_handler)
        self._local_limits = local_preface.settings.limits()
        self._peer_limits = peer_preface.settings.limits()
        self._local_role = negotiated.local_role
        self._next_bidi = first_local_stream_id(self._local_role, True)
        self._next_uni = first_local_stream_id(self._local_role, False)
        self._next_peer_bidi = first_peer_stream_id(self._local_role, True)
        self._next_peer_uni = first_peer_stream_id(self._local_role, False)
        self._last_accepted_peer_bidi = 0
        self._last_accepted_peer_uni = 0
        self._streams: dict[int, NativeStream] = {}
        self._accept_bidi: Deque[NativeStream] = deque()
        self._accept_uni: Deque[NativeStream] = deque()
        self._provisional_bidi: Deque[NativeStream] = deque()
        self._provisional_uni: Deque[NativeStream] = deque()
        # Local opens refused at the provisional cap, and provisionals that
        # expired before committing (session stats, as in zmux-go).
        self._provisional_limited = 0
        self._provisional_expired = 0
        self._accept_visibility: dict[int, int] = {}
        self._next_visibility_sequence = 0
        self._visible_accept_refused = 0
        self._terminal_state = TerminalBookkeepingState(
            tombstone_limit=self._runtime_policy.tombstone_limit,
            marker_only_used_stream_limit=self._runtime_policy.marker_only_used_stream_limit,
            hidden_tombstone_limit=self._runtime_policy.hidden_control_opened_limit,
        )
        self._terminal_streams: set[int] = set()
        self._terminal_stream_causes: dict[int, LateDataCause] = {}
        self._terminal_stream_order: Deque[int] = deque()
        self._lock = threading.Condition(threading.RLock())
        # Lock order: _lock may be held while taking _write_cond, never the
        # reverse.  Only the writer thread performs transport writes.
        self._write_cond = threading.Condition(threading.Lock())
        self._urgent_writes: Deque[_WriteRequest] = deque()
        self._data_writes: Deque[_WriteRequest] = deque()
        self._inflight_writes: Tuple[_WriteRequest, ...] = ()
        self._queued_data_bytes = 0
        self._queued_data_by_stream: dict[int, int] = {}
        self._queued_droppable_bytes = 0
        self._pending_max_data: dict[int, _WriteRequest] = {}
        self._writer_closed = False
        self._writer_stop = False
        self._closed_event = threading.Event()
        self._state = SessionState.READY
        self._close_error: Optional[BaseException] = None
        self._peer_go_away_error: Optional[ApplicationError] = None
        self._peer_close_error: Optional[ApplicationError] = None
        self._local_go_away_bidi = MAX_VARINT62
        self._local_go_away_uni = MAX_VARINT62
        self._peer_go_away_bidi: Optional[int] = None
        self._peer_go_away_uni: Optional[int] = None
        # Highest peer ID per class refused for being above our GOAWAY
        # watermark; such refusals are monotonic, so ABORT(REFUSED_STREAM) is
        # sent at most once per ID (DESIGN D6).
        self._go_away_refused_peer_bidi = 0
        self._go_away_refused_peer_uni = 0
        self._local_ids_exhausted = False
        self._graceful_close_active = False
        self._graceful_close_timeouts = 0
        self._sent_frames = 0
        self._received_frames = 0
        self._sent_data_bytes = 0
        self._received_data_bytes = 0
        # Late DATA bytes counted by streams still in ``_streams``; together
        # with the retained tombstones' count this is the aggregate late-data
        # accounting, which tracks retained state rather than a lifetime total
        # (DESIGN D2).
        self._live_late_data_retained = 0
        self._late_data_after_close_read = 0
        self._late_data_after_reset = 0
        self._late_data_after_abort = 0
        self._hidden_unread_bytes_discarded = 0
        self._send_session_max = peer_preface.settings.initial_max_data
        self._send_session_used = 0
        # Last limit a local session BLOCKED reported (SPEC section 6.6: no
        # duplicate BLOCKED without a changed limiting offset).
        self._session_blocked_sent_at: Optional[int] = None
        # Receive accounting: ``buffered`` bytes were accepted into stream
        # read buffers and not yet consumed or discarded; ``pending`` bytes
        # were released by the application but not yet re-advertised.
        # Credit is only granted from released bytes (IMPLEMENTATION 3.2).
        self._recv_session_received = 0
        self._recv_session_advertised = local_preface.settings.initial_max_data
        self._recv_session_buffered = 0
        self._recv_session_pending = 0
        self._peer_session_blocked_at = -1
        self._peer_session_blocked_floor = 0
        self._open_streams = 0
        self._accepted_streams = 0
        self._reset_reasons: dict[int, int] = {}
        self._abort_reasons: dict[int, int] = {}
        self._reset_overflow = 0
        self._abort_overflow = 0
        self._pings: dict[bytes, _PendingPing] = {}
        self._ping_state = _PingState.from_config(config)
        self._last_ping_rtt = 0.0
        self._last_ping_sent_at: Optional[float] = None
        self._last_pong_at: Optional[float] = None
        now = time.monotonic()
        self._last_inbound_frame_at: Optional[float] = now
        self._last_transport_write_at: Optional[float] = now
        self._read_idle_ping_due_at: Optional[float] = None
        self._write_idle_ping_due_at: Optional[float] = None
        self._max_ping_due_at: Optional[float] = None
        self._reset_keepalive_schedules_locked(now)
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name="zmux-writer",
            daemon=True,
        )
        self._reader_thread = threading.Thread(
            target=self._read_loop,
            name="zmux-reader",
            daemon=True,
        )
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            name="zmux-keepalive",
            daemon=True,
        )
        self._writer_thread.start()
        self._reader_thread.start()
        self._keepalive_thread.start()

    @classmethod
    def establish(cls, transport: object, config: Config) -> "Conn":
        io = _FrameIO(transport)
        try:
            local = config.local_preface()
            payload = config.local_preface_payload(local)
        except BaseException:
            # Nothing reached the wire yet, so there is no preface for a CLOSE
            # to follow; just release the transport.
            _best_effort_close(io)
            raise
        deadline = deadline_after(_establishment_timeout(config))
        # The local preface is written concurrently with reading the peer
        # preface (SPEC section 2), and both are bounded by the establishment
        # timeout so a silent or non-reading peer cannot hang the caller.
        progress = threading.Event()
        writer = _BackgroundCall(
            "zmux-preface-writer",
            lambda: _write_all_and_flush(io, payload),
            progress,
        )
        peer = None
        try:
            reader = _BackgroundCall(
                "zmux-preface-reader",
                lambda: read_preface(io),
                progress,
            )
            while not reader.done():
                if writer.failed():
                    writer.result()
                if not progress.wait(_remaining(deadline)):
                    raise _establishment_stalled(
                        "read preface",
                        "peer preface read stalled during establishment",
                    )
                progress.clear()
            peer = reader.result()
            negotiated = negotiate_prefaces(local, peer)
            write_wait = None
            if deadline is not None:
                write_wait = max(_remaining(deadline), ESTABLISHMENT_SUCCESS_WRITE_WAIT)
            if not writer.wait(write_wait):
                raise _establishment_stalled(
                    "write preface",
                    "local preface write stalled during establishment",
                )
            writer.result()
        except BaseException as exc:
            _finish_establishment_failure(io, writer, local, peer, exc)
            raise
        try:
            return cls(transport, io, config, local, peer, negotiated)
        except BaseException:
            _best_effort_abort(io)
            raise

    _establish = establish

    def __enter__(self) -> "Conn":
        return self

    # noinspection PyTypeHints
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def accept_stream(self, timeout: Optional[float] = None) -> "NativeStream":
        return self._accept(self._accept_bidi, timeout)

    def accept_uni_stream(self, timeout: Optional[float] = None) -> "NativeStream":
        return self._accept(self._accept_uni, timeout)

    def open_stream(
        self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> "NativeStream":
        return self._open_stream(True, options, timeout)

    def open_uni_stream(
        self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> "NativeStream":
        return self._open_stream(False, options, timeout)

    def open_and_send(
        self,
        data: ReadableBuffer,
        options: Optional[OpenOptions] = None,
        *,
        timeout: Optional[float] = None,
    ) -> "NativeStream":
        start = time.monotonic()
        stream = self.open_stream(options, timeout=timeout)
        try:
            stream.write_all(data, timeout=_remaining_after(start, timeout))
        except BaseException as exc:
            _abort_open_send_failure(stream, exc, "open_and_send failed")
            raise
        return stream

    def open_uni_and_send(
        self,
        data: ReadableBuffer,
        options: Optional[OpenOptions] = None,
        *,
        timeout: Optional[float] = None,
    ) -> "NativeStream":
        start = time.monotonic()
        stream = self.open_uni_stream(options, timeout=timeout)
        try:
            stream.write_final(data, timeout=_remaining_after(start, timeout))
        except BaseException as exc:
            _abort_open_send_failure(stream, exc, "open_uni_and_send failed")
            raise
        return stream

    def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        # The deadline covers queueing the PING behind a stalled writer as
        # well as waiting for the PONG.
        deadline = deadline_after(timeout)
        self._check_open(ErrorOperation.PING)
        payload, pending = self._register_ping(_bytes_like(echo, "echo"), deadline)
        try:
            self._queue_frame(Frame(FrameType.PING, 0, 0, payload))
            if not pending.done.wait(_remaining(deadline)):
                raise PingTimeout()
            error = pending.error_holder[0] if pending.error_holder else None
            if error is not None:
                raise error
            self._last_ping_rtt = pending.rtt_holder[0]
            return pending.rtt_holder[0]
        finally:
            with self._lock:
                self._pings.pop(payload, None)
                self._lock_notify_all()

    def _register_ping(
        self,
        echo_bytes: bytes,
        deadline: Optional[float] = None,
        *,
        wait: bool = True,
    ) -> Optional[Tuple[bytes, _PendingPing]]:
        """Claim the session's single outstanding-PING slot and build the PING.

        At most one locally originated PING is outstanding (IMPLEMENTATION
        sections 2.3 and 4, like Go, Rust and Java): user and keepalive PINGs
        share the slot.  A caller waits for it until ``deadline``
        (PingTimeout); with ``wait=False`` a busy slot returns None.
        """

        # SPEC section 6.4: the PING, and so the peer's verbatim PONG, must fit
        # both the peer's and our own max_control_payload_bytes.
        limit = ping_payload_limit(self._local_preface.settings, self._peer_preface.settings)
        payload_len = ping_payload_len(len(echo_bytes))
        if payload_len > limit:
            raise _local_ping_too_large(payload_len, limit)
        with self._lock:
            while True:
                self._check_open_locked(ErrorOperation.PING)
                if not self._pings:
                    break
                if not wait:
                    return None
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise PingTimeout()
                self._lock_wait(remaining)
            # The nonce/padding state only advances while the slot is held.
            nonce = next_session_nonce(self._ping_state)
            padded_echo, allows_padded_pong = build_padded_ping_echo(
                self._ping_state,
                self._local_preface.settings,
                self._peer_preface.settings,
                echo_bytes,
                nonce,
            )
            payload = build_ping_payload(padded_echo, nonce)
            if len(payload) > limit:
                raise _local_ping_too_large(len(payload), limit)
            pending = _PendingPing(
                threading.Event(),
                time.monotonic(),
                [0.0],
                allows_padded_pong,
                [None],
            )
            self._pings[payload] = pending
            self._last_ping_sent_at = pending.started_at
            self._reset_max_ping_due_locked(pending.started_at)
            self._lock_notify_all()
        return payload, pending

    def go_away(
        self,
        last_accepted_bidi: int,
        last_accepted_uni: int,
        code: int = 0,
        reason: str = "",
    ) -> None:
        self._check_open(ErrorOperation.CLOSE)
        self._validate_local_go_away(last_accepted_bidi, last_accepted_uni)
        payload = build_go_away_payload(
            last_accepted_bidi,
            last_accepted_uni,
            code,
            reason,
            self._peer_limits.max_control_payload_bytes,
        )
        with self._lock:
            self._queue_local_go_away_locked(last_accepted_bidi, last_accepted_uni, payload)

    def _validate_local_go_away(self, last_accepted_bidi: int, last_accepted_uni: int) -> None:
        try:
            validate_go_away_watermark_for_direction(last_accepted_bidi, True)
            validate_go_away_watermark_creator(self._negotiated.peer_role, last_accepted_bidi)
            validate_go_away_watermark_for_direction(last_accepted_uni, False)
            validate_go_away_watermark_creator(self._negotiated.peer_role, last_accepted_uni)
        except ProtocolError as exc:
            # The shared validators label violations as remote read errors;
            # here they are the caller's own arguments.
            raise _local_go_away_error(str(exc)) from None

    def _local_go_away_issued_locked(self) -> bool:
        # A valid bidirectional watermark is never MAX_VARINT62 (that ID is
        # unidirectional), so the initial sentinel pair means "none sent".
        return (
            self._local_go_away_bidi != MAX_VARINT62
            or self._local_go_away_uni != MAX_VARINT62
        )

    def _queue_local_go_away_locked(
        self,
        last_accepted_bidi: int,
        last_accepted_uni: int,
        payload: bytes,
        *,
        best_effort: bool = False,
    ) -> bool:
        """Commit a local GOAWAY and queue it in the same ``_lock`` hold.

        Every local GOAWAY (application, graceful close, ID exhaustion) is
        committed and queued under ``_lock`` onto the FIFO urgent lane, so the
        wire order always equals the commit order and the advertised
        watermarks can never increase (SPEC sections 6.9 and 10.1).  A request
        already covered by an earlier GOAWAY is a successful no-op, like Go,
        Rust and Java; returns whether a frame was queued.  ``best_effort``
        drops the frame instead of raising if the writer already shut down.
        """

        self._check_open_locked(ErrorOperation.CLOSE)
        if self._state is SessionState.CLOSING:
            raise SessionClosed(operation=ErrorOperation.CLOSE, source=ErrorSource.LOCAL)
        current_bidi = self._local_go_away_bidi
        current_uni = self._local_go_away_uni
        if (
            self._local_go_away_issued_locked()
            and last_accepted_bidi >= current_bidi
            and last_accepted_uni >= current_uni
        ):
            return False
        if last_accepted_bidi > current_bidi or last_accepted_uni > current_uni:
            raise _local_go_away_error("GOAWAY watermarks must be non-increasing")
        self._local_go_away_bidi = last_accepted_bidi
        self._local_go_away_uni = last_accepted_uni
        if self._state is SessionState.READY:
            self._state = SessionState.DRAINING
        # Queued on the urgent lane without waiting for the transport, so a
        # stalled writer cannot hang go_away() or the graceful close path.
        self._queue_frame(Frame(FrameType.GOAWAY, 0, 0, payload), from_reader=best_effort)
        return True

    def _queue_graceful_go_away_locked(self, last_accepted_bidi: int, last_accepted_uni: int) -> None:
        self._validate_local_go_away(last_accepted_bidi, last_accepted_uni)
        payload = build_go_away_payload(
            last_accepted_bidi,
            last_accepted_uni,
            int(ErrorCode.NO_ERROR),
            "",
            self._peer_limits.max_control_payload_bytes,
        )
        self._queue_local_go_away_locked(
            last_accepted_bidi,
            last_accepted_uni,
            payload,
            best_effort=True,
        )

    def close(self) -> None:
        drain_timeout = graceful_close_drain_timeout(
            self._runtime_policy.graceful_close_drain_timeout,
            self._last_ping_rtt,
        )
        await_existing = False
        graceful_drain = False
        terminal = False
        with self._lock:
            if self._state.terminal():
                terminal = True
            elif self._state is SessionState.CLOSING or self._graceful_close_active:
                await_existing = True
            elif self._has_graceful_close_pending_work_locked():
                self._graceful_close_active = True
                self._state = SessionState.DRAINING
                graceful_drain = True
                if not self._local_go_away_issued_locked():
                    # Committed with the drain decision: a concurrent
                    # go_away() is ordered entirely before or after it.
                    self._queue_graceful_go_away_locked(
                        self._effective_go_away_send_watermark_locked(True),
                        self._effective_go_away_send_watermark_locked(False),
                    )
                self._lock_notify_all()
            else:
                self._graceful_close_active = True
                self._lock_notify_all()
        if terminal:
            # Another closer owns termination; it finishes within its bounded
            # CLOSE wait, so wait for the transport release.
            self._closed_event.wait(self._close_completion_bound())
            return
        if await_existing:
            bound = (
                drain_timeout
                + go_away_drain_interval(
                    self._runtime_policy.go_away_drain_interval,
                    self._last_ping_rtt,
                )
                + self._close_completion_bound()
            )
            if not self._closed_event.wait(bound):
                raise GracefulCloseTimeout()
            return
        close_error = None
        if graceful_drain:
            self._sleep_unless_closed(
                go_away_drain_interval(
                    self._runtime_policy.go_away_drain_interval,
                    self._last_ping_rtt,
                )
            )
            with self._lock:
                if self._state.terminal():
                    return
                # Refined from the watermark committed now (an application
                # go_away() may have lowered it meanwhile), in the same hold.
                refined_bidi = min(self._local_go_away_bidi, self._last_accepted_peer_bidi)
                refined_uni = min(self._local_go_away_uni, self._last_accepted_peer_uni)
                if (
                    refined_bidi < self._local_go_away_bidi
                    or refined_uni < self._local_go_away_uni
                ):
                    self._queue_graceful_go_away_locked(refined_bidi, refined_uni)
            self._reclaim_graceful_close_local_streams()
            if not self._wait_for_graceful_close_drain(drain_timeout):
                with self._lock:
                    self._graceful_close_timeouts = _sat_add(
                        self._graceful_close_timeouts,
                        1,
                    )
                close_error = GracefulCloseTimeout()
        self.close_with_error(0, "")
        self._closed_event.wait(drain_timeout + 1.0)
        if close_error is not None:
            raise close_error

    def close_with_error(self, code: int, reason: str = "") -> None:
        code = _application_code(code)
        reason = "" if reason is None else str(reason)
        payload = build_error_payload(
            code,
            reason,
            self._peer_limits.max_control_payload_bytes,
        )
        error = None
        if code:
            error = ApplicationError(
                code,
                reason,
                scope=ErrorScope.SESSION,
                operation=ErrorOperation.CLOSE,
                source=ErrorSource.LOCAL,
                termination_kind=TerminationKind.SESSION_TERMINATION,
            )
        # Terminal state is committed (and blocked operations woken) before the
        # CLOSE is written; the CLOSE write itself is bounded.  Only the first
        # closer emits CLOSE.
        if not self._terminate(error, failed=bool(code), close_payload=payload):
            self._closed_event.wait(self._close_completion_bound())

    def _close_completion_bound(self) -> float:
        return close_frame_send_timeout(self._last_ping_rtt) + _CLOSE_COMPLETION_GRACE

    def _sleep_unless_closed(self, delay: float) -> None:
        if delay <= 0:
            return
        self._closed_event.wait(delay)

    def _wait_for_graceful_close_drain(self, timeout: float) -> bool:
        deadline = deadline_after(timeout)
        with self._lock:
            while not self._state.terminal() and self._has_graceful_close_pending_work_locked():
                remaining = _remaining(deadline)
                if remaining == 0:
                    return False
                self._lock_wait(remaining)
            return True

    def wait(self, timeout: Optional[float] = None) -> None:
        if not self._closed_event.wait(maybe_timeout(timeout)):
            raise SessionWaitTimeout()
        self._join_runtime_threads()
        self._raise_wait_error_if_failed()

    def wait_timeout(self, timeout: Optional[float] = None) -> bool:
        if not self._closed_event.wait(maybe_timeout(timeout)):
            return False
        self._join_runtime_threads()
        self._raise_wait_error_if_failed()
        return True

    def _join_runtime_threads(self) -> None:
        for thread in (self._reader_thread, self._keepalive_thread, self._writer_thread):
            if thread is not threading.current_thread() and thread.is_alive():
                thread.join(0)

    def _raise_wait_error_if_failed(self) -> None:
        with self._lock:
            failed = self._state == SessionState.FAILED
            error = self._close_error
        if failed:
            if error is not None:
                raise error
            raise SessionClosed(operation=ErrorOperation.CLOSE, source=ErrorSource.LOCAL)

    @property
    def closed(self) -> bool:
        return self._closed_event.is_set()

    @property
    def local_addr(self) -> Optional[object]:
        return self._io.local_addr()

    @property
    def remote_addr(self) -> Optional[object]:
        return self._io.remote_addr()

    @property
    def close_error(self) -> Optional[BaseException]:
        return self._close_error

    @property
    def state(self) -> SessionState:
        with self._lock:
            state = self._state
        return state

    @property
    def stats(self) -> SessionStats:
        with self._lock:
            active = self._active_stream_stats_locked()
            now = time.monotonic()
            terminal = self._state.terminal()
            keepalive_interval = 0.0 if terminal else self._keepalive_interval_locked()
            keepalive_max_ping_interval = (
                0.0 if terminal else self._keepalive_max_ping_interval_locked()
            )
            keepalive_timeout = self._effective_keepalive_timeout_locked()
            ping_outstanding = bool(self._pings) and not terminal
            oldest_ping = min(
                (pending.started_at for pending in self._pings.values()),
                default=None,
            )
            ping_stalled = (
                ping_outstanding
                and oldest_ping is not None
                and keepalive_timeout > 0
                and now - oldest_ping > keepalive_timeout / 2
            )
            inbound_idle_for = (
                0.0
                if terminal or self._last_inbound_frame_at is None
                else max(0.0, now - self._last_inbound_frame_at)
            )
            outbound_idle_for = (
                0.0
                if terminal or self._last_transport_write_at is None
                else max(0.0, now - self._last_transport_write_at)
            )
            progress = ProgressStats(
                inbound_frame_at=self._last_inbound_frame_at,
                control_progress_at=self._last_inbound_frame_at,
                transport_write_at=self._last_transport_write_at,
                ping_sent_at=self._last_ping_sent_at,
                pong_at=self._last_pong_at,
            )
            liveness = LivenessStats(
                keepalive_interval=keepalive_interval,
                keepalive_max_ping_interval=keepalive_max_ping_interval,
                keepalive_timeout=keepalive_timeout,
                ping_outstanding=ping_outstanding,
                ping_stalled=ping_stalled,
                last_ping_rtt=self._last_ping_rtt,
                inbound_idle_for=inbound_idle_for,
                outbound_idle_for=outbound_idle_for,
            )
            tracked_memory = self._tracked_session_memory_locked()
            memory_hard_cap = self._session_memory_hard_cap_locked()
            aggregate_late_data = self._aggregate_late_data_locked()
            stats = SessionStats(
                state=self._state,
                sent_frames=self._sent_frames,
                received_frames=self._received_frames,
                sent_data_bytes=self._sent_data_bytes,
                received_data_bytes=self._received_data_bytes,
                open_streams=self._open_streams,
                accepted_streams=self._accepted_streams,
                keepalive_interval=keepalive_interval,
                keepalive_max_ping_interval=keepalive_max_ping_interval,
                keepalive_timeout=keepalive_timeout,
                ping_outstanding=ping_outstanding,
                ping_stalled=ping_stalled,
                progress=progress,
                last_ping_sent_at=self._last_ping_sent_at,
                last_pong_at=self._last_pong_at,
                last_ping_rtt=self._last_ping_rtt,
                active_streams=active,
                reasons=ReasonStats(
                    reset=self._reset_reasons,
                    reset_overflow=self._reset_overflow,
                    abort=self._abort_reasons,
                    abort_overflow=self._abort_overflow,
                ),
                accept_backlog=AcceptBacklogStats(
                    count=len(self._accept_bidi) + len(self._accept_uni),
                    count_limit=self._runtime_policy.accept_backlog_limit,
                    bytes=self._accept_backlog_bytes_locked(),
                    bytes_limit=self._runtime_policy.accept_backlog_bytes_limit,
                    refused=self._visible_accept_refused,
                    bidi=len(self._accept_bidi),
                    uni=len(self._accept_uni),
                ),
                provisionals=ProvisionalStats(
                    bidi=len(self._provisional_bidi),
                    uni=len(self._provisional_uni),
                    bidi_limit=self._config.max_provisional_streams_bidi,
                    uni_limit=self._config.max_provisional_streams_uni,
                    limited=self._provisional_limited,
                    expired=self._provisional_expired,
                ),
                pressure=PressureStats(
                    receive_backlog_bytes=self._recv_session_buffered,
                    receive_backlog_high=(
                        self._recv_session_advertised > 0
                        and self._recv_session_buffered
                        >= self._recv_session_advertised // 2
                    ),
                    aggregate_late_data_bytes=aggregate_late_data,
                    aggregate_late_data_at_cap=(
                        self._runtime_policy.aggregate_late_data_cap > 0
                        and aggregate_late_data
                        >= self._runtime_policy.aggregate_late_data_cap
                    ),
                    tracked_buffered_bytes=tracked_memory,
                    tracked_buffered_limit=memory_hard_cap,
                    tracked_buffered_high=(
                        tracked_memory >= session_memory_high_threshold(memory_hard_cap)
                    ),
                    tracked_buffered_at_cap=tracked_memory >= memory_hard_cap,
                    buffered_receive_bytes=self._recv_session_buffered,
                    recv_session_advertised_bytes=self._recv_session_advertised,
                    recv_session_received_bytes=self._recv_session_received,
                    recv_session_pending_bytes=self._recv_session_pending,
                ),
                hidden=HiddenStats(
                    refused=self._visible_accept_refused,
                    unread_bytes_discarded=self._hidden_unread_bytes_discarded,
                ),
                diagnostics=DiagnosticStats(
                    late_data_after_close_read=self._late_data_after_close_read,
                    late_data_after_reset=self._late_data_after_reset,
                    late_data_after_abort=self._late_data_after_abort,
                    graceful_close_timeouts=self._graceful_close_timeouts,
                ),
                abuse=AbuseStats(
                    ignored_control=self._inbound_budget.ignored_control.count,
                    ignored_control_budget=self._inbound_budget.config.ignored_control_budget,
                    no_op_zero_data=self._inbound_budget.no_op_zero_data.count,
                    no_op_zero_data_budget=self._inbound_budget.config.no_op_zero_data_budget,
                    inbound_ping=self._inbound_budget.inbound_ping.count,
                    inbound_ping_budget=self._inbound_budget.config.inbound_ping_budget,
                    no_op_max_data=self._inbound_budget.no_op_max_data.count,
                    no_op_max_data_budget=self._inbound_budget.config.no_op_max_data_budget,
                    no_op_blocked=self._inbound_budget.no_op_blocked.count,
                    no_op_blocked_budget=self._inbound_budget.config.no_op_blocked_budget,
                    no_op_priority_update=self._inbound_budget.no_op_priority_update.count,
                    no_op_priority_update_budget=self._inbound_budget.config.no_op_priority_update_budget,
                    dropped_priority_update=self._inbound_budget.dropped_priority_updates,
                    inbound_control_frames=self._inbound_budget.control.frames,
                    inbound_control_frame_budget=self._inbound_budget.config.inbound_control_frame_budget,
                    inbound_control_bytes=self._inbound_budget.control.bytes,
                    inbound_control_bytes_budget=self._inbound_budget.config.inbound_control_bytes_budget,
                    inbound_ext_frames=self._inbound_budget.ext.frames,
                    inbound_ext_frame_budget=self._inbound_budget.config.inbound_ext_frame_budget,
                    inbound_ext_bytes=self._inbound_budget.ext.bytes,
                    inbound_ext_bytes_budget=self._inbound_budget.config.inbound_ext_bytes_budget,
                    inbound_mixed_frames=self._inbound_budget.mixed.frames,
                    inbound_mixed_frame_budget=self._inbound_budget.config.inbound_mixed_frame_budget,
                    inbound_mixed_bytes=self._inbound_budget.mixed.bytes,
                    inbound_mixed_bytes_budget=self._inbound_budget.config.inbound_mixed_bytes_budget,
                    group_rebucket_churn=self._inbound_budget.group_rebucket_churn.count,
                    group_rebucket_churn_budget=self._inbound_budget.config.group_rebucket_churn_budget,
                    hidden_abort_churn=self._inbound_budget.hidden_abort_churn.count,
                    hidden_abort_churn_budget=self._inbound_budget.config.hidden_abort_churn_budget,
                    visible_terminal_churn=self._inbound_budget.visible_terminal_churn.count,
                    visible_terminal_churn_budget=self._inbound_budget.config.visible_terminal_churn_budget,
                ),
                liveness=liveness,
            )
        return stats

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        return None if self._peer_go_away_error is None else self._peer_go_away_error.clone()

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        return None if self._peer_close_error is None else self._peer_close_error.clone()

    @property
    def config(self) -> Config:
        return self._config

    @property
    def peer_limits(self) -> Limits:
        return self._peer_limits

    def local_preface(self) -> Preface:
        return self._local_preface

    def peer_preface(self) -> Preface:
        return self._peer_preface

    def negotiated(self) -> Negotiated:
        return self._negotiated

    def send_frame(self, frame: Frame) -> None:
        self._send_frame(frame)

    def emit_stream_opened(self, stream: "NativeStream") -> None:
        self._emit_stream_opened(stream)

    def forget_stream(self, stream: "NativeStream") -> None:
        self._forget_stream(stream)

    def _accept(
        self, queue: Deque["NativeStream"], timeout: Optional[float]
    ) -> "NativeStream":
        deadline = deadline_after(timeout)
        stream = None
        with self._lock:
            while True:
                if queue:
                    stream = queue.popleft()
                    self._accept_visibility.pop(stream.stream_id, None)
                    if stream.closed and self._streams.get(stream.stream_id) is stream:
                        self._retire_stream_locked(
                            stream,
                            stream.terminal_late_data_cause(),
                            action=stream.terminal_late_data_action(),
                            late_data_cap=stream.terminal_late_data_cap(),
                        )
                    if stream.bidirectional:
                        self._last_accepted_peer_bidi = max(
                            self._last_accepted_peer_bidi,
                            stream.stream_id,
                        )
                    else:
                        self._last_accepted_peer_uni = max(
                            self._last_accepted_peer_uni,
                            stream.stream_id,
                        )
                    self._accepted_streams = _sat_add(self._accepted_streams, 1)
                    break
                if self._state.terminal():
                    raise self._visible_closed_error(ErrorOperation.ACCEPT)
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise AcceptTimeout()
                self._lock_wait(remaining)
        # A stream accepted under a zero receive window gets its first grant
        # now; otherwise its opener could never be followed by data (D7).
        self._replenish_for_blocked_reader(stream)
        self._emit_stream_event(EventType.STREAM_ACCEPTED, stream)
        return stream

    def _open_stream(
        self,
        bidirectional: bool,
        options: Optional[OpenOptions],
        timeout: Optional[float],
    ) -> "NativeStream":
        if maybe_timeout(timeout) == 0:
            from .errors import OpenTimeout

            raise OpenTimeout()
        options = OpenOptions() if options is None else options
        if not isinstance(options, OpenOptions):
            raise TypeError("options must be OpenOptions or None")
        # Stream group 0 means "no explicit group" (SPEC section 7.4).
        metadata = StreamMetadata(
            options.initial_priority,
            normalize_stream_group(options.initial_group),
            options.open_info,
        )
        with self._lock:
            self._check_local_open_allowed_locked()
            # Metadata the opener cannot carry is rejected here, before any
            # stream ID is reserved, so a failed open never leaves an ID gap
            # on the wire (SPEC section 3.1).
            _open_metadata_prefix(
                self._negotiated.capabilities,
                metadata,
                self._peer_limits.max_frame_payload,
            )
            limit = (
                self._peer_preface.settings.max_incoming_streams_bidi
                if bidirectional
                else self._peer_preface.settings.max_incoming_streams_uni
            )
            self._reap_expired_provisionals_locked(bidirectional, time.monotonic())
            active = sum(
                1
                for stream in self._streams.values()
                if (
                    stream.opened_locally
                    and stream.bidirectional == bidirectional
                    and not stream.closed
                )
            )
            queue = self._provisional_queue_locked(bidirectional)
            provisional_count = len(queue)
            if active >= limit or active + provisional_count >= limit:
                raise ApplicationError(
                    int(ErrorCode.REFUSED_STREAM),
                    "peer incoming stream limit reached",
                    scope=ErrorScope.SESSION,
                    operation=ErrorOperation.OPEN,
                    source=ErrorSource.REMOTE,
                    direction=ErrorDirection.BOTH,
                    termination_kind=TerminationKind.ABORT,
                )
            provisional_limit = (
                self._config.max_provisional_streams_bidi
                if bidirectional
                else self._config.max_provisional_streams_uni
            )
            if provisional_limit and provisional_count >= provisional_limit:
                self._provisional_limited = _sat_add(self._provisional_limited, 1)
                raise OpenLimited()
            next_id = self._next_bidi if bidirectional else self._next_uni
            stream_id = projected_local_open_id(next_id, provisional_count)
            if stream_id > MAX_VARINT62:
                self._note_local_ids_exhausted_locked()
                raise OpenLimited(_LOCAL_STREAM_IDS_EXHAUSTED_MESSAGE)
            peer_go_away = (
                self._peer_go_away_bidi if bidirectional else self._peer_go_away_uni
            )
            if stream_id > (MAX_VARINT62 if peer_go_away is None else peer_go_away):
                raise ApplicationError(
                    int(ErrorCode.REFUSED_STREAM),
                    "",
                    scope=ErrorScope.SESSION,
                    operation=ErrorOperation.OPEN,
                    source=ErrorSource.REMOTE,
                    direction=ErrorDirection.BOTH,
                    termination_kind=TerminationKind.ABORT,
                )
            stream = NativeStream(
                self,
                0,
                opened_locally=True,
                bidirectional=bidirectional,
                local_send=True,
                local_receive=bidirectional,
                metadata=metadata,
            )
            stream._provisional_created_at = time.monotonic()
            queue.append(stream)
            self._lock_notify_all()
        return stream

    def _send_frame(self, frame: Frame) -> None:
        """Queue ``frame`` and wait until the writer handed it to the transport."""

        self._wait_write(self._queue_frame(frame))

    def _queue_frame(
        self,
        frame: Frame,
        *,
        from_reader: bool = False,
        droppable: bool = False,
    ) -> Optional[_WriteRequest]:
        """Queue ``frame`` for the writer thread without blocking.

        DATA uses the ordered data lane; other frames use the urgent lane,
        except stream-scoped control for a stream that still has queued DATA,
        which stays behind that DATA so it can never overtake the stream's
        opener.  Reader-originated frames are dropped silently once the
        session is closing, and ``droppable`` ones (PONG, ABORT replies) are
        dropped when the pending-control budget is exhausted, so the reader
        never waits for the writer or the transport.
        """

        if not from_reader and self._state.terminal():
            raise self._visible_closed_error(ErrorOperation.WRITE)
        data = _encode_frame(frame, self._peer_limits)
        closed = False
        request = None
        with self._write_cond:
            if self._writer_closed:
                closed = True
            else:
                request = self._queue_frame_locked(frame, data, droppable)
        if closed:
            if from_reader:
                return None
            raise self._visible_closed_error(ErrorOperation.WRITE)
        return request

    def _queue_frame_locked(
        self,
        frame: Frame,
        data: bytes,
        droppable: bool,
    ) -> Optional[_WriteRequest]:
        frame_type = frame.frame_type
        stream_id = frame.stream_id
        if frame_type == FrameType.MAX_DATA:
            pending = self._pending_max_data.get(stream_id)
            if pending is not None:
                # Credit only grows; coalesce into the not-yet-written update.
                if _max_data_value(frame) > _max_data_value(pending.frame):
                    pending.frame = frame
                    pending.data = data
                return pending
        if droppable:
            budget = self._runtime_policy.pending_control_bytes_budget
            if budget and self._queued_droppable_bytes + len(data) > budget:
                return None
        request = _WriteRequest(frame, data, droppable=droppable)
        if frame_type == FrameType.DATA:
            request.data_lane = True
            self._queued_data_bytes = _sat_add(self._queued_data_bytes, len(data))
            self._queued_data_by_stream[stream_id] = (
                self._queued_data_by_stream.get(stream_id, 0) + 1
            )
        elif (
            stream_id != 0
            and frame_type != FrameType.MAX_DATA
            and self._queued_data_by_stream.get(stream_id)
        ):
            request.data_lane = True
        if request.data_lane:
            self._data_writes.append(request)
        else:
            self._urgent_writes.append(request)
        if droppable:
            self._queued_droppable_bytes = _sat_add(
                self._queued_droppable_bytes,
                len(data),
            )
        if frame_type == FrameType.MAX_DATA:
            self._pending_max_data[stream_id] = request
        self._write_cond.notify_all()
        return request

    def _wait_write(
        self,
        request: Optional[_WriteRequest],
        deadline_source=None,
    ) -> None:
        """Wait for ``request`` to reach the transport.

        ``deadline_source`` returns the current absolute deadline (re-read on
        every wake-up so deadline changes apply).  On timeout the frame stays
        queued: it was already committed (stream credit and ordering), so a
        timed-out write may still be delivered later.
        """

        if request is None:
            return
        with self._write_cond:
            while not request.done:
                deadline = None if deadline_source is None else deadline_source()
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise WriteTimeout()
                self._write_cond.wait(remaining)
            error = request.error
        if error is not None:
            raise error

    def _notify_writers(self) -> None:
        with self._write_cond:
            self._write_cond.notify_all()

    def _writer_loop(self) -> None:
        try:
            while True:
                with self._write_cond:
                    while not self._urgent_writes and not self._data_writes:
                        if self._writer_stop:
                            return
                        self._write_cond.wait()
                    batch, final = self._take_write_batch_locked()
                    self._inflight_writes = batch
                payload = batch[0].data if len(batch) == 1 else b"".join(
                    request.data for request in batch
                )
                _write_all_and_flush(self._io, payload)
                self._note_frames_written(batch)
                with self._write_cond:
                    self._inflight_writes = ()
                    self._complete_requests_locked(batch, None)
                    if final is not None:
                        self._writer_stop = True
                        return
        except BaseException as exc:
            with self._write_cond:
                self._writer_closed = True
                self._writer_stop = True
                self._complete_requests_locked(self._inflight_writes, exc)
                self._inflight_writes = ()
                self._drop_queued_writes_locked(exc, include_urgent=True)
            # The writer can no longer emit anything, so no CLOSE can follow.
            self._finish(exc, failed=True, close_transport=True)

    def _take_write_batch_locked(
        self,
    ) -> Tuple[Tuple[_WriteRequest, ...], Optional[_WriteRequest]]:
        batch = []
        size = 0
        final = None
        max_frames = self._runtime_policy.write_batch_max_frames or _WRITER_BATCH_MAX_FRAMES
        while self._urgent_writes and len(batch) < max_frames:
            request = self._urgent_writes.popleft()
            self._mark_write_started_locked(request)
            batch.append(request)
            size += len(request.data)
            if request.final:
                final = request
                break
        if final is None:
            while (
                self._data_writes
                and len(batch) < max_frames
                and (not batch or size + len(self._data_writes[0].data) <= _WRITER_BATCH_MAX_BYTES)
            ):
                request = self._data_writes.popleft()
                self._mark_write_started_locked(request)
                batch.append(request)
                size += len(request.data)
        return tuple(batch), final

    def _mark_write_started_locked(self, request: _WriteRequest) -> None:
        request.started = True
        self._forget_queued_write_locked(request)

    def _forget_queued_write_locked(self, request: _WriteRequest) -> None:
        frame = request.frame
        if frame.frame_type == FrameType.DATA:
            self._queued_data_bytes = max(0, self._queued_data_bytes - len(request.data))
            count = self._queued_data_by_stream.get(frame.stream_id, 0) - 1
            if count > 0:
                self._queued_data_by_stream[frame.stream_id] = count
            else:
                self._queued_data_by_stream.pop(frame.stream_id, None)
        elif frame.frame_type == FrameType.MAX_DATA:
            if self._pending_max_data.get(frame.stream_id) is request:
                del self._pending_max_data[frame.stream_id]
        if request.droppable:
            self._queued_droppable_bytes = max(
                0,
                self._queued_droppable_bytes - len(request.data),
            )

    def _complete_requests_locked(
        self,
        requests: Iterable[_WriteRequest],
        error: Optional[BaseException],
    ) -> None:
        for request in requests:
            if not request.done:
                request.error = error
                request.done = True
        self._write_cond.notify_all()

    def _drop_queued_writes_locked(
        self,
        error: BaseException,
        *,
        include_urgent: bool,
    ) -> None:
        dropped = list(self._data_writes)
        self._data_writes.clear()
        if include_urgent:
            dropped.extend(self._urgent_writes)
            self._urgent_writes.clear()
        for request in dropped:
            self._forget_queued_write_locked(request)
        self._complete_requests_locked(dropped, error)

    def _note_frames_written(self, batch: Iterable[_WriteRequest]) -> None:
        with self._lock:
            now = time.monotonic()
            self._last_transport_write_at = now
            self._reset_write_idle_ping_due_locked(now)
            for request in batch:
                frame = request.frame
                self._sent_frames = _sat_add(self._sent_frames, 1)
                if frame.frame_type == FrameType.DATA:
                    parsed = parse_data_payload_view(frame.payload, frame.flags)
                    self._sent_data_bytes = _sat_add(
                        self._sent_data_bytes,
                        len(parsed.app_data),
                    )
                elif frame.frame_type == FrameType.MAX_DATA:
                    self._note_sent_max_data_frame_locked(frame)
            self._lock_notify_all()

    def _shutdown_writer(
        self,
        close_payload: Optional[bytes],
        error: BaseException,
    ) -> bool:
        """Stop admitting writes and emit at most one bounded CLOSE.

        Queued DATA is dropped.  When a CLOSE is requested it is appended to
        the urgent lane (after control frames already queued there) and this
        waits at most ``close_frame_send_timeout``; the caller then closes the
        transport, which also releases a writer stuck in a transport write.
        Returns whether the CLOSE reached the transport.
        """

        close_request = None
        if close_payload is not None:
            frame = Frame(FrameType.CLOSE, 0, 0, close_payload)
            try:
                close_request = _WriteRequest(
                    frame,
                    _encode_frame(frame, self._peer_limits),
                    final=True,
                )
            except BaseException:
                close_request = None
        with self._write_cond:
            writer_usable = (
                not self._writer_closed
                and self._writer_thread.is_alive()
                and threading.current_thread() is not self._writer_thread
            )
            self._writer_closed = True
            if close_request is not None and writer_usable:
                self._drop_queued_writes_locked(error, include_urgent=False)
                self._urgent_writes.append(close_request)
            else:
                close_request = None
                self._writer_stop = True
                self._drop_queued_writes_locked(error, include_urgent=True)
            self._write_cond.notify_all()
            if close_request is None:
                return False
            deadline = deadline_after(close_frame_send_timeout(self._last_ping_rtt))
            while not close_request.done:
                remaining = _remaining(deadline)
                if remaining == 0:
                    break
                self._write_cond.wait(remaining)
            return close_request.done and close_request.error is None

    def _read_loop(self) -> None:
        while True:
            if self._state.terminal():
                return
            try:
                # EXT subtype rules wait for the negotiated capabilities
                # (SPEC section 7.6); classify_inbound_frame applies them.
                frame = read_session_frame(self._io, self._local_limits)
            except TransportError as exc:
                # The transport itself failed (EOF, reset, local close): there
                # is nothing to signal the peer with.
                self._finish(exc, failed=True, close_transport=True)
                return
            except BaseException as exc:
                self._fail_session(exc)
                return
            if self._state.terminal():
                return
            try:
                with self._lock:
                    now = time.monotonic()
                    self._received_frames = _sat_add(self._received_frames, 1)
                    self._last_inbound_frame_at = now
                    self._reset_read_idle_ping_due_locked(now)
                    self._lock_notify_all()
                self._dispatch_frame(frame)
            except BaseException as exc:
                self._fail_session(exc)
                return

    def _dispatch_frame(self, frame: Frame) -> None:
        if frame.frame_type != FrameType.CLOSE:
            state = self._state
            if state is SessionState.CLOSING or state.terminal():
                # Once closing, peer frames other than CLOSE are ignored
                # without validation or budget side effects.
                return
        now = time.monotonic()
        self._inbound_budget.record_frame(frame, now)
        parsed = classify_inbound_frame(
            frame,
            capabilities=self._negotiated.capabilities,
            local_role=self._local_role,
            peer_go_away_bidi=self._peer_go_away_bidi,
            peer_go_away_uni=self._peer_go_away_uni,
        )
        if parsed.kind == ParsedFrameKind.DATA:
            self._handle_data(parsed, now)
        elif parsed.kind == ParsedFrameKind.PING:
            self._inbound_budget.record_inbound_ping(now)
            payload = pong_payload_for_ping(
                self._ping_state,
                self._local_preface.settings,
                self._peer_preface.settings,
                frame.payload,
            )
            # Never block the reader on the writer; a PONG may be dropped under
            # pending-control pressure like the other implementations do.
            self._queue_frame(
                Frame(FrameType.PONG, 0, 0, payload),
                from_reader=True,
                droppable=True,
            )
        elif parsed.kind == ParsedFrameKind.PONG:
            self._handle_pong(frame.payload)
        elif parsed.kind == ParsedFrameKind.GO_AWAY:
            self._handle_go_away(parsed.go_away)
        elif parsed.kind == ParsedFrameKind.CLOSE:
            self._handle_close(frame.payload)
        elif parsed.kind == ParsedFrameKind.STOP_SENDING:
            self._handle_stop_sending(frame.stream_id, frame.payload, now)
        elif parsed.kind == ParsedFrameKind.RESET:
            self._handle_reset(frame.stream_id, frame.payload, now)
        elif parsed.kind == ParsedFrameKind.ABORT:
            self._handle_abort(frame.stream_id, frame.payload, now)
        elif parsed.kind == ParsedFrameKind.EXT:
            self._handle_ext(
                frame.stream_id,
                parsed.priority_update,
                parsed.priority_update_valid,
                now,
            )
        elif parsed.kind == ParsedFrameKind.MAX_DATA:
            self._handle_max_data(parsed.stream_id, parsed.value, now, len(frame.payload))
        elif parsed.kind == ParsedFrameKind.BLOCKED:
            self._handle_blocked(parsed.stream_id, parsed.value, now, len(frame.payload))

    def _handle_data(self, parsed, now: Optional[float] = None) -> None:
        with self._lock:
            existing = self._streams.get(parsed.stream_id)
            # A live stream wins over used-ID bookkeeping: a coarsened marker
            # floor also covers lower IDs that are still open.
            terminal = (
                self._terminal_state.terminal_data_disposition_for(parsed.stream_id)
                if existing is None
                else None
            )
        terminal_found = terminal is not None and terminal.found()
        if parsed.metadata is not None and (existing is not None or terminal_found):
            raise ProtocolError(
                "OPEN_METADATA is only valid on the opening DATA frame",
                code=int(ErrorCode.PROTOCOL),
            )
        if terminal_found:
            self._handle_terminal_data(
                parsed.stream_id,
                len(parsed.app_data),
                terminal.disposition,
                fin=parsed.fin,
            )
            return
        stream = self._get_or_create_peer_stream(
            parsed.stream_id,
            parsed.metadata if parsed.metadata is not None else StreamMetadata(),
        )
        app_data = parsed.app_data
        if stream is None:
            # Refused or already-terminal open: the bytes still consumed the
            # peer's session credit, so count and release them.
            self._discard_unowned_peer_data(len(app_data))
            return
        self._inbound_budget.update_no_op_zero_data(
            stream_existed=existing is not None,
            app_len=len(app_data),
            flags=parsed.frame.flags,
            now=now,
        )
        if not stream._local_receive:
            # DATA on our send-only unidirectional stream (SPEC section 9.6):
            # the bytes still count against and return session credit.
            self._discard_unowned_peer_data(len(app_data))
            if not stream.closed:
                self._reject_live_stream(stream, ErrorCode.STREAM_STATE)
            return
        if stream._peer_fin_seen and stream._read_error is None:
            # DATA (even empty, even DATA|FIN) after the peer's FIN is a
            # stream-state violation whether or not this side stopped reading
            # (SPEC sections 9.2 and 9.6, DESIGN D2).  Not late data.
            self._discard_unowned_peer_data(len(app_data))
            self._reject_live_stream(stream, ErrorCode.STREAM_CLOSED)
            return
        if app_data:
            if stream.read_closed:
                if not self._record_late_peer_data(
                    stream,
                    len(app_data),
                    hidden=not stream.opened_locally
                    and stream not in self._accept_bidi
                    and stream not in self._accept_uni,
                ):
                    # Beyond the stream credit still outstanding when this
                    # side stopped reading (SPEC section 8).
                    self._abort_stream_for_flow_control(stream)
                    return
                if parsed.fin:
                    # recv_stop_sent -> recv_fin: the stopped direction is
                    # now concluded, and DATA after it is invalid.
                    stream.receive_fin()
                return
            if not self._account_peer_data(stream, len(app_data)):
                self._abort_stream_for_flow_control(stream)
                return
            # Credit is not granted here: it is released when the
            # application consumes (or the stack discards) the bytes, so the
            # advertised windows bound what is buffered and this reader
            # never has to wait for the application.
            if not stream.receive_data(app_data):
                self._discard_receive(stream, len(app_data))
            with self._lock:
                refused = self._enforce_accept_backlog_locked()
                self._received_data_bytes = _sat_add(
                    self._received_data_bytes,
                    len(app_data),
                )
            for refused_stream in refused:
                self._send_refused_stream_abort(refused_stream)
            if stream in refused:
                return
        if parsed.fin:
            stream.receive_fin()

    def _handle_terminal_data(
        self,
        stream_id: int,
        length: int,
        disposition: TerminalDataDisposition,
        *,
        fin: bool = False,
    ) -> None:
        self._record_terminal_late_peer_data(stream_id, length, disposition.cause)
        if disposition.action is LateDataAction.ABORT_CLOSED:
            self._send_terminal_abort(stream_id, int(ErrorCode.STREAM_CLOSED))
        elif disposition.action is LateDataAction.ABORT_STATE:
            self._send_terminal_abort(stream_id, int(ErrorCode.STREAM_STATE))
        elif fin and disposition.cause is LateDataCause.CLOSE_READ:
            self._note_peer_fin_after_stop(stream_id)

    def _note_peer_fin_after_stop(self, stream_id: int) -> None:
        """Record the peer's FIN on a stream compacted after a local read stop.

        A stream whose send half had already finished is compacted as soon as
        its receive half is stopped.  The peer's DATA|FIN then moves that
        direction to recv_fin, so later DATA must get ABORT(STREAM_CLOSED)
        exactly as on a live stream (STATE_MACHINE sections 5.1 and 8.1).
        """

        with self._lock:
            lookup = self._terminal_state.tombstone_for(stream_id)
            if not lookup.found():
                return
            record = lookup.tombstone
            if record.tombstone.data_action is not LateDataAction.IGNORE:
                return
            # The used-stream marker is taken from the record when it is reaped.
            record.tombstone = replace(
                record.tombstone,
                data_action=LateDataAction.ABORT_CLOSED,
            )

    def _reject_live_stream(
        self,
        stream: "NativeStream",
        code: ErrorCode,
        local_reason: str = "",
    ) -> None:
        """Answer a peer stream-level violation on a live stream with ABORT(code).

        The stream is aborted locally before the ABORT is queued, so none of
        its DATA can follow it.  A stream that is already fully terminal keeps
        its outcome; it only gets the (droppable) ABORT, like a tombstone.
        """

        already_terminal = stream.closed
        if not already_terminal:
            stream.abort(
                ApplicationError(
                    int(code),
                    local_reason,
                    scope=ErrorScope.STREAM,
                    operation=ErrorOperation.CLOSE,
                    source=ErrorSource.LOCAL,
                    direction=ErrorDirection.BOTH,
                    termination_kind=TerminationKind.ABORT,
                )
            )
        self._queue_frame(
            Frame(
                FrameType.ABORT,
                stream.stream_id,
                0,
                build_error_payload(
                    int(code),
                    "",
                    self._peer_limits.max_control_payload_bytes,
                ),
            ),
            from_reader=True,
            droppable=already_terminal,
        )

    def _send_terminal_abort(self, stream_id: int, code: int) -> None:
        self._queue_frame(
            Frame(
                FrameType.ABORT,
                stream_id,
                0,
                build_error_payload(
                    code,
                    "",
                    self._peer_limits.max_control_payload_bytes,
                ),
            ),
            from_reader=True,
            droppable=True,
        )

    def _get_or_create_peer_stream(
        self, stream_id: int, metadata: StreamMetadata
    ) -> Optional["NativeStream"]:
        refused = ()
        refuse_above_go_away = False
        with self._lock:
            existing = self._streams.get(stream_id)
            if existing is not None:
                stream = existing
            else:
                if self._terminal_state.has_terminal_marker(stream_id):
                    return None
                if stream_is_local(self._local_role, stream_id):
                    raise ProtocolError(
                        "peer used locally-owned stream_id %d" % stream_id,
                        code=int(ErrorCode.PROTOCOL),
                    )
                bidirectional = stream_is_bidi(stream_id)
                if self._peer_open_refused_locked(stream_id, bidirectional):
                    # Above our GOAWAY watermark: refused even when it is not
                    # the next expected ID, without consuming the ID or
                    # moving the expected-ID cursor (SPEC section 3.1).
                    refuse_above_go_away = self._note_go_away_refusal_locked(
                        stream_id,
                        bidirectional,
                    )
                    stream = None
                else:
                    stream, refused = self._admit_peer_stream_locked(
                        stream_id,
                        bidirectional,
                        metadata,
                    )
        if refuse_above_go_away:
            self._send_terminal_abort(stream_id, int(ErrorCode.REFUSED_STREAM))
        for refused_stream in refused:
            self._send_refused_stream_abort(refused_stream)
        if stream is None or stream in refused:
            return None
        return stream

    def _admit_peer_stream_locked(
        self,
        stream_id: int,
        bidirectional: bool,
        metadata: StreamMetadata,
    ) -> Tuple[Optional["NativeStream"], Tuple["NativeStream", ...]]:
        """Consume the next expected peer ID and admit or refuse its stream.

        Returns the admitted stream (``None`` when refused) and the streams to
        refuse with ABORT(REFUSED_STREAM).  An ID refused for the incoming
        stream limit or the accept backlog is still consumed (CONFORMANCE
        section 4).
        """

        local_send, local_receive = stream_kind_for_local(self._local_role, stream_id)
        expected = self._next_peer_bidi if bidirectional else self._next_peer_uni
        if expected > MAX_VARINT62:
            raise ProtocolError(
                "peer stream id overflow",
                code=int(ErrorCode.PROTOCOL),
            )
        if stream_id != expected:
            raise ProtocolError(
                "peer stream id skipped expected id",
                code=int(ErrorCode.PROTOCOL),
            )
        if bidirectional:
            self._next_peer_bidi += 4
        else:
            self._next_peer_uni += 4
        stream = NativeStream(
            self,
            stream_id,
            opened_locally=False,
            bidirectional=bidirectional,
            local_send=local_send,
            local_receive=local_receive,
            metadata=metadata,
            opened_sent=True,
        )
        if not self._peer_stream_within_limit_locked(bidirectional):
            # Refused at open: the peer may still have its whole initial
            # stream window in flight, so that is its late-data allowance.
            self._remember_terminal_stream_locked(
                stream_id,
                LateDataCause.ABORT,
                late_data_cap=self._late_data_allowance_locked(stream, stopped_locally=True)
                or None,
            )
            self._lock_notify_all()
            return None, (stream,)
        self._streams[stream_id] = stream
        self._next_visibility_sequence = _sat_add(self._next_visibility_sequence, 1)
        self._accept_visibility[stream_id] = self._next_visibility_sequence
        if bidirectional:
            self._accept_bidi.append(stream)
        else:
            self._accept_uni.append(stream)
        refused = self._enforce_accept_backlog_locked()
        self._lock_notify_all()
        return stream, refused

    def _record_late_peer_data(
        self,
        stream: "NativeStream",
        length: int,
        *,
        hidden: bool,
    ) -> bool:
        """Discard DATA for a live stream whose receive half no longer takes it.

        The bytes are checked against and counted in the session window, and
        their session credit is released at once.  A direction this side
        stopped reading still enforces the stream credit it advertised (SPEC
        section 8): DATA beyond it is not late data, and ``False`` tells the
        caller to abort the stream with FLOW_CONTROL.  Late bytes count
        against the per-direction allowance, which a peer that stayed within
        its credit can never exceed; the aggregate is accounting only and
        never fails the session (DESIGN D2).
        """

        if length <= 0:
            return True
        cause = stream._receive_late_data_cause()
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                length,
            ):
                raise FlowControlError(
                    "session max_data exceeded",
                    code=int(ErrorCode.FLOW_CONTROL),
                )
            self._recv_session_received = _sat_add(self._recv_session_received, length)
            self._received_data_bytes = _sat_add(self._received_data_bytes, length)
            if (
                stream._read_stopped
                and stream._read_error is None
                and receive_window_exceeded(
                    stream._recv_received,
                    stream._recv_advertised,
                    length,
                )
            ):
                self._release_discarded_session_credit_locked(length)
                return False
            # Late bytes advance the stream's received offset too, so the
            # credit outstanding at a local stop stays derivable from the
            # frozen advertised limit (see _late_data_allowance_locked).
            stream._recv_received = _sat_add(stream._recv_received, length)
            stream._late_data_received = _sat_add(stream._late_data_received, length)
            self._live_late_data_retained = _sat_add(self._live_late_data_retained, length)
            self._note_late_data_locked(cause, length, hidden)
            allowance = self._late_data_allowance_locked(stream)
            if allowance and stream._late_data_received > allowance:
                raise ProtocolError("late-data cap exceeded", code=int(ErrorCode.PROTOCOL))
            self._release_discarded_session_credit_locked(length)
        return True

    def _record_terminal_late_peer_data(
        self,
        stream_id: int,
        length: int,
        cause: LateDataCause,
    ) -> None:
        """Discard DATA for a compacted stream.

        A retained tombstone counts the bytes against the allowance it carries
        over from the live stream; a reaped (marker-only) ID retains nothing,
        so its bytes only go through the session window and are released.
        """

        if length <= 0:
            return
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                length,
            ):
                raise FlowControlError(
                    "session max_data exceeded",
                    code=int(ErrorCode.FLOW_CONTROL),
                )
            terminal_result = self._terminal_state.record_terminal_late_data(
                stream_id,
                length,
            )
            self._recv_session_received = _sat_add(self._recv_session_received, length)
            self._received_data_bytes = _sat_add(self._received_data_bytes, length)
            self._note_late_data_locked(cause, length, terminal_result.hidden)
            if terminal_result.cap_exceeded:
                raise ProtocolError("late-data cap exceeded", code=int(ErrorCode.PROTOCOL))
            self._release_discarded_session_credit_locked(length)

    def _note_late_data_locked(self, cause: LateDataCause, length: int, hidden: bool) -> None:
        if cause is LateDataCause.CLOSE_READ:
            self._late_data_after_close_read = _sat_add(
                self._late_data_after_close_read,
                length,
            )
        elif cause is LateDataCause.RESET:
            self._late_data_after_reset = _sat_add(
                self._late_data_after_reset,
                length,
            )
        elif cause is LateDataCause.ABORT:
            self._late_data_after_abort = _sat_add(
                self._late_data_after_abort,
                length,
            )
        if hidden:
            self._hidden_unread_bytes_discarded = _sat_add(
                self._hidden_unread_bytes_discarded,
                length,
            )

    def _aggregate_late_data_locked(self) -> int:
        """Late bytes counted by live streams and retained tombstones."""

        return _sat_add(self._live_late_data_retained, self._terminal_state.late_data_retained)

    def _late_data_allowance_locked(
        self,
        stream: "NativeStream",
        *,
        stopped_locally: Optional[bool] = None,
    ) -> int:
        """Return the per-direction late-data allowance (0: unlimited).

        Repository cap, raised once this side stopped reading or aborted the
        stream to the stream credit still outstanding at that moment, which
        is the most a compliant peer can have in flight (DESIGN D2).  Stream
        credit is never re-advertised after a stop or abort and every late
        byte advances both ``_recv_received`` and ``_late_data_received``, so
        that outstanding credit is derived here instead of being captured.
        """

        cap = self._late_data_per_stream_cap_locked(stream.stream_id)
        if stopped_locally is None:
            stopped_locally = stream._receive_stopped_locally()
        if cap == 0 or not stopped_locally:
            return cap
        outstanding = stream._recv_advertised - (
            stream._recv_received - stream._late_data_received
        )
        return max(cap, outstanding)

    def _discard_unowned_peer_data(self, length: int) -> None:
        """Charge and release DATA that no stream will take.

        Used for a peer open that was refused or dropped and for DATA
        rejected with a stream ABORT (after FIN, wrong direction): the bytes
        still count against the session window and their credit returns at
        once, but they are not late data (DESIGN D2, D6).
        """

        if length <= 0:
            return
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                length,
            ):
                raise FlowControlError(
                    "session max_data exceeded",
                    code=int(ErrorCode.FLOW_CONTROL),
                )
            self._recv_session_received = _sat_add(self._recv_session_received, length)
            self._received_data_bytes = _sat_add(self._received_data_bytes, length)
            self._release_discarded_session_credit_locked(length)

    def _late_data_per_stream_cap_locked(self, stream_id: int) -> int:
        configured = self._runtime_policy.late_data_per_stream_cap
        if configured is not None:
            return configured
        settings = self._local_preface.settings
        if not stream_is_bidi(stream_id):
            window = settings.initial_max_stream_data_uni
        elif stream_is_local(self._local_role, stream_id):
            window = settings.initial_max_stream_data_bidi_locally_opened
        else:
            window = settings.initial_max_stream_data_bidi_peer_opened
        payload = negotiated_frame_payload(self._local_preface.settings, self._peer_preface.settings)
        return late_data_per_stream_cap(window, payload)

    def _handle_pong(self, payload: bytes) -> None:
        with self._lock:
            matched_payload = None
            matched = None
            for ping_payload, pending in self._pings.items():
                if pong_payload_matches_ping(
                    payload,
                    ping_payload,
                    allow_padding=pending.allows_padded_pong,
                ):
                    matched_payload = ping_payload
                    matched = pending
                    break
            if matched is not None:
                if matched_payload is not None:
                    self._pings.pop(matched_payload, None)
                now = time.monotonic()
                matched.rtt_holder[0] = max(0.0, now - matched.started_at)
                self._last_ping_rtt = matched.rtt_holder[0]
                self._last_pong_at = now
                self._reset_read_idle_ping_due_locked(now)
                self._reset_write_idle_ping_due_locked(now)
                self._lock_notify_all()
                matched.done.set()
                self._inbound_budget.clear_no_op_control_budgets()
                return
        self._inbound_budget.record_ignored_control()

    def _handle_go_away(self, parsed) -> None:
        if parsed is None:
            return
        # The latest GOAWAY's cause is kept even for NO_ERROR, so its
        # debug_text stays observable (as in Go, Rust and Java).
        app = ApplicationError(
            parsed.code,
            parsed.reason,
            scope=ErrorScope.SESSION,
            operation=ErrorOperation.CLOSE,
            source=ErrorSource.REMOTE,
            termination_kind=TerminationKind.SESSION_TERMINATION,
        )
        with self._lock:
            if self._ignore_peer_non_close_frame_locked():
                # STATE_MACHINE section 10 has no closing -> draining: a GOAWAY
                # that races session termination changes nothing.
                return
            changed = (
                self._peer_go_away_bidi is None
                or self._peer_go_away_uni is None
                or parsed.last_accepted_bidi < self._peer_go_away_bidi
                or parsed.last_accepted_uni < self._peer_go_away_uni
            )
            self._peer_go_away_bidi = parsed.last_accepted_bidi
            self._peer_go_away_uni = parsed.last_accepted_uni
            self._peer_go_away_error = app
            # Only provisionals can be reclaimed: committing a local stream
            # queues its opener in the same critical section, so every
            # committed ID reaches the peer (DESIGN D5).
            self._reclaim_provisionals_locked(True, parsed.last_accepted_bidi)
            self._reclaim_provisionals_locked(False, parsed.last_accepted_uni)
            if self._state is SessionState.READY:
                self._state = SessionState.DRAINING
            self._lock_notify_all()
        if changed:
            self._inbound_budget.clear_no_op_control_budgets()
        else:
            self._inbound_budget.record_ignored_control()

    def _handle_close(self, payload: bytes) -> None:
        code, reason = parse_error_payload(payload)
        app = (
            None
            if code == 0
            else ApplicationError(
                code,
                reason,
                scope=ErrorScope.SESSION,
                operation=ErrorOperation.CLOSE,
                source=ErrorSource.REMOTE,
                termination_kind=TerminationKind.SESSION_TERMINATION,
            )
        )
        self._peer_close_error = app
        self._finish(app, failed=app is not None, close_transport=True)

    def _handle_stop_sending(
        self,
        stream_id: int,
        payload: bytes,
        now: Optional[float] = None,
    ) -> None:
        code, reason = parse_error_payload(payload)
        stream = self._streams.get(stream_id)
        if stream is None:
            self._ignore_terminal_control_or_raise(stream_id, "STOP_SENDING", now)
            return
        if stream.closed:
            # Late control on a fully terminal stream is ignored.
            self._inbound_budget.record_ignored_control(now)
            return
        if not stream._local_send:
            # STOP_SENDING on our receive-only unidirectional stream.
            self._reject_live_stream(stream, ErrorCode.STREAM_STATE)
            return
        app = ApplicationError(
            code,
            reason,
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.WRITE,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.WRITE,
            termination_kind=TerminationKind.STOPPED,
        )
        if not stream.stop_write(app):
            # Our FIN, RESET or ABORT (or an earlier STOP_SENDING) already
            # concluded the half (STATE_MACHINE section 5.2).
            self._inbound_budget.record_ignored_control(now)
            return
        self._finish_peer_terminal_control(stream, now)
        self._queue_frame(
            Frame(
                FrameType.RESET,
                stream_id,
                0,
                build_error_payload(
                    int(ErrorCode.CANCELLED),
                    "",
                    self._peer_limits.max_control_payload_bytes,
                ),
            ),
            from_reader=True,
        )

    def _handle_reset(
        self,
        stream_id: int,
        payload: bytes,
        now: Optional[float] = None,
    ) -> None:
        code, reason = parse_error_payload(payload)
        stream = self._streams.get(stream_id)
        if stream is None:
            self._ignore_terminal_control_or_raise(stream_id, "RESET", now)
            return
        if stream.closed:
            self._inbound_budget.record_ignored_control(now)
            return
        if not stream._local_receive:
            # RESET on our send-only unidirectional stream.
            self._reject_live_stream(stream, ErrorCode.STREAM_STATE)
            return
        applied = stream.reset_read(
            ApplicationError(
                code,
                reason,
                scope=ErrorScope.STREAM,
                operation=ErrorOperation.READ,
                source=ErrorSource.REMOTE,
                direction=ErrorDirection.READ,
                termination_kind=TerminationKind.RESET,
            )
        )
        if not applied:
            # RESET after the peer's FIN, or a repeated RESET, leaves the
            # half unchanged (STATE_MACHINE section 5.1).
            self._inbound_budget.record_ignored_control(now)
            return
        self._note_reason(self._reset_reasons, code, "_reset_overflow")
        self._finish_peer_terminal_control(stream, now)

    def _handle_abort(
        self,
        stream_id: int,
        payload: bytes,
        now: Optional[float] = None,
    ) -> None:
        code, reason = parse_error_payload(payload)
        stream = self._streams.get(stream_id)
        if stream is None:
            self._note_reason(self._abort_reasons, code, "_abort_overflow")
            self._remember_hidden_peer_abort(stream_id, now)
            return
        if stream.closed:
            # Fully terminal (or already aborted) streams keep their outcome.
            self._inbound_budget.record_ignored_control(now)
            return
        self._note_reason(self._abort_reasons, code, "_abort_overflow")
        stream.abort(
            ApplicationError(
                code,
                reason,
                scope=ErrorScope.STREAM,
                operation=ErrorOperation.CLOSE,
                source=ErrorSource.REMOTE,
                direction=ErrorDirection.BOTH,
                termination_kind=TerminationKind.ABORT,
            )
        )
        self._finish_peer_terminal_control(stream, now)

    def _finish_peer_terminal_control(
        self,
        stream: "NativeStream",
        now: Optional[float],
    ) -> None:
        """Account a peer RESET, STOP_SENDING or ABORT that changed a stream.

        An effective terminal control clears the no-op control budgets.  A
        peer stream it leaves fully terminal while the stream still waits,
        unaccepted, in the accept queue is open-then-terminal churn, counted
        once per stream against the visible churn budget (IMPLEMENTATION
        section 7, SPEC section 13).
        """

        self._inbound_budget.clear_no_op_control_budgets()
        with self._lock:
            churn = (
                not stream.opened_locally
                and not stream._churn_counted
                and stream.stream_id in self._accept_visibility
                and stream.closed
            )
            if churn:
                stream._churn_counted = True
        if churn:
            self._inbound_budget.record_visible_terminal_churn(now)

    def _ignore_terminal_control_or_raise(
        self,
        stream_id: int,
        frame_name: str,
        now: Optional[float] = None,
    ) -> None:
        with self._lock:
            if self._terminal_state.has_terminal_marker(stream_id):
                return
            known_absent = self._peer_open_refused_by_go_away_locked(stream_id)
        if known_absent:
            # A peer stream above our GOAWAY watermark was refused (or never
            # opened): its control frames are ignored, not a session error
            # (DESIGN D6).
            self._inbound_budget.record_ignored_control(now)
            return
        raise ProtocolError(
            "%s on unknown stream %d" % (frame_name, stream_id),
            code=int(ErrorCode.PROTOCOL),
        )

    def _remember_hidden_peer_abort(self, stream_id: int, now: Optional[float] = None) -> None:
        refuse_above_go_away = False
        already_refused = False
        hidden = False
        with self._lock:
            if self._terminal_state.has_terminal_marker(stream_id):
                return
            if stream_is_local(self._local_role, stream_id):
                raise ProtocolError(
                    "peer used locally-owned stream_id %d" % stream_id,
                    code=int(ErrorCode.PROTOCOL),
                )
            bidirectional = stream_is_bidi(stream_id)
            if self._peer_open_refused_locked(stream_id, bidirectional):
                # An ABORT-first open above our GOAWAY watermark is refused
                # like a DATA-first one: the ID is not consumed and the
                # expected-ID cursor does not move (SPEC section 3.1).
                refuse_above_go_away = self._note_go_away_refusal_locked(
                    stream_id,
                    bidirectional,
                )
                already_refused = not refuse_above_go_away
            else:
                self._remember_hidden_peer_abort_locked(stream_id, bidirectional)
                hidden = True
        if hidden:
            # Open-then-ABORT that the application never saw: bounded by the
            # hidden churn budget (IMPLEMENTATION section 7).
            self._inbound_budget.record_hidden_abort_churn(now)
        elif refuse_above_go_away:
            self._send_terminal_abort(stream_id, int(ErrorCode.REFUSED_STREAM))
        elif already_refused:
            # A repeat for an ID already refused changes nothing (DESIGN D6).
            self._inbound_budget.record_ignored_control(now)

    def _remember_hidden_peer_abort_locked(self, stream_id: int, bidirectional: bool) -> None:
        expected = self._next_peer_bidi if bidirectional else self._next_peer_uni
        if expected > MAX_VARINT62:
            raise ProtocolError(
                "peer stream id overflow",
                code=int(ErrorCode.PROTOCOL),
            )
        if stream_id != expected:
            raise ProtocolError(
                "peer stream id skipped expected id",
                code=int(ErrorCode.PROTOCOL),
            )
        if bidirectional:
            self._next_peer_bidi += 4
        else:
            self._next_peer_uni += 4
        # The peer aborted before sending anything: DATA after its own ABORT
        # only gets the repository late-data cap.
        self._remember_terminal_stream_locked(
            stream_id,
            LateDataCause.ABORT,
            hidden=True,
            late_data_cap=self._late_data_per_stream_cap_locked(stream_id) or None,
        )
        self._lock_notify_all()

    def _handle_ext(
        self,
        stream_id: int,
        metadata: Optional[StreamMetadata],
        valid: bool,
        now: Optional[float] = None,
    ) -> None:
        if not valid:
            # A negotiated PRIORITY_UPDATE with an unusable TLV block.
            self._inbound_budget.record_dropped_priority_update()
            return
        if metadata is None:
            return
        no_op = False
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                # Unseen or compacted: ignored, and never creates state.
                return
            if stream.closed:
                # SPEC section 7.6: an update for a terminal stream is ignored.
                no_op = True
            elif stream.opened_locally and not stream._opened_sent:
                # The peer cannot have seen this stream yet.
                return
            else:
                no_op = not stream.apply_metadata_update(metadata)
        if no_op:
            self._inbound_budget.record_no_op_priority_update(now)
        else:
            self._inbound_budget.clear_no_op_priority_update()

    def _handle_max_data(
        self,
        stream_id: int,
        value: Optional[int],
        now: Optional[float] = None,
        payload_len: int = 0,
    ) -> None:
        if value is None:
            return
        updated = False
        wrong_side = None
        with self._lock:
            if stream_id == 0:
                if value > self._send_session_max:
                    self._send_session_max = value
                    updated = True
                    self._lock_notify_all()
            else:
                stream = self._streams.get(stream_id)
                if stream is None:
                    self._check_stream_control_target_locked(stream_id, "MAX_DATA")
                elif stream.closed:
                    pass
                elif not stream._local_send:
                    # MAX_DATA for our receive-only unidirectional stream.
                    wrong_side = stream
                elif value > stream._send_max:
                    stream._send_max = value
                    updated = True
                    self._lock_notify_all()
        if wrong_side is not None:
            self._reject_live_stream(wrong_side, ErrorCode.STREAM_STATE)
            return
        if updated:
            # Raising a limit is flow-control progress, never abuse: it is not
            # charged to the inbound control-rate budgets (DESIGN D3).
            self._inbound_budget.clear_no_op_max_data()
        else:
            self._record_no_op_flow_control(payload_len, now)
            self._inbound_budget.record_no_op_max_data(now)

    def _handle_blocked(
        self,
        stream_id: int,
        blocked_at: Optional[int],
        now: Optional[float] = None,
        payload_len: int = 0,
    ) -> None:
        if blocked_at is None:
            return
        progressed = False
        wrong_side = None
        with self._lock:
            if stream_id == 0:
                progressed = self._note_peer_blocked_locked(None, blocked_at)
                if self._replenish_session_locked(force=True):
                    progressed = True
            else:
                stream = self._streams.get(stream_id)
                if stream is None:
                    self._check_stream_control_target_locked(stream_id, "BLOCKED")
                elif stream.closed:
                    pass
                elif not stream._local_receive:
                    # BLOCKED for our send-only unidirectional stream.
                    wrong_side = stream
                else:
                    progressed = self._note_peer_blocked_locked(stream, blocked_at)
                    if self._replenish_stream_locked(stream, force=True):
                        progressed = True
                    if self._replenish_session_locked(force=True):
                        progressed = True
        if wrong_side is not None:
            self._reject_live_stream(wrong_side, ErrorCode.STREAM_STATE)
            return
        if progressed:
            # A BLOCKED at a new limiting offset, or one that releases credit,
            # is legitimate backpressure (SPEC section 6.6), not no-op control.
            self._inbound_budget.clear_no_op_blocked()
        else:
            self._record_no_op_flow_control(payload_len, now)
            self._inbound_budget.record_no_op_blocked(now)

    def _record_no_op_flow_control(self, payload_len: int, now: Optional[float]) -> None:
        # MAX_DATA/BLOCKED skip the up-front rate charge in record_frame and
        # are charged here only when they did not advance any state.
        self._inbound_budget.record_control(payload_len, now)
        self._inbound_budget.record_mixed(payload_len, now)

    def _note_peer_blocked_locked(
        self, stream: Optional["NativeStream"], blocked_at: int
    ) -> bool:
        """Return whether a peer BLOCKED reports a new limiting offset.

        A sender reports each limit it was given at most once (SPEC section
        6.6).  A repeat, a limit never advertised, or one already superseded
        when the previous BLOCKED for this scope arrived is not progress, so a
        peer cannot replay BLOCKED frames past the no-op budget.
        """

        if stream is None:
            last = self._peer_session_blocked_at
            floor = self._peer_session_blocked_floor
            advertised = self._recv_session_advertised
        else:
            last = stream._peer_blocked_at
            floor = stream._peer_blocked_floor
            advertised = stream._recv_advertised
        if not (last < blocked_at <= advertised and blocked_at >= floor):
            return False
        if stream is None:
            self._peer_session_blocked_at = blocked_at
            self._peer_session_blocked_floor = advertised
        else:
            stream._peer_blocked_at = blocked_at
            stream._peer_blocked_floor = advertised
        return True

    def _check_stream_control_target_locked(self, stream_id: int, frame_name: str) -> None:
        """Validate stream-scoped MAX_DATA/BLOCKED for a stream not in ``_streams``.

        On a used (terminal, compacted) stream they are ignored.  On a stream
        ID that was never opened they would change credit for a stream the
        peer cannot know, so SPEC section 9.1 makes them a session PROTOCOL
        error, except for peer IDs above the local GOAWAY watermark, which are
        known-absent and ignored.
        """

        if self._terminal_state.has_terminal_marker(stream_id):
            return
        bidirectional = stream_is_bidi(stream_id)
        if stream_is_local(self._local_role, stream_id):
            next_id = self._next_bidi if bidirectional else self._next_uni
        else:
            if self._peer_open_refused_locked(stream_id, bidirectional):
                return
            next_id = self._next_peer_bidi if bidirectional else self._next_peer_uni
        if stream_id >= next_id:
            raise ProtocolError(
                "%s on unknown stream %d" % (frame_name, stream_id),
                code=int(ErrorCode.PROTOCOL),
            )

    def _account_peer_data(self, stream: "NativeStream", byte_count: int) -> bool:
        """Charge arriving DATA for a live stream to both receive windows.

        A session-window overrun fails the session with FLOW_CONTROL.  When
        only the stream window is exceeded the bytes are still counted against
        the session and immediately released (they are discarded), and
        ``False`` tells the caller to fail just that stream (SPEC section 8).
        """

        if byte_count <= 0:
            return True
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                byte_count,
            ):
                raise FlowControlError(
                    "session max_data exceeded",
                    code=int(ErrorCode.FLOW_CONTROL),
                )
            self._recv_session_received = _sat_add(self._recv_session_received, byte_count)
            if receive_window_exceeded(
                stream._recv_received,
                stream._recv_advertised,
                byte_count,
            ):
                self._received_data_bytes = _sat_add(self._received_data_bytes, byte_count)
                self._release_discarded_session_credit_locked(byte_count)
                return False
            stream._recv_received = _sat_add(stream._recv_received, byte_count)
            stream._recv_buffered = _sat_add(stream._recv_buffered, byte_count)
            self._recv_session_buffered = _sat_add(self._recv_session_buffered, byte_count)
            return True

    def _abort_stream_for_flow_control(self, stream: "NativeStream") -> None:
        # DATA beyond only the stream window fails just that stream with
        # ABORT(FLOW_CONTROL); the session and its other streams stay usable.
        self._reject_live_stream(
            stream,
            ErrorCode.FLOW_CONTROL,
            local_reason="stream max_data exceeded",
        )

    def _consume_receive(self, stream: "NativeStream", byte_count: int) -> None:
        """Release credit for ``byte_count`` bytes the application read."""

        if byte_count <= 0:
            return
        with self._lock:
            released = min(byte_count, self._recv_session_buffered)
            self._recv_session_buffered -= released
            self._recv_session_pending = _sat_add(self._recv_session_pending, released)
            stream_released = min(byte_count, stream._recv_buffered)
            stream._recv_buffered -= stream_released
            stream._recv_pending = _sat_add(stream._recv_pending, stream_released)
            self._replenish_session_locked()
            self._replenish_stream_locked(stream)

    def _discard_receive(self, stream: Optional["NativeStream"], byte_count: int) -> None:
        """Release credit for buffered bytes dropped without being read.

        The stream no longer accepts data, so only session credit returns,
        immediately, like the late-data discard path.
        """

        if byte_count <= 0:
            return
        with self._lock:
            released = min(byte_count, self._recv_session_buffered)
            self._recv_session_buffered -= released
            if stream is not None:
                stream._recv_buffered -= min(byte_count, stream._recv_buffered)
                stream._recv_pending = 0
            self._release_discarded_session_credit_locked(released)

    def _release_discarded_session_credit_locked(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        desired = min(MAX_VARINT62, _sat_add(self._recv_session_advertised, byte_count))
        if desired > self._recv_session_advertised:
            self._recv_session_advertised = desired
            self._queue_max_data_locked(0, desired)

    def _replenish_for_blocked_reader(self, stream: "NativeStream") -> None:
        """Force a grant for a reader about to wait with no credit outstanding.

        Credit normally comes back only as data is consumed, so a scope whose
        initial window is zero would never get any.  A blocking read or an
        accept with zero remaining credit forces the standing grant (DESIGN
        D7).  Stream credit is only forced for peer-opened streams: for a local
        stream the peer may not have seen the opener yet, and its BLOCKED
        triggers the grant instead.
        """

        if stream is None or not stream._local_receive:
            return
        with self._lock:
            if self._streams.get(stream.stream_id) is not stream:
                return
            if not stream.opened_locally and not window_remaining(
                stream._recv_advertised,
                stream._recv_received,
            ):
                self._replenish_stream_locked(stream, force=True)
            if not window_remaining(
                self._recv_session_advertised,
                self._recv_session_received,
            ):
                self._replenish_session_locked(force=True)

    def _replenish_session_locked(self, *, force: bool = False) -> bool:
        """Re-advertise released session credit; return whether MAX_DATA was queued."""

        if self._state.terminal():
            return False
        advertised = self._recv_session_advertised
        received = self._recv_session_received
        pending = self._recv_session_pending
        target = self._session_window_target_locked()
        payload = self._receive_frame_payload_locked()
        if not should_replenish_pending_window(
            window_remaining(advertised, received),
            target,
            advertised,
            pending,
            session_emergency_threshold(payload),
            replenish_min_pending(target, payload),
            force=force,
        ):
            return False
        desired = next_credit_limit(
            advertised,
            pending,
            received,
            target,
            standing_growth_allowed(
                self._memory_pressure_high_locked(),
                self._recv_session_buffered,
                pending,
                self._runtime_policy.session_queued_data_hwm,
            ),
        )
        self._recv_session_pending = 0
        if desired <= advertised:
            return False
        self._recv_session_advertised = desired
        self._queue_max_data_locked(0, desired)
        return True

    def _replenish_stream_locked(
        self, stream: "NativeStream", *, force: bool = False
    ) -> bool:
        """Re-advertise released stream credit; return whether MAX_DATA was queued."""

        if not self._stream_accepts_peer_data_locked(stream):
            # STOP_SENDING, FIN, RESET or ABORT: the peer sends no more DATA,
            # so released bytes only return session credit.
            stream._recv_pending = 0
            return False
        advertised = stream._recv_advertised
        received = stream._recv_received
        pending = stream._recv_pending
        target = self._stream_window_target_locked(stream)
        payload = self._receive_frame_payload_locked()
        if not should_replenish_pending_window(
            window_remaining(advertised, received),
            target,
            advertised,
            pending,
            stream_emergency_threshold(target, payload),
            replenish_min_pending(target, payload),
            force=force,
        ):
            return False
        desired = next_credit_limit(
            advertised,
            pending,
            received,
            target,
            standing_growth_allowed(
                self._memory_pressure_high_locked(),
                stream._recv_buffered,
                pending,
                self._runtime_policy.per_stream_queued_data_hwm,
            ),
        )
        stream._recv_pending = 0
        if desired <= advertised:
            return False
        stream._recv_advertised = desired
        self._queue_max_data_locked(stream.stream_id, desired)
        return True

    def _stream_accepts_peer_data_locked(self, stream: "NativeStream") -> bool:
        return (
            stream._local_receive
            and not stream._read_closed
            and not stream._read_finished
            and stream._read_error is None
            and not self._state.terminal()
            and self._streams.get(stream.stream_id) is stream
        )

    def _queue_max_data_locked(self, stream_id: int, value: int) -> None:
        # Queued under the session lock so concurrent releases can never put a
        # smaller limit on the wire after a larger one (the writer coalesces
        # per scope).  Never raises: a closing session simply drops it.
        self._queue_frame(
            Frame(FrameType.MAX_DATA, stream_id, 0, encode_varint(value)),
            from_reader=True,
        )

    def _session_window_target_locked(self) -> int:
        return session_window_target(
            self._local_preface.settings,
            self._runtime_policy.session_queued_data_hwm,
        )

    def _stream_window_target_locked(self, stream: "NativeStream") -> int:
        return stream_window_target(
            self._initial_receive_credit_for_stream(stream),
            self._runtime_policy.per_stream_queued_data_hwm,
        )

    def _receive_frame_payload_locked(self) -> int:
        return negotiated_frame_payload(
            self._local_preface.settings,
            self._peer_preface.settings,
        )

    def _tracked_session_memory_locked(self) -> int:
        # Unread receive buffers plus DATA queued for the writer.
        return _sat_add(self._recv_session_buffered, self._queued_data_bytes)

    def _session_memory_hard_cap_locked(self) -> int:
        return session_memory_hard_cap(self._local_preface.settings, self._runtime_policy)

    def _memory_pressure_high_locked(self) -> bool:
        return self._tracked_session_memory_locked() >= session_memory_high_threshold(
            self._session_memory_hard_cap_locked()
        )

    def _note_sent_max_data_frame_locked(self, frame: Frame) -> None:
        try:
            value, consumed = parse_varint(frame.payload)
        except Exception:
            return
        if consumed != len(frame.payload):
            return
        if frame.stream_id == 0:
            self._recv_session_advertised = max(self._recv_session_advertised, value)
            return
        stream = self._streams.get(frame.stream_id)
        if stream is not None:
            stream._recv_advertised = max(stream._recv_advertised, value)

    def _reserve_send_credit(
        self,
        stream: "NativeStream",
        byte_count: int,
        timeout_deadline: Optional[float],
    ) -> int:
        if byte_count <= 0:
            return 0
        while True:
            blocked = []
            with self._lock:
                self._check_open_locked(ErrorOperation.WRITE)
                stream._check_writable()
                hwm = self._runtime_policy.session_queued_data_hwm
                if hwm and self._queued_data_bytes >= hwm:
                    # Bound memory held by DATA frames left queued behind a
                    # stalled transport (e.g. after earlier write timeouts).
                    deadline = _merge_deadline(
                        stream._write_deadline,
                        timeout_deadline,
                    )
                    remaining = _remaining(deadline)
                    if remaining == 0:
                        raise WriteTimeout()
                    self._lock_wait(remaining)
                    continue
                chunk = self._take_send_credit_locked(stream, byte_count)
                if chunk > 0:
                    return chunk
                session_credit = max(0, self._send_session_max - self._send_session_used)
                stream_credit = max(0, stream._send_max - stream._send_sent)
                # One BLOCKED per scope and limiting offset (SPEC section 6.6).
                # Stream BLOCKED may never precede the stream's opener (SPEC
                # section 9.1); _send_data_vectored emits a zero-length opener
                # first when the stream starts without credit.
                if session_credit == 0 and self._session_blocked_sent_at != self._send_session_max:
                    blocked.append((0, self._send_session_max))
                    self._session_blocked_sent_at = self._send_session_max
                if (
                    stream_credit == 0
                    and stream._opened_sent
                    and stream._blocked_sent_at != stream._send_max
                ):
                    blocked.append((stream.stream_id, stream._send_max))
                    stream._blocked_sent_at = stream._send_max
                if not blocked:
                    deadline = _merge_deadline(
                        stream._write_deadline,
                        timeout_deadline,
                    )
                    remaining = _remaining(deadline)
                    if remaining == 0:
                        raise WriteTimeout()
                    self._lock_wait(remaining)
                    continue
            for blocked_stream_id, limit in blocked:
                # Advisory only: queue it and keep waiting for credit.
                self._queue_frame(
                    Frame(FrameType.BLOCKED, blocked_stream_id, 0, encode_varint(limit))
                )

    def _take_send_credit_locked(self, stream: "NativeStream", byte_count: int) -> int:
        """Reserve up to ``byte_count`` bytes of send credit without waiting.

        Returns 0 when either window is exhausted or the queued-DATA high-water
        mark is reached; the caller then waits (``_reserve_send_credit``) or,
        for an opener, sends a zero-length opening DATA.
        """

        if byte_count <= 0:
            return 0
        hwm = self._runtime_policy.session_queued_data_hwm
        if hwm and self._queued_data_bytes >= hwm:
            return 0
        chunk = min(
            byte_count,
            max(0, self._send_session_max - self._send_session_used),
            max(0, stream._send_max - stream._send_sent),
        )
        if chunk > 0:
            self._send_session_used = _sat_add(self._send_session_used, chunk)
            stream._send_sent = _sat_add(stream._send_sent, chunk)
        return chunk

    def _refund_send_credit(self, stream: "NativeStream", byte_count: int) -> None:
        """Return credit reserved for DATA that was never queued.

        A write whose stream was reset or aborted between reserving credit and
        framing the bytes drops them; the peer never counts them, so neither
        may the local send windows.
        """

        if byte_count <= 0:
            return
        with self._lock:
            self._send_session_used = max(0, self._send_session_used - byte_count)
            stream._send_sent = max(0, stream._send_sent - byte_count)
            self._lock_notify_all()

    def _notify_stream_state_changed(self) -> None:
        with self._lock:
            self._lock_notify_all()
        self._notify_writers()

    def _initial_receive_credit_for_stream(self, stream: "NativeStream") -> int:
        return _initial_stream_receive_window(
            self,
            stream.opened_locally,
            stream.bidirectional,
            True,
        )

    def _finish(
        self,
        error: Optional[BaseException],
        *,
        failed: bool,
        close_transport: bool,
    ) -> None:
        """Terminate without emitting CLOSE (peer CLOSE or transport failure)."""

        self._terminate(error, failed=failed, close_transport=close_transport)

    def _fail_session(self, error: BaseException) -> None:
        """Fail the session for a locally detected fatal error.

        The error is signalled with a best-effort, bounded ``CLOSE(code)``
        before the transport is closed (SPEC section 10.2), unless it is a
        transport failure or the peer already closed the session.
        """

        if isinstance(error, ProtocolError) and error.code is None:
            # Bare protocol exceptions carry no code.  Give the local error the
            # code its CLOSE reports, so close_error, wait() and the peer agree.
            error.code = _uncoded_close_code(error)
        self._terminate(error, failed=True, close_for_error=True)

    def _terminate(
        self,
        error: Optional[BaseException],
        *,
        failed: bool,
        close_payload: Optional[bytes] = None,
        close_for_error: bool = False,
        close_transport: bool = True,
    ) -> bool:
        """Commit terminal state, then emit CLOSE (bounded) and close the transport.

        Only the first caller owns termination and returns ``True``.  Terminal
        state is visible and blocked operations are woken before any transport
        I/O; ``closed`` becomes true only after the transport was released.
        """

        with self._lock:
            if self._state.terminal():
                return False
            self._state = SessionState.FAILED if failed else SessionState.CLOSED
            self._close_error = error
            streams = list(self._streams.values())
            streams.extend(self._provisional_bidi)
            streams.extend(self._provisional_uni)
            self._streams.clear()
            self._live_late_data_retained = 0
            self._accept_bidi.clear()
            self._accept_uni.clear()
            self._provisional_bidi.clear()
            self._provisional_uni.clear()
            pending_pings = list(self._pings.values())
            self._pings.clear()
            if close_for_error:
                close_payload = self._fatal_close_payload_locked(error)
            self._lock_notify_all()
        visible_error = error or SessionClosed(
            operation=ErrorOperation.WRITE,
            source=ErrorSource.LOCAL,
        )
        try:
            for stream in streams:
                stream.session_closed(error)
            for pending in pending_pings:
                if pending.error_holder is not None and pending.error_holder[0] is None:
                    pending.error_holder[0] = error or SessionClosed(
                        operation=ErrorOperation.PING,
                        source=ErrorSource.LOCAL,
                    )
                pending.done.set()
            close_sent = self._shutdown_writer(close_payload, visible_error)
            if close_sent:
                delay = _close_transport_drain_delay(error)
                if delay > 0:
                    time.sleep(delay)
        finally:
            if close_transport:
                _best_effort_abort(self._io)
            with self._write_cond:
                # A writer stuck in a transport write is released by the
                # transport close above; complete its requests anyway so no
                # caller waits on a transport that ignores close.
                self._complete_requests_locked(self._inflight_writes, visible_error)
                self._writer_closed = True
                self._writer_stop = True
                self._write_cond.notify_all()
            self._closed_event.set()
        self._emit_event(
            Event(
                EventType.SESSION_CLOSED,
                session_state=self._state,
                error=error,
            )
        )
        return True

    def _fatal_close_payload_locked(
        self,
        error: Optional[BaseException],
    ) -> Optional[bytes]:
        if error is None:
            return None
        if isinstance(error, (TransportError, SessionClosed)):
            return None
        if self._peer_close_error is not None:
            return None
        try:
            return build_close_payload(error, self._peer_limits.max_control_payload_bytes)
        except BaseException:
            return None

    def _check_open(self, operation: ErrorOperation) -> None:
        with self._lock:
            self._check_open_locked(operation)

    def _check_open_locked(self, operation: ErrorOperation) -> None:
        if self._state.terminal():
            raise self._visible_closed_error(operation)

    def _ignore_peer_non_close_frame_locked(self) -> bool:
        return ignore_peer_non_close_frame(self._state, self._close_error is not None)

    def _check_local_open_allowed_locked(self) -> None:
        """Refuse new local opens once the session is closing.

        A local graceful close stops admitting local streams immediately
        (SPEC section 10.1 step 1, API_SEMANTICS section 8.1); a peer GOAWAY
        alone does not.
        """

        outcome = plan_local_open(
            self._state,
            self._graceful_close_active,
            self._close_error is not None,
        )
        if outcome is LocalOpenOutcome.RETURN_EXISTING:
            raise self._visible_closed_error(ErrorOperation.OPEN)
        if outcome is LocalOpenOutcome.RETURN_CLOSED:
            raise SessionClosed(operation=ErrorOperation.OPEN, source=ErrorSource.LOCAL)

    def _note_local_ids_exhausted_locked(self) -> None:
        """Begin graceful replacement once a local stream-ID class runs out.

        IDs are never wrapped or reused (SPEC section 3.1).  The first
        exhaustion queues one GOAWAY that keeps the current watermarks, so the
        peer learns the session is draining without any of its streams being
        refused; opens of the other class keep working.
        """

        if self._local_ids_exhausted or self._state.terminal():
            return
        self._local_ids_exhausted = True
        bidi = self._effective_go_away_send_watermark_locked(True)
        uni = self._effective_go_away_send_watermark_locked(False)
        payload = build_go_away_payload(
            bidi,
            uni,
            int(ErrorCode.NO_ERROR),
            "",
            self._peer_limits.max_control_payload_bytes,
        )
        self._local_go_away_bidi = bidi
        self._local_go_away_uni = uni
        if self._state is SessionState.READY:
            self._state = SessionState.DRAINING
        self._queue_frame(Frame(FrameType.GOAWAY, 0, 0, payload), from_reader=True)
        self._lock_notify_all()

    def _visible_closed_error(self, operation: ErrorOperation) -> BaseException:
        if self._close_error is not None:
            return self._close_error
        return SessionClosed(operation=operation, source=ErrorSource.LOCAL)

    def _active_stream_stats_locked(self) -> ActiveStreamStats:
        local_bidi = local_uni = peer_bidi = peer_uni = 0
        for stream in self._streams.values():
            if stream.closed:
                continue
            if stream.opened_locally and stream.bidirectional:
                local_bidi += 1
            elif stream.opened_locally:
                local_uni += 1
            elif stream.bidirectional:
                peer_bidi += 1
            else:
                peer_uni += 1
        return ActiveStreamStats(local_bidi, local_uni, peer_bidi, peer_uni)

    def _has_graceful_close_pending_work_locked(self) -> bool:
        """Whether a graceful close still has local work to drain.

        Provisional opens count until ``close`` reclaims them.  Streams block
        only while they have local send work outstanding (see
        ``NativeStream._blocks_graceful_close_locked``); the accept backlog and
        unread inbound bytes never delay the close (API_SEMANTICS section 8.1).
        """

        if self._provisional_bidi or self._provisional_uni:
            return True
        with self._write_cond:
            queued = frozenset(self._queued_data_by_stream)
        return any(
            stream._blocks_graceful_close_locked(stream_id in queued)
            for stream_id, stream in self._streams.items()
        )

    def _reclaim_graceful_close_local_streams(self) -> None:
        """Refuse local opens the peer has not seen before the drain wait.

        Provisional streams have no ID yet, so they fail locally with
        REFUSED_STREAM and nothing goes on the wire (IMPLEMENTATION section 8
        step 5).  Committed streams always have their opener queued in ID
        order, so they are peer-visible and drain normally.
        """

        with self._lock:
            if self._state.terminal():
                return
            for queue in (self._provisional_bidi, self._provisional_uni):
                while queue:
                    self._fail_provisional_locked(
                        queue.pop(),
                        ApplicationError(
                            int(ErrorCode.REFUSED_STREAM),
                            "",
                            scope=ErrorScope.STREAM,
                            operation=ErrorOperation.OPEN,
                            source=ErrorSource.LOCAL,
                            direction=ErrorDirection.BOTH,
                            termination_kind=TerminationKind.ABORT,
                        ),
                    )
            self._lock_notify_all()

    def _provisional_queue_locked(self, bidirectional: bool) -> Deque["NativeStream"]:
        return self._provisional_bidi if bidirectional else self._provisional_uni

    def _fail_provisional_locked(
        self, stream: "NativeStream", error: BaseException
    ) -> None:
        stream._provisional_created_at = None
        with stream._cond:
            stream._read_finished = True
            stream._read_closed = True
            stream._write_closed = True
            stream._closed = True
            stream._read_error = error
            stream._write_error = error
            stream._cond.notify_all()
        self._lock_notify_all()

    def _abort_provisional_open(
        self, stream: "NativeStream", error: BaseException
    ) -> bool:
        with self._lock:
            if (
                stream is None
                or stream._opened_sent
                or stream._stream_id != 0
                or not stream.opened_locally
            ):
                return False
            queue = self._provisional_queue_locked(stream.bidirectional)
            try:
                queue.remove(stream)
            except ValueError:
                return False
            self._fail_provisional_locked(stream, error)
            return True

    def _reap_expired_provisionals_locked(
        self, bidirectional: bool, now: float
    ) -> None:
        queue = self._provisional_queue_locked(bidirectional)
        max_age = provisional_open_max_age(self._last_ping_rtt)
        while queue:
            stream = queue[0]
            created = stream._provisional_created_at
            if (
                created is None
                or max_age <= 0
                # Only idle provisional time counts: a stream waiting for its
                # commit turn does not age.
                or stream._provisional_commit_waiters
                or now - created <= max_age
            ):
                return
            queue.popleft()
            self._provisional_expired = _sat_add(self._provisional_expired, 1)
            self._fail_provisional_locked(stream, OpenExpired())

    @staticmethod
    def _begin_provisional_commit_wait_locked(stream: "NativeStream") -> None:
        if stream._provisional_commit_waiters == 0:
            stream._provisional_commit_wait_started = time.monotonic()
        stream._provisional_commit_waiters += 1

    @staticmethod
    def _end_provisional_commit_wait_locked(stream: "NativeStream") -> None:
        if stream._provisional_commit_waiters == 0:
            return
        stream._provisional_commit_waiters -= 1
        if stream._provisional_commit_waiters:
            return
        waited = max(0.0, time.monotonic() - stream._provisional_commit_wait_started)
        if stream._provisional_created_at is not None:
            stream._provisional_created_at += waited

    def _reclaim_provisionals_locked(
        self, bidirectional: bool, peer_watermark: int
    ) -> None:
        """Fail the provisionals a peer GOAWAY watermark leaves no ID for.

        Newest first, each fails locally with REFUSED_STREAM (recorded as an
        abort reason); nothing goes on the wire because none has an ID yet.
        """

        queue = self._provisional_queue_locked(bidirectional)
        next_id = self._next_bidi if bidirectional else self._next_uni
        available = provisional_available_count(next_id, peer_watermark)
        while len(queue) > available:
            stream = queue.pop()
            error = ApplicationError(
                int(ErrorCode.REFUSED_STREAM),
                "",
                scope=ErrorScope.STREAM,
                operation=ErrorOperation.OPEN,
                source=ErrorSource.REMOTE,
                direction=ErrorDirection.BOTH,
                termination_kind=TerminationKind.ABORT,
            )
            self._note_reason(self._abort_reasons, error.code, "_abort_overflow")
            self._fail_provisional_locked(stream, error)

    def _commit_local_open(
        self,
        stream: "NativeStream",
        timeout_deadline: Optional[float],
        queue_opener: Callable[[], _T],
    ) -> Optional[_T]:
        """Assign ``stream`` its ID and queue its opener in one critical section.

        Streams of a class commit in provisional (FIFO) order, and
        ``queue_opener`` runs under the session lock right after the ID is
        assigned, before the next stream of the class can commit.  It must
        not block; it only takes the stream's and the writer's locks.  The
        writer's data lane is FIFO, so openers reach the wire in ID order and
        every committed ID is consumed (SPEC section 3.1, DESIGN D5).
        Returns ``queue_opener``'s result, or ``None`` if the stream was
        already committed.
        """

        bidirectional = stream.bidirectional
        with self._lock:
            while True:
                if stream._opened_sent or self._streams.get(stream._stream_id) is stream:
                    return None
                # A provisional failed while waiting (reclaimed, expired,
                # refused) reports that outcome even if the session ended.
                if stream._write_error is not None:
                    raise stream._write_error
                self._check_open_locked(ErrorOperation.WRITE)
                queue = self._provisional_queue_locked(bidirectional)
                self._reap_expired_provisionals_locked(bidirectional, time.monotonic())
                if stream._write_error is not None:
                    raise stream._write_error
                if stream not in queue:
                    raise SessionClosed(
                        operation=ErrorOperation.WRITE,
                        source=ErrorSource.LOCAL,
                    )
                if queue[0] is not stream:
                    deadline = _merge_deadline(
                        stream._write_deadline,
                        timeout_deadline,
                    )
                    remaining = _remaining(deadline)
                    if remaining == 0:
                        raise WriteTimeout()
                    wait_for = remaining
                    head = queue[0]
                    # A head that is itself waiting for its commit turn does
                    # not age; it commits (and notifies) as soon as it can.
                    head_created = (
                        None
                        if head._provisional_commit_waiters
                        else head._provisional_created_at
                    )
                    if head_created is not None:
                        expires_in = (
                            head_created
                            + provisional_open_max_age(self._last_ping_rtt)
                            - time.monotonic()
                        )
                        if expires_in <= 0:
                            wait_for = 0.0
                        elif wait_for is None:
                            wait_for = expires_in
                        else:
                            wait_for = min(wait_for, expires_in)
                    self._begin_provisional_commit_wait_locked(stream)
                    try:
                        self._lock_wait(wait_for)
                    finally:
                        self._end_provisional_commit_wait_locked(stream)
                    continue

                stream_id = self._next_bidi if bidirectional else self._next_uni
                if stream_id > MAX_VARINT62:
                    queue.popleft()
                    error = OpenLimited(_LOCAL_STREAM_IDS_EXHAUSTED_MESSAGE)
                    self._fail_provisional_locked(stream, error)
                    self._note_local_ids_exhausted_locked()
                    raise error
                peer_go_away = (
                    self._peer_go_away_bidi if bidirectional else self._peer_go_away_uni
                )
                if stream_id > (MAX_VARINT62 if peer_go_away is None else peer_go_away):
                    queue.popleft()
                    error = ApplicationError(
                        int(ErrorCode.REFUSED_STREAM),
                        "",
                        scope=ErrorScope.STREAM,
                        operation=ErrorOperation.OPEN,
                        source=ErrorSource.REMOTE,
                        direction=ErrorDirection.BOTH,
                        termination_kind=TerminationKind.ABORT,
                    )
                    self._fail_provisional_locked(stream, error)
                    raise error
                limit = (
                    self._peer_preface.settings.max_incoming_streams_bidi
                    if bidirectional
                    else self._peer_preface.settings.max_incoming_streams_uni
                )
                active = sum(
                    1
                    for existing in self._streams.values()
                    if (
                        existing.opened_locally
                        and existing.bidirectional == bidirectional
                        and not existing.closed
                    )
                )
                if active >= limit:
                    queue.popleft()
                    error = ApplicationError(
                        int(ErrorCode.REFUSED_STREAM),
                        "peer incoming stream limit reached",
                        scope=ErrorScope.SESSION,
                        operation=ErrorOperation.OPEN,
                        source=ErrorSource.REMOTE,
                        direction=ErrorDirection.BOTH,
                        termination_kind=TerminationKind.ABORT,
                    )
                    self._fail_provisional_locked(stream, error)
                    raise error

                queue.popleft()
                stream._stream_id = stream_id
                stream._send_max = initial_local_opened_send_window(
                    self._peer_preface.settings,
                    bidirectional,
                )
                stream._provisional_created_at = None
                self._streams[stream_id] = stream
                if bidirectional:
                    self._next_bidi += 4
                else:
                    self._next_uni += 4
                self._open_streams = _sat_add(self._open_streams, 1)
                try:
                    return queue_opener()
                finally:
                    self._lock_notify_all()

    def _effective_go_away_send_watermark_locked(self, bidirectional: bool) -> int:
        configured = self._local_go_away_bidi if bidirectional else self._local_go_away_uni
        if configured != MAX_VARINT62:
            return configured
        arity = StreamArity.BIDI if bidirectional else StreamArity.UNI
        return max_peer_go_away_watermark(self._local_role, arity)

    def _forget_stream(self, stream: "NativeStream") -> None:
        if stream is None or not stream.closed:
            return
        with self._lock:
            if self._streams.get(stream.stream_id) is not stream:
                return
            for queue in (self._accept_bidi, self._accept_uni):
                if stream in queue:
                    return
            self._retire_stream_locked(
                stream,
                stream.terminal_late_data_cause(),
                action=stream.terminal_late_data_action(),
                late_data_cap=stream.terminal_late_data_cap(),
            )
            self._accept_visibility.pop(stream.stream_id, None)
            self._lock_notify_all()

    def _accept_backlog_bytes_locked(self) -> int:
        total = 0
        for queue in (self._accept_bidi, self._accept_uni):
            for stream in queue:
                total = _sat_add(total, stream._read_buffered)
        return total

    def _accept_backlog_open_info_bytes_locked(self) -> int:
        total = 0
        for queue in (self._accept_bidi, self._accept_uni):
            for stream in queue:
                total = _sat_add(total, stream.open_info_len)
        return total

    def _enforce_accept_backlog_locked(self) -> Tuple["NativeStream", ...]:
        refused = []
        while self._accept_backlog_over_limit_locked():
            stream = self._poll_newest_accepted_locked()
            if stream is None:
                break
            self._visible_accept_refused = _sat_add(self._visible_accept_refused, 1)
            self._retire_stream_locked(
                stream,
                LateDataCause.ABORT,
                late_data_cap=self._late_data_allowance_locked(stream, stopped_locally=True)
                or None,
            )
            refused.append(stream)
        return tuple(refused)

    def _accept_backlog_over_limit_locked(self) -> bool:
        policy = self._runtime_policy
        count = len(self._accept_bidi) + len(self._accept_uni)
        if policy.accept_backlog_limit and count > policy.accept_backlog_limit:
            return True
        if (
            policy.accept_backlog_bytes_limit
            and self._accept_backlog_bytes_locked() > policy.accept_backlog_bytes_limit
        ):
            return True
        if (
            policy.retained_open_info_bytes_budget
            and self._accept_backlog_open_info_bytes_locked()
            > policy.retained_open_info_bytes_budget
        ):
            return True
        cap = self._config.session_memory_cap
        return bool(cap and self._accept_backlog_bytes_locked() > cap)

    def _peer_open_refused_locked(self, stream_id: int, bidirectional: bool) -> bool:
        watermark = self._local_go_away_bidi if bidirectional else self._local_go_away_uni
        return stream_id > watermark

    def _peer_open_refused_by_go_away_locked(self, stream_id: int) -> bool:
        return not stream_is_local(self._local_role, stream_id) and self._peer_open_refused_locked(
            stream_id,
            stream_is_bidi(stream_id),
        )

    def _note_go_away_refusal_locked(self, stream_id: int, bidirectional: bool) -> bool:
        """Record a peer open refused by our GOAWAY; return whether to send ABORT.

        Watermarks never increase, so refusals are monotonic: only an ID above
        the highest one already refused in its class gets ABORT(REFUSED_STREAM),
        which therefore goes out at most once per ID (DESIGN D6).
        """

        if bidirectional:
            if stream_id <= self._go_away_refused_peer_bidi:
                return False
            self._go_away_refused_peer_bidi = stream_id
        else:
            if stream_id <= self._go_away_refused_peer_uni:
                return False
            self._go_away_refused_peer_uni = stream_id
        return True

    def _peer_stream_within_limit_locked(self, bidirectional: bool) -> bool:
        limit = (
            self._local_preface.settings.max_incoming_streams_bidi
            if bidirectional
            else self._local_preface.settings.max_incoming_streams_uni
        )
        # A stream stops being active once it is fully terminal, even while it
        # still waits in the accept queue (SPEC section 2.5).
        active = 0
        for stream in self._streams.values():
            if (
                not stream.opened_locally
                and stream.bidirectional == bidirectional
                and not stream.closed
            ):
                active += 1
        return active < limit

    def _poll_newest_accepted_locked(self) -> Optional["NativeStream"]:
        newest_bidi = self._accept_bidi[-1] if self._accept_bidi else None
        newest_uni = self._accept_uni[-1] if self._accept_uni else None
        if newest_bidi is None and newest_uni is None:
            return None
        if newest_uni is None:
            return self._pop_accepted_tail_locked(self._accept_bidi)
        if newest_bidi is None:
            return self._pop_accepted_tail_locked(self._accept_uni)
        bidi_sequence = self._accept_visibility.get(newest_bidi.stream_id, 0)
        uni_sequence = self._accept_visibility.get(newest_uni.stream_id, 0)
        if bidi_sequence > uni_sequence:
            return self._pop_accepted_tail_locked(self._accept_bidi)
        return self._pop_accepted_tail_locked(self._accept_uni)

    def _pop_accepted_tail_locked(
        self, queue: Deque["NativeStream"]
    ) -> Optional["NativeStream"]:
        if not queue:
            return None
        stream = queue.pop()
        self._accept_visibility.pop(stream.stream_id, None)
        return stream

    def _send_refused_stream_abort(self, stream: "NativeStream") -> None:
        error = ApplicationError(
            int(ErrorCode.REFUSED_STREAM),
            "",
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.CLOSE,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.ABORT,
        )
        stream.abort(error)
        self._queue_frame(
            Frame(
                FrameType.ABORT,
                stream.stream_id,
                0,
                build_error_payload(
                    int(ErrorCode.REFUSED_STREAM),
                    "",
                    self._peer_limits.max_control_payload_bytes,
                ),
            ),
            from_reader=True,
            droppable=True,
        )

    def _retire_stream_locked(
        self,
        stream: "NativeStream",
        cause: LateDataCause,
        *,
        action: LateDataAction = LateDataAction.IGNORE,
        late_data_cap: Optional[int] = None,
    ) -> None:
        """Compact a stream leaving ``_streams`` into its tombstone.

        Its counted late bytes move from the live accounting into the
        tombstone, so its allowance still covers both and the aggregate keeps
        them until the tombstone is reaped (DESIGN D2).
        """

        late = stream._late_data_received
        stream._late_data_received = 0
        self._live_late_data_retained = max(0, self._live_late_data_retained - late)
        self._remember_terminal_stream_locked(
            stream.stream_id,
            cause,
            action=action,
            late_data_cap=late_data_cap,
            late_data_received=late,
        )
        self._streams.pop(stream.stream_id, None)

    def _remember_terminal_stream_locked(
        self,
        stream_id: int,
        cause: LateDataCause = LateDataCause.NONE,
        *,
        action: LateDataAction = LateDataAction.IGNORE,
        hidden: bool = False,
        late_data_cap: Optional[int] = None,
        late_data_received: int = 0,
    ) -> None:
        self._terminal_state.record_tombstone(
            stream_id,
            StreamTombstoneRecord(
                tombstone=StreamTombstone(
                    data_action=action,
                    terminal_kind=TerminalKind.UNKNOWN,
                ),
                hidden=hidden,
                late_data_cause=cause,
                late_data_cap=late_data_cap,
                late_data_received=late_data_received,
            ),
            enforce=True,
        )
        if self._config.tombstone_limit == 0:
            marker_limit = self._config.marker_only_used_stream_limit
            limit = self._config.used_marker_limit if marker_limit is None else marker_limit
        else:
            limit = self._config.tombstone_limit
        limit = max(0, limit)
        if limit == 0:
            return
        if stream_id in self._terminal_streams:
            self._terminal_stream_causes[stream_id] = cause
            return
        self._terminal_streams.add(stream_id)
        self._terminal_stream_causes[stream_id] = cause
        self._terminal_stream_order.append(stream_id)
        while len(self._terminal_stream_order) > limit:
            old = self._terminal_stream_order.popleft()
            self._terminal_streams.discard(old)
            self._terminal_stream_causes.pop(old, None)

    def _keepalive_interval_locked(self) -> float:
        interval = self._config.keepalive_interval
        return 0.0 if interval is None else float(interval)

    def _keepalive_max_ping_interval_locked(self) -> float:
        interval = self._config.keepalive_max_ping_interval
        return 0.0 if interval is None else float(interval)

    def _effective_keepalive_timeout_locked(self) -> float:
        configured = self._config.keepalive_timeout or 0.0
        return effective_keepalive_timeout(
            self._keepalive_interval_locked(),
            configured,
            self._last_ping_rtt,
        )

    def _reset_keepalive_schedules_locked(self, now: float) -> None:
        self._reset_read_idle_ping_due_locked(now)
        self._reset_write_idle_ping_due_locked(now)
        self._reset_max_ping_due_locked(now)

    def _reset_read_idle_ping_due_locked(self, now: float) -> None:
        interval = self._keepalive_interval_locked()
        if interval <= 0:
            self._read_idle_ping_due_at = None
            return
        self._read_idle_ping_due_at = now + keepalive_lead_jittered_delay(
            interval,
            self._ping_state,
        )

    def _reset_write_idle_ping_due_locked(self, now: float) -> None:
        interval = self._keepalive_interval_locked()
        if interval <= 0:
            self._write_idle_ping_due_at = None
            return
        self._write_idle_ping_due_at = now + keepalive_lead_jittered_delay(
            interval,
            self._ping_state,
        )

    def _reset_max_ping_due_locked(self, now: float) -> None:
        interval = self._keepalive_max_ping_interval_locked()
        if self._keepalive_interval_locked() <= 0 or interval <= 0:
            self._max_ping_due_at = None
            return
        self._max_ping_due_at = now + keepalive_lead_jittered_delay(
            interval,
            self._ping_state,
        )

    def _ensure_keepalive_schedules_locked(self, now: float) -> None:
        if self._keepalive_interval_locked() <= 0:
            self._read_idle_ping_due_at = None
            self._write_idle_ping_due_at = None
            self._max_ping_due_at = None
            return
        if self._read_idle_ping_due_at is None:
            self._reset_read_idle_ping_due_locked(self._last_inbound_frame_at or now)
        if self._write_idle_ping_due_at is None:
            self._reset_write_idle_ping_due_locked(self._last_transport_write_at or now)
        if self._max_ping_due_at is None:
            self._reset_max_ping_due_locked(now)

    def _next_keepalive_action_locked(self, now: float) -> Tuple[float, bool, bool]:
        interval = self._keepalive_interval_locked()
        if self._state.terminal() or interval <= 0:
            return 0.0, False, False
        if self._pings:
            timeout = self._effective_keepalive_timeout_locked()
            oldest = min(pending.started_at for pending in self._pings.values())
            elapsed = max(0.0, now - oldest)
            if timeout > 0 and elapsed > timeout:
                return 0.0, False, True
            delay = timeout - elapsed if timeout > 0 else interval
            return max(delay, 0.0), False, False
        self._ensure_keepalive_schedules_locked(now)
        due_values = [
            due
            for due in (
                self._read_idle_ping_due_at,
                self._write_idle_ping_due_at,
                self._max_ping_due_at,
            )
            if due is not None
        ]
        if not due_values:
            return interval, False, False
        next_due = min(due_values)
        if next_due <= now:
            return 0.0, True, False
        return next_due - now, False, False

    def _wait_keepalive_delay(self, delay: float) -> bool:
        with self._lock:
            if self._state.terminal():
                return True
            self._lock_wait(max(delay, 0.001))
            return self._state.terminal()

    def _keepalive_loop(self) -> None:
        # The keepalive PING is only queued, never awaited, so this loop keeps
        # evaluating the outstanding-PING deadline even while a transport write
        # is stalled (IMPLEMENTATION section 4).
        while True:
            with self._lock:
                delay, send_ping, timed_out = self._next_keepalive_action_locked(
                    time.monotonic()
                )
                if self._state.terminal() or self._keepalive_interval_locked() <= 0:
                    return
            if timed_out:
                self._fail_session(KeepaliveTimeout())
                return
            if send_ping:
                try:
                    self._start_keepalive_ping()
                except BaseException as exc:
                    if self._state.terminal():
                        return
                    self._fail_session(exc)
                    return
                continue
            if self._wait_keepalive_delay(delay):
                return

    def _start_keepalive_ping(self) -> None:
        registered = self._register_ping(b"", wait=False)
        if registered is None:
            # A user PING took the slot first; it is the outstanding PING now.
            return
        payload, _ = registered
        try:
            self._queue_frame(Frame(FrameType.PING, 0, 0, payload))
        except BaseException:
            with self._lock:
                self._pings.pop(payload, None)
                self._lock_notify_all()
            raise

    def _note_reason(self, bucket: dict[int, int], code: int, overflow_attr: str) -> None:
        with self._lock:
            if len(bucket) < 64 or code in bucket:
                bucket[code] = _sat_add(bucket.get(code, 0), 1)
            else:
                setattr(self, overflow_attr, _sat_add(getattr(self, overflow_attr), 1))

    def _emit_stream_opened(self, stream: "NativeStream") -> None:
        self._emit_stream_event(EventType.STREAM_OPENED, stream)

    def _emit_stream_event(self, event_type: EventType, stream: "NativeStream") -> None:
        self._emit_event(
            Event(
                event_type,
                session_state=self._state,
                stream=StreamEventInfo(
                    stream.stream_id,
                    stream.metadata,
                    local=stream.opened_locally,
                    bidirectional=stream.bidirectional,
                    application_visible=True,
                    local_addr=stream.local_addr,
                    remote_addr=stream.remote_addr,
                ),
            )
        )

    def _emit_event(self, event: Event) -> None:
        self._event_dispatcher.emit(event)

    def _lock_wait(self, timeout: Optional[float]) -> None:
        self._lock.wait(timeout)

    def _lock_notify_all(self) -> None:
        self._lock.notify_all()


class NativeStream(object):
    """Native synchronous ZMux stream."""

    __slots__ = (
        "_session",
        "_stream_id",
        "_opened_locally",
        "_bidirectional",
        "_local_send",
        "_local_receive",
        "_metadata",
        "_open_info",
        "_opened_sent",
        "_provisional_created_at",
        "_provisional_commit_waiters",
        "_provisional_commit_wait_started",
        "_read_buf",
        "_read_buffered",
        "_read_finished",
        "_read_closed",
        "_read_stopped",
        "_peer_fin_seen",
        "_read_error",
        "_write_closed",
        "_write_error",
        "_session_error",
        "_send_max",
        "_send_sent",
        "_blocked_sent_at",
        "_recv_received",
        "_recv_advertised",
        "_recv_buffered",
        "_recv_pending",
        "_peer_blocked_at",
        "_peer_blocked_floor",
        "_late_data_received",
        "_churn_counted",
        "_closed",
        "_read_deadline",
        "_write_deadline",
        "_cond",
        "_write_mutex",
    )

    def __init__(
        self,
        session: Conn,
        stream_id: int,
        *,
        opened_locally: bool,
        bidirectional: bool,
        local_send: bool,
        local_receive: bool,
        metadata: StreamMetadata,
        opened_sent: bool = False,
    ) -> None:
        self._session = session
        self._stream_id = stream_id
        self._opened_locally = opened_locally
        self._bidirectional = bidirectional
        self._local_send = local_send
        self._local_receive = local_receive
        self._metadata = metadata
        self._open_info = metadata.open_info
        self._opened_sent = opened_sent
        self._provisional_created_at: Optional[float] = None
        # Commit-turn waits in progress and the start of the current waiting
        # stretch.  Waiting behind an earlier same-class opener is not idle
        # provisional time, so it does not age the stream (even when that
        # opener is later abandoned); a finished stretch shifts
        # ``_provisional_created_at`` forward by its length.
        self._provisional_commit_waiters = 0
        self._provisional_commit_wait_started = 0.0
        self._read_buf = StreamReadBuffer()
        self._read_buffered = 0
        self._read_finished = not local_receive
        self._read_closed = not local_receive
        # ``_read_stopped`` is a genuine local read stop (close_read/cancel_read
        # or close() of a finished half); ``_peer_fin_seen`` is the peer's FIN
        # (recv_fin), which a local stop alone never implies.
        self._read_stopped = False
        self._peer_fin_seen = False
        self._read_error: Optional[BaseException] = None
        self._write_closed = not local_send
        self._write_error: Optional[BaseException] = None
        # Visible session error once the session terminated (D9).
        self._session_error: Optional[BaseException] = None
        if opened_locally and stream_id == 0 and local_send:
            self._send_max = initial_local_opened_send_window(
                session.peer_preface().settings,
                bidirectional,
            )
        else:
            self._send_max = _initial_stream_send_max(session, stream_id, local_send)
        self._send_sent = 0
        self._blocked_sent_at: Optional[int] = None
        # Receive flow-control accounting, guarded by the session lock.
        self._recv_received = 0
        self._recv_advertised = _initial_stream_receive_window(
            session,
            opened_locally,
            bidirectional,
            local_receive,
        )
        self._recv_buffered = 0
        self._recv_pending = 0
        self._peer_blocked_at = -1
        self._peer_blocked_floor = 0
        # Late DATA bytes discarded after this receive half closed, counted
        # against its allowance and carried into its tombstone (DESIGN D2).
        self._late_data_received = 0
        # Visible open-then-terminal churn is counted once per stream.
        self._churn_counted = False
        self._closed = False
        self._read_deadline = None
        self._write_deadline = None
        self._cond = threading.Condition(threading.RLock())
        self._write_mutex = threading.Lock()

    def __enter__(self) -> "NativeStream":
        return self

    # noinspection PyTypeHints
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    @property
    def stream_id(self) -> int:
        return self._stream_id

    @property
    def opened_locally(self) -> bool:
        return self._opened_locally

    @property
    def bidirectional(self) -> bool:
        return self._bidirectional

    @property
    def open_info(self) -> bytes:
        return self._open_info

    @property
    def open_info_len(self) -> int:
        return len(self._open_info)

    @property
    def has_open_info(self) -> bool:
        return bool(self._open_info)

    @property
    def metadata(self) -> StreamMetadata:
        return self._metadata

    @property
    def local_addr(self) -> object:
        return ZmuxSocketAddress.local_stream(self._stream_id)

    @property
    def remote_addr(self) -> object:
        return ZmuxSocketAddress.remote_stream(self._stream_id)

    @property
    def read_closed(self) -> bool:
        return self._read_closed or self._read_finished or self._read_error is not None

    @property
    def write_closed(self) -> bool:
        return self._write_closed or self._write_error is not None

    @property
    def closed(self) -> bool:
        return self._closed or (self._read_terminal() and self._write_terminal())

    def read(self, max_bytes: int = -1, *, timeout: Optional[float] = None) -> bytes:
        if max_bytes < -1:
            raise ValueError("max_bytes must be >= -1")
        if max_bytes == 0:
            return b""
        if max_bytes == -1:
            parts = []
            while True:
                chunk = self.read(DEFAULT_READ_CHUNK, timeout=timeout)
                if not chunk:
                    return b"".join(parts)
                parts.append(chunk)
        out = bytearray(max_bytes)
        n = self.readinto(out, timeout=timeout)
        return bytes(out[:n])

    def readinto(self, buffer: WritableBuffer, *, timeout: Optional[float] = None) -> int:
        view = _writable_view(buffer)
        if not view:
            return 0
        timeout_deadline = deadline_after(timeout)
        self._before_read_wait()
        with self._cond:
            self._check_readable()
            while self._read_buf.is_empty():
                if self._read_finished:
                    # _check_readable already raised for every terminal
                    # cause other than a graceful peer FIN.
                    bytes_read = 0
                    break
                deadline = _merge_deadline(self._read_deadline, timeout_deadline)
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise ReadTimeout()
                self._cond.wait(remaining)
                self._check_readable()
            else:
                result = self._read_buf.readinto(view)
                bytes_read = result.bytes_read
                self._read_buffered = len(self._read_buf)
                self._cond.notify_all()
        self._release_consumed(bytes_read)
        return bytes_read

    def read_vectored(
        self, buffers: Iterable[WritableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        views = _writable_views(buffers)
        if not views:
            return 0
        timeout_deadline = deadline_after(timeout)
        self._before_read_wait()
        with self._cond:
            self._check_readable()
            while self._read_buf.is_empty():
                if self._read_finished:
                    return 0
                deadline = _merge_deadline(self._read_deadline, timeout_deadline)
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise ReadTimeout()
                self._cond.wait(remaining)
                self._check_readable()

            result = self._read_buf.readv_into(views)
            total = result.bytes_read
            self._read_buffered = len(self._read_buf)
            self._cond.notify_all()
        self._release_consumed(total)
        return total

    def read_exact(self, n: int, *, timeout: Optional[float] = None) -> bytes:
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError("n must be an integer")
        if n < 0:
            raise ValueError("n must be >= 0")
        out = bytearray(n)
        view = memoryview(out)
        offset = 0
        deadline = deadline_after(timeout)
        while offset < n:
            read = self.readinto(view[offset:], timeout=_remaining(deadline))
            if read == 0:
                raise EOFError("unexpected EOF while reading stream")
            offset += read
        return bytes(out)

    def write(self, data: ReadableBuffer, *, timeout: Optional[float] = None) -> int:
        view = _readable_view(data)
        if not view:
            return 0
        self._send_data(view, fin=False, timeout=timeout)
        return len(view)

    def write_all(self, data: ReadableBuffer, *, timeout: Optional[float] = None) -> None:
        self.write(data, timeout=timeout)

    def write_vectored(
        self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        views, total = _readable_views(parts)
        if total == 0:
            return 0
        self._send_data_vectored(views, fin=False, timeout=timeout)
        return total

    def write_final(
        self, data: ReadableBuffer = b"", *, timeout: Optional[float] = None
    ) -> int:
        view = _readable_view(data)
        self._send_data(view, fin=True, timeout=timeout)
        return len(view)

    def write_vectored_final(
        self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        views, total = _readable_views(parts)
        self._send_data_vectored(views, fin=True, timeout=timeout)
        return total

    def set_deadline(self, deadline) -> None:
        self.set_read_deadline(deadline)
        self.set_write_deadline(deadline)

    def set_timeout(self, timeout: Optional[float]) -> None:
        self.set_deadline(deadline_after(timeout))

    def set_read_deadline(self, deadline) -> None:
        with self._cond:
            self._read_deadline = deadline
            self._cond.notify_all()

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self.set_read_deadline(deadline_after(timeout))

    def set_write_deadline(self, deadline) -> None:
        self._write_deadline = deadline
        notify = getattr(self._session, "_notify_stream_state_changed", None)
        if notify is not None:
            notify()

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        self.set_write_deadline(deadline_after(timeout))

    def close_read(self) -> None:
        self.cancel_read(int(ErrorCode.CANCELLED))

    def cancel_read(self, code: int) -> None:
        if not self._local_receive:
            raise StreamNotReadable()
        payload = build_error_payload(
            _application_code(code),
            "",
            self._session.peer_limits.max_control_payload_bytes,
        )
        with self._cond:
            if self._read_stopped:
                raise self._read_closed_error()
            if self._read_error is not None:
                raise self._read_error
            if self._read_closed or self._read_finished:
                raise self._read_closed_error()
            self._read_closed = True
            self._read_stopped = True
            self._read_finished = True
            discarded = self._clear_read_buffer_locked()
            self._cond.notify_all()
            forget = self.closed
        self._release_discarded(discarded)
        self._ensure_opened_before_terminal()
        self._queue_control_frame(Frame(FrameType.STOP_SENDING, self._stream_id, 0, payload))
        if forget:
            self._session.forget_stream(self)

    def close_write(self, *, timeout: Optional[float] = None) -> None:
        if not self._local_send:
            raise StreamNotWritable()
        with self._cond:
            closed = self._write_closed
            error = self._write_error
        if closed or error is not None:
            # STATE_MACHINE section 4.1: DATA|FIN on a finished, reset or
            # aborted send half is a local error.  Only a half that peer
            # STOP_SENDING already concluded (with our RESET) stays a no-op.
            self._raise_if_session_terminated()
            if (
                error is not None
                and error_termination_kind(error) is TerminationKind.STOPPED
                and getattr(error, "source", None) is ErrorSource.REMOTE
            ):
                return
            if error is not None:
                raise error
            raise WriteClosed()
        self._send_data(memoryview(b""), fin=True, timeout=timeout)

    def cancel_write(self, code: int) -> None:
        self._check_writable()
        app_code = _application_code(code)
        app = ApplicationError(
            app_code,
            "",
            scope=ErrorScope.STREAM,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.WRITE,
            termination_kind=TerminationKind.RESET,
        )
        abort_provisional = getattr(self._session, "_abort_provisional_open", None)
        if abort_provisional is not None and abort_provisional(self, app):
            return
        payload = build_error_payload(
            app_code,
            "",
            self._session.peer_limits.max_control_payload_bytes,
        )
        self._ensure_opened_before_terminal()
        # Commit the reset before RESET is queued: DATA is only queued while
        # the send half is still open (checked under _cond), so no DATA or
        # DATA|FIN can follow the RESET (SPEC section 6.7).
        with self._cond:
            self._check_writable()
            self._write_closed = True
            self._write_error = app
            self._cond.notify_all()
            forget = self.closed
        self._notify_session_state_changed()
        self._queue_control_frame(Frame(FrameType.RESET, self._stream_id, 0, payload))
        if forget:
            self._session.forget_stream(self)

    def update_metadata(self, update: MetadataUpdate) -> None:
        if not isinstance(update, MetadataUpdate):
            raise TypeError("update must be MetadataUpdate")
        if update.is_empty():
            raise EmptyMetadataUpdate()
        # Serialized with writes like Go's write permit: an update racing the
        # first write either merges into the opener before it is built or,
        # once the opener is queued, goes out as PRIORITY_UPDATE behind it.
        # It never only changes the local snapshot.
        if not self._write_mutex.acquire(timeout=_lock_timeout(self._write_deadline)):
            raise WriteTimeout()
        try:
            self._check_writable()
            metadata = StreamMetadata(
                update.priority if update.priority is not None else self._metadata.priority,
                # Group 0 clears the explicit group (SPEC section 7.4); the
                # PRIORITY_UPDATE below still carries the 0.
                (
                    normalize_stream_group(update.group)
                    if update.group is not None
                    else self._metadata.group
                ),
                self._metadata.open_info,
            )
            if not self._opened_sent:
                capabilities = self._session.negotiated().capabilities
                validate_open_metadata_update_capability(capabilities, update)
                _open_metadata_prefix(
                    capabilities,
                    metadata,
                    self._session.peer_limits.max_frame_payload,
                )
                self._metadata = metadata
                self._open_info = metadata.open_info
                return
            payload = build_priority_update_payload(
                self._session.negotiated().capabilities,
                update,
                self._session.peer_limits.max_extension_payload_bytes,
            )
            self._queue_control_frame(Frame(FrameType.EXT, self._stream_id, 0, payload))
            self._metadata = metadata
        finally:
            self._write_mutex.release()

    def close(self) -> None:
        """Conclude both halves (API_SEMANTICS section 6.5).

        The send half gets DATA|FIN if it is still open; when that cannot be
        queued in time it is reset with CANCELLED instead, so the peer never
        waits on a half the local side has abandoned.  The receive half gets
        STOP_SENDING only if it is still open.  A half the peer or a local
        terminal operation already ended is not an error here.
        """

        errors = []
        with self._cond:
            needs_write = self._local_send and not self._write_terminal()
        if needs_write:
            try:
                self.close_write()
            except (WriteClosed, StreamNotWritable):
                pass
            except BaseException as exc:
                # A peer ABORT or STOP_SENDING that landed after the snapshot
                # above ended the half just as if it had come first.
                if not self._ended_by_peer(exc, read=False):
                    errors.append(exc)
                    if isinstance(exc, WriteTimeout):
                        try:
                            self.cancel_write(int(ErrorCode.CANCELLED))
                        except (WriteClosed, StreamNotWritable, SessionClosed):
                            pass
                        except BaseException as cancel_exc:
                            errors.append(cancel_exc)
        discarded = 0
        with self._cond:
            needs_read = self._local_receive and not self._read_terminal()
            if (
                self._local_receive
                and not needs_read
                and not self._read_stopped
                and self._read_error is None
            ):
                # The peer already finished this direction: nothing to stop,
                # but further reads fail promptly and unread bytes are dropped
                # (returning their session credit).
                self._read_stopped = True
                discarded = self._clear_read_buffer_locked()
                self._cond.notify_all()
        self._release_discarded(discarded)
        if needs_read:
            try:
                self.close_read()
            except (ReadClosed, StreamNotReadable):
                pass
            except BaseException as exc:
                # Likewise for a peer RESET or ABORT that raced the stop.
                if not self._ended_by_peer(exc, read=True):
                    errors.append(exc)
        with self._cond:
            concluded = self._write_terminal() or self._session_error is not None
            if concluded:
                self._closed = True
        if concluded:
            self._session.forget_stream(self)
        if errors:
            raise errors[0]

    def close_with_error(self, code: int, reason: str = "") -> None:
        app_code = _application_code(code)
        reason = "" if reason is None else str(reason)
        payload = build_error_payload(
            app_code,
            reason,
            self._session.peer_limits.max_control_payload_bytes,
        )
        app = ApplicationError(
            app_code,
            reason,
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.CLOSE,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.ABORT,
        )
        with self._cond:
            # A repeated local abort, or one after the peer's ABORT, changes
            # nothing and sends nothing (STATE_MACHINE section 4.1); the first
            # committed abort error stays visible.
            if self._abort_committed_locked():
                return
        self._raise_if_session_terminated()
        abort_provisional = getattr(self._session, "_abort_provisional_open", None)
        if abort_provisional is not None and abort_provisional(self, app):
            return
        self._ensure_opened_before_terminal()
        # Commit before queueing ABORT so no DATA of this stream can follow it.
        if not self._abort(app):
            return
        self._queue_control_frame(Frame(FrameType.ABORT, self._stream_id, 0, payload))

    def _send_data(
        self,
        data: memoryview,
        *,
        fin: bool,
        timeout: Optional[float],
        wait: bool = True,
    ) -> None:
        parts = () if len(data) == 0 else (data,)
        self._send_data_vectored(parts, fin=fin, timeout=timeout, wait=wait)

    def _send_data_vectored(
        self,
        parts: Tuple[memoryview, ...],
        *,
        fin: bool,
        timeout: Optional[float],
        wait: bool = True,
    ) -> None:
        parts = tuple(part for part in parts if len(part) > 0)
        timeout_deadline = deadline_after(timeout)

        def current_deadline() -> Optional[float]:
            return _merge_deadline(self._write_deadline, timeout_deadline)

        with self._write_mutex:
            self._check_writable()
            if _remaining(current_deadline()) == 0:
                raise WriteTimeout()
            first = not self._opened_sent
            prefix = b""
            if first:
                prefix = self._opening_prefix()
            elif not parts and not fin:
                return
            part_index = 0
            part_offset = 0
            # Keep at most one earlier frame of this write in flight while the
            # next one is prepared, so the writer thread stays busy.
            previous = None
            try:
                while True:
                    if _remaining(current_deadline()) == 0:
                        raise WriteTimeout()
                    room = fragment_cap(
                        self._session.peer_limits.max_frame_payload,
                        len(prefix),
                        self._metadata.priority or 0,
                        self._session.negotiated().peer_settings.scheduler_hints,
                    )
                    desired = 0
                    if part_index < len(parts):
                        if room > 0:
                            desired = min(len(parts[part_index]) - part_offset, room)
                        elif not prefix:
                            raise ValueError("peer max_frame_payload leaves no DATA payload room")
                    if first:
                        # The stream ID is assigned and the opener queued in one
                        # step, with whatever credit is free right now.  Without
                        # credit the opener is a zero-length DATA, so the peer
                        # learns the stream before any stream BLOCKED and can
                        # grant credit for it (SPEC sections 3.1 and 9.1).
                        queued = self._session._commit_local_open(
                            self,
                            timeout_deadline,
                            partial(
                                self._queue_opener_locked,
                                parts,
                                part_index,
                                part_offset,
                                desired,
                                prefix,
                                fin,
                            ),
                        )
                        first = False
                        prefix = b""
                        if queued is None:
                            # Already committed by an earlier call.
                            if not parts and not fin:
                                return
                            continue
                        self._session.emit_stream_opened(self)
                    else:
                        take = 0
                        if desired > 0:
                            reserve = getattr(self._session, "_reserve_send_credit", None)
                            take = (
                                reserve(self, desired, timeout_deadline)
                                if reserve is not None
                                else desired
                            )
                        queued = self._queue_data_chunk(
                            parts,
                            part_index,
                            part_offset,
                            take,
                            b"",
                            fin,
                        )
                    request, part_index, part_offset, done, forget = queued
                    if forget:
                        self._session.forget_stream(self)
                    if wait:
                        self._wait_data_frame(previous, current_deadline)
                        previous = request
                    if done:
                        if wait:
                            self._wait_data_frame(previous, current_deadline)
                        return
            except Exception as exc:
                # Queued DATA is committed and still goes out after a timeout
                # or later error, so report how much of this call was taken,
                # like BlockingIOError: a retry resumes after those bytes.
                written = _queued_prefix_len(parts, part_index, part_offset)
                if not written:
                    raise
                raise _with_characters_written(exc, written) from exc.__cause__

    def _opening_prefix(self) -> bytes:
        """Build the opener's OPEN_METADATA prefix before the ID is committed.

        ``open_stream`` and ``update_metadata`` already validated the metadata;
        if it still cannot be carried the provisional stream is dropped, so no
        stream ID is consumed without an opener (SPEC section 3.1).
        """

        try:
            return _open_metadata_prefix(
                self._session.negotiated().capabilities,
                self._metadata,
                self._session.peer_limits.max_frame_payload,
            )
        except BaseException as exc:
            abort_provisional = getattr(self._session, "_abort_provisional_open", None)
            if abort_provisional is not None:
                abort_provisional(self, exc)
            raise

    def _queue_opener_locked(
        self,
        parts: Tuple[memoryview, ...],
        part_index: int,
        part_offset: int,
        desired: int,
        prefix: bytes,
        fin: bool,
    ) -> Tuple[object, int, int, bool, bool]:
        # Runs under the session lock right after the ID is assigned, so it
        # only takes credit that is free now and never waits.
        take = self._session._take_send_credit_locked(self, desired)
        return self._queue_data_chunk(
            parts,
            part_index,
            part_offset,
            take,
            prefix,
            fin,
            opener=True,
        )

    def _queue_data_chunk(
        self,
        parts: Tuple[memoryview, ...],
        part_index: int,
        part_offset: int,
        take: int,
        prefix: bytes,
        fin: bool,
        *,
        opener: bool = False,
    ) -> Tuple[object, int, int, bool, bool]:
        """Frame the next ``take`` reserved bytes and queue them.

        Returns ``(request, part_index, part_offset, done, forget)``.  Terminal
        paths (RESET, ABORT, STOP_SENDING, session close) commit under _cond
        before queueing their frame, so checking here, atomically with the
        enqueue, keeps DATA from ever following them (SPEC sections 6.3, 6.7).
        """

        chunk = memoryview(b"")
        if take > 0:
            current = parts[part_index]
            chunk = current[part_offset: part_offset + take]
            part_offset += take
            if part_offset >= len(current):
                part_index += 1
                part_offset = 0
        done = part_index >= len(parts)
        is_final = fin and done
        flags = (FRAME_FLAG_OPEN_METADATA if prefix else 0) | (
            FRAME_FLAG_FIN if is_final else 0
        )
        frame = Frame(FrameType.DATA, self._stream_id, flags, prefix + chunk.tobytes())
        request = None
        forget = False
        with self._cond:
            suppressed = self._write_terminal()
            if not suppressed:
                request = self._queue_data_frame(frame)
                # The frame is committed once queued: mark FIN with it so a
                # timed-out wait can never cause DATA after FIN.
                if is_final:
                    self._write_closed = True
                    self._cond.notify_all()
                    forget = self.closed
            elif opener:
                # Only a non-conforming peer can end the send half of a stream
                # it has not seen yet.  The committed ID is still consumed in
                # order, with an empty opener (DESIGN D5).
                request = self._queue_data_frame(Frame(FrameType.DATA, self._stream_id, 0, b""))
            if opener:
                # Marked with the opener, so a timed-out wait or a terminal
                # operation can never cause a second opener.
                self._opened_sent = True
        if suppressed:
            # Reserved but never framed: the peer will not count it.
            self._refund_send_credit(len(chunk))
            self._check_writable()
            raise WriteClosed()
        return request, part_index, part_offset, done, forget

    def _queue_data_frame(self, frame: Frame) -> object:
        queue = getattr(self._session, "_queue_frame", None)
        if queue is None:
            self._session.send_frame(frame)
            return None
        return queue(frame)

    def _wait_data_frame(self, request: object, deadline_source) -> None:
        if request is None:
            return
        self._session._wait_write(request, deadline_source)

    def _queue_control_frame(self, frame: Frame) -> None:
        # Stream control is queued without waiting for the transport; the
        # writer keeps it behind this stream's queued DATA (and opener).
        queue = getattr(self._session, "_queue_frame", None)
        if queue is None:
            self._session.send_frame(frame)
            return
        queue(frame)

    def _ensure_opened_before_terminal(self) -> None:
        # Committing a stream queues its opener, so a RESET, ABORT or
        # STOP_SENDING can never be its first frame on the wire.
        if not self._opened_sent:
            self._send_data(memoryview(b""), fin=False, timeout=None, wait=False)

    def receive_data(self, data: memoryview) -> bool:
        return self._receive_data(data)

    def receive_fin(self) -> None:
        self._receive_fin()

    def stop_write(self, error: BaseException) -> bool:
        return self._stop_write(error)

    def reset_read(self, error: BaseException) -> bool:
        return self._reset_read(error)

    def abort(self, error: BaseException) -> bool:
        return self._abort(error)

    def session_closed(self, error: Optional[BaseException]) -> None:
        self._session_closed(error)

    def apply_metadata_update(self, metadata: StreamMetadata) -> bool:
        return self._apply_metadata_update(metadata)

    def terminal_late_data_cause(self) -> LateDataCause:
        for error in (self._read_error, self._write_error):
            kind = error_termination_kind(error) if error is not None else TerminationKind.UNKNOWN
            if kind is TerminationKind.RESET:
                return LateDataCause.RESET
            if kind is TerminationKind.ABORT:
                return LateDataCause.ABORT
        if self._local_receive and self._read_closed:
            return LateDataCause.CLOSE_READ
        return LateDataCause.NONE

    def terminal_late_data_action(self) -> LateDataAction:
        # Once the peer's FIN was seen, later DATA on that direction is a
        # stream-state violation, even after a local read stop (SPEC section
        # 9.2, STATE_MACHINE section 8.1).
        if self._local_receive and self._peer_fin_seen and self._read_error is None:
            return LateDataAction.ABORT_CLOSED
        return LateDataAction.IGNORE

    def terminal_late_data_cap(self) -> Optional[int]:
        if self._stream_id == 0:
            return None
        # A send-only stream advertised no credit, so it gets the repository
        # cap; DATA on it is never legitimate.
        return self._session._late_data_allowance_locked(self) or None

    def _receive_late_data_cause(self) -> LateDataCause:
        """Why this receive half discards DATA: peer RESET, ABORT or a local stop."""

        error = self._read_error
        kind = error_termination_kind(error) if error is not None else TerminationKind.UNKNOWN
        if kind is TerminationKind.RESET:
            return LateDataCause.RESET
        if kind is TerminationKind.ABORT:
            return LateDataCause.ABORT
        return LateDataCause.CLOSE_READ

    def _receive_stopped_locally(self) -> bool:
        """Whether this side stopped the receive half (read stop or local ABORT)."""

        if self._read_stopped:
            return True
        error = self._read_error
        return (
            error is not None
            and error_termination_kind(error) is TerminationKind.ABORT
            and getattr(error, "source", None) is ErrorSource.LOCAL
        )

    def _receive_data(self, data: memoryview) -> bool:
        """Buffer peer DATA; return ``False`` if the read side no longer accepts it.

        Runs on the session reader thread and never waits: the advertised
        receive windows bound what can be buffered here.
        """

        view = memoryview(data)
        if not view:
            return True
        with self._cond:
            if self._read_closed or self._read_finished or self._read_error is not None:
                return False
            self._read_buf.append(view)
            self._read_buffered = len(self._read_buf)
            self._cond.notify_all()
        return True

    def _receive_fin(self) -> None:
        with self._cond:
            if self._local_receive and self._read_error is None:
                # recv_open / recv_stop_sent -> recv_fin.  A FIN behind a
                # RESET or ABORT is ignored with the rest of that tail.
                self._peer_fin_seen = True
            self._read_finished = True
            self._cond.notify_all()
            forget = self.closed
        if forget:
            self._session.forget_stream(self)

    def _stop_write(self, error: BaseException) -> bool:
        """Apply peer STOP_SENDING; return ``False`` if the half already ended.

        A send half that already committed FIN, RESET or ABORT, or saw an
        earlier STOP_SENDING, keeps its outcome (STATE_MACHINE section 5.2).
        """

        with self._cond:
            if self._write_closed or self._write_error is not None:
                return False
            self._write_closed = True
            self._write_error = error
            self._cond.notify_all()
            forget = self.closed
        self._notify_session_state_changed()
        if forget:
            self._session.forget_stream(self)
        return True

    def _reset_read(self, error: BaseException) -> bool:
        """Apply peer RESET; return ``False`` if the half already ended.

        RESET after the peer's FIN, or a repeated RESET, leaves the half
        unchanged (STATE_MACHINE section 5.1, SPEC section 6.7).  RESET after
        a local read stop is applied: recv_stop_sent -> recv_reset.
        """

        # Unread bytes of a reset direction are discarded and their session
        # credit returned (SPEC section 8 discard-and-release).
        with self._cond:
            if self._peer_fin_seen or self._read_error is not None:
                return False
            self._read_finished = True
            self._read_error = error
            discarded = self._clear_read_buffer_locked()
            self._cond.notify_all()
            forget = self.closed
        self._release_discarded(discarded)
        if forget:
            self._session.forget_stream(self)
        return True

    def _abort(self, error: BaseException) -> bool:
        """Abort both halves; return ``False`` if the stream already was.

        Unread bytes are discarded and later reads and writes fail with
        ``error`` (API_SEMANTICS section 3).  The first committed abort stays
        visible: a repeated or late abort changes nothing.
        """

        with self._cond:
            if self._abort_committed_locked():
                return False
            self._read_finished = True
            self._read_closed = True
            self._write_closed = True
            self._closed = True
            self._read_error = error
            self._write_error = error
            discarded = self._clear_read_buffer_locked()
            self._cond.notify_all()
        self._release_discarded(discarded)
        self._notify_session_state_changed()
        self._session.forget_stream(self)
        return True

    def _abort_committed_locked(self) -> bool:
        return any(
            error is not None
            and error_termination_kind(error) is TerminationKind.ABORT
            for error in (self._read_error, self._write_error)
        )

    def _notify_session_state_changed(self) -> None:
        notify = getattr(self._session, "_notify_stream_state_changed", None)
        if notify is not None:
            notify()

    def _raise_if_session_terminated(self) -> None:
        error = self._session_error
        if error is None and self._session.closed:
            error = SessionClosed(operation=ErrorOperation.CLOSE, source=ErrorSource.LOCAL)
        if error is not None:
            raise error

    def _refund_send_credit(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        refund = getattr(self._session, "_refund_send_credit", None)
        if refund is not None:
            refund(self, byte_count)

    def _clear_read_buffer_locked(self) -> int:
        discarded = len(self._read_buf)
        self._read_buf.clear()
        self._read_buffered = 0
        return discarded

    def _before_read_wait(self) -> None:
        # Unlocked peek: a reader that may wait with nothing buffered lets the
        # session force a grant for an exhausted zero-credit window.
        if not self._read_buf.is_empty():
            return
        replenish = getattr(self._session, "_replenish_for_blocked_reader", None)
        if replenish is not None:
            replenish(self)

    def _release_consumed(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        consume = getattr(self._session, "_consume_receive", None)
        if consume is not None:
            consume(self, byte_count)

    def _release_discarded(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        discard = getattr(self._session, "_discard_receive", None)
        if discard is not None:
            discard(self, byte_count)

    def _session_closed(self, error: Optional[BaseException]) -> None:
        """Fail every half the session termination left unfinished.

        A receive half without the peer's FIN reports the session error (or
        ``SessionClosed`` for a benign close) instead of EOF and drops its
        unread bytes (SPEC section 6.10, DESIGN D9); only a real peer FIN ends
        in EOF, after its buffered bytes.  Halves that already finished, were
        reset, aborted or stopped keep their outcome.
        """

        with self._cond:
            if self._session_error is None:
                self._session_error = error or SessionClosed(
                    operation=ErrorOperation.CLOSE,
                    source=ErrorSource.LOCAL,
                )
            if (
                self._local_receive
                and self._read_error is None
                and not self._read_stopped
                and not self._peer_fin_seen
            ):
                self._read_error = error or SessionClosed(
                    operation=ErrorOperation.READ,
                    source=ErrorSource.LOCAL,
                )
                # The session is gone, so no credit is re-advertised.
                self._clear_read_buffer_locked()
            if self._local_send and self._write_error is None and not self._write_closed:
                self._write_error = error or SessionClosed(
                    operation=ErrorOperation.WRITE,
                    source=ErrorSource.LOCAL,
                )
            self._read_finished = True
            self._read_closed = True
            self._write_closed = True
            self._closed = True
            self._cond.notify_all()
        self._notify_session_state_changed()
        self._session.forget_stream(self)

    def _apply_metadata_update(self, metadata: StreamMetadata) -> bool:
        """Apply advisory metadata; return whether priority or group changed."""

        # A present group 0 clears the explicit group (SPEC section 7.4); an
        # absent group keeps it.
        updated = StreamMetadata(
            metadata.priority if metadata.priority is not None else self._metadata.priority,
            (
                normalize_stream_group(metadata.group)
                if metadata.group is not None
                else self._metadata.group
            ),
            self._metadata.open_info,
        )
        changed = (
            updated.priority != self._metadata.priority
            or updated.group != self._metadata.group
        )
        self._metadata = updated
        return changed

    def _check_readable(self) -> None:
        """Raise the receive half's terminal error, if it has one.

        A local read stop takes precedence (STATE_MACHINE section 3.2), then
        the committed RESET, ABORT or session error with its code.  Those
        transitions discard unread bytes, so nothing stale is returned ahead
        of the error.  A graceful peer FIN is not an error: reads return EOF
        once the buffer is drained.
        """

        if not self._local_receive:
            raise StreamNotReadable()
        if self._read_stopped:
            raise self._read_closed_error()
        if self._read_error is not None:
            raise self._read_error

    def _read_closed_error(self) -> ReadClosed:
        if self._read_stopped:
            return ReadClosed(
                source=ErrorSource.LOCAL,
                termination_kind=TerminationKind.STOPPED,
            )
        if self._read_finished:
            return ReadClosed(
                source=ErrorSource.REMOTE,
                termination_kind=TerminationKind.GRACEFUL,
            )
        return ReadClosed()

    def _check_writable(self) -> None:
        if not self._local_send:
            raise StreamNotWritable()
        if self._write_error is not None:
            raise self._write_error
        if self._write_closed:
            raise WriteClosed()
        if self._session.closed:
            raise SessionClosed(operation=ErrorOperation.WRITE, source=ErrorSource.LOCAL)

    def _blocks_graceful_close_locked(self, data_queued: bool) -> bool:
        """Whether this stream keeps a graceful session close draining.

        Locally opened streams block until fully terminal.  A peer-opened
        stream blocks only while local send work is outstanding: DATA (or
        DATA|FIN) still queued for the writer, which the final CLOSE would
        drop, or a send half that carried data and is still open.  Unread
        inbound bytes alone never delay the close (API_SEMANTICS section 8.1).
        """

        if self.closed:
            return False
        if self._opened_locally:
            return True
        if not self._local_send:
            return False
        if data_queued:
            return True
        if self._send_sent == 0:
            return False
        return not self._write_terminal()

    def _read_terminal(self) -> bool:
        return (
            not self._local_receive
            or self._read_closed
            or self._read_finished
            or self._read_error is not None
        )

    def _write_terminal(self) -> bool:
        return not self._local_send or self._write_closed or self._write_error is not None

    def _ended_by_peer(self, error: BaseException, *, read: bool) -> bool:
        """Whether ``error`` is the peer RESET, ABORT or STOP_SENDING that ended a half."""

        with self._cond:
            stored = self._read_error if read else self._write_error
        return (
            error is stored
            and getattr(error, "source", None) is ErrorSource.REMOTE
            and error_termination_kind(error)
            in (TerminationKind.RESET, TerminationKind.ABORT, TerminationKind.STOPPED)
        )


class _FrameIO(object):
    __slots__ = ("_transport",)

    def __init__(self, transport: object) -> None:
        self._transport = transport

    @property
    def transport(self) -> object:
        return self._transport

    def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        method = getattr(self._transport, "read", None)
        if method is None:
            method = getattr(self._transport, "recv", None)
        if method is None:
            raise StreamNotReadable()
        data = method(max_bytes)
        if data is None:
            raise OSError("zmux transport returned no read progress")
        return bytes(memoryview(data))

    def readinto(self, buffer: WritableBuffer) -> int:
        view = _writable_view(buffer)
        method = getattr(self._transport, "readinto", None)
        if method is None:
            method = getattr(self._transport, "recv_into", None)
        if method is not None:
            n = method(view)
            if isinstance(n, bool) or not isinstance(n, int) or n < 0 or n > len(view):
                raise OSError("zmux transport reported invalid read progress")
            return n
        data = self.read(len(view))
        n = len(data)
        view[:n] = data
        return n

    def write(self, data: ReadableBuffer) -> int:
        view = _readable_view(data)
        if not view:
            return 0
        method = getattr(self._transport, "write_all", None)
        if method is not None:
            method(view)
            return len(view)
        method = getattr(self._transport, "sendall", None)
        if method is not None:
            method(view)
            return len(view)
        method = getattr(self._transport, "write", None)
        if method is None:
            raise StreamNotWritable()
        written = method(view)
        if written is None:
            # A bare write() follows io.RawIOBase: None means a non-blocking
            # transport accepted nothing.  Treating it as a full write would
            # silently drop frame bytes; transports that always write
            # everything should expose write_all() or sendall() instead.
            raise BlockingIOError("zmux transport returned no write progress")
        if isinstance(written, bool) or not isinstance(written, int):
            raise OSError("zmux transport reported invalid write progress")
        if written <= 0 or written > len(view):
            raise OSError("zmux transport reported invalid write progress")
        return written

    def flush(self) -> None:
        method = getattr(self._transport, "flush", None)
        if method is not None:
            method()

    def close(self) -> None:
        method = getattr(self._transport, "close", None)
        if method is not None:
            method()

    def local_addr(self) -> Optional[object]:
        return _addr(self._transport, ("local_addr", "local_address", "getsockname"))

    def remote_addr(self) -> Optional[object]:
        return _addr(self._transport, ("remote_addr", "remote_address", "getpeername"))


def _coerce_transport(transport: object) -> object:
    if transport is None:
        raise NilConnection()
    if isinstance(transport, socket.socket):
        return SocketTransport(transport)
    return transport


def _bytes_like(value: object, label: str) -> bytes:
    try:
        return bytes(_readable_view(value))
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % label) from exc


def _readable_view(data: object) -> memoryview:
    if isinstance(data, (bool, int)):
        raise TypeError("data must be bytes-like")
    return byte_view(data)


def _readable_views(parts: Iterable[object]) -> Tuple[Tuple[memoryview, ...], int]:
    if parts is None:
        raise TypeError("parts must be an iterable of bytes-like objects")
    views = []
    total = 0
    for part in parts:
        view = _readable_view(part)
        if not view:
            continue
        views.append(view)
        total += len(view)
    return tuple(views), total


def _writable_views(parts: Iterable[object]) -> Tuple[memoryview, ...]:
    if parts is None:
        raise TypeError("buffers must be an iterable of writable bytes-like objects")
    views = []
    for part in parts:
        view = _writable_view(part)
        if view:
            views.append(view)
    return tuple(views)


def _initial_stream_send_max(session: object, stream_id: int, local_send: bool) -> int:
    if not local_send:
        return 0
    local_role = getattr(session, "_local_role", None)
    peer_preface = getattr(session, "_peer_preface", None)
    if local_role is None or peer_preface is None:
        return MAX_VARINT62
    return initial_send_window(local_role, peer_preface.settings, stream_id)


def _initial_stream_receive_window(
    session: object,
    opened_locally: bool,
    bidirectional: bool,
    local_receive: bool,
) -> int:
    if not local_receive:
        return 0
    local_preface = getattr(session, "_local_preface", None)
    if local_preface is None:
        return MAX_VARINT62
    settings = local_preface.settings
    if not bidirectional:
        return settings.initial_max_stream_data_uni
    if opened_locally:
        return settings.initial_max_stream_data_bidi_locally_opened
    return settings.initial_max_stream_data_bidi_peer_opened


def _writable_view(data: object) -> memoryview:
    view = memoryview(data)
    if view.readonly:
        raise TypeError("buffer must be writable")
    if view.ndim == 1 and view.itemsize == 1 and view.format in ("B", "b", "c"):
        return view
    return view.cast("B")


def _application_code(code: int) -> int:
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError("code must be an integer")
    if code < 0 or code > MAX_VARINT62:
        raise ValueError("code must be within varint62 range")
    return int(code)


def _open_metadata_prefix(
    capabilities: int,
    metadata: StreamMetadata,
    max_frame_payload: int,
) -> bytes:
    """Build the opener's OPEN_METADATA prefix, raising the typed open errors."""

    try:
        return build_open_metadata_prefix(
            capabilities,
            metadata.priority,
            metadata.group,
            metadata.open_info,
            max_frame_payload,
        )
    except (OpenInfoUnavailable, OpenMetadataTooLarge):
        raise
    except ProtocolError as exc:
        if open_info_unavailable(exc):
            raise OpenInfoUnavailable(scope=ErrorScope.STREAM) from exc
        if open_metadata_too_large(exc):
            raise OpenMetadataTooLarge(scope=ErrorScope.STREAM) from exc
        raise


def _abort_open_send_failure(
    stream: "NativeStream", exc: BaseException, reason: str
) -> None:
    code = getattr(exc, "numeric_code", None)
    if code is None:
        code = int(ErrorCode.CANCELLED)
    try:
        stream.close_with_error(code, reason)
    except BaseException:
        pass


def _local_go_away_error(message: str) -> ProtocolError:
    """Reject a local GOAWAY request: the caller's own arguments are at fault."""

    return ProtocolError(
        message,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.CLOSE,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.BOTH,
    )


def _local_ping_too_large(payload_len: int, limit: int) -> FrameSizeError:
    return FrameSizeError(
        "PING payload %d exceeds control payload limit %d" % (payload_len, limit),
        code=int(ErrorCode.FRAME_SIZE),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.PING,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.WRITE,
    )


def _queued_prefix_len(parts: Tuple[memoryview, ...], part_index: int, part_offset: int) -> int:
    return sum(len(part) for part in parts[:part_index]) + part_offset


def _with_characters_written(exc: Exception, written: int) -> Exception:
    """Return ``exc`` carrying ``characters_written`` like ``BlockingIOError``.

    Stored stream/session errors are raised to many callers, so the count is
    set on a shallow copy; the original instance is never modified.
    """

    try:
        annotated = exc.__class__.__new__(exc.__class__)
        annotated.__dict__.update(exc.__dict__)
        annotated.args = exc.args
        annotated.characters_written = written
    except (AttributeError, TypeError):
        return exc
    return annotated.with_traceback(exc.__traceback__)


def _remaining(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def _lock_timeout(deadline: Optional[float]) -> float:
    # ``Lock.acquire`` spells "no deadline" as -1.
    remaining = _remaining(deadline)
    return -1 if remaining is None else remaining


def _merge_deadline(first: Optional[float], second: Optional[float]) -> Optional[float]:
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


def _remaining_after(start: float, timeout: Optional[float]) -> Optional[float]:
    timeout = maybe_timeout(timeout)
    if timeout is None:
        return None
    return max(0.0, timeout - (time.monotonic() - start))


def _sat_add(left: int, right: int) -> int:
    return min((1 << 64) - 1, max(0, int(left)) + max(0, int(right)))


def _best_effort_close(obj: object) -> None:
    try:
        close = getattr(obj, "close", None)
        if close is not None:
            close()
    except BaseException:
        pass


def _best_effort_abort(io: "_FrameIO") -> None:
    """Close the transport so threads blocked in its reads/writes wake up.

    Sockets are shut down first: on Linux, closing a socket descriptor does not
    interrupt another thread blocked in ``send``/``recv``.
    """

    sock = getattr(io.transport, "socket", None)
    if not isinstance(sock, socket.socket):
        sock = io.transport if isinstance(io.transport, socket.socket) else None
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except BaseException:
            pass
    _best_effort_close(io)


def _write_all_and_flush(io: "_FrameIO", data: bytes) -> None:
    # _FrameIO.write may report partial progress for transports exposing only
    # write(); loop until every byte is written.
    _frame_write_all(io, data)
    io.flush()


def _encode_frame(frame: Frame, limits: Limits) -> bytearray:
    # Same validation as frame.write_frame, encoded into one buffer for the
    # writer thread.
    limits = normalize_limits(limits)
    validate_frame(frame, limits, False)
    if len(frame.payload) > inbound_payload_limit(frame.frame_type, limits):
        raise frame_size_error(ERR_PAYLOAD_TOO_LARGE, ErrorOperation.WRITE)
    out = bytearray()
    append_frame_header_trusted(out, frame.code(), frame.stream_id, len(frame.payload))
    out += frame.payload
    return out


def _max_data_value(frame: Frame) -> int:
    try:
        value, _ = parse_varint(frame.payload)
    except Exception:
        return 0
    return value


def _close_transport_drain_delay(error: Optional[BaseException]) -> float:
    # Give the peer a brief chance to read an error CLOSE before the transport
    # close can turn it into a bare EOF or reset (mirrors zmux-go).
    if error is None:
        return 0.0
    if isinstance(error, KeepaliveTimeout):
        return _KEEPALIVE_CLOSE_DRAIN_DELAY
    if isinstance(error, ApplicationError) and error.code == int(ErrorCode.NO_ERROR):
        return 0.0
    return _ERROR_CLOSE_DRAIN_DELAY


def _establishment_timeout(config: Config) -> Optional[float]:
    timeout = getattr(config, "establishment_timeout", None)
    if timeout is None or timeout == 0:
        return DEFAULT_ESTABLISHMENT_TIMEOUT
    return timeout


def _establishment_stalled(operation: str, message: str) -> BaseException:
    return wrap_error(ErrorCode.INTERNAL, operation, TimeoutError(message))


def _finish_establishment_failure(
    io: "_FrameIO",
    preface_writer: _BackgroundCall,
    local: Preface,
    peer: Optional[Preface],
    error: BaseException,
) -> None:
    """Send a fatal establishment CLOSE only after a complete local preface.

    A CLOSE that precedes or splices into an unfinished preface cannot be
    parsed by the peer, so it is skipped unless the preface write finished.
    Every write here is bounded; the transport is always closed.
    """

    try:
        if preface_writer.wait(ESTABLISHMENT_FAILURE_WRITE_WAIT) and preface_writer.succeeded():
            frame = build_establishment_close_frame(local, peer, error)
            closer = _BackgroundCall(
                "zmux-establishment-close",
                lambda: _write_all_and_flush(io, frame),
            )
            if closer.wait(ESTABLISHMENT_FAILURE_WRITE_WAIT) and closer.succeeded():
                delay = establishment_close_drain_delay(error)
                if delay > 0:
                    time.sleep(delay)
    except BaseException:
        pass
    _best_effort_abort(io)


def _addr(obj: object, names: tuple[str, ...]) -> Optional[object]:
    for name in names:
        method = getattr(obj, name, None)
        if method is None:
            continue
        try:
            return method()
        except OSError:
            return None
    return None


__all__ = (
    "Conn",
    "NativeStream",
    "client",
    "client_io",
    "open",
    "open_io",
    "server",
    "server_io",
)
