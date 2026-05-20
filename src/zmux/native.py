"""Native synchronous ZMux session implementation."""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from types import TracebackType
from typing import Deque, Iterable, Optional, Tuple

from ._buffers import byte_view
from ._runtime.keepalive import (
    build_padded_ping_echo,
    build_ping_payload,
    effective_keepalive_timeout,
    init_keepalive_jitter_state,
    init_session_nonce_state,
    keepalive_lead_jittered_delay,
    next_session_nonce,
    pong_payload_for_ping,
    pong_payload_matches_ping,
)
from ._runtime.flow import (
    late_data_per_stream_cap,
    negotiated_frame_payload,
    receive_window_exceeded,
)
from ._runtime.read_loop import (
    InboundBudgetTracker,
    LateDataCause,
    ParsedFrameKind,
    classify_inbound_frame,
    validate_go_away_watermark_creator,
    validate_go_away_watermark_for_direction,
)
from ._runtime.session import (
    EventDispatcher,
    RuntimePolicy,
    StreamArity,
    build_establishment_close_frame,
    establishment_close_drain_delay,
    go_away_drain_interval,
    graceful_close_drain_timeout,
    max_peer_go_away_watermark,
    provisional_open_max_age,
)
from ._runtime.stream import StreamReadBuffer
from ._runtime.write_policy import fragment_cap
from ._state.open import (
    initial_local_opened_send_window,
    initial_send_window,
    projected_local_open_id,
    provisional_available_count,
)
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
from .config import Config, Limits, OpenOptions, clone_config
from .errors import (
    AcceptTimeout,
    ApplicationError,
    EmptyMetadataUpdate,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    GracefulCloseTimeout,
    KeepaliveTimeout,
    NilConnection,
    OpenExpired,
    OpenLimited,
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
)
from .events import Event, EventType, StreamEventInfo
from .frame import Frame, read_frame, write_frame
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
        seed = getattr(config.nonce_source, "seed", 0)
        if not isinstance(seed, int) or isinstance(seed, bool):
            seed = 0
        return cls(
            ping_padding=config.ping_padding,
            ping_padding_min=config.ping_padding_min_bytes,
            ping_padding_max=config.ping_padding_max_bytes,
            ping_nonce_state=init_session_nonce_state(seed),
            keepalive_jitter_state=init_keepalive_jitter_state(seed),
        )


@dataclass
class _PendingPing(object):
    done: threading.Event
    started_at: float
    rtt_holder: list[float]
    allows_padded_pong: bool
    error_holder: Optional[list[Optional[BaseException]]] = None


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
        "_accept_visibility",
        "_next_visibility_sequence",
        "_visible_accept_refused",
        "_terminal_state",
        "_terminal_streams",
        "_terminal_stream_causes",
        "_terminal_stream_order",
        "_lock",
        "_write_lock",
        "_closed_event",
        "_state",
        "_close_error",
        "_peer_go_away_error",
        "_peer_close_error",
        "_local_go_away_bidi",
        "_local_go_away_uni",
        "_peer_go_away_bidi",
        "_peer_go_away_uni",
        "_graceful_close_active",
        "_graceful_close_timeouts",
        "_sent_frames",
        "_received_frames",
        "_sent_data_bytes",
        "_received_data_bytes",
        "_aggregate_late_data_received",
        "_late_data_by_stream",
        "_late_data_after_close_read",
        "_late_data_after_reset",
        "_late_data_after_abort",
        "_hidden_unread_bytes_discarded",
        "_send_session_max",
        "_send_session_used",
        "_recv_session_received",
        "_recv_session_advertised",
        "_recv_stream_received",
        "_recv_stream_advertised",
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
        self._write_lock = threading.Lock()
        self._closed_event = threading.Event()
        self._state = SessionState.READY
        self._close_error: Optional[BaseException] = None
        self._peer_go_away_error: Optional[ApplicationError] = None
        self._peer_close_error: Optional[ApplicationError] = None
        self._local_go_away_bidi = MAX_VARINT62
        self._local_go_away_uni = MAX_VARINT62
        self._peer_go_away_bidi: Optional[int] = None
        self._peer_go_away_uni: Optional[int] = None
        self._graceful_close_active = False
        self._graceful_close_timeouts = 0
        self._sent_frames = 0
        self._received_frames = 0
        self._sent_data_bytes = 0
        self._received_data_bytes = 0
        self._aggregate_late_data_received = 0
        self._late_data_by_stream: dict[int, int] = {}
        self._late_data_after_close_read = 0
        self._late_data_after_reset = 0
        self._late_data_after_abort = 0
        self._hidden_unread_bytes_discarded = 0
        self._send_session_max = peer_preface.settings.initial_max_data
        self._send_session_used = 0
        self._recv_session_received = 0
        self._recv_session_advertised = local_preface.settings.initial_max_data
        self._recv_stream_received: dict[int, int] = {}
        self._recv_stream_advertised: dict[int, int] = {}
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
        self._reader_thread.start()
        self._keepalive_thread.start()

    @classmethod
    def establish(cls, transport: object, config: Config) -> "Conn":
        io = _FrameIO(transport)
        local = config.local_preface()
        peer = None
        try:
            io.write(config.local_preface_payload(local))
            io.flush()
            peer = read_preface(io)
            negotiated = negotiate_prefaces(local, peer)
        except BaseException as exc:
            _best_effort_send_establishment_close(io, local, peer, exc)
            _best_effort_close(io)
            raise
        return cls(transport, io, config, local, peer, negotiated)

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
        self._check_open(ErrorOperation.PING)
        echo_bytes = _bytes_like(echo, "echo")
        nonce = next_session_nonce(self._ping_state)
        padded_echo, allows_padded_pong = build_padded_ping_echo(
            self._ping_state,
            self._local_preface.settings,
            self._peer_preface.settings,
            echo_bytes,
            nonce,
        )
        payload = build_ping_payload(padded_echo, nonce)
        if len(payload) > self._peer_limits.max_control_payload_bytes:
            raise ValueError("ping payload exceeds peer max_control_payload_bytes")
        done = threading.Event()
        holder = [0.0]
        error_holder: list[Optional[BaseException]] = [None]
        pending = _PendingPing(
            done,
            time.monotonic(),
            holder,
            allows_padded_pong,
            error_holder,
        )
        with self._lock:
            self._pings[payload] = pending
            self._last_ping_sent_at = pending.started_at
            self._reset_max_ping_due_locked(pending.started_at)
            self._lock_notify_all()
        try:
            self._send_frame(Frame(FrameType.PING, 0, 0, payload))
            if not done.wait(maybe_timeout(timeout)):
                raise PingTimeout()
            if error_holder[0] is not None:
                raise error_holder[0]
            self._last_ping_rtt = holder[0]
            return holder[0]
        finally:
            with self._lock:
                self._pings.pop(payload, None)
                self._lock_notify_all()

    def go_away(
        self,
        last_accepted_bidi: int,
        last_accepted_uni: int,
        code: int = 0,
        reason: str = "",
    ) -> None:
        self._check_open(ErrorOperation.CLOSE)
        validate_go_away_watermark_for_direction(last_accepted_bidi, True)
        validate_go_away_watermark_creator(self._negotiated.peer_role, last_accepted_bidi)
        validate_go_away_watermark_for_direction(last_accepted_uni, False)
        validate_go_away_watermark_creator(self._negotiated.peer_role, last_accepted_uni)
        payload = build_go_away_payload(
            last_accepted_bidi,
            last_accepted_uni,
            code,
            reason,
            self._peer_limits.max_control_payload_bytes,
        )
        with self._lock:
            if (
                last_accepted_bidi > self._local_go_away_bidi
                or last_accepted_uni > self._local_go_away_uni
            ):
                raise ProtocolError("GOAWAY watermarks must be non-increasing")
            self._local_go_away_bidi = last_accepted_bidi
            self._local_go_away_uni = last_accepted_uni
            if not self._state.terminal():
                self._state = SessionState.DRAINING
        self._send_frame(Frame(FrameType.GOAWAY, 0, 0, payload))

    def close(self) -> None:
        drain_timeout = graceful_close_drain_timeout(
            self._runtime_policy.graceful_close_drain_timeout,
            self._last_ping_rtt,
        )
        await_existing = False
        graceful_drain = False
        send_initial_go_away = False
        initial_bidi = 0
        initial_uni = 0
        with self._lock:
            if self._state.terminal():
                return
            if self._state is SessionState.CLOSING or self._graceful_close_active:
                await_existing = True
            elif self._has_graceful_close_pending_work_locked():
                self._graceful_close_active = True
                self._state = SessionState.DRAINING
                graceful_drain = True
                send_initial_go_away = (
                    self._local_go_away_bidi == MAX_VARINT62
                    and self._local_go_away_uni == MAX_VARINT62
                )
                initial_bidi = self._effective_go_away_send_watermark_locked(True)
                initial_uni = self._effective_go_away_send_watermark_locked(False)
                self._lock_notify_all()
            else:
                self._graceful_close_active = True
                self._lock_notify_all()
        if await_existing:
            self._closed_event.wait(drain_timeout + 1.0)
            return
        close_error = None
        if graceful_drain:
            if send_initial_go_away:
                self._send_graceful_go_away(initial_bidi, initial_uni)
            self._sleep_unless_closed(
                go_away_drain_interval(
                    self._runtime_policy.go_away_drain_interval,
                    self._last_ping_rtt,
                )
            )
            with self._lock:
                if self._state.terminal():
                    return
                refined_bidi = min(self._local_go_away_bidi, self._last_accepted_peer_bidi)
                refined_uni = min(self._local_go_away_uni, self._last_accepted_peer_uni)
                send_refined = (
                    refined_bidi < self._local_go_away_bidi
                    or refined_uni < self._local_go_away_uni
                )
            if send_refined:
                self._send_graceful_go_away(refined_bidi, refined_uni)
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
        with self._lock:
            if self._state.terminal():
                return
            self._state = SessionState.CLOSING
        try:
            payload = build_error_payload(
                code,
                reason,
                self._peer_limits.max_control_payload_bytes,
            )
            self._send_frame(Frame(FrameType.CLOSE, 0, 0, payload))
        except BaseException as exc:
            self._finish(exc, failed=True, close_transport=True)
            return
        error = None
        failed = False
        if code:
            failed = True
            error = ApplicationError(
                code,
                reason,
                scope=ErrorScope.SESSION,
                operation=ErrorOperation.CLOSE,
                source=ErrorSource.LOCAL,
                termination_kind=TerminationKind.SESSION_TERMINATION,
            )
        self._finish(error, failed=failed, close_transport=True)

    def _send_graceful_go_away(self, bidi: int, uni: int) -> None:
        self.go_away(bidi, uni, int(ErrorCode.NO_ERROR), "")

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
        thread = self._reader_thread
        if thread is not threading.current_thread() and thread.is_alive():
            thread.join(0)
        keepalive_thread = self._keepalive_thread
        if (
            keepalive_thread is not threading.current_thread()
            and keepalive_thread.is_alive()
        ):
            keepalive_thread.join(0)

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
                ),
                pressure=PressureStats(
                    receive_backlog_bytes=self._recv_session_received,
                    aggregate_late_data_bytes=self._aggregate_late_data_received,
                    aggregate_late_data_at_cap=(
                        self._runtime_policy.aggregate_late_data_cap > 0
                        and self._aggregate_late_data_received
                        >= self._runtime_policy.aggregate_late_data_cap
                    ),
                    recv_session_advertised_bytes=self._recv_session_advertised,
                    recv_session_received_bytes=self._recv_session_received,
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
                        self._remember_terminal_stream_locked(
                            stream.stream_id,
                            stream.terminal_late_data_cause(),
                            action=stream.terminal_late_data_action(),
                            late_data_cap=stream.terminal_late_data_cap(),
                        )
                        self._streams.pop(stream.stream_id, None)
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
        with self._lock:
            self._check_open_locked(ErrorOperation.OPEN)
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
                raise OpenLimited()
            next_id = self._next_bidi if bidirectional else self._next_uni
            stream_id = projected_local_open_id(next_id, provisional_count)
            if stream_id > MAX_VARINT62:
                raise OpenLimited()
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
                metadata=StreamMetadata(
                    options.initial_priority,
                    options.initial_group,
                    options.open_info,
                ),
            )
            stream._provisional_created_at = time.monotonic()
            queue.append(stream)
            self._lock_notify_all()
        return stream

    def _send_frame(self, frame: Frame) -> None:
        self._check_open(ErrorOperation.WRITE)
        with self._write_lock:
            try:
                write_frame(self._io, frame, self._peer_limits)
                self._io.flush()
            except BaseException as exc:
                self._finish(exc, failed=True, close_transport=True)
                raise
        with self._lock:
            now = time.monotonic()
            self._sent_frames = _sat_add(self._sent_frames, 1)
            self._last_transport_write_at = now
            self._reset_write_idle_ping_due_locked(now)
            if frame.frame_type == FrameType.DATA:
                parsed = parse_data_payload_view(frame.payload, frame.flags)
                self._sent_data_bytes = _sat_add(
                    self._sent_data_bytes,
                    len(parsed.app_data),
                )
            elif frame.frame_type == FrameType.MAX_DATA:
                self._note_sent_max_data_frame_locked(frame)
            self._lock_notify_all()

    def _read_loop(self) -> None:
        while True:
            if self.closed:
                return
            try:
                frame = read_frame(self._io, self._local_limits)
            except TransportError as exc:
                if self.closed:
                    return
                self._finish(exc, failed=True, close_transport=True)
                return
            except BaseException as exc:
                if self.closed:
                    return
                self._finish(exc, failed=True, close_transport=True)
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
                self._finish(exc, failed=True, close_transport=True)
                return

    def _dispatch_frame(self, frame: Frame) -> None:
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
            self._send_frame(Frame(FrameType.PONG, 0, 0, payload))
        elif parsed.kind == ParsedFrameKind.PONG:
            self._handle_pong(frame.payload)
        elif parsed.kind == ParsedFrameKind.GO_AWAY:
            self._handle_go_away(parsed.go_away)
        elif parsed.kind == ParsedFrameKind.CLOSE:
            self._handle_close(frame.payload)
        elif parsed.kind == ParsedFrameKind.STOP_SENDING:
            self._handle_stop_sending(frame.stream_id, frame.payload)
        elif parsed.kind == ParsedFrameKind.RESET:
            self._handle_reset(frame.stream_id, frame.payload)
        elif parsed.kind == ParsedFrameKind.ABORT:
            self._handle_abort(frame.stream_id, frame.payload)
        elif parsed.kind == ParsedFrameKind.EXT:
            self._handle_ext(frame.stream_id, parsed.priority_update, parsed.priority_update_valid)
        elif parsed.kind == ParsedFrameKind.MAX_DATA:
            self._handle_max_data(parsed.stream_id, parsed.value, now)
        elif parsed.kind == ParsedFrameKind.BLOCKED:
            self._handle_blocked(now)

    def _handle_data(self, parsed, now: Optional[float] = None) -> None:
        with self._lock:
            existing = self._streams.get(parsed.stream_id)
            terminal = self._terminal_state.terminal_data_disposition_for(parsed.stream_id)
        terminal_found = terminal.found()
        if parsed.metadata is not None and (existing is not None or terminal_found):
            raise ProtocolError("OPEN_METADATA is only valid on the opening DATA frame")
        if terminal_found:
            self._handle_terminal_data(
                parsed.stream_id,
                len(parsed.app_data),
                terminal.disposition,
            )
            return
        stream = self._get_or_create_peer_stream(
            parsed.stream_id,
            parsed.metadata if parsed.metadata is not None else StreamMetadata(),
        )
        if stream is None:
            return
        app_data = parsed.app_data
        self._inbound_budget.update_no_op_zero_data(
            stream_existed=existing is not None,
            app_len=len(app_data),
            flags=parsed.frame.flags,
            now=now,
        )
        if app_data:
            if stream.read_closed:
                self._record_late_peer_data(
                    parsed.stream_id,
                    len(app_data),
                    LateDataCause.CLOSE_READ,
                    hidden=not stream.opened_locally
                    and stream not in self._accept_bidi
                    and stream not in self._accept_uni,
                )
                return
            self._check_receive_credit_for_data(stream, len(app_data))
            stream.receive_data(app_data)
            self._note_received_data_for_flow_control(stream, len(app_data))
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
    ) -> None:
        self._record_terminal_late_peer_data(stream_id, length, disposition.cause)
        if disposition.action is LateDataAction.ABORT_CLOSED:
            self._send_terminal_abort(stream_id, int(ErrorCode.STREAM_CLOSED))
        elif disposition.action is LateDataAction.ABORT_STATE:
            self._send_terminal_abort(stream_id, int(ErrorCode.STREAM_STATE))

    def _send_terminal_abort(self, stream_id: int, code: int) -> None:
        self._send_frame(
            Frame(
                FrameType.ABORT,
                stream_id,
                0,
                build_error_payload(
                    code,
                    "",
                    self._peer_limits.max_control_payload_bytes,
                ),
            )
        )

    def _get_or_create_peer_stream(
        self, stream_id: int, metadata: StreamMetadata
    ) -> Optional["NativeStream"]:
        refused = ()
        with self._lock:
            existing = self._streams.get(stream_id)
            if existing is not None:
                stream = existing
            else:
                if self._terminal_state.has_terminal_marker(stream_id):
                    return None
                if stream_is_local(self._local_role, stream_id):
                    raise ProtocolError("peer used locally-owned stream_id %d" % stream_id)
                bidirectional = stream_is_bidi(stream_id)
                local_send, local_receive = stream_kind_for_local(self._local_role, stream_id)
                expected = self._next_peer_bidi if bidirectional else self._next_peer_uni
                if expected > MAX_VARINT62:
                    raise ProtocolError("peer stream id overflow")
                if stream_id != expected:
                    raise ProtocolError("peer stream id skipped expected id")
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
                if self._peer_open_refused_locked(stream_id, bidirectional):
                    self._remember_terminal_stream_locked(
                        stream_id,
                        LateDataCause.ABORT,
                    )
                    refused = (stream,)
                    self._lock_notify_all()
                    stream = None
                elif not self._peer_stream_within_limit_locked(bidirectional):
                    self._remember_terminal_stream_locked(
                        stream_id,
                        LateDataCause.ABORT,
                    )
                    refused = (stream,)
                    self._lock_notify_all()
                    stream = None
                else:
                    self._streams[stream_id] = stream
                    self._next_visibility_sequence = _sat_add(
                        self._next_visibility_sequence,
                        1,
                    )
                    self._accept_visibility[stream_id] = self._next_visibility_sequence
                    if bidirectional:
                        self._accept_bidi.append(stream)
                    else:
                        self._accept_uni.append(stream)
                    refused = self._enforce_accept_backlog_locked()
                    self._lock_notify_all()
        for refused_stream in refused:
            self._send_refused_stream_abort(refused_stream)
        if stream is None or stream in refused:
            return None
        return stream

    def _record_late_peer_data(
        self,
        stream_id: int,
        length: int,
        cause: LateDataCause,
        *,
        hidden: bool,
    ) -> None:
        if length <= 0:
            return
        max_data = None
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                length,
            ):
                raise ProtocolError("session max_data exceeded")
            self._recv_session_received = _sat_add(self._recv_session_received, length)
            self._received_data_bytes = _sat_add(self._received_data_bytes, length)
            self._aggregate_late_data_received = _sat_add(
                self._aggregate_late_data_received,
                length,
            )
            self._late_data_by_stream[stream_id] = _sat_add(
                self._late_data_by_stream.get(stream_id, 0),
                length,
            )
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
            desired = min(MAX_VARINT62, self._recv_session_advertised + length)
            if desired > self._recv_session_advertised:
                self._recv_session_advertised = desired
                max_data = desired
            self._check_late_data_caps_locked(stream_id)
        if max_data is not None:
            self._send_frame(Frame(FrameType.MAX_DATA, 0, 0, encode_varint(max_data)))

    def _record_terminal_late_peer_data(
        self,
        stream_id: int,
        length: int,
        cause: LateDataCause,
    ) -> None:
        if length <= 0:
            return
        max_data = None
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                length,
            ):
                raise ProtocolError("session max_data exceeded")
            terminal_result = self._terminal_state.record_terminal_late_data(
                stream_id,
                length,
            )
            self._recv_session_received = _sat_add(self._recv_session_received, length)
            self._received_data_bytes = _sat_add(self._received_data_bytes, length)
            self._aggregate_late_data_received = _sat_add(
                self._aggregate_late_data_received,
                length,
            )
            self._late_data_by_stream[stream_id] = _sat_add(
                self._late_data_by_stream.get(stream_id, 0),
                length,
            )
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
            if terminal_result.hidden:
                self._hidden_unread_bytes_discarded = _sat_add(
                    self._hidden_unread_bytes_discarded,
                    length,
                )
            desired = min(MAX_VARINT62, self._recv_session_advertised + length)
            if desired > self._recv_session_advertised:
                self._recv_session_advertised = desired
                max_data = desired
            if terminal_result.cap_exceeded:
                raise ProtocolError("late-data cap exceeded")
            self._check_late_data_caps_locked(stream_id)
        if max_data is not None:
            self._send_frame(Frame(FrameType.MAX_DATA, 0, 0, encode_varint(max_data)))

    def _check_late_data_caps_locked(self, stream_id: int) -> None:
        aggregate_cap = self._runtime_policy.aggregate_late_data_cap
        if aggregate_cap and self._aggregate_late_data_received > aggregate_cap:
            raise ProtocolError("late-data cap exceeded")
        per_stream_cap = self._late_data_per_stream_cap_locked(stream_id)
        if per_stream_cap and self._late_data_by_stream.get(stream_id, 0) > per_stream_cap:
            raise ProtocolError("late-data cap exceeded")

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
        app = (
            None
            if parsed.code == 0
            else ApplicationError(
                parsed.code,
                parsed.reason,
                scope=ErrorScope.SESSION,
                operation=ErrorOperation.CLOSE,
                source=ErrorSource.REMOTE,
                termination_kind=TerminationKind.SESSION_TERMINATION,
            )
        )
        reclaimed: list[NativeStream] = []
        with self._lock:
            changed = (
                self._peer_go_away_bidi is None
                or self._peer_go_away_uni is None
                or parsed.last_accepted_bidi < self._peer_go_away_bidi
                or parsed.last_accepted_uni < self._peer_go_away_uni
            )
            self._peer_go_away_bidi = parsed.last_accepted_bidi
            self._peer_go_away_uni = parsed.last_accepted_uni
            self._peer_go_away_error = app
            reclaimed.extend(
                self._reclaim_provisionals_locked(True, parsed.last_accepted_bidi)
            )
            reclaimed.extend(
                self._reclaim_provisionals_locked(False, parsed.last_accepted_uni)
            )
            for stream in tuple(self._streams.values()):
                if not stream.opened_locally or stream._opened_sent or stream.closed:
                    continue
                watermark = (
                    parsed.last_accepted_bidi
                    if stream.bidirectional
                    else parsed.last_accepted_uni
                )
                if stream.stream_id > watermark:
                    reclaimed.append(stream)
            if not self._state.terminal():
                self._state = SessionState.DRAINING
            self._lock_notify_all()
        if changed:
            self._inbound_budget.clear_no_op_control_budgets()
        else:
            self._inbound_budget.record_ignored_control()
        for stream in reclaimed:
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
            stream.abort(error)

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

    def _handle_stop_sending(self, stream_id: int, payload: bytes) -> None:
        code, reason = parse_error_payload(payload)
        stream = self._streams.get(stream_id)
        if stream is None:
            self._ignore_terminal_control_or_raise(stream_id, "STOP_SENDING")
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
        send_reset = stream._local_send and not stream.write_closed
        stream.stop_write(app)
        if send_reset:
            self._send_frame(
                Frame(
                    FrameType.RESET,
                    stream_id,
                    0,
                    build_error_payload(
                        int(ErrorCode.CANCELLED),
                        "",
                        self._peer_limits.max_control_payload_bytes,
                    ),
                )
            )

    def _handle_reset(self, stream_id: int, payload: bytes) -> None:
        code, reason = parse_error_payload(payload)
        stream = self._streams.get(stream_id)
        if stream is None:
            self._ignore_terminal_control_or_raise(stream_id, "RESET")
            return
        self._note_reason(self._reset_reasons, code, "_reset_overflow")
        stream.reset_read(
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

    def _handle_abort(self, stream_id: int, payload: bytes) -> None:
        code, reason = parse_error_payload(payload)
        stream = self._streams.get(stream_id)
        if stream is None:
            self._note_reason(self._abort_reasons, code, "_abort_overflow")
            self._remember_hidden_peer_abort(stream_id)
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

    def _ignore_terminal_control_or_raise(self, stream_id: int, frame_name: str) -> None:
        with self._lock:
            if self._terminal_state.has_terminal_marker(stream_id):
                return
        raise ProtocolError("%s on unknown stream %d" % (frame_name, stream_id))

    def _remember_hidden_peer_abort(self, stream_id: int) -> None:
        with self._lock:
            if self._terminal_state.has_terminal_marker(stream_id):
                return
            if stream_is_local(self._local_role, stream_id):
                raise ProtocolError("peer used locally-owned stream_id %d" % stream_id)
            bidirectional = stream_is_bidi(stream_id)
            expected = self._next_peer_bidi if bidirectional else self._next_peer_uni
            if expected > MAX_VARINT62:
                raise ProtocolError("peer stream id overflow")
            if stream_id != expected:
                raise ProtocolError("peer stream id skipped expected id")
            if bidirectional:
                self._next_peer_bidi += 4
            else:
                self._next_peer_uni += 4
            self._remember_terminal_stream_locked(
                stream_id,
                LateDataCause.ABORT,
                hidden=True,
            )
            self._lock_notify_all()

    def _handle_ext(
        self,
        stream_id: int,
        metadata: Optional[StreamMetadata],
        valid: bool,
    ) -> None:
        if not valid or metadata is None:
            return
        stream = self._streams.get(stream_id)
        if stream is not None:
            stream.apply_metadata_update(metadata)

    def _handle_max_data(
        self, stream_id: int, value: Optional[int], now: Optional[float] = None
    ) -> None:
        if value is None:
            return
        updated = False
        with self._lock:
            if stream_id == 0:
                if value > self._send_session_max:
                    self._send_session_max = value
                    updated = True
                    self._lock_notify_all()
            else:
                stream = self._streams.get(stream_id)
                if stream is None or not stream._local_send:
                    return
                if value > stream._send_max:
                    stream._send_max = value
                    updated = True
                    self._lock_notify_all()
        if updated:
            self._inbound_budget.clear_no_op_max_data()
        else:
            self._inbound_budget.record_no_op_max_data(now)

    def _handle_blocked(self, now: Optional[float] = None) -> None:
        self._inbound_budget.record_no_op_blocked(now)

    def _note_received_data_for_flow_control(
        self, stream: "NativeStream", byte_count: int
    ) -> None:
        if byte_count <= 0:
            return
        updates = []
        with self._lock:
            self._recv_session_received = _sat_add(
                self._recv_session_received,
                byte_count,
            )
            session_max = _next_receive_credit(
                self._recv_session_received,
                self._recv_session_advertised,
                self._local_preface.settings.initial_max_data,
            )
            if session_max is not None:
                self._recv_session_advertised = session_max
                updates.append((0, session_max))

            stream_id = stream.stream_id
            stream_window = self._initial_receive_credit_for_stream(stream)
            received = _sat_add(
                self._recv_stream_received.get(stream_id, 0),
                byte_count,
            )
            advertised = self._recv_stream_advertised.get(stream_id, stream_window)
            stream_max = _next_receive_credit(received, advertised, stream_window)
            self._recv_stream_received[stream_id] = received
            if stream_max is not None:
                self._recv_stream_advertised[stream_id] = stream_max
                updates.append((stream_id, stream_max))

        for stream_id, max_data in updates:
            self._send_frame(Frame(FrameType.MAX_DATA, stream_id, 0, encode_varint(max_data)))

    def _check_receive_credit_for_data(
        self, stream: "NativeStream", byte_count: int
    ) -> None:
        if byte_count <= 0:
            return
        with self._lock:
            if receive_window_exceeded(
                self._recv_session_received,
                self._recv_session_advertised,
                byte_count,
            ):
                raise ProtocolError("session max_data exceeded")
            stream_id = stream.stream_id
            stream_window = self._initial_receive_credit_for_stream(stream)
            advertised = self._recv_stream_advertised.get(stream_id, stream_window)
            received = self._recv_stream_received.get(stream_id, 0)
            if receive_window_exceeded(received, advertised, byte_count):
                raise ProtocolError("stream max_data exceeded")

    def _note_sent_max_data_frame_locked(self, frame: Frame) -> None:
        try:
            value, consumed = parse_varint(frame.payload)
        except Exception:
            return
        if consumed != len(frame.payload):
            return
        if frame.stream_id == 0:
            self._recv_session_advertised = max(self._recv_session_advertised, value)
        else:
            current = self._recv_stream_advertised.get(frame.stream_id)
            if current is None:
                stream = self._streams.get(frame.stream_id)
                current = 0 if stream is None else self._initial_receive_credit_for_stream(stream)
            self._recv_stream_advertised[frame.stream_id] = max(
                current,
                value,
            )

    def _send_credit_available(self, stream: "NativeStream") -> int:
        with self._lock:
            return min(
                max(0, self._send_session_max - self._send_session_used),
                max(0, stream._send_max - stream._send_sent),
            )

    def _reserve_send_credit(
        self,
        stream: "NativeStream",
        byte_count: int,
        timeout_deadline: Optional[float],
    ) -> int:
        if byte_count <= 0:
            return 0
        session_blocked_sent = False
        stream_blocked_sent = False
        while True:
            blocked = []
            with self._lock:
                self._check_open_locked(ErrorOperation.WRITE)
                stream._check_writable()
                session_credit = max(0, self._send_session_max - self._send_session_used)
                stream_credit = max(0, stream._send_max - stream._send_sent)
                chunk = min(byte_count, session_credit, stream_credit)
                if chunk > 0:
                    self._send_session_used = _sat_add(self._send_session_used, chunk)
                    stream._send_sent = _sat_add(stream._send_sent, chunk)
                    return chunk
                if session_credit == 0 and not session_blocked_sent:
                    blocked.append((0, self._send_session_max))
                    session_blocked_sent = True
                if stream_credit == 0 and not stream_blocked_sent:
                    blocked.append((stream.stream_id, stream._send_max))
                    stream_blocked_sent = True
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
                self._send_frame(
                    Frame(FrameType.BLOCKED, blocked_stream_id, 0, encode_varint(limit))
                )

    def _notify_stream_state_changed(self) -> None:
        with self._lock:
            self._lock_notify_all()

    def _initial_receive_credit_for_stream(self, stream: "NativeStream") -> int:
        settings = self._local_preface.settings
        if not stream.bidirectional:
            return settings.initial_max_stream_data_uni
        if stream.opened_locally:
            return settings.initial_max_stream_data_bidi_locally_opened
        return settings.initial_max_stream_data_bidi_peer_opened

    def _finish(
        self,
        error: Optional[BaseException],
        *,
        failed: bool,
        close_transport: bool,
    ) -> None:
        streams = []
        with self._lock:
            if self._state.terminal():
                return
            self._state = SessionState.FAILED if failed else SessionState.CLOSED
            self._close_error = error
            streams = list(self._streams.values())
            streams.extend(self._provisional_bidi)
            streams.extend(self._provisional_uni)
            self._streams.clear()
            self._accept_bidi.clear()
            self._accept_uni.clear()
            self._provisional_bidi.clear()
            self._provisional_uni.clear()
            pending_pings = list(self._pings.values())
            self._pings.clear()
            self._lock_notify_all()
            self._closed_event.set()
        for stream in streams:
            stream.session_closed(error)
        for pending in pending_pings:
            if pending.error_holder is not None and pending.error_holder[0] is None:
                pending.error_holder[0] = error or SessionClosed(
                    operation=ErrorOperation.PING,
                    source=ErrorSource.LOCAL,
                )
            pending.done.set()
        if close_transport:
            _best_effort_close(self._io)
        self._emit_event(
            Event(
                EventType.SESSION_CLOSED,
                session_state=self._state,
                error=error,
            )
        )

    def _check_open(self, operation: ErrorOperation) -> None:
        with self._lock:
            self._check_open_locked(operation)

    def _check_open_locked(self, operation: ErrorOperation) -> None:
        if self._state.terminal():
            raise self._visible_closed_error(operation)

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
        if (
            self._accept_bidi
            or self._accept_uni
            or self._provisional_bidi
            or self._provisional_uni
        ):
            return True
        return any(not stream.closed for stream in self._streams.values())

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
            if created is None or max_age <= 0 or now - created <= max_age:
                return
            queue.popleft()
            self._fail_provisional_locked(stream, OpenExpired())

    def _reclaim_provisionals_locked(
        self, bidirectional: bool, peer_watermark: int
    ) -> Tuple["NativeStream", ...]:
        queue = self._provisional_queue_locked(bidirectional)
        next_id = self._next_bidi if bidirectional else self._next_uni
        available = provisional_available_count(next_id, peer_watermark)
        reclaimed = []
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
            self._fail_provisional_locked(stream, error)
            reclaimed.append(stream)
        return tuple(reclaimed)

    def _commit_local_open(
        self, stream: "NativeStream", timeout_deadline: Optional[float]
    ) -> None:
        bidirectional = stream.bidirectional
        with self._lock:
            while True:
                if stream._opened_sent or self._streams.get(stream._stream_id) is stream:
                    return
                self._check_open_locked(ErrorOperation.WRITE)
                if stream._write_error is not None:
                    raise stream._write_error
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
                    head_created = queue[0]._provisional_created_at
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
                    self._lock_wait(wait_for)
                    continue

                stream_id = self._next_bidi if bidirectional else self._next_uni
                if stream_id > MAX_VARINT62:
                    queue.popleft()
                    error = OpenLimited()
                    self._fail_provisional_locked(stream, error)
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
                self._lock_notify_all()
                return

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
            self._remember_terminal_stream_locked(
                stream.stream_id,
                stream.terminal_late_data_cause(),
                action=stream.terminal_late_data_action(),
                late_data_cap=stream.terminal_late_data_cap(),
            )
            self._streams.pop(stream.stream_id, None)
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
            self._remember_terminal_stream_locked(
                stream.stream_id,
                LateDataCause.ABORT,
            )
            self._streams.pop(stream.stream_id, None)
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

    def _peer_stream_within_limit_locked(self, bidirectional: bool) -> bool:
        limit = (
            self._local_preface.settings.max_incoming_streams_bidi
            if bidirectional
            else self._local_preface.settings.max_incoming_streams_uni
        )
        active = 0
        for stream in self._streams.values():
            if not stream.opened_locally and stream.bidirectional == bidirectional:
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
        self._send_frame(
            Frame(
                FrameType.ABORT,
                stream.stream_id,
                0,
                build_error_payload(
                    int(ErrorCode.REFUSED_STREAM),
                    "",
                    self._peer_limits.max_control_payload_bytes,
                ),
            )
        )

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
            self._lock_wait(None if delay <= 0 else delay)
            return self._state.terminal()

    def _keepalive_loop(self) -> None:
        while True:
            with self._lock:
                delay, send_ping, timed_out = self._next_keepalive_action_locked(
                    time.monotonic()
                )
                if self._state.terminal() or self._keepalive_interval_locked() <= 0:
                    return
            if timed_out:
                self._finish(KeepaliveTimeout(), failed=True, close_transport=True)
                return
            if send_ping:
                timeout = None
                with self._lock:
                    effective_timeout = self._effective_keepalive_timeout_locked()
                    if effective_timeout > 0:
                        timeout = effective_timeout
                try:
                    self.ping(timeout=timeout)
                except PingTimeout:
                    self._finish(KeepaliveTimeout(), failed=True, close_transport=True)
                    return
                except SessionClosed:
                    return
                except BaseException as exc:
                    if self.closed:
                        return
                    self._finish(exc, failed=True, close_transport=True)
                    return
                continue
            if self._wait_keepalive_delay(delay):
                return

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
        "_read_buf",
        "_read_buffered",
        "_read_finished",
        "_read_closed",
        "_read_error",
        "_write_closed",
        "_write_error",
        "_send_max",
        "_send_sent",
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
        self._read_buf = StreamReadBuffer()
        self._read_buffered = 0
        self._read_finished = not local_receive
        self._read_closed = not local_receive
        self._read_error: Optional[BaseException] = None
        self._write_closed = not local_send
        self._write_error: Optional[BaseException] = None
        if opened_locally and stream_id == 0 and local_send:
            self._send_max = initial_local_opened_send_window(
                session.peer_preface().settings,
                bidirectional,
            )
        else:
            self._send_max = _initial_stream_send_max(session, stream_id, local_send)
        self._send_sent = 0
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
        with self._cond:
            self._check_readable()
            while self._read_buf.is_empty():
                if self._read_error is not None:
                    raise self._read_error
                if self._read_finished:
                    bytes_read = 0
                    break
                deadline = _merge_deadline(self._read_deadline, timeout_deadline)
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise ReadTimeout()
                self._cond.wait(remaining)
            else:
                result = self._read_buf.readinto(view)
                bytes_read = result.bytes_read
                self._read_buffered = len(self._read_buf)
                self._cond.notify_all()
        return bytes_read

    def read_vectored(
        self, buffers: Iterable[WritableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        views = _writable_views(buffers)
        if not views:
            return 0
        timeout_deadline = deadline_after(timeout)
        with self._cond:
            self._check_readable()
            while self._read_buf.is_empty():
                if self._read_error is not None:
                    raise self._read_error
                if self._read_finished:
                    return 0
                deadline = _merge_deadline(self._read_deadline, timeout_deadline)
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise ReadTimeout()
                self._cond.wait(remaining)

            result = self._read_buf.readv_into(views)
            total = result.bytes_read
            self._read_buffered = len(self._read_buf)
            self._cond.notify_all()
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
            if self._read_error is not None:
                raise self._read_error
            if self._read_closed or self._read_finished:
                raise self._read_closed_error()
            self._read_closed = True
            self._read_finished = True
            self._read_buf.clear()
            self._read_buffered = 0
            self._cond.notify_all()
            forget = self.closed
        self._ensure_opened_before_terminal()
        self._session.send_frame(Frame(FrameType.STOP_SENDING, self._stream_id, 0, payload))
        if forget:
            self._session.forget_stream(self)

    def close_write(self, *, timeout: Optional[float] = None) -> None:
        if self._write_closed:
            return
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
        self._session.send_frame(Frame(FrameType.RESET, self._stream_id, 0, payload))
        with self._cond:
            self._write_closed = True
            self._write_error = app
            self._cond.notify_all()
            forget = self.closed
        if forget:
            self._session.forget_stream(self)

    def update_metadata(self, update: MetadataUpdate) -> None:
        if not isinstance(update, MetadataUpdate):
            raise TypeError("update must be MetadataUpdate")
        if update.is_empty():
            raise EmptyMetadataUpdate()
        self._check_writable()
        metadata = StreamMetadata(
            update.priority if update.priority is not None else self._metadata.priority,
            update.group if update.group is not None else self._metadata.group,
            self._metadata.open_info,
        )
        if not self._opened_sent:
            capabilities = self._session.negotiated().capabilities
            validate_open_metadata_update_capability(capabilities, update)
            build_open_metadata_prefix(
                capabilities,
                metadata.priority,
                metadata.group,
                metadata.open_info,
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
        self._session.send_frame(Frame(FrameType.EXT, self._stream_id, 0, payload))
        self._metadata = metadata

    def close(self) -> None:
        errors = []
        try:
            if self._local_send and not self._write_closed:
                self.close_write()
        except BaseException as exc:
            errors.append(exc)
        try:
            if self._local_receive and not self._read_closed:
                self.close_read()
        except BaseException as exc:
            errors.append(exc)
        self._closed = True
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
        abort_provisional = getattr(self._session, "_abort_provisional_open", None)
        if abort_provisional is not None and abort_provisional(self, app):
            return
        self._ensure_opened_before_terminal()
        self._session.send_frame(Frame(FrameType.ABORT, self._stream_id, 0, payload))
        self._abort(app)
        self._session.forget_stream(self)

    def _send_data(
        self, data: memoryview, *, fin: bool, timeout: Optional[float]
    ) -> None:
        parts = () if len(data) == 0 else (data,)
        self._send_data_vectored(parts, fin=fin, timeout=timeout)

    def _send_data_vectored(
        self,
        parts: Tuple[memoryview, ...],
        *,
        fin: bool,
        timeout: Optional[float],
    ) -> None:
        parts = tuple(part for part in parts if len(part) > 0)
        timeout_deadline = deadline_after(timeout)
        with self._write_mutex:
            self._check_writable()
            deadline = _merge_deadline(self._write_deadline, timeout_deadline)
            if _remaining(deadline) == 0:
                raise WriteTimeout()
            first = not self._opened_sent
            if first:
                self._session._commit_local_open(self, timeout_deadline)
            prefix = b""
            first_flags = 0
            if first:
                prefix = build_open_metadata_prefix(
                    self._session.negotiated().capabilities,
                    self._metadata.priority,
                    self._metadata.group,
                    self._metadata.open_info,
                    self._session.peer_limits.max_frame_payload,
                )
                if prefix:
                    first_flags |= FRAME_FLAG_OPEN_METADATA
            if not parts and not fin and not prefix:
                return
            part_index = 0
            part_offset = 0
            while first or part_index < len(parts) or fin:
                deadline = _merge_deadline(self._write_deadline, timeout_deadline)
                if _remaining(deadline) == 0:
                    raise WriteTimeout()
                max_payload = self._session.peer_limits.max_frame_payload
                if len(prefix) > max_payload:
                    raise ValueError("open metadata exceeds peer max_frame_payload")
                room = fragment_cap(
                    max_payload,
                    len(prefix),
                    self._metadata.priority or 0,
                    self._session.negotiated().peer_settings.scheduler_hints,
                )
                desired = 0
                if part_index < len(parts) and room > 0:
                    current = parts[part_index]
                    desired = min(len(current) - part_offset, room)
                if desired > 0:
                    credit_available = getattr(self._session, "_send_credit_available", None)
                    if first and prefix and credit_available is not None and credit_available(self) == 0:
                        take = 0
                    else:
                        reserve = getattr(self._session, "_reserve_send_credit", None)
                        take = (
                            reserve(self, desired, timeout_deadline)
                            if reserve is not None
                            else desired
                        )
                    current = parts[part_index]
                    chunk = current[part_offset: part_offset + take]
                    part_offset += take
                    if part_offset >= len(current):
                        part_index += 1
                        part_offset = 0
                elif part_index < len(parts) and room <= 0 and not prefix:
                    raise ValueError("peer max_frame_payload leaves no DATA payload room")
                else:
                    chunk = memoryview(b"")
                remaining = part_index < len(parts)
                is_final = fin and not remaining
                flags = first_flags | (FRAME_FLAG_FIN if is_final else 0)
                payload = prefix + chunk.tobytes()
                self._session.send_frame(Frame(FrameType.DATA, self._stream_id, flags, payload))
                if first:
                    self._opened_sent = True
                    self._session.emit_stream_opened(self)
                first = False
                prefix = b""
                first_flags = 0
                if not remaining:
                    if fin:
                        with self._cond:
                            self._write_closed = True
                            self._cond.notify_all()
                            forget = self.closed
                        if forget:
                            self._session.forget_stream(self)
                    return

    def _ensure_opened_before_terminal(self) -> None:
        if self._opened_sent:
            return
        self._send_data(memoryview(b""), fin=False, timeout=None)
        if not self._opened_sent:
            self._session.send_frame(Frame(FrameType.DATA, self._stream_id, 0, b""))
            self._opened_sent = True
            self._session.emit_stream_opened(self)

    def receive_data(self, data: memoryview) -> None:
        self._receive_data(data)

    def receive_fin(self) -> None:
        self._receive_fin()

    def stop_write(self, error: BaseException) -> None:
        self._stop_write(error)

    def reset_read(self, error: BaseException) -> None:
        self._reset_read(error)

    def abort(self, error: BaseException) -> None:
        self._abort(error)

    def session_closed(self, error: Optional[BaseException]) -> None:
        self._session_closed(error)

    def apply_metadata_update(self, metadata: StreamMetadata) -> None:
        self._apply_metadata_update(metadata)

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
        if self._local_receive and self._read_finished and not self._read_closed and self._read_error is None:
            return LateDataAction.ABORT_CLOSED
        return LateDataAction.IGNORE

    def terminal_late_data_cap(self) -> Optional[int]:
        if not self._local_receive or self._stream_id == 0:
            return None
        return self._session._late_data_per_stream_cap_locked(self._stream_id)

    def _receive_data(self, data: memoryview) -> None:
        view = memoryview(data)
        if not view:
            return
        with self._cond:
            limit = self._session.config.per_stream_queued_data_hwm or 256 * 1024
            while (
                limit
                and self._read_buffered + len(view) > limit
                and not self._read_closed
                and self._read_error is None
            ):
                self._cond.wait(0.05)
            if self._read_closed:
                return
            self._read_buf.append(view)
            self._read_buffered = len(self._read_buf)
            self._cond.notify_all()

    def _receive_fin(self) -> None:
        with self._cond:
            self._read_finished = True
            self._cond.notify_all()
            forget = self.closed
        if forget:
            self._session.forget_stream(self)

    def _stop_write(self, error: BaseException) -> None:
        with self._cond:
            self._write_closed = True
            self._write_error = error
            self._cond.notify_all()
            forget = self.closed
        self._session._notify_stream_state_changed()
        if forget:
            self._session.forget_stream(self)

    def _reset_read(self, error: BaseException) -> None:
        with self._cond:
            self._read_finished = True
            self._read_error = error
            self._cond.notify_all()
            forget = self.closed
        if forget:
            self._session.forget_stream(self)

    def _abort(self, error: BaseException) -> None:
        with self._cond:
            self._read_finished = True
            self._read_closed = True
            self._write_closed = True
            self._closed = True
            self._read_error = error
            self._write_error = error
            self._cond.notify_all()
        self._session._notify_stream_state_changed()
        self._session.forget_stream(self)

    def _session_closed(self, error: Optional[BaseException]) -> None:
        with self._cond:
            self._read_finished = True
            self._read_error = error
            self._write_error = error
            self._read_closed = True
            self._write_closed = True
            self._closed = True
            self._cond.notify_all()
        self._session._notify_stream_state_changed()
        self._session.forget_stream(self)

    def _apply_metadata_update(self, metadata: StreamMetadata) -> None:
        self._metadata = StreamMetadata(
            metadata.priority if metadata.priority is not None else self._metadata.priority,
            metadata.group if metadata.group is not None else self._metadata.group,
            self._metadata.open_info,
        )

    def _check_readable(self) -> None:
        if not self._local_receive:
            raise StreamNotReadable()
        if self._read_closed and self._read_buf.is_empty():
            raise self._read_closed_error()

    def _read_closed_error(self) -> ReadClosed:
        if self._read_closed:
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

    def _read_terminal(self) -> bool:
        return (
            not self._local_receive
            or self._read_closed
            or self._read_finished
            or self._read_error is not None
        )

    def _write_terminal(self) -> bool:
        return not self._local_send or self._write_closed or self._write_error is not None


class _FrameIO(object):
    __slots__ = ("_transport",)

    def __init__(self, transport: object) -> None:
        self._transport = transport

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
            return len(view)
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


def _remaining(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


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


def _next_receive_credit(
    received: int,
    advertised: int,
    window: int,
) -> Optional[int]:
    if window <= 0 or advertised >= MAX_VARINT62:
        return None
    remaining = max(0, advertised - received)
    if remaining > max(1, window // 2):
        return None
    return min(MAX_VARINT62, received + window)


def _best_effort_close(obj: object) -> None:
    try:
        close = getattr(obj, "close", None)
        if close is not None:
            close()
    except BaseException:
        pass


def _best_effort_send_establishment_close(
    io: "_FrameIO",
    local: Preface,
    peer: Optional[Preface],
    error: BaseException,
) -> None:
    try:
        io.write(build_establishment_close_frame(local, peer, error))
        io.flush()
        delay = establishment_close_drain_delay(error)
        if delay > 0:
            time.sleep(delay)
    except BaseException:
        pass


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
