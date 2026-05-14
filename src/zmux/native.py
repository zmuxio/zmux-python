"""Native synchronous ZMux session implementation."""

from __future__ import annotations

import secrets
import socket
import threading
import time
from collections import deque
from dataclasses import replace
from types import TracebackType
from typing import Deque, Iterable, Optional, Type

from ._state.stream_id import (
    first_local_stream_id,
    stream_is_bidi,
    stream_is_local,
    stream_kind_for_local,
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
    NilConnection,
    PingTimeout,
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
    parse_go_away_payload,
    parse_priority_update_payload,
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
from .session import ActiveStreamStats, ReasonStats, SessionState, SessionStats
from .streams import ReadableBuffer, WritableBuffer, maybe_timeout
from .transports import DEFAULT_READ_CHUNK, SocketTransport, ZmuxSocketAddress, deadline_after


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


class Conn:
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
        "_local_limits",
        "_peer_limits",
        "_local_role",
        "_next_bidi",
        "_next_uni",
        "_streams",
        "_accept_bidi",
        "_accept_uni",
        "_lock",
        "_write_lock",
        "_closed_event",
        "_state",
        "_close_error",
        "_peer_go_away_error",
        "_peer_close_error",
        "_sent_frames",
        "_received_frames",
        "_sent_data_bytes",
        "_received_data_bytes",
        "_open_streams",
        "_accepted_streams",
        "_reset_reasons",
        "_abort_reasons",
        "_reset_overflow",
        "_abort_overflow",
        "_pings",
        "_last_ping_rtt",
        "_reader_thread",
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
        self._local_limits = local_preface.settings.limits()
        self._peer_limits = peer_preface.settings.limits()
        self._local_role = negotiated.local_role
        self._next_bidi = first_local_stream_id(self._local_role, True)
        self._next_uni = first_local_stream_id(self._local_role, False)
        self._streams: dict[int, NativeStream] = {}
        self._accept_bidi: Deque[NativeStream] = deque()
        self._accept_uni: Deque[NativeStream] = deque()
        self._lock = threading.Condition(threading.RLock())
        self._write_lock = threading.Lock()
        self._closed_event = threading.Event()
        self._state = SessionState.READY
        self._close_error: Optional[BaseException] = None
        self._peer_go_away_error: Optional[ApplicationError] = None
        self._peer_close_error: Optional[ApplicationError] = None
        self._sent_frames = 0
        self._received_frames = 0
        self._sent_data_bytes = 0
        self._received_data_bytes = 0
        self._open_streams = 0
        self._accepted_streams = 0
        self._reset_reasons: dict[int, int] = {}
        self._abort_reasons: dict[int, int] = {}
        self._reset_overflow = 0
        self._abort_overflow = 0
        self._pings: dict[bytes, tuple[threading.Event, float, list[float]]] = {}
        self._last_ping_rtt = 0.0
        self._reader_thread = threading.Thread(
            target=self._read_loop,
            name="zmux-reader",
            daemon=True,
        )
        self._reader_thread.start()

    @classmethod
    def establish(cls, transport: object, config: Config) -> "Conn":
        io = _FrameIO(transport)
        local = config.local_preface()
        try:
            io.write(config.local_preface_payload(local))
            io.flush()
            peer = read_preface(io)
            negotiated = negotiate_prefaces(local, peer)
        except BaseException:
            _best_effort_close(io)
            raise
        return cls(transport, io, config, local, peer, negotiated)

    _establish = establish

    def __enter__(self) -> "Conn":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
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
        stream.write_all(data, timeout=_remaining_after(start, timeout))
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
        stream.write_final(data, timeout=_remaining_after(start, timeout))
        return stream

    def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        self._check_open(ErrorOperation.PING)
        echo_bytes = _bytes_like(echo, "echo")
        payload = secrets.token_bytes(8) + echo_bytes
        if len(payload) > self._peer_limits.max_control_payload_bytes:
            raise ValueError("ping payload exceeds peer max_control_payload_bytes")
        done = threading.Event()
        holder = [0.0]
        with self._lock:
            self._pings[payload] = (done, time.monotonic(), holder)
        try:
            self._send_frame(Frame(FrameType.PING, 0, 0, payload))
            if not done.wait(maybe_timeout(timeout)):
                raise PingTimeout()
            self._last_ping_rtt = holder[0]
            return holder[0]
        finally:
            with self._lock:
                self._pings.pop(payload, None)

    def go_away(
        self,
        last_accepted_bidi: int,
        last_accepted_uni: int,
        code: int = 0,
        reason: str = "",
    ) -> None:
        self._check_open(ErrorOperation.CLOSE)
        payload = build_go_away_payload(
            last_accepted_bidi,
            last_accepted_uni,
            code,
            reason,
            self._peer_limits.max_control_payload_bytes,
        )
        with self._lock:
            if not self._state.terminal():
                self._state = SessionState.DRAINING
        self._send_frame(Frame(FrameType.GOAWAY, 0, 0, payload))

    def close(self) -> None:
        self.close_with_error(0, "")

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

    def wait(self, timeout: Optional[float] = None) -> None:
        if not self._closed_event.wait(maybe_timeout(timeout)):
            raise SessionWaitTimeout()
        thread = self._reader_thread
        if thread is not threading.current_thread() and thread.is_alive():
            thread.join(0)

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
            stats = SessionStats(
                state=self._state,
                sent_frames=self._sent_frames,
                received_frames=self._received_frames,
                sent_data_bytes=self._sent_data_bytes,
                received_data_bytes=self._received_data_bytes,
                open_streams=self._open_streams,
                accepted_streams=self._accepted_streams,
                last_ping_rtt=self._last_ping_rtt,
                active_streams=active,
                reasons=ReasonStats(
                    reset=self._reset_reasons,
                    reset_overflow=self._reset_overflow,
                    abort=self._abort_reasons,
                    abort_overflow=self._abort_overflow,
                ),
            )
        return stats

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        return self._peer_go_away_error

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        return self._peer_close_error

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

    def _accept(
        self, queue: Deque["NativeStream"], timeout: Optional[float]
    ) -> "NativeStream":
        deadline = deadline_after(timeout)
        stream = None
        with self._lock:
            while True:
                if queue:
                    stream = queue.popleft()
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
            used = sum(
                1
                for stream in self._streams.values()
                if stream.opened_locally and stream.bidirectional == bidirectional
            )
            if limit and used >= limit:
                from .errors import OpenLimited

                raise OpenLimited()
            stream_id = self._next_bidi if bidirectional else self._next_uni
            if stream_id > MAX_VARINT62:
                from .errors import OpenLimited

                raise OpenLimited()
            if bidirectional:
                self._next_bidi += 4
            else:
                self._next_uni += 4
            stream = NativeStream(
                self,
                stream_id,
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
            self._streams[stream_id] = stream
            self._open_streams = _sat_add(self._open_streams, 1)
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
            self._sent_frames = _sat_add(self._sent_frames, 1)
            if frame.frame_type == FrameType.DATA:
                parsed = parse_data_payload_view(frame.payload, frame.flags)
                self._sent_data_bytes = _sat_add(
                    self._sent_data_bytes,
                    len(parsed.app_data),
                )

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
                    self._received_frames = _sat_add(self._received_frames, 1)
                self._dispatch_frame(frame)
            except BaseException as exc:
                self._finish(exc, failed=True, close_transport=True)
                return

    def _dispatch_frame(self, frame: Frame) -> None:
        if frame.frame_type == FrameType.DATA:
            self._handle_data(frame)
        elif frame.frame_type == FrameType.PING:
            self._send_frame(Frame(FrameType.PONG, 0, 0, frame.payload))
        elif frame.frame_type == FrameType.PONG:
            self._handle_pong(frame.payload)
        elif frame.frame_type == FrameType.GOAWAY:
            self._handle_go_away(frame.payload)
        elif frame.frame_type == FrameType.CLOSE:
            self._handle_close(frame.payload)
        elif frame.frame_type == FrameType.STOP_SENDING:
            self._handle_stop_sending(frame.stream_id, frame.payload)
        elif frame.frame_type == FrameType.RESET:
            self._handle_reset(frame.stream_id, frame.payload)
        elif frame.frame_type == FrameType.ABORT:
            self._handle_abort(frame.stream_id, frame.payload)
        elif frame.frame_type == FrameType.EXT:
            self._handle_ext(frame.stream_id, frame.payload)

    def _handle_data(self, frame: Frame) -> None:
        parsed = parse_data_payload_view(frame.payload, frame.flags)
        stream = self._get_or_create_peer_stream(frame.stream_id, parsed.metadata.to_owned())
        if parsed.app_data:
            stream.receive_data(parsed.app_data)
            with self._lock:
                self._received_data_bytes = _sat_add(
                    self._received_data_bytes,
                    len(parsed.app_data),
                )
        if frame.flags & FRAME_FLAG_FIN:
            stream.receive_fin()

    def _get_or_create_peer_stream(
        self, stream_id: int, metadata: StreamMetadata
    ) -> "NativeStream":
        with self._lock:
            existing = self._streams.get(stream_id)
            if existing is not None:
                stream = existing
            else:
                if stream_is_local(self._local_role, stream_id):
                    raise ValueError("peer used locally-owned stream_id %d" % stream_id)
                bidirectional = stream_is_bidi(stream_id)
                local_send, local_receive = stream_kind_for_local(self._local_role, stream_id)
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
                self._streams[stream_id] = stream
                if bidirectional:
                    self._accept_bidi.append(stream)
                else:
                    self._accept_uni.append(stream)
                self._lock_notify_all()
        return stream

    def _handle_pong(self, payload: bytes) -> None:
        with self._lock:
            pending = self._pings.get(payload)
            if pending is None:
                return
            done, started, holder = pending
            holder[0] = max(0.0, time.monotonic() - started)
            done.set()

    def _handle_go_away(self, payload: bytes) -> None:
        parsed = parse_go_away_payload(payload)
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
        with self._lock:
            self._peer_go_away_error = app
            if not self._state.terminal():
                self._state = SessionState.DRAINING
            self._lock_notify_all()

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
        stream = self._streams.get(stream_id)
        if stream is None:
            return
        code, reason = parse_error_payload(payload)
        app = ApplicationError(
            code,
            reason,
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.WRITE,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.WRITE,
            termination_kind=TerminationKind.STOPPED,
        )
        stream.stop_write(app)

    def _handle_reset(self, stream_id: int, payload: bytes) -> None:
        stream = self._streams.get(stream_id)
        if stream is None:
            return
        code, reason = parse_error_payload(payload)
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
        stream = self._streams.get(stream_id)
        if stream is None:
            return
        code, reason = parse_error_payload(payload)
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

    def _handle_ext(self, stream_id: int, payload: bytes) -> None:
        metadata, valid = parse_priority_update_payload(payload)
        if not valid:
            return
        stream = self._streams.get(stream_id)
        if stream is not None:
            stream.apply_metadata_update(metadata)

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
            self._lock_notify_all()
            self._closed_event.set()
        for stream in streams:
            stream.session_closed(error)
        for done, _, _ in list(self._pings.values()):
            done.set()
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
        handler = self._config.event_handler
        if handler is None:
            return
        try:
            handler(event)
        except BaseException:
            pass

    def _lock_wait(self, timeout: Optional[float]) -> None:
        self._lock.wait(timeout)

    def _lock_notify_all(self) -> None:
        self._lock.notify_all()


class NativeStream:
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
        "_read_buf",
        "_read_buffered",
        "_read_finished",
        "_read_closed",
        "_read_error",
        "_write_closed",
        "_write_error",
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
        self._read_buf: Deque[memoryview] = deque()
        self._read_buffered = 0
        self._read_finished = not local_receive
        self._read_closed = not local_receive
        self._read_error: Optional[BaseException] = None
        self._write_closed = not local_send
        self._write_error: Optional[BaseException] = None
        self._closed = False
        self._read_deadline = None
        self._write_deadline = None
        self._cond = threading.Condition(threading.RLock())
        self._write_mutex = threading.Lock()

    def __enter__(self) -> "NativeStream":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
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
        return self._read_closed

    @property
    def write_closed(self) -> bool:
        return self._write_closed

    @property
    def closed(self) -> bool:
        return self._closed or (self._read_closed and self._write_closed)

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
        deadline = _merge_deadline(self._read_deadline, deadline_after(timeout))
        with self._cond:
            self._check_readable()
            while not self._read_buf:
                if self._read_error is not None:
                    raise self._read_error
                if self._read_finished:
                    bytes_read = 0
                    break
                remaining = _remaining(deadline)
                if remaining == 0:
                    raise ReadTimeout()
                self._cond.wait(remaining)
            else:
                chunk = self._read_buf[0]
                bytes_read = min(len(view), len(chunk))
                view[:bytes_read] = chunk[:bytes_read]
                if bytes_read == len(chunk):
                    self._read_buf.popleft()
                else:
                    self._read_buf[0] = chunk[bytes_read:]
                self._read_buffered -= bytes_read
                self._cond.notify_all()
        return bytes_read

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
            self._check_writable_for_zero_write()
            return 0
        self._send_data(view, fin=False, timeout=timeout)
        return len(view)

    def write_all(self, data: ReadableBuffer, *, timeout: Optional[float] = None) -> None:
        self.write(data, timeout=timeout)

    def write_vectored(
        self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        total = 0
        for part in parts:
            total += self.write(part, timeout=timeout)
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
        total = self.write_vectored(parts, timeout=timeout)
        self.close_write(timeout=timeout)
        return total

    def set_deadline(self, deadline) -> None:
        self._read_deadline = deadline
        self._write_deadline = deadline

    def set_timeout(self, timeout: Optional[float]) -> None:
        self.set_deadline(deadline_after(timeout))

    def set_read_deadline(self, deadline) -> None:
        self._read_deadline = deadline

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self.set_read_deadline(deadline_after(timeout))

    def set_write_deadline(self, deadline) -> None:
        self._write_deadline = deadline

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
            if self._read_closed:
                return
            self._read_closed = True
            self._read_finished = True
            self._read_buf.clear()
            self._read_buffered = 0
            self._cond.notify_all()
        self._ensure_opened_before_terminal()
        self._session.send_frame(Frame(FrameType.STOP_SENDING, self._stream_id, 0, payload))

    def close_write(self, *, timeout: Optional[float] = None) -> None:
        if self._write_closed:
            return
        self._send_data(memoryview(b""), fin=True, timeout=timeout)

    def cancel_write(self, code: int) -> None:
        self._check_writable()
        payload = build_error_payload(
            _application_code(code),
            "",
            self._session.peer_limits.max_control_payload_bytes,
        )
        self._ensure_opened_before_terminal()
        self._session.send_frame(Frame(FrameType.RESET, self._stream_id, 0, payload))
        with self._cond:
            self._write_closed = True
            self._write_error = WriteClosed()
            self._cond.notify_all()

    def update_metadata(self, update: MetadataUpdate) -> None:
        if not isinstance(update, MetadataUpdate):
            raise TypeError("update must be MetadataUpdate")
        if update.is_empty():
            raise EmptyMetadataUpdate()
        if not self._opened_locally:
            from .errors import PriorityUpdateUnavailable

            raise PriorityUpdateUnavailable()
        metadata = StreamMetadata(
            update.priority if update.priority is not None else self._metadata.priority,
            update.group if update.group is not None else self._metadata.group,
            self._metadata.open_info,
        )
        if not self._opened_sent:
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
        if errors:
            raise errors[0]

    def close_with_error(self, code: int, reason: str = "") -> None:
        app_code = _application_code(code)
        payload = build_error_payload(
            app_code,
            "" if reason is None else str(reason),
            self._session.peer_limits.max_control_payload_bytes,
        )
        self._ensure_opened_before_terminal()
        self._session.send_frame(Frame(FrameType.ABORT, self._stream_id, 0, payload))
        app = ApplicationError(
            app_code,
            "" if reason is None else str(reason),
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.CLOSE,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.ABORT,
        )
        self._abort(app)

    def _send_data(
        self, data: memoryview, *, fin: bool, timeout: Optional[float]
    ) -> None:
        deadline = _merge_deadline(self._write_deadline, deadline_after(timeout))
        with self._write_mutex:
            self._check_writable()
            if _remaining(deadline) == 0:
                raise WriteTimeout()
            first = not self._opened_sent
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
            if not data and not fin and not prefix:
                return
            remaining = data
            while first or remaining or fin:
                if _remaining(deadline) == 0:
                    raise WriteTimeout()
                max_payload = self._session.peer_limits.max_frame_payload
                room = max_payload - len(prefix)
                if room < 0:
                    raise ValueError("open metadata exceeds peer max_frame_payload")
                take = min(len(remaining), room)
                chunk = remaining[:take]
                remaining = remaining[take:]
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
            self._read_buffered += len(view)
            self._cond.notify_all()

    def _receive_fin(self) -> None:
        with self._cond:
            self._read_finished = True
            self._cond.notify_all()

    def _stop_write(self, error: BaseException) -> None:
        with self._cond:
            self._write_closed = True
            self._write_error = error
            self._cond.notify_all()

    def _reset_read(self, error: BaseException) -> None:
        with self._cond:
            self._read_finished = True
            self._read_error = error
            self._cond.notify_all()

    def _abort(self, error: BaseException) -> None:
        with self._cond:
            self._read_finished = True
            self._read_closed = True
            self._write_closed = True
            self._closed = True
            self._read_error = error
            self._write_error = error
            self._cond.notify_all()

    def _session_closed(self, error: Optional[BaseException]) -> None:
        with self._cond:
            self._read_finished = True
            self._read_error = error
            self._write_error = error
            self._read_closed = True
            self._write_closed = True
            self._closed = True
            self._cond.notify_all()

    def _apply_metadata_update(self, metadata: StreamMetadata) -> None:
        self._metadata = StreamMetadata(
            metadata.priority if metadata.priority is not None else self._metadata.priority,
            metadata.group if metadata.group is not None else self._metadata.group,
            self._metadata.open_info,
        )

    def _check_readable(self) -> None:
        if not self._local_receive:
            raise StreamNotReadable()
        if self._read_closed and not self._read_buf:
            raise ReadClosed()

    def _check_writable(self) -> None:
        if not self._local_send:
            raise StreamNotWritable()
        if self._write_error is not None:
            raise self._write_error
        if self._write_closed:
            raise WriteClosed()
        if self._session.closed:
            raise SessionClosed(operation=ErrorOperation.WRITE, source=ErrorSource.LOCAL)

    def _check_writable_for_zero_write(self) -> None:
        if not self._local_send:
            raise StreamNotWritable()
        if self._write_error is not None:
            raise self._write_error
        if self._write_closed:
            raise WriteClosed()


class _FrameIO:
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
    view = memoryview(data)
    if view.ndim == 1 and view.itemsize == 1 and view.format in ("B", "b", "c"):
        return view
    try:
        return view.cast("B")
    except TypeError:
        return memoryview(view.tobytes())


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


def _best_effort_close(obj: object) -> None:
    try:
        close = getattr(obj, "close", None)
        if close is not None:
            close()
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
    "open",
    "server",
)
