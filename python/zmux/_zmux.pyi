"""Native layer. Every coroutine here is cancellation-safe unless noted:
cancelling the awaiting task drops the pending operation and leaves the
session, stream or pipe usable. Use `asyncio.timeout()` for per-call
deadlines; durations are seconds."""

from collections.abc import Iterable, Mapping
from os import PathLike
from types import TracebackType
from typing import Any, Self, final

from . import _types as _t
from ._types import (
    CloseInfo,
    Direction,
    ErrorKind,
    Event,
    PipePolicy,
    PipeState,
    PipeStats,
    Preamble,
    Priority,
    Role,
    SessionState,
    SessionStats,
    Tlv,
)

_Pem = str | PathLike[str] | bytes
_Prio = Priority | tuple[int, bool]
_Tlvs = Iterable[Tlv | tuple[int, bytes]]
_Headers = Mapping[str, str] | Iterable[tuple[str, str]]

class ZmuxError(Exception):
    """Base of every zmux error.

    `kind` names the native error variant (an `ErrorKind`, or `str` for
    variants this version does not know). `retryable` is true when the same
    operation may succeed on a new session (see `EarlyDataRejected`).
    `code` is the application error code where one applies."""

    kind: ErrorKind | str
    retryable: bool
    code: int | None

class ConnectError(ZmuxError):
    """Dialling the carrier or establishing the session failed."""

class SessionClosed(ZmuxError):
    """The session ended. `code`/`reason` are the close's error code and
    phrase (application or transport close); `remote` tells whether the
    peer ended it (`None` when unknown)."""

    reason: bytes | None
    remote: bool | None

class EarlyDataRejected(ZmuxError):
    """The peer processed none of the early data (`retryable` is true).
    Open the same streams again on a new session without early data, and
    `QuicClient.forget()` the server when using QUIC 0-RTT."""

    reason: bytes | None
    remote: bool | None

class StreamError(ZmuxError):
    """A stream operation failed."""

class StreamReset(StreamError):
    """The peer reset the stream; `code` is its application error code."""

class StreamStopped(StreamError):
    """The peer stopped reading (STOP_SENDING); `code` is its application error code."""

class IncompleteRead(StreamError):
    """The stream finished before `read_exact` got its bytes."""

class LimitExceeded(StreamError):
    """`read_to_end` found the stream longer than its limit."""

class OpenError(ZmuxError):
    """Opening a stream failed (for example after GOAWAY, or a preamble too large)."""

class DatagramError(ZmuxError):
    """Sending a datagram failed: not negotiated, larger than `max_datagram_size`, or the session ended."""

class PipeError(ZmuxError):
    """A pipe operation failed."""

class ListenerClosed(ZmuxError):
    """`Listener.accept()` after the listener was closed."""

@final
class Config:
    """Native configuration; use `zmux.Config` instead."""

    def __init__(self, **kwargs: Any) -> None: ...

@final
class TlsConfig:
    """TLS settings for the TLS, QUIC, HTTP and WebTransport carriers.

    PEM `str`/path arguments are file paths, `bytes` are PEM contents.
    Clients without `ca` trust the bundled web roots; `verify=False`
    disables server verification (testing only). Servers need `cert` and
    `key`. `alpn` overrides the carrier's protocol list."""

    def __init__(
        self,
        *,
        cert: _Pem | None = None,
        key: _Pem | None = None,
        ca: _Pem | None = None,
        verify: bool = True,
        alpn: list[str] | None = None,
    ) -> None: ...

@final
class PipeIo:
    """A carrier connection not yet given to a session; usable once."""

@final
class PipeEnd:
    """The application's end of `pipe_pair()`."""

    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes the session wrote; `b""` once it closed."""
    async def write(self, data: bytes) -> None:
        """Delivers `data` to the session; `b""` ends the pipe."""

def pipe_pair() -> tuple[PipeIo, PipeEnd]:
    """An in-memory pipe: give the `PipeIo` to a session, drive the `PipeEnd` yourself."""

async def dial_tcp(addr: str) -> PipeIo:
    """A pipe on a new TCP connection to `host:port`."""

async def dial_tls(addr: str, *, tls: TlsConfig | None = None, server_name: str | None = None) -> PipeIo:
    """A pipe on TLS over TCP; `server_name` defaults to the host of `addr`."""

async def dial_quic(
    addr: str, *, tls: TlsConfig | None = None, server_name: str | None = None, lanes: int = 4
) -> PipeIo:
    """A pipe on a new QUIC connection using up to `lanes` QUIC streams."""

async def dial_websocket(url: str, *, tls: TlsConfig | None = None, headers: _Headers | None = None) -> PipeIo:
    """A pipe on a WebSocket (`ws://` or `wss://`); `headers` go on the upgrade
    request, for example a `PipeReservation.header` as `Zmux-Pipe-Join`."""

async def dial_http(addr: str, *, path: str = "/zmux") -> PipeIo:
    """A pipe on an HTTP/1.1 upgrade request to `path`."""

async def dial_h3(url: str, *, tls: TlsConfig | None = None, addr: str | None = None, lanes: int = 4) -> PipeIo:
    """A pipe on an HTTP/3 request to `url` (`https://`), sent to `addr` when given."""

async def dial_webtransport(url: str, *, tls: TlsConfig | None = None, lanes: int = 4) -> PipeIo:
    """A pipe on a new WebTransport session to `url` (`https://`)."""

@final
class Http2Connection:
    """An HTTP/2 connection whose exchanges carry pipes: prior knowledge
    without `tls`, ALPN `h2` with it. Open several pipes on one connection."""

    @staticmethod
    async def connect(
        addr: str, *, path: str = "/zmux", tls: TlsConfig | None = None, server_name: str | None = None
    ) -> Http2Connection: ...
    async def open_pipe(self) -> PipeIo:
        """A pipe on a new exchange."""

@final
class ZeroRtt:
    """What became of the QUIC 0-RTT data of a session (live: values may change until known)."""

    @property
    def sent(self) -> bool:
        """0-RTT data was sent."""
    @property
    def accepted(self) -> bool | None:
        """Whether the server accepted it; `None` while unknown or when none was sent."""
    @property
    def rewritten(self) -> bool:
        """Rejected 0-RTT data was sent again after the handshake."""

@final
class QuicClient:
    """A QUIC client endpoint reused across connections so TLS sessions resume.
    With `zero_rtt` it remembers each server's parameters and sends a
    session's first records as 0-RTT when `Config(carrier_early_data=True)`.
    0-RTT data may be replayed by an attacker: send only idempotent requests
    early, and check `RecvStream.is_replayable` on the server."""

    def __init__(
        self,
        tls: TlsConfig | None = None,
        *,
        lanes: int = 4,
        zero_rtt: bool = False,
        memory_capacity: int | None = None,
        bind: str = "0.0.0.0:0",
    ) -> None: ...
    async def dial(self, addr: str, *, server_name: str | None = None) -> PipeIo:
        """A pipe on a new connection."""
    async def connect(self, addr: str, *, server_name: str | None = None, config: _t.Config | None = None) -> Session:
        """A session on a new connection; see `Session.zero_rtt`."""
    def forget(self, server_name: str) -> None:
        """Forgets the parameters remembered for `server_name` (after `EarlyDataRejected`)."""
    def clear(self) -> None:
        """Forgets every remembered server."""
    def remembers(self, server_name: str) -> bool:
        """Whether parameters are remembered for `server_name`."""

@final
class SendStream:
    """The sending half of a stream.

    `finish()` ends it cleanly, `reset(code)` abandons it (unsent data is
    dropped). Both are idempotent in effect: a later call fails with
    `StreamError` (kind `ClosedLocally`). Use `async with` to finish on a
    normal exit and reset on an exception; leaving a stream neither
    finished nor reset keeps it half-open until the session ends. One
    operation at a time: a second concurrent call raises `RuntimeError`."""

    @property
    def id(self) -> int | None:
        """The stream ID; `None` until the stream is opened on the wire."""
    @property
    def priority(self) -> Priority:
        """The local scheduling priority."""
    async def write(self, data: bytes) -> None:
        """Writes all of `data`, waiting for flow control. If cancelled, a
        prefix of `data` may have been sent."""
    async def finish(self) -> None:
        """Ends the stream (FIN) after the written data."""
    async def reset(self, code: int = 0) -> None:
        """Abandons the stream with an application error code (< 2**62)."""
    def set_priority(self, priority: _Prio) -> None:
        """Sets the scheduling priority; urgency 0..7, lower first."""
    async def stopped(self) -> int | None:
        """Waits until the peer stops the stream (returns its code) or acknowledged all data (`None`)."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> bool: ...

@final
class RecvStream:
    """The receiving half of a stream; `async for chunk in stream` reads to the end.

    `stop(code)` asks the peer to stop sending. Cancelling a pending read
    loses no data. `async with` stops the stream on an exception."""

    @property
    def id(self) -> int | None:
        """The stream ID."""
    @property
    def is_replayable(self) -> bool:
        """The stream arrived as early data and may be a replay: process
        only idempotent requests from it, or refuse with `stop()`."""
    @property
    def preamble(self) -> Preamble:
        """Metadata the opener attached (`info`, `tlvs`)."""
    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes; `b""` at the end of the stream. Raises `StreamReset` if the peer reset it."""
    async def read_exact(self, n: int) -> bytes:
        """Exactly `n` bytes, or `IncompleteRead`."""
    async def read_to_end(self, limit: int = 16777216) -> bytes:
        """The rest of the stream; `LimitExceeded` beyond `limit` bytes."""
    async def stop(self, code: int = 0) -> None:
        """Asks the peer to stop sending (STOP_SENDING) with an application error code."""
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> bytes: ...
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> bool: ...

@final
class Pipe:
    """One pipe (carrier) of a multipath session. `close()` removes it
    gracefully (drain), `abort()` at once; `async with` closes it on a
    normal exit and aborts on an exception. Watch `Session.events()` for
    its state changes."""

    @property
    def id(self) -> int: ...
    @property
    def policy(self) -> PipePolicy | None:
        """The effective outbound policy; `None` once the pipe's state is released."""
    @property
    def state(self) -> PipeState | None:
        """The outbound direction's state (else the inbound one's); `None` once released."""
    async def joined(self) -> None:
        """Waits until the peer confirmed the join; `PipeError` if it failed."""
    def set_policy(self, policy: PipePolicy) -> None:
        """Applies the non-`None` fields of `policy`."""
    def close(self) -> None: ...
    def abort(self) -> None: ...
    def stats(self) -> PipeStats | None:
        """A snapshot; `None` once the session released the pipe's state."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> bool: ...

@final
class PipeReservation:
    """A pipe reserved for an out-of-band join: send `header` (as the
    `Zmux-Pipe-Join` request header) or `frame` with the carrier's request,
    then `attach` the carrier. Attach or cancel exactly once."""

    @property
    def id(self) -> int: ...
    @property
    def frame(self) -> bytes:
        """The PIPE_JOIN frame, for carriers that deliver bytes out of band."""
    @property
    def header(self) -> str:
        """The `Zmux-Pipe-Join` header value."""
    def attach(self, pipe: PipeIo) -> Pipe: ...
    def cancel(self) -> None: ...

@final
class EventStream:
    """`Session.events()`; ends with the session."""

    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Event: ...

@final
class DatagramStream:
    """`Session.datagrams()`; ends with the session."""

    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> bytes: ...

@final
class Session:
    """A zmux session: a cheap handle; the session runs on the binding's runtime.

    `close()` ends it at once (unsent data is dropped); `await shutdown()`
    sends GOAWAY and closes once the open streams ended. `async with`
    closes on exit; `async for send, recv in session` accepts bidirectional
    streams until it ends."""

    @staticmethod
    async def connect(pipe: PipeIo, config: _t.Config | None = None) -> Session:
        """Establishes a session as the dialling side of `pipe`."""
    @staticmethod
    async def accept(pipe: PipeIo, config: _t.Config | None = None) -> Session:
        """Establishes a single-pipe session as the accepting side of `pipe`."""
    @staticmethod
    async def peer(pipe: PipeIo, config: _t.Config | None = None) -> Session:
        """Establishes a session over a symmetric carrier; roles are negotiated."""
    async def open_bi(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        priority: _Prio | None = None,
        peer_priority: _Prio | None = None,
    ) -> tuple[SendStream, RecvStream]:
        """Opens a bidirectional stream, waiting for stream credit. A
        cancelled open leaves no stream behind for the caller."""
    async def open_uni(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        priority: _Prio | None = None,
    ) -> SendStream:
        """Opens a unidirectional stream."""
    async def accept_bi(self) -> tuple[SendStream, RecvStream]:
        """The next bidirectional stream the peer opened; `SessionClosed` once the session ended."""
    async def accept_uni(self) -> RecvStream:
        """The next unidirectional stream the peer opened."""
    def send_datagram(self, data: bytes) -> None:
        """Queues an unreliable datagram; never waits. When the queue is full
        the oldest datagram is dropped. `DatagramError` if datagrams are not
        negotiated or `data` exceeds `max_datagram_size`."""
    async def read_datagram(self) -> bytes:
        """The next received datagram; `SessionClosed` once the session ended."""
    def datagrams(self) -> DatagramStream:
        """Received datagrams as an async iterator."""
    @property
    def max_datagram_size(self) -> int | None:
        """The largest datagram payload; `None` without datagram support."""
    def close(self, code: int = 0, reason: bytes = b"") -> None:
        """Closes at once with an application error code."""
    async def shutdown(self, code: int = 0, reason: bytes = b"") -> None:
        """Graceful: GOAWAY, then close once the streams ended."""
    async def wait_closed(self) -> CloseInfo:
        """Waits for the end of the session and tells why it ended."""
    async def ping(self) -> float:
        """A round trip; the RTT in seconds."""
    async def next_event(self) -> Event | None:
        """The next session event; `None` once the session ended."""
    def events(self) -> EventStream:
        """Session events as an async iterator (each event is delivered to one reader)."""
    def stats(self) -> SessionStats: ...
    def add_pipe(self, pipe: PipeIo, *, policy: PipePolicy | None = None) -> Pipe:
        """Adds a carrier as a further pipe (multipath); returns at once, see `Pipe.joined()`."""
    def reserve_pipe(
        self, direction: Direction | str = Direction.BIDI, *, policy: PipePolicy | None = None
    ) -> PipeReservation:
        """Reserves a pipe for an out-of-band join."""
    @property
    def join_ready(self) -> bool:
        """Whether a pipe added now would join at once rather than wait for the handshake."""
    def revalidate_pipes(self) -> None:
        """Probes every live outbound pipe again, for example after a network change."""
    def pipes(self) -> list[Pipe]: ...
    def pipe_stats(self) -> list[PipeStats]: ...
    @property
    def zero_rtt(self) -> ZeroRtt | None:
        """For sessions from `QuicClient.connect`: what became of the 0-RTT data."""
    @property
    def role(self) -> Role: ...
    @property
    def rtt(self) -> float | None:
        """Smoothed RTT in seconds, once sampled."""
    @property
    def protocol(self) -> str | None:
        """The application protocol (carrier ALPN or `Config.protocols`)."""
    @property
    def is_plain_qmux_peer(self) -> bool:
        """The peer speaks plain QMux without zmux extensions."""
    @property
    def state(self) -> SessionState: ...
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> bool: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> tuple[SendStream, RecvStream]: ...

@final
class Listener:
    """Accepts sessions (and multipath joins) from any number of carriers.
    Each `serve_*` binds `addr` (port 0 picks one) and returns the bound
    address. `async for session in listener` until `close()`."""

    def __init__(self, config: _t.Config | None = None) -> None: ...
    async def serve_tcp(self, addr: str) -> str: ...
    async def serve_tls(self, addr: str, *, tls: TlsConfig) -> str: ...
    async def serve_quic(self, addr: str, *, tls: TlsConfig, lanes: int = 4, zero_rtt: bool = False) -> str:
        """With `zero_rtt`, 0-RTT is accepted when `Config(carrier_early_data=True)`."""
    async def serve_h3(self, addr: str, *, tls: TlsConfig, lanes: int = 4) -> str: ...
    async def serve_webtransport(self, addr: str, *, tls: TlsConfig, lanes: int = 4) -> str: ...
    async def serve_websocket(self, addr: str, *, tls: TlsConfig | None = None) -> str: ...
    async def serve_http(self, addr: str, *, path: str = "/zmux", tls: TlsConfig | None = None) -> str:
        """HTTP/1.1 upgrade and HTTP/2 (prior knowledge, or ALPN with `tls`)."""
    async def handle_pipe(self, pipe: PipeIo) -> None:
        """Hands over a carrier the application accepted itself."""
    async def accept(self) -> Session:
        """The next established session; `ListenerClosed` once closed."""
    def close(self) -> None: ...
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> bool: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Session: ...
