"""Native layer. Every coroutine here is cancellation-safe unless noted:
cancelling the awaiting task drops the pending operation and leaves the
session, stream or pipe usable. Use `asyncio.timeout()` for per-call
deadlines; durations are seconds."""

from collections.abc import Awaitable, Buffer, Callable, Iterable, Mapping
from os import PathLike
from typing import Any, ClassVar, Literal, Self, final

from . import _types as _t
from ._layer import Layer
from ._types import (
    CapacityFloor,
    CloseInfo,
    Direction,
    EarlyDataState,
    ErrorKind,
    Event,
    InboundState,
    Limiter,
    ListenerStats,
    OutboundState,
    PipeOptions,
    PipeStats,
    Preamble,
    Priority,
    QualityBand,
    Resolved,
    Role,
    Scheduler,
    SessionState,
    SessionStats,
    Spliced,
    StreamStats,
    Tlv,
)

type _Pem = str | PathLike[str] | bytes
type _Prio = Priority | tuple[int, bool]
type _Headers = Mapping[str, str] | Iterable[tuple[str, str]]

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
    """Opening a stream failed (for example after GOAWAY)."""

class DatagramError(ZmuxError):
    """Sending a datagram failed: not negotiated, larger than `max_datagram_size`, or the session ended."""

class PipeError(ZmuxError):
    """A pipe operation failed."""

class PreambleTooLargeError(ValueError):
    """A stream's preamble (OPEN_INFO, TLVs, PIPE_CARRIER) is larger than the
    limit known: the peer's Maximum Preamble Size, before its parameters the
    remembered one or 1024 bytes, at most 4096. Raised by the open call, or,
    when the peer's parameters arrived with a smaller limit before the
    stream's first frame, by the stream's operations: only that stream
    fails, nothing of it was sent."""

class ListenerClosed(ZmuxError):
    """`Listener.accept()` after the listener was closed."""

DEFAULT_KEEP_ALIVE_PERIOD: float
"""Default keep-alive period, seconds (15)."""
DEFAULT_IDLE_TIMEOUT: float
"""Default idle timeout, seconds (30)."""
DEFAULT_PROBE_JITTER: float
"""Default probe jitter (0.25)."""
DEFAULT_STANDBY_PROBE: float
"""Default standby probe interval, seconds (1)."""
DEFAULT_MAX_RECORD_SIZE: int
"""Record size limit before the peer's parameters, bytes (16382)."""
DEFAULT_BACKOFF_MAX: float
"""Largest redial delay of a pipe pool, seconds (60)."""
MIN_MAX_LEN: int
"""Smallest shaping `max_len` honoured, bytes (64)."""
STARTUP_ALLOWANCE: int
"""PADDING always allowed under a padding ratio limit, bytes (16382)."""

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
class UnsentCount:
    """A carrier's unsent count that the application keeps up to date,
    typically at each write to the carrier (`PipeIo.with_unsent`)."""

    def __init__(self, n: int | None = None) -> None: ...
    def set(self, n: int | None) -> None:
        """Sets the count: the bytes the carrier took and has not yet
        transmitted, or `None` when it cannot tell."""
    @property
    def value(self) -> int | None:
        """The count as last set."""

@final
class PipeIo:
    """A carrier connection not yet given to a session; usable once."""

    def with_carrier(self, kind: _t.CarrierKind | str) -> PipeIo:
        """This carrier labelled with carrier kind `kind`: what a by-kind
        shaper picks by, and the kind in pipe events and statistics. This
        object is used up."""
    def with_unsent(self, count: UnsentCount) -> PipeIo:
        """This carrier with an unsent count: `count` holds the bytes the
        carrier took and has not yet transmitted, or `None` when it cannot
        tell, as last set. It feeds `PipeStats.queued_bytes` and the
        scheduler's queue estimate; the session's driver reads it without
        the interpreter lock. This object is used up."""
    def with_write_overhead(self, overhead: int) -> PipeIo:
        """This carrier with a write overhead: the fixed bytes (0 to 65535,
        `ValueError` otherwise) the layers below zmux add to each write on
        it, such as a wrapping layer's record header and tag, which a shaper
        takes into account. This object is used up."""
    def into_stream(self) -> CarrierStream:
        """The carrier's halves as one byte stream, for a layer that runs
        over a stream; bytes a listener already read from it come first.
        Every other property is dropped (`wrap` keeps them). This object is
        used up. `open_carrier` gives it as asyncio streams."""
    async def wrap(
        self,
        layer: Layer,
        *,
        server_side: bool = False,
    ) -> PipeIo:
        """Runs a layer over the carrier: `layer(reader, writer)`, given the
        carrier as asyncio streams, returns the layer's streams (for example
        after `await writer.start_tls(context)`), which become the carrier's
        halves; the carrier keeps its framing, kind and other properties.
        Each write on the carrier is one write on the layer's writer, then a
        drain; a layer must turn each write on it into exactly one write
        below and never merge writes (asyncio's TLS writes once below per
        write), so that every carrier write stays one write on the
        connection. With `server_side`, `writer.start_tls` takes the server
        side. This object is used up; the layer runs on the running event
        loop. A layer's error raises `ConnectError`."""
    @property
    def carrier(self) -> str | None:
        """The carrier kind's name, or `None`."""

@final
class CarrierStream:
    """A carrier's halves as one byte stream (`PipeIo.into_stream()`). On a
    carrier with message framing each write is one message and reads
    return the messages' bytes in order."""

    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes; `b""` at the end (also without a receiving half)."""
    async def write(self, data: bytes) -> None:
        """Exactly one write on the carrier; fails without a sending half."""
    async def shutdown(self) -> None:
        """Ends the sending half gracefully."""

@final
class LayerEnd:
    """Internal: the Python side of the stream a `PipeIo.wrap` layer returns."""

    async def read(self) -> bytes: ...
    async def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...

@final
class PipeHint:
    """What a listener knows of a carrier when its `inbound_transform` runs."""

    @property
    def source(self) -> tuple[str, int] | None:
        """The carrier's source, `(host, port)`: the client a trusted
        intermediary reported, else the peer."""
    @property
    def peer(self) -> tuple[str, int] | None:
        """The directly connected peer, `(host, port)`."""
    @property
    def split(self) -> bool:
        """Whether the carrier is one half of a split bootstrap."""
    @property
    def admitted(self) -> Any:
        """The admission's value for the carrier (`Verdict.accept(value=...)`),
        `None` without one."""

@final
class PipeEnd:
    """The application's end of `pipe_pair()`."""

    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes the session wrote; `b""` once it closed."""
    async def write(self, data: bytes) -> None:
        """Delivers `data` to the session; `b""` ends the pipe."""

def pipe_pair(*, carrier: _t.CarrierKind | str | None = None) -> tuple[PipeIo, PipeEnd]:
    """An in-memory pipe: give the `PipeIo` to a session, drive the `PipeEnd` yourself.
    `carrier` labels it with a carrier kind (`PipeIo.with_carrier`)."""

@final
class CarrierInfo:
    """The metadata of a carrier, given to an `Admission` decider and to a
    credential for the duration of one call."""

    @property
    def source(self) -> tuple[str, int] | None:
        """The carrier's source, `(host, port)`: the client a trusted
        intermediary reports (port 0 when it reported none), else the peer."""
    @property
    def peer(self) -> tuple[str, int] | None:
        """The directly connected peer, `(host, port)`."""
    @property
    def alpn(self) -> bytes | None:
        """The application protocol the TLS or QUIC handshake negotiated."""
    @property
    def server_name(self) -> str | None:
        """The server name of the TLS or QUIC handshake."""
    @property
    def headers(self) -> list[tuple[str, bytes]] | None:
        """The request header fields of an HTTP carrier, names in lower case;
        None for other carriers."""
    @property
    def head(self) -> bool:
        """Whether the carrier is decided on its HTTP request head (WebSocket,
        WebTransport): there is no prefix, and a credential travels in a
        request header field."""
    def export(
        self, label: bytes, context: bytes = b"", length: int = 32
    ) -> bytes | None:
        """`length` bytes of the TLS exporter of the carrier's completed
        handshake; None without one, or after the call that was given this
        object has returned (for an `async` decide, its first `await`)."""

@final
class Verdict:
    """An admission decision."""

    FALLBACK: ClassVar[Verdict]
    """To the fallback handler, every byte read replayed; without one the
    carrier is stalled (an HTTP request gets 404)."""
    STALL: ClassVar[Verdict]
    """Nothing is sent; what arrives is discarded until the stall interval
    has passed, then the carrier is closed."""
    CLOSE: ClassVar[Verdict]
    """The carrier is closed at once."""
    @staticmethod
    def accept(skip: int = 0, value: Any = None) -> Verdict:
        """To the listener, without the first `skip` bytes of the prefix;
        `value`, any object, is the carrier's admitted value
        (`PipeHint.admitted`, `Session.admitted`, `Pipe.admitted`)."""
    @property
    def skip(self) -> int | None:
        """An accept's `skip`; `None` for another verdict."""
    @property
    def value(self) -> Any:
        """An accept's value."""

@final
class Admission:
    """A listener's admission of new carriers (`Listener(admission=...)`),
    applied at every entry, joins and resumptions included:
    `decide(info, prefix)` is called once per carrier, after its outer
    handshake, with its metadata and up to `peek` first bytes (none on
    carriers decided on an HTTP request head) and returns a `Verdict`, or is
    `async` and resolves to one. A synchronous one runs on a native thread
    holding the GIL, so it must be quick and must not block; an `async` one
    runs on the event loop the `Listener` was made in, and is cancelled
    (`CancelledError`) when the peek timeout ends or the listener closes.
    An exception or another return value closes the carrier.
    `peek_timeout` (seconds, from the end of the outer handshake) bounds the
    reading of the prefix and the decision; `stall` is the `(min, max)`
    seconds a stalled carrier is held open. Unset ones are drawn at random. Within the interval, every carrier
    from one source is held open for the same duration during the listener's
    lifetime, and a held carrier counts against the listener's
    `max_pending_per_source` (beyond it, it is closed at once)."""

    def __init__(
        self,
        decide: Callable[[CarrierInfo, bytes], Verdict | Awaitable[Verdict]],
        *,
        peek: int = 0,
        peek_timeout: float | None = None,
        stall: tuple[float, float] | None = None,
    ) -> None: ...
    @staticmethod
    def prefix_auth(
        auth: PrefixAuth,
        *,
        skew: int,
        max_nonces: int = 65536,
        peek_timeout: float | None = None,
        stall: tuple[float, float] | None = None,
    ) -> Admission:
        """Admission by `auth`'s tokens: `skew` slots of clock difference
        accepted, at most `max_nonces` Nonces recorded. The token is the
        carrier's first 32 bytes, or the request header field on a carrier
        decided on its request head; a carrier without a valid one goes to
        the fallback."""
    @property
    def peek(self) -> int: ...
    @property
    def peek_timeout(self) -> float: ...
    @property
    def stall(self) -> tuple[float, float]: ...

@final
class PrefixAuth:
    """Prefix authentication parameters both ends agree on: `psk`, `slot`
    (whole seconds), `bind_tls` (tokens bound to the TLS or QUIC handshake
    of the carrier) and `header`, the request header field of carriers
    decided on their request head (default `Zmux-Prefix-Auth`). A client's
    credential: a fresh token first on the carrier, or in the header field;
    a server admits with `Admission.prefix_auth`."""

    def __init__(
        self,
        psk: bytes,
        *,
        slot: int,
        bind_tls: bool = False,
        header: str | None = None,
    ) -> None: ...
    @property
    def bind_tls(self) -> bool: ...
    @property
    def header(self) -> str: ...

type _Credential = PrefixAuth | _t.Credential

async def dial_tcp(addr: str, *, credential: _Credential | None = None) -> PipeIo:
    """A pipe on a new TCP connection to `host:port`; with `credential`, its
    prefix is sent first (given no exporter)."""

async def dial_tls(
    addr: str,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    credential: _Credential | None = None,
) -> PipeIo:
    """A pipe on TLS over TCP; `server_name` defaults to the host of `addr`.
    With `credential`, its prefix is sent after the handshake. Without ALPN
    identifiers in `tls`, zmux's are offered."""

async def dial_quic(
    addr: str,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    lanes: int = 4,
    credential: _Credential | None = None,
) -> PipeIo:
    """A pipe on a new QUIC connection using up to `lanes` QUIC streams. With
    `credential`, its prefix is the first stream's first bytes."""

async def dial_websocket(
    url: str,
    *,
    tls: TlsConfig | None = None,
    headers: _Headers | None = None,
    credential: _Credential | None = None,
) -> PipeIo:
    """A pipe on a WebSocket (`ws://` or `wss://`); `headers` go on the upgrade
    request, for example a `PipeReservation.header` as `Zmux-Pipe-Join`, and
    the credential's header field (given the TLS exporter with `wss://`)."""

type _HttpCarrier = Literal["bidirectional", "uplink", "downlink"]

async def dial_http(
    addr: str,
    *,
    path: str = "/zmux",
    credential: _Credential | None = None,
    carrier: _HttpCarrier = "bidirectional",
    join: str | None = None,
) -> PipeIo:
    """A carrier on an HTTP/1.1 request to `path`: `bidirectional` (a POST
    whose request and response bodies are the two directions), `uplink` (a
    POST whose request body is the only one) or `downlink` (a GET whose
    response body is), with `join` the `Zmux-Pipe-Join` value of a
    `PipeReservation`. With `credential` (unbound: the adapter has no
    exporter), its prefix is the first bytes of a request body, and a GET
    carries its header form."""

async def dial_http_split(
    addr: str, *, path: str = "/zmux", credential: _Credential | None = None
) -> PipeIo:
    """A split bootstrap over two HTTP/1.1 connections: an uplink POST and a
    downlink GET paired by a fresh token in `Zmux-Pipe-Pair`. The token is a
    bearer secret until the session is established: use TLS to the server
    or to a trusted TLS-terminating intermediary."""

async def join_http_split(
    session: Session,
    addr: str,
    *,
    path: str = "/zmux",
    credential: _Credential | None = None,
    options: PipeOptions | None = None,
) -> list[Pipe]:
    """Joins a split carrier over two HTTP/1.1 connections to `session` as
    two further pipes with `options`: a downlink GET joined out of band and
    an uplink POST joined in band, opened at once; returns `[downlink,
    uplink]` once both joins are confirmed. A split bootstrap's carrier
    (`dial_http_split`) joins no session: `add_pipe` refuses it with
    `ValueError`. A `PipePool(join=...)` keeps such pairs up."""

class ModeError(ZmuxError):
    """No candidate of a carrier mode was usable; `args[1]` is the list of
    `CandidateResult`s, one per try."""

@final
class PoolPolicy:
    """A pool policy read from a JSON object; its decisions run natively.

    Optional members: `count` (a value, rounded, that cannot draw below 1: a
    distribution that can needs a `min` of at least 1), `dial_after`
    (a list of values: entry `min(failures, len - 1)` is the least delay in
    seconds after the last dial; a negative one is passed on, and a pool
    rejects that decision), `dial_jitter` (a
    number in [0, 1), only with `dial_after`: each wait for a dial is
    reduced by its own random fraction of up to it; a new wait starts when
    `failures` changes or `since_dial` gets shorter or first appears),
    `retire` (a list of `{"metric": name, "above": value, "jitter": j}`; a
    member is retired, once and in view order, when any rule's metric is
    strictly above its threshold, reduced by a fraction of up to `j` drawn
    once per member), `probe_interval` (a value in seconds, at least 1, for
    the pipes a pool adds from then on) and `probe_jitter` (a number in
    [0, 1), only with `probe_interval`). Metrics: `age`, `idle` (seconds;
    a pool's pipe is idle for its `since_last_traffic`), `pipes`,
    `bytes_sent`, `bytes_received`, `bytes` (their sum). Values have the form and
    validation of a shaping definition's values; scope `shared` draws once
    per policy, `pipe` once per member while it stays in view (only in
    `retire`), `each` or empty at every decision. Absent members keep the
    pool's own behaviour; unknown members, metrics or scopes raise
    `ValueError`. Pools given the same object share its state."""

    def __init__(self, json: str | bytes | Mapping[str, Any]) -> None: ...
    @staticmethod
    def from_json(json: str | bytes | Mapping[str, Any]) -> PoolPolicy: ...
    def decide(
        self,
        failures: int = 0,
        members: Iterable[Mapping[str, float]] = (),
        *,
        since_dial: float | None = None,
    ) -> PoolPolicyDecision:
        """One decision for members given as dicts with `id` and optional
        `age`, `idle` (s), `pipes`, `bytes_sent`, `bytes_received`, the last
        dial having started `since_dial` seconds ago (`None`: none)."""

@final
class PoolPolicyDecision:
    """One answer of `PoolPolicy.decide`; `None` keeps the pool's own value.
    Made directly, `probe_interval` below 1, `probe_jitter` outside [0, 1)
    or a negative time raises `ValueError`."""

    def __init__(
        self,
        *,
        count: int | None = None,
        dial_after: float | None = None,
        retire: Iterable[int] = (),
        recheck: float | None = None,
        probe_interval: float | None = None,
        probe_jitter: float | None = None,
    ) -> None: ...
    @property
    def count(self) -> int | None:
        """Members to keep (at least 1)."""
    @property
    def dial_after(self) -> float | None:
        """Least delay in seconds of the next dial after the last one."""
    @property
    def retire(self) -> list[int]:
        """IDs of members to retire, in view order, each once."""
    @property
    def recheck(self) -> float | None:
        """Seconds within which to decide again even if nothing changes: the
        soonest an `age` or `idle` rule of a member kept fires, or
        `dial_after` elapses after the last dial; never 0. A `PipePool`
        with this policy wakes its maintainer by it."""
    @property
    def probe_interval(self) -> float | None:
        """Idle-probe interval in seconds of the pipes added from now on, as
        drawn (0: no idle probes); `None`: not set. Any other value below 1
        makes the decision invalid: a pool rejects it as a whole."""
    @property
    def probe_jitter(self) -> float | None:
        """Their idle-probe jitter; `None`: not set."""

@final
class PipePool:
    """Members to keep up over one path, `count` usable ones: with `dial()`,
    each a pipe on the carrier it opens; with `join(session, options)`
    instead, each the pipes it joins itself (such as `join_http_split`),
    usable while all of them are, counted once, and redialled, rotated and
    retired as a whole. Exactly one of the two is given (`TypeError`
    otherwise). Redials back off from the start of the previous attempt.
    Rotation replaces a usable member make before break once it carried
    `rotate_max_bytes` either way or is `rotate_max_age` seconds old, each
    reduced by a random fraction of up to `rotate_jitter`. `pool_policy`
    (a `PoolPolicy` or its JSON) is consulted at each look of the
    maintainer: at once after a pipe changed state or the session was
    suspended or resumed (it keeps dialling while suspended), and at least
    every 100 ms; its `dial_after` replaces the backoff's delay, and its
    probe settings apply to the pipes added after it. `options` are the
    `PipeOptions` of every pipe of the pool. A policy decision that is not
    valid (a probe interval other than 0 below 1 s) is rejected as a whole:
    the pool keeps its own behaviour and calls `decision_rejected(reason)`,
    if given, on the event loop."""

    def __init__(
        self,
        count: int,
        dial: Callable[[], Awaitable[PipeIo]] | None = None,
        *,
        join: Callable[[Session, PipeOptions], Awaitable[Iterable[Pipe]]] | None = None,
        rotate_max_bytes: int | None = None,
        rotate_max_age: float | None = None,
        rotate_jitter: float = 0.0,
        pool_policy: PoolPolicy | str | bytes | Mapping[str, Any] | None = None,
        options: PipeOptions | None = None,
        decision_rejected: Callable[[str], object] | None = None,
    ) -> None: ...
    @staticmethod
    def mode(
        mode: Mode,
        *,
        count: int = 1,
        cache: CarrierCache | None = None,
        key: str = "",
        timer_factor: float = 3.0,
        timer_min: float = 1.0,
        timer_max: float = 3.0,
        settle: float = 1.0,
        drop_window: float = 30.0,
        rotate_max_bytes: int | None = None,
        rotate_max_age: float | None = None,
        rotate_jitter: float = 0.0,
        pool_policy: PoolPolicy | str | bytes | Mapping[str, Any] | None = None,
        options: PipeOptions | None = None,
        decision_rejected: Callable[[str], object] | None = None,
    ) -> PipePool:
        """A pool whose members are dialed over the carrier kinds of `mode`:
        each over the most robust kind available (one `cache` holds as
        usable under `key`, else the exchange carrier, else the last),
        skipping the kinds held as failed unless all are; a split candidate
        joins as a downlink and an uplink, one member. A member of a kind a
        preferred kind not backing off could replace is upgraded to it make
        before break, one upgrade at a time and only with room within
        `max_pipes`: the replacement takes over once it stayed usable for
        `settle` seconds, and the old member is closed gracefully. A kind
        whose join fails, whose replacement ends before it settled, or whose
        member fails within `drop_window` of being joined is recorded as
        failed. Every try is a `CarrierCandidate` event. `Mode.explicit`
        dials its one kind without the cache. The other arguments are as
        `PipePool`'s; an invalid mode or policy raises `ValueError`."""
    @property
    def count(self) -> int: ...

@final
class MaintainHandle:
    """Stops a pool's maintainer on `stop()` or when collected; it also ends with the session."""

    def stop(self) -> None:
        """Stops the maintainer; pipes it added stay in the session."""
    @property
    def finished(self) -> bool: ...

@final
class Candidate:
    """One carrier kind a `Mode` may use. Credentials go on the candidate;
    the exchange authenticates with its options' PSK."""

    @staticmethod
    def streaming(
        addr: str, *, path: str = "/zmux", credential: _Credential | None = None
    ) -> Candidate:
        """A bidirectional streaming POST over HTTP/1.1."""
    @staticmethod
    def split(
        addr: str, *, path: str = "/zmux", credential: _Credential | None = None
    ) -> Candidate:
        """A split bootstrap; as a further pipe, a downlink and an uplink."""
    @staticmethod
    def exchange(addr: str, *, options: ExchangeOptions | None = None) -> Candidate:
        """The exchange carrier (paths that buffer whole bodies)."""
    @staticmethod
    def websocket(
        url: str, *, tls: TlsConfig | None = None, credential: _Credential | None = None
    ) -> Candidate:
        """A WebSocket to a `ws://` or `wss://` URL."""
    @staticmethod
    def quic(
        addr: str,
        *,
        tls: TlsConfig | None = None,
        server_name: str | None = None,
        lanes: int = 4,
        credential: _Credential | None = None,
    ) -> Candidate:
        """A QUIC connection, where the client reaches the server directly (as `dial_quic`)."""
    @staticmethod
    def http3(
        url: str,
        *,
        tls: TlsConfig | None = None,
        addr: str | None = None,
        lanes: int = 4,
        credential: _Credential | None = None,
    ) -> Candidate:
        """An HTTP/3 request to an `https://` URL, sent to `addr` when given (as `dial_h3`)."""
    @staticmethod
    def webtransport(
        url: str,
        *,
        tls: TlsConfig | None = None,
        lanes: int = 4,
        credential: _Credential | None = None,
    ) -> Candidate:
        """A WebTransport session to an `https://` URL (as `dial_webtransport`)."""
    @property
    def kind(self) -> str: ...

@final
class Mode:
    """How `dial_mode` chooses the carrier."""

    @staticmethod
    def explicit(candidate: Candidate) -> Mode:
        """That kind only: a failure is reported, never replaced."""
    @staticmethod
    def auto(candidates: list[Candidate]) -> Mode:
        """A choice among `candidates`, most preferred first."""
    @property
    def is_auto(self) -> bool: ...

@final
class CarrierCache:
    """Which carrier kinds worked per server and local network (`key`),
    shared by the dials given it: a usable kind for `success_ttl`, a failed
    one skipped for a backoff doubling from `backoff_min` to `backoff_max`
    (seconds)."""

    def __init__(
        self,
        *,
        success_ttl: float = 21600.0,
        backoff_min: float = 60.0,
        backoff_max: float = 21600.0,
    ) -> None: ...
    def is_usable(self, key: str, carrier: str) -> bool: ...
    def is_failed(self, key: str, carrier: str) -> bool: ...
    def snapshot(self) -> str:
        """What the cache knows as JSON text (versioned, times in RFC 3339
        UTC, shared by every implementation), to `restore` later, such as
        in the next run of the process. Expired entries are left out."""
    def restore(self, snapshot: str) -> None:
        """Merges a `snapshot` in: of two entries for one key and kind the
        newer is kept, a backoff outside this cache's bounds is brought
        within them, and expired entries, unknown fields and unknown kinds
        are dropped. Malformed text raises `ValueError` and changes nothing."""

async def dial_mode(
    mode: Mode,
    config: _t.Config | None = None,
    *,
    cache: CarrierCache | None = None,
    key: str = "",
    timer_factor: float = 3.0,
    timer_min: float = 1.0,
    timer_max: float = 3.0,
    settle: float = 1.0,
    drop_window: float = 30.0,
    no_join: bool = False,
) -> Session:
    """A session over the carrier `mode` selects. `Mode.auto` sends no early
    data and races no candidates: it skips kinds the cache holds as failed,
    abandons a candidate whose transport parameters do not arrive within its
    timer (`timer_factor` (3) times the carrier's opening round trip, within
    `timer_min` 1 s and `timer_max` 3 s), and with `max_pipes` above 1
    establishes on the most robust candidate and joins the preferred ones in
    the background, retiring the replaced pipes once a join has settled
    (`settle`, 1 s). A kind that fails within `drop_window` (30 s) of its
    choice counts as failed. Every try and the choice are session events
    (`CarrierCandidate`, `CarrierChosen`) and in `Session.stats()`. Raises
    `ModeError` when no candidate was usable."""

@final
class ExchangeOptions:
    """The HTTP exchange carrier's options; both ends must agree on `psk` and
    `encoding`, the rest is local. Unset values keep the defaults. A carrier
    is authenticated by `psk`; without one it must be declined explicitly
    with `unauthenticated=True` (the MACs then only bind responses to
    requests), else `dial_exchange` and `serve_http` raise ValueError."""

    def __init__(
        self,
        *,
        psk: bytes | None = None,
        unauthenticated: bool = False,
        encoding: Literal["binary", "base64"] = "binary",
        path: str | None = None,
        down_path: str | None = None,
        query: str | None = None,
        down_requests: int | None = None,
        up_requests: int | None = None,
        up_piece: int | None = None,
        max_down_piece: int | None = None,
        backoff_initial: float | None = None,
        backoff_max: float | None = None,
        request_timeout: float | None = None,
        deadline: float | None = None,
        hold: float | None = None,
        coalesce: float | None = None,
        down_piece: int | None = None,
        down_window: int | None = None,
        max_up_piece: int | None = None,
        up_store: int | None = None,
        idle_timeout: float | None = None,
        gone_memory: float | None = None,
        max_carriers: int | None = None,
        time_window: float | None = None,
        max_recorded: int | None = None,
    ) -> None:
        """`path` (default `/zmux/exchange`) and `down_path` (default: `path`)
        are client templates: `{instance}` becomes a per-carrier token,
        `{nonce}` a fresh value per request (else added as query parameter
        `query`, default `n`); the server matches the part before the first
        placeholder. Client: `down_requests`/`up_requests` 2, `up_piece` and
        `max_down_piece` 1 MiB, backoff 0.02 s doubling to 2 s,
        `request_timeout` 25 s, `deadline` 30 s. Server: `hold` 20 s,
        `coalesce` 0.002 s, `down_piece` and `max_up_piece` 1 MiB,
        `down_window` 32, `up_store` 4 MiB, `idle_timeout` and `gone_memory`
        60 s, `max_carriers` unlimited, `time_window` 60 s (whole seconds;
        requests whose time differs more are not authenticated),
        `max_recorded` 262144 request nonces."""
    @property
    def encoding(self) -> Literal["binary", "base64"]: ...
    @property
    def path(self) -> str: ...
    @property
    def down_path(self) -> str | None: ...

async def dial_exchange(
    addr: str,
    *,
    options: ExchangeOptions | None = None,
    down_addr: str | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    credential: PrefixAuth | _t.Credential | None = None,
) -> PipeIo:
    """An HTTP exchange carrier: plain HTTP/1.1 POST requests to `addr`
    (`host:port`), DOWN requests to `down_addr` when given, over TLS with
    `tls`; with `credential`, its prefix starts the uplink, for a server's
    admission. Returns without a round trip."""

async def dial_h3(
    url: str,
    *,
    tls: TlsConfig | None = None,
    addr: str | None = None,
    lanes: int = 4,
    credential: _Credential | None = None,
) -> PipeIo:
    """A pipe on an HTTP/3 request to `url` (`https://`), sent to `addr` when given.
    With `credential`, its prefix is the first bytes of every request body."""

async def dial_webtransport(
    url: str,
    *,
    tls: TlsConfig | None = None,
    lanes: int = 4,
    credential: _Credential | None = None,
) -> PipeIo:
    """A pipe on a new WebTransport session to `url` (`https://`); the
    credential's header field goes on the session request."""

@final
class Http2Connection:
    """An HTTP/2 connection whose exchanges carry pipes: prior knowledge
    without `tls`, ALPN `h2` with it. Open several pipes on one connection."""

    @staticmethod
    async def connect(
        addr: str,
        *,
        path: str = "/zmux",
        tls: TlsConfig | None = None,
        server_name: str | None = None,
        credential: _Credential | None = None,
    ) -> Http2Connection:
        """With `credential` (unbound), its prefix is the first bytes of every
        request body."""
    async def open_pipe(self) -> PipeIo:
        """A pipe on a new exchange."""
    async def open_carrier(
        self, carrier: _HttpCarrier = "bidirectional", join: str | None = None
    ) -> PipeIo:
        """A carrier of `carrier`'s direction on a new request (see `dial_http`)."""
    async def open_split(self) -> PipeIo:
        """A split bootstrap on two new requests of the connection."""
    async def join_split(
        self, session: Session, *, options: PipeOptions | None = None
    ) -> list[Pipe]:
        """Joins a split carrier on two new requests of the connection to
        `session` as two further pipes (see `join_http_split`)."""

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
        credential: _Credential | None = None,
    ) -> None:
        """With `credential`, its prefix is the first stream's first bytes
        and no 0-RTT data is sent."""
    async def dial(self, addr: str, *, server_name: str | None = None) -> PipeIo:
        """A pipe on a new connection."""
    async def connect(
        self,
        addr: str,
        *,
        server_name: str | None = None,
        config: _t.Config | None = None,
    ) -> Session:
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
    async def write_chunk(self, buffer: Buffer) -> None:
        """Writes any buffer-protocol object without copying it; the caller
        does not modify it afterwards."""
    def set_reliable_boundary(self) -> None:
        """Marks the bytes written so far as delivered even if the stream is
        reset later (RESET_STREAM_AT Reliable Size)."""
    def send_capacity(self) -> int:
        """The bytes the part could transmit now: the smaller of its stream
        and session credit, minus what it holds unsent."""
    async def wait_send_capacity(self, min: int) -> int:
        """Waits until the send capacity is at least `min` (>= 1), or above 0
        while nothing is unsent, and returns it; the stream's error otherwise."""
    def set_send_buffer(self, n: int) -> None:
        """The written-but-unreleased bytes this part may hold."""
    def set_scheduler(self, scheduler: Scheduler | None) -> None:
        """The part's scheduling policy; `None` follows the session's."""
    def set_redundant(self, on: bool | None) -> None:
        """Sends the part's chunks redundantly on a second pipe of the tier
        (multipath): `True` on, `False` off, `None` following the session's
        `redundancy`."""
    def send_datagram(self, payload: bytes, context: int = 0) -> None:
        """Sends a datagram of the stream with the context ID `context`."""
    def stats(self) -> StreamStats:
        """A snapshot of the stream; its final values once the session released it."""
    async def stopped(self) -> int | None:
        """Waits until the peer stops the stream (returns its code) or acknowledged all data (`None`)."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...

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
        """Metadata the opener attached (`info`, `tlvs`, `pipe_carrier`)."""
    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes; `b""` at the end of the stream. Raises `StreamReset` if the peer reset it."""
    async def read_exact(self, n: int) -> bytes:
        """Exactly `n` bytes, or `IncompleteRead`."""
    async def read_to_end(self, limit: int = 16777216) -> bytes:
        """The rest of the stream; `LimitExceeded` beyond `limit` bytes."""
    async def stop(self, code: int = 0) -> None:
        """Asks the peer to stop sending (STOP_SENDING) with an application error code."""
    async def read_chunk(self, max: int = 65536) -> memoryview:
        """Up to `max` bytes as a read-only view of the received buffer,
        without a copy; empty at the end of the stream."""
    def reject(self) -> None:
        """Declines the stream before reading it (ZMUX_REJECTED); the handle,
        and the sending one of a stream not written to, are used up."""
    def set_receive_window(self, initial: int, max: int) -> None:
        """The stream's receive window: `initial` now, auto-tuned up to `max`."""
    def set_peer_priority(self, priority: _Prio) -> None:
        """Asks the peer to send the stream with `priority`."""
    async def read_datagram(self) -> tuple[int, bytes]:
        """The next datagram of the stream: `(context, payload)`."""
    def stats(self) -> StreamStats:
        """A snapshot of the stream; its final values once the session released it."""
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> bytes: ...
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...

@final
class Pipe:
    """One pipe (carrier) of a multipath session. `close()` removes it
    gracefully (drain), `abort()` at once; `async with` closes it on a
    normal exit and aborts on an exception. Watch `Session.events()` for
    its state changes."""

    @property
    def id(self) -> int: ...
    @property
    def admitted(self) -> Any:
        """The value the listener's admission gave the carrier that brought
        the pipe (`Verdict.accept(value=...)`): its join's carrier, the
        session's for pipe 0; `None` without one and once the session forgot
        the pipe."""
    @property
    def options(self) -> PipeOptions | None:
        """The options in force, with the fields `update` set (the effective
        values, which may follow the peer's request, are in `stats()`);
        `None` once the pipe's state is released."""
    @property
    def state(self) -> OutboundState | InboundState | str | None:
        """The outbound direction's state (else the inbound one's); `None`
        once the pipe is retired or the session released it."""
    @property
    def session(self) -> Session:
        """The session the pipe belongs to (its `zero_rtt` report is `None`)."""
    async def joined(self) -> None:
        """Waits until the peer confirmed the join; `PipeError` if it failed."""
    async def closed(self) -> None:
        """Waits until the pipe ended: returns once every direction closed
        (or the session released it); `PipeError` if it failed or the
        session ended first."""
    def update(
        self,
        *,
        send_priority: int | None = ...,
        receive_priority: int = ...,
        send_standby: bool | None = ...,
        receive_standby: bool = ...,
        weight: int = ...,
        probation: float = ...,
    ) -> None:
        """Changes these settings together (both receive fields: one
        PIPE_STATUS); a keyword left out keeps its value, and
        `send_priority=None` or `send_standby=None` clears the local setting
        (the peer's request applies). A field fixed when the pipe is added,
        an unknown name or `None` for another field raises `TypeError`; an
        invalid value raises `ValueError` and changes nothing."""
    def close(self) -> None: ...
    def abort(self) -> None: ...
    def stats(self) -> PipeStats | None:
        """A snapshot; `None` once the pipe is retired or the session
        released it (reads never raise; operations then raise `PipeError`)."""
    def set_quality_band(self, band: QualityBand | None) -> None:
        """The pipe's own quality band; `None` uses the session's."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...

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
    @property
    def admitted(self) -> Any:
        """The value the listener's admission gave the carrier that started
        the session (`Verdict.accept(value=...)`; a split bootstrap's
        uplink's), for the session's lifetime, resumptions included; `None`
        without one and on a client."""
    async def open_bi(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        pipe_carrier: bool = False,
        priority: _Prio | None = None,
        peer_priority: _Prio | None = None,
    ) -> tuple[SendStream, RecvStream]:
        """Opens a bidirectional stream, waiting for stream credit; the
        preamble (`info`, `tlvs`, `pipe_carrier`) is fixed before its first
        frame. A cancelled open leaves no stream behind for the caller."""
    def try_open_bi(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        pipe_carrier: bool = False,
        priority: _Prio | None = None,
        peer_priority: _Prio | None = None,
    ) -> tuple[SendStream, RecvStream]:
        """Opens a bidirectional stream if stream credit is available now;
        `OpenError` otherwise. Never waits."""
    async def open_pipe_stream(
        self, tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None
    ) -> PipeIo:
        """Opens a carrier stream (PIPE_CARRIER) with the application TLVs
        `tlvs`, as the pipe input of a nested session."""
    def set_quality_band(self, band: QualityBand | None) -> None:
        """The default quality band of the session's pipes; `None`: no reports."""
    def set_capacity_floor(self, floor: CapacityFloor | None) -> None:
        """The floor under the session's outbound capacity; `None`: none."""
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
    def set_shaper(
        self,
        *,
        json: str | None = None,
        sequence: str | None = None,
        by_kind: Mapping[_t.CarrierKind | str | None, str] | None = None,
        limits: _t.ShapingSizeLimits | None = None,
        seed: bytes | None = None,
    ) -> None:
        """Shapes every outbound pipe by a definition (JSON or sequence form),
        bounded by `limits`; none: no shaping. `by_kind` maps carrier kinds
        (`None`: the default, for a pipe of no kind or of a kind not listed)
        to definitions in the JSON form; a pipe without a definition is not
        shaped. `seed` (for tests) makes
        every pipe draw the same deterministic sequence instead of the
        operating system's generator; never use it for real traffic."""
    def shaping_stats(self) -> dict[str, int | float]:
        """Shaping counters: padding_bytes, injected, inject_dropped, clamped, pause_total (s), faults."""
    def add_pipe(self, pipe: PipeIo, *, options: PipeOptions | None = None) -> Pipe:
        """Adds a carrier as a further pipe (multipath); returns at once, see `Pipe.joined()`."""
    def maintain_pipes(self, pool: PipePool) -> MaintainHandle:
        """Keeps `pool`'s pipes up (dials, redials with backoff, rotation, the
        pool policy's decisions); needs a running event loop, on which `dial` runs."""
    def reserve_pipe(
        self,
        direction: Direction | str = Direction.BIDI,
        *,
        options: PipeOptions | None = None,
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
    @property
    def early_data(self) -> EarlyDataState:
        """What became of the early data: not sent, pending, accepted or rejected."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> tuple[SendStream, RecvStream]: ...

@final
class Listener:
    """Accepts sessions (and multipath joins) from any number of carriers.
    Each `serve_*` binds `addr` (port 0 picks one) and returns the bound
    address. `async for session in listener` until `close()`."""

    def __init__(
        self,
        config: _t.Config | None = None,
        *,
        max_pending: int | None = None,
        max_pending_per_source: int | None = None,
        max_pending_per_session: int | None = None,
        first_record_timeout: float | None = None,
        handshake_timeout: float | None = None,
        max_record_size: int | None = None,
        accept_sessions: bool | None = None,
        max_suspended: int | None = None,
        memory_budget: float | None = None,
        instance_id: bytes | None = None,
        on_memory_pressure: Callable[[int, int, bool], None] | None = None,
        trusted_proxies: list[str] | None = None,
        forwarded_header: str | None = None,
        proxy_protocol: bool = False,
        admission: Admission | None = None,
        inbound_transform: Callable[[PipeIo, PipeHint], Awaitable[PipeIo] | PipeIo]
        | None = None,
        answer_unknown_joins: bool = False,
    ) -> None:
        """Arguments left out keep the defaults: `max_pending` 64 carriers being
        classified, `max_pending_per_source` 8, `max_pending_per_session` 4
        pending joins, `first_record_timeout` 2 s, `handshake_timeout` 10 s,
        `max_record_size` 65535, `accept_sessions` True, `max_suspended` 1024,
        `memory_budget` 1 GiB (`math.inf`: unlimited). `instance_id` (at most 8 bytes)
        starts every session locator, for load-balancer stickiness.
        `on_memory_pressure(used, budget, active)` is called when memory
        pressure starts and ends.

        Behind reverse proxies, load balancers or CDNs, `trusted_proxies`
        lists their networks (`"10.0.0.0/8"`, a bare address): a carrier from
        one of them has as its source, for the per-source limits and the
        admission, the client the intermediary reports, in a PROXY protocol
        header with `proxy_protocol`, or in the HTTP header field
        `forwarded_header` (`Forwarded`, or a list such as
        `X-Forwarded-For`). Reports from other peers are ignored.

        `admission` applies at every entry (every `serve_*` and
        `handle_pipe`), in one order: the carrier takes a slot of its
        source's `max_pending_per_source` (refused at once beyond it), then
        its outer handshake (TLS, HTTP upgrade, QUIC), then the admission,
        then its first record.

        `inbound_transform(pipe, hint)` runs once for every carrier after its
        admission and before its first record, each half of a split
        bootstrap included, and returns the carrier the listener goes on
        with (typically `await pipe.wrap(layer, server_side=True)`, or `pipe`
        itself); `async`, it runs on the event loop of the listener's
        creation, which must be running (`RuntimeError` otherwise). It holds
        the carrier's source slot and `handshake_timeout` bounds it (then it
        is cancelled); the first-record timeout runs from its return. A
        carrier of another kind (other halves or framing), an exception or
        the bound closes the carrier as a setup failure; an exception other
        than a cancellation is reported as unraisable.

        With `answer_unknown_joins`, an admitted, well-formed join whose
        locator begins with `instance_id` and names no session here is
        answered with CONNECTION_CLOSE `TransportErrorCode.RESUME_FAILED`,
        so that the joiner ends a suspended session at once (`SessionClosed`
        with that `code`) instead of retrying until its resume timeout; the
        answered join counts as rejected, and every other rejection stays
        silent. Turn it on only where a locator with this `instance_id`
        reaches no other instance (one instance, or distinct identifiers):
        a joiner sent to the wrong instance would end a session that lives
        on there."""
    async def serve_tcp(self, addr: str) -> str:
        """With the listener's `admission`, a connection reaches it once admitted."""
    async def serve_tls(self, addr: str, *, tls: TlsConfig) -> str:
        """Without ALPN identifiers in `tls`, zmux's are accepted. The
        admission decides after the handshake, with its exporter."""
    async def serve_quic(
        self,
        addr: str,
        *,
        tls: TlsConfig,
        lanes: int = 4,
        zero_rtt: bool = False,
    ) -> str:
        """With `zero_rtt`, 0-RTT is accepted when `Config(carrier_early_data=True)`.
        With the listener's `admission`, the prefix is the first stream's
        first bytes; it excludes `zero_rtt` (ValueError)."""
    async def serve_h3(self, addr: str, *, tls: TlsConfig, lanes: int = 4) -> str:
        """With the listener's `admission`, each request is decided on the
        first bytes of its body."""
    async def serve_webtransport(
        self, addr: str, *, tls: TlsConfig, lanes: int = 4
    ) -> str:
        """With the listener's `admission`, each session request is decided
        on its request head (no prefix), with the QUIC connection's exporter."""
    async def serve_websocket(self, addr: str, *, tls: TlsConfig | None = None) -> str:
        """With the listener's `admission`, each upgrade is decided on its
        request head (no prefix), with the TLS exporter under `tls`."""
    async def serve_http(
        self,
        addr: str,
        *,
        path: str = "/zmux",
        tls: TlsConfig | None = None,
        exchange: ExchangeOptions | None = None,
        websocket: bool = False,
    ) -> str:
        """One HTTP endpoint for every HTTP carrier: HTTP/1.1 and HTTP/2
        (prior knowledge, or ALPN with `tls`), each request classified by its
        head: bidirectional, uplink and downlink requests and split
        bootstraps on `path`, with `exchange` the exchange carrier on its
        paths, with `websocket` WebSocket upgrades on `path`. With the
        listener's `admission`, a request is decided on the first bytes of its
        body, or on its head when it has none (a credential's header form);
        a new exchange carrier is decided on the first bytes of its uplink. A
        carrier request forwarded from TLS early data (`Early-Data: 1`) is
        answered 425."""
    async def handle_pipe(
        self,
        pipe: PipeIo,
        *,
        peer: tuple[str, int] | None = None,
        source: tuple[str, int] | None = None,
    ) -> None:
        """Hands over a carrier the application accepted itself: `peer` is its
        directly connected peer, `source` the client the application resolved
        (unset, the peer; the peer unset, `127.0.0.1:0`). It takes a source
        slot and goes through the listener's admission, joins and
        resumptions too."""
    async def shutdown(self, code: int = 0, reason: bytes = b"") -> None:
        """Closes gracefully: new sessions are refused at once while joins
        and resumptions of the live sessions are still taken; every session
        is shut down with `code` and `reason`, and once they all ended the
        listener closes. Cancelled (a timeout), it closes at once."""
    async def accept(self) -> Session:
        """The next established session; `ListenerClosed` once closed."""
    def close(self) -> None:
        """Closes at once: everything new is refused, joins and resumptions
        included, and the `serve_*` loops end."""
    def stats(self) -> ListenerStats:
        """What happened to the carriers handed to the listener: counts since it was made."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Session: ...

def stream_pipe(send: SendStream, recv: RecvStream) -> PipeIo:
    """A bidirectional stream as a pipe input: one that carries
    PIPE_CARRIER, or any the application knows to be a carrier. The two
    handles are used up."""

async def splice(
    a: tuple[SendStream, RecvStream],
    b: tuple[SendStream, RecvStream],
    *,
    chunk: int = 65536,
    a_to_b: Limiter | None = None,
    b_to_a: Limiter | None = None,
) -> Spliced:
    """Forwards two bidirectional streams into each other until both
    directions ended; the handles are used up. Splicing a stream into
    itself raises `ValueError`; cancelling the task cancels the splice."""

def resolve_duplicate(
    s1: Session,
    s2: Session,
    *,
    local_identity: bytes | None = None,
    peer_identity: bytes | None = None,
    rejoin: Callable[[], Awaitable[PipeIo]] | None = None,
) -> Resolved:
    """Decides between two sessions that raced between the same endpoints:
    keeps one, drains the other, and starts `rejoin` (on the running event
    loop) to keep the loser's route as a pipe of the survivor. An
    undecidable pair or one with the same dialer raises `ValueError`."""
