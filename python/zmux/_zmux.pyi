"""Native layer. Every coroutine here is cancellation-safe unless noted:
cancelling the awaiting task drops the pending operation and leaves the
session, stream or pipe usable. Use `asyncio.timeout()` for per-call
deadlines; durations are seconds."""

import os
from collections.abc import Awaitable, Buffer, Callable, Iterable, Mapping
from typing import Any, ClassVar, Literal, Protocol, Self, final

from . import _types as _t
from ._layer import Layer
from ._streams import StreamPairReader, StreamPairWriter
from ._errors import SessionClosedError
from ._types import (
    BiStream,
    CapacityFloor,
    EarlyDataState,
    Event,
    InboundState,
    Limiter,
    ListenerStats,
    OutboundState,
    Packet,
    PacketStats,
    PipeOptions,
    PipeStats,
    Preamble,
    Priority,
    QualityBand,
    ReplayVerdict,
    Resolved,
    Role,
    Scheduler,
    SendPolicy,
    Sent,
    SessionState,
    SessionStats,
    Spliced,
    StreamDatagram,
    StreamStats,
    Tlv,
)

type _Pem = str | os.PathLike[str] | bytes
type _Prio = Priority | tuple[int, bool]
type _Headers = Mapping[str, str] | Iterable[tuple[str, str]]

DEFAULT_KEEP_ALIVE_PERIOD: float
"""Default keep-alive period, seconds (15)."""
DEFAULT_IDLE_TIMEOUT: float
"""Default idle timeout, seconds (30)."""
DEFAULT_PROBE_JITTER: float
"""Default probe jitter (0.25)."""
DEFAULT_STANDBY_PROBE: float
"""Default standby probe interval, seconds (1)."""
DEFAULT_SUSPECT_FLOOR: float
"""Default floor of a pipe's suspicion, seconds."""
MAX_FIRST_BYTES: int
"""The most bytes `classify_first_bytes` needs (5)."""
MAX_STREAM_CREDIT: int
"""The largest stream count the protocol can count, 2**60: the value that
grants the peer as many streams as it can, in effect no limit. It is the top
of the range of `Config.max_incoming_streams`,
`Config.max_incoming_uni_streams` and `Session.raise_incoming_streams`, a
value of that range and not a setting: 0 keeps meaning none."""
RESERVED_EXPORTER_PREFIX: str
"""The start of the exporter labels zmux itself uses."""
DEFAULT_MAX_RECORD_SIZE: int
"""Record size limit before the peer's parameters, bytes (16382)."""
DEFAULT_MIN_BACKOFF: float
"""Shortest redial wait of the `redial` hook and of a pipe pool, seconds (1)."""
DEFAULT_MAX_BACKOFF: float
"""Longest redial wait of the `redial` hook and of a pipe pool, seconds (60)."""
DEFAULT_BACKOFF_JITTER: float
"""Default jitter of a `Backoff`: each wait shortened by up to this fraction
(0.2)."""
DEFAULT_LANES: int
"""Default number of QUIC streams a QUIC, HTTP/3 or WebTransport carrier uses
as lanes (4)."""
DEFAULT_JOIN_TIMEOUT: float
"""Default join deadline, seconds (10)."""
MIN_MAX_LEN: int
"""Smallest shaping `max_len` honoured, bytes (64)."""
DEFAULT_MAX_DELAY: float
"""Default longest delay a shaper may hold a record, seconds (1)."""
DEFAULT_MAX_APP_DATA: int
"""Default bound of the application data of a received handshake message, bytes (256)."""
DEFAULT_MAX_SLOTS: int
"""Default bound on the counters and timers of a shaping candidate (4096)."""
_KEYALG_X25519: int
_KEYALG_MLDSA44: int

def _config_defaults() -> dict[str, Any]:
    """Internal: the library's defaults of the `zmux.Config` fields."""

def _listener_defaults() -> dict[str, Any]:
    """Internal: the library's defaults of the `zmux.ListenerConfig` fields."""

def shaping_limits_from_json(text: str) -> _t.ShapingLimits:
    """Reads local limits from JSON; any error raises `ValueError`."""

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
    typically at each write to the carrier (`pipe_pair(unsent=...)`)."""

    def __init__(self, n: int | None = None) -> None: ...
    def set(self, n: int | None) -> None:
        """Sets the count: the bytes the carrier took and has not yet
        transmitted, or `None` when it cannot tell."""
    @property
    def value(self) -> int | None:
        """The count as last set."""

@final
class PipeIo:
    """A pipe input: a carrier, or the pair of carriers of a split, not yet
    given to a session; usable once. Its settings are properties, changed in
    place until the input is given to a session (then reading or writing one
    raises `PipeUsedError`); what a carrier's author sets once is a
    parameter of the function that builds the input (`pipe_pair`,
    `pipe_from_streams`)."""

    @property
    def carrier_kind(self) -> _t.CarrierKind | str | None:
        """The carrier kind, or `None`: what a by-kind shaper picks by, and
        the kind in pipe events and statistics."""
    @carrier_kind.setter
    def carrier_kind(self, kind: _t.CarrierKind | str) -> None: ...
    @property
    def variant(self) -> str | None:
        """The host's name of the transform the carrier runs, or `None`:
        reported in `PipeStats.variant`, and what
        `Shaper(by_variant=...)` picks by."""
    @variant.setter
    def variant(self, variant: str) -> None: ...
    @property
    def write_overhead(self) -> int:
        """The fixed bytes (0 to 65535, `ValueError` otherwise) the layers
        below zmux add to each write on the carrier, such as a wrapping
        layer's record header and tag, which a shaper takes into account."""
    @write_overhead.setter
    def write_overhead(self, overhead: int) -> None: ...
    @property
    def terminated_tls(self) -> _t.TlsState | None:
        """The TLS or QUIC handshake this process ran for the carrier,
        complete; `None` without TLS or where it ends at a proxy. Assigning
        a `TlsState` declares such a handshake; not to be set where TLS ends
        at a proxy. No proof of an end-to-end handshake: exporters come from
        the `exporter` parameter of the function that builds the input."""
    @terminated_tls.setter
    def terminated_tls(self, state: _t.TlsState) -> None: ...
    def declare_secure(self) -> None:
        """Declares the carrier secure: it meets the secure carrier's Bound
        contract, record confidentiality and integrity included, so a
        `record_policy` may choose `RecordMode.BOUND` on it
        (`RecordPolicyInput.secure`). An exporter alone is no such
        declaration; a carrier whose TLS ends outside the process is not
        secure."""
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
class _LayerEnd:
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
        """The admission's value for the carrier (`AdmissionVerdict.accept(value=...)`),
        `None` without one."""

@final
class PipeEnd:
    """The application's end of `pipe_pair()`."""

    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes the session wrote; `b""` once it closed."""
    async def write(self, data: bytes) -> None:
        """Delivers `data` to the session; `b""` ends the pipe."""

def pipe_pair(
    *,
    carrier_kind: _t.CarrierKind | str | None = None,
    unsent: UnsentCount | None = None,
    max_record: int | None = None,
    exporter: Callable[[str, bytes, int], bytes | None] | None = None,
) -> tuple[PipeIo, PipeEnd]:
    """An in-memory pipe: give the `PipeIo` to a session, drive the
    `PipeEnd` yourself. `carrier_kind` labels it with a carrier kind
    (`PipeIo.carrier_kind`). `unsent` is the carrier's unsent count, which
    the application keeps up to date with the bytes the carrier took and has
    not yet transmitted (it feeds `PipeStats.queued_bytes` and the
    scheduler's queue estimate; the session's driver reads it without the
    interpreter lock). `max_record` (at least 1) is the largest record
    plaintext the carrier takes, applied beside the peer's
    `max_record_size`. `exporter(label, context, length)` is the exporter of
    the carrier's innermost end-to-end handshake, the one source of
    `PipeAuth.exporter()`, carrier-bound joins and
    `Session.export_keying_material`: it returns `length` bytes, or `None`
    while the handshake is incomplete; an exception or another length gives
    no value and is reported as unraisable. It is called from any thread
    when a value is needed, possibly with the session's lock held: it must
    be quick and must not call this session. Where the session's thread
    waits, it waits at most a second for the interpreter, then has no value.
    Never give an early exporter. A stream carrier ignores it."""

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
class AdmissionVerdict:
    """The outcome of an admission decision."""

    FALLBACK: ClassVar[AdmissionVerdict]
    """To the fallback handler, every byte read replayed; without one the
    carrier is stalled (an HTTP request gets 404)."""
    STALL: ClassVar[AdmissionVerdict]
    """Nothing is sent; what arrives is discarded until the stall interval
    has passed, then the carrier is closed."""
    CLOSE: ClassVar[AdmissionVerdict]
    """The carrier is closed at once."""
    @staticmethod
    def accept(skip: int = 0, value: Any = None) -> AdmissionVerdict:
        """To the listener, without the first `skip` bytes of the prefix;
        `value`, any object, is the carrier's admitted value
        (`PipeHint.admitted`, `Session.admitted`, `Pipe.admitted`)."""
    @staticmethod
    def more(need: int) -> AdmissionVerdict:
        """Reads until the prefix holds `need` bytes in all (or the carrier
        ends, or the peek timeout passes, all rounds sharing it), then decides
        again with the longer prefix. `need` exceeds the prefix and is at most
        `Admission.max_peek`, on a byte stream; otherwise, and on a carrier
        that ended short, it counts as `CLOSE`."""
    def labelled(self, variant: str) -> Decision:
        """A `Decision` of this verdict labelled `variant`."""
    @property
    def need(self) -> int | None:
        """A `more`'s `need`; `None` for another verdict."""
    @property
    def skip(self) -> int | None:
        """An accept's `skip`; `None` for another verdict."""
    @property
    def value(self) -> Any:
        """An accept's value."""

@final
class Decision:
    """A decision on a carrier: its verdict and the host's label of the kind
    of carrier."""

    def __init__(
        self, verdict: AdmissionVerdict, *, variant: str | None = None
    ) -> None:
        """A label counts the verdict in `AdmissionStats.variants` and, on an
        accept, becomes the carrier's variant. It is one of a few constants of
        the host, never derived from the peer's bytes."""
    @property
    def verdict(self) -> AdmissionVerdict: ...
    @property
    def variant(self) -> str | None: ...

@final
class Admission:
    """A listener's admission of new carriers (`ListenerConfig(admission=...)`),
    applied at every entry, joins and resumptions included:
    `decide(info, prefix)` is called once per carrier, after its outer
    handshake, with its metadata and up to `peek` first bytes (none on
    carriers decided on an HTTP request head) and returns an `AdmissionVerdict` or
    `Decision`, or is
    `async` and resolves to one. A synchronous one runs on a native thread
    holding the GIL, so it must be quick and must not block; an `async` one
    runs on the event loop the `Listener` was made in, and is cancelled
    (`CancelledError`) when the peek timeout ends or the listener closes.
    An exception or another return value closes the carrier.
    `max_peek` is the largest prefix `AdmissionVerdict.more` may ask for and the
    largest first message of a message-framed carrier taken as a prefix (`peek`
    when larger; a longer message closes the carrier).
    `peek_timeout` (seconds, from the end of the outer handshake) bounds the
    reading of the prefix and the decision; `stall` is the `(min, max)`
    seconds a stalled carrier is held open; `AUTO` (the default) draws them
    at random. Within the interval, every carrier
    from one source is held open for the same duration during the listener's
    lifetime, and a held carrier counts against the listener's
    `max_pending_per_source` (beyond it, it is closed at once).
    A byte-stream carrier whose prefix has not arrived when the peek timeout
    ends is closed, or with `fallback_on_peek_timeout` taken to the fallback
    with the bytes read replayed (counted in both `peek_timed_out` and
    `fallback`). A message-framed carrier, an HTTP request carrier and a
    decision that does not return in time are closed either way."""

    def __init__(
        self,
        decide: Callable[
            [CarrierInfo, bytes],
            AdmissionVerdict | Decision | Awaitable[AdmissionVerdict | Decision],
        ],
        *,
        peek: int = 0,
        max_peek: int = 0,
        peek_timeout: float | _t.Auto = _t.AUTO,
        stall: tuple[float, float] | _t.Auto = _t.AUTO,
        fallback_on_peek_timeout: bool = False,
    ) -> None: ...
    @staticmethod
    def prefix_auth(
        auth: PrefixAuth,
        *,
        skew: int,
        max_nonces: int = 65536,
        peek_timeout: float | _t.Auto = _t.AUTO,
        stall: tuple[float, float] | _t.Auto = _t.AUTO,
        fallback_on_peek_timeout: bool = False,
    ) -> Admission:
        """Admission by `auth`'s tokens: `skew` slots of clock difference
        accepted, at most `max_nonces` Nonces recorded. The token is the
        carrier's first 32 bytes, or the request header field on a carrier
        decided on its request head; a carrier without a valid one goes to
        the fallback."""
    @property
    def peek(self) -> int: ...
    @property
    def max_peek(self) -> int:
        """The largest prefix, at least `peek`."""
    @property
    def fallback_on_peek_timeout(self) -> bool: ...
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

type _CarrierCredential = PrefixAuth | _t.CarrierCredential

async def dial_tcp(
    host: str, port: int, *, carrier_credential: _CarrierCredential | None = None
) -> PipeIo:
    """A pipe input on a new TCP connection to `host` and `port`; with
    `carrier_credential`, its prefix is sent first (given no exporter)."""

async def dial_tls(
    host: str,
    port: int,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _CarrierCredential | None = None,
) -> PipeIo:
    """A pipe input on TLS over TCP; `server_name` defaults to `host`.
    With `carrier_credential`, its prefix is sent after the handshake. Without ALPN
    identifiers in `tls`, zmux's are offered."""

async def dial_quic(
    host: str,
    port: int,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _CarrierCredential | None = None,
) -> PipeIo:
    """A pipe input on a new QUIC connection using up to `lanes` QUIC
    streams. With `carrier_credential`, its prefix is the first stream's
    first bytes."""

async def dial_websocket(
    url: str,
    *,
    tls: TlsConfig | None = None,
    headers: _Headers | None = None,
    carrier_credential: _CarrierCredential | None = None,
    no_subprotocol: bool = False,
) -> PipeIo:
    """A pipe input on a WebSocket (`ws://` or `wss://`); `headers` go on the upgrade
    request, with the carrier credential's header field (given the TLS exporter with `wss://`).
    With `no_subprotocol` the request offers no subprotocol, so the carrier has
    no application protocol identifier; the server must allow it
    (`serve_http(websocket_no_subprotocol=True)`)."""

async def dial_streaming(
    host: str,
    port: int,
    *,
    path: str = "/zmux",
    carrier_credential: _CarrierCredential | None = None,
    direction: _t.Direction | str = _t.Direction.BIDI,
    pair_field: str | None = None,
) -> PipeIo:
    """A pipe input on an HTTP/1.1 request to `path` (carrier kind
    `streaming`) of `direction`: `BIDI` (a POST whose request and response
    bodies are the two directions), `OUT` (an uplink POST whose request
    body is the only one) or `IN` (a downlink GET whose response body is).
    With `carrier_credential` (unbound: the adapter has no exporter), its
    prefix is the first bytes of a request body, and a GET carries its
    header form."""

async def dial_split(
    host: str,
    port: int,
    *,
    path: str = "/zmux",
    carrier_credential: _CarrierCredential | None = None,
    pair_field: str | None = None,
) -> PipeIo:
    """A split bootstrap over two HTTP/1.1 connections: an uplink POST and a
    downlink GET paired by a fresh token in the request field `pair_field`
    (default `Zmux-Pipe-Pair`; the server must use the same one). The token is a
    bearer secret until the session is established: use TLS to the server
    or to a trusted TLS-terminating intermediary."""

async def join_split(
    session: Session,
    host: str,
    port: int,
    *,
    path: str = "/zmux",
    carrier_credential: _CarrierCredential | None = None,
    pair_field: str | None = None,
    options: PipeOptions | None = None,
) -> list[Pipe]:
    """Joins a split carrier over two HTTP/1.1 connections to `session`: one
    join across a POST and a GET paired by a token, one further pipe of the
    two directions, `options` choosing its direction; returns `[pipe]` as
    `add_pipe` does. A split bootstrap's carrier
    (`dial_split`) joins no session: `add_pipe` refuses it with
    `PipeError`. A `PipePool(join=...)` keeps such pairs up."""

@final
class PoolPolicy:
    """A pool policy read from a JSON object; its decisions run natively.

    Absent members keep the pool's own behaviour; unknown members raise
    `ValueError`. Pools given the same object share its state."""

    def __init__(self, definition: str | bytes | Mapping[str, Any]) -> None:
        """Reads a policy from its JSON `definition`; an invalid one raises
        `ValueError`."""
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
    """Members to keep up over one path, `count` usable ones, given exactly
    one way to make them (`TypeError` otherwise): with `dial()`, each a pipe
    on the carrier it opens; with `join(session, options)`, each the pipes
    it joins itself (such as `join_split`), usable while all of them
    are, counted once, and redialled, rotated and retired as a whole; with
    `choice` (a `CarrierChoice`, under `choice_policy`), each over the most
    robust kind available (one the policy's cache holds as usable, else the
    exchange carrier, else the last), skipping the kinds held as failed
    unless all are, and a member of a kind a preferred kind not backing off
    could replace is upgraded to it make before break, one upgrade at a
    time and only with room within `max_pipes`: the replacement takes over
    once it stayed usable for the policy's `settle`, and a kind whose join
    fails, whose replacement ends before it settled, or whose member fails
    within `drop_window` of being joined is recorded as failed; every try
    is a `CarrierCandidate` event. An invalid choice or policy raises
    `ValueError`.

    Redials back off from the start of the previous attempt, by `backoff`
    (a `Backoff`; `None`: the default one). Rotation
    replaces a usable member make before break once it carried
    `rotate_max_bytes` either way or is `rotate_max_age` seconds old, each
    reduced by a random fraction of up to `rotate_jitter` (`None`: no
    rotation by that measure). `pool_policy` (a `PoolPolicy` or its JSON)
    is consulted at each look of the maintainer: at once after a pipe
    changed state or the session was suspended or resumed (it keeps
    dialling while suspended), and at least every 100 ms; its `dial_after`
    replaces the backoff's delay, and its probe settings apply to the pipes
    added after it. `options` are the `PipeOptions` of every pipe of the
    pool. A policy decision that is not valid (a probe interval other than
    0 below 1 s) is rejected as a whole: the pool keeps its own behaviour
    and calls `decision_rejected(reason)`, if given, on the event loop."""

    def __init__(
        self,
        count: int = 1,
        dial: Callable[[], Awaitable[PipeIo]] | None = None,
        *,
        join: Callable[[Session, PipeOptions], Awaitable[Iterable[Pipe]]] | None = None,
        choice: CarrierChoice | None = None,
        choice_policy: CarrierChoicePolicy | None = None,
        rotate_max_bytes: int | None = None,
        rotate_max_age: float | None = None,
        rotate_jitter: float = 0.0,
        backoff: _t.Backoff | None = None,
        pool_policy: PoolPolicy | str | bytes | Mapping[str, Any] | None = None,
        options: PipeOptions | None = None,
        decision_rejected: Callable[[str], object] | None = None,
    ) -> None: ...
    @property
    def count(self) -> int:
        """Usable members to keep."""

@final
class MaintainHandle:
    """Stops a pool's maintainer on `stop()` or when collected; it also ends with the session."""

    def stop(self) -> None:
        """Stops the maintainer; pipes it added stay in the session."""
    @property
    def finished(self) -> bool: ...

@final
class Candidate:
    """One carrier kind a `CarrierChoice` may use; each constructor is named
    after the `dial_*` function that opens the same carrier. Carrier
    credentials go on the candidate; the exchange authenticates with its
    options' PSK."""

    @staticmethod
    def streaming(
        host: str,
        port: int,
        *,
        path: str = "/zmux",
        carrier_credential: _CarrierCredential | None = None,
        pair_field: str | None = None,
    ) -> Candidate:
        """A bidirectional streaming POST over HTTP/1.1 (kind `streaming`, as
        `dial_streaming`)."""
    @staticmethod
    def split(
        host: str,
        port: int,
        *,
        path: str = "/zmux",
        carrier_credential: _CarrierCredential | None = None,
        pair_field: str | None = None,
    ) -> Candidate:
        """A split bootstrap (kind `split`, as `dial_split`); as a
        further pipe, a downlink and an uplink. Its halves are paired by the
        request field `pair_field` (default `Zmux-Pipe-Pair`)."""
    @staticmethod
    def exchange(
        host: str, port: int, *, options: ExchangeOptions | None = None
    ) -> Candidate:
        """The exchange carrier, for paths that buffer whole bodies (kind
        `exchange`, as `dial_exchange`)."""
    @staticmethod
    def websocket(
        url: str,
        *,
        tls: TlsConfig | None = None,
        carrier_credential: _CarrierCredential | None = None,
        no_subprotocol: bool = False,
    ) -> Candidate:
        """A WebSocket to a `ws://` or `wss://` URL (kind `websocket`, as
        `dial_websocket`)."""
    @staticmethod
    def quic(
        host: str,
        port: int,
        *,
        tls: TlsConfig | None = None,
        server_name: str | None = None,
        lanes: int = DEFAULT_LANES,
        carrier_credential: _CarrierCredential | None = None,
    ) -> Candidate:
        """A QUIC connection, where the client reaches the server directly
        (kind `quic`, as `dial_quic`)."""
    @staticmethod
    def http3(
        url: str,
        *,
        tls: TlsConfig | None = None,
        addr: tuple[str, int] | None = None,
        lanes: int = DEFAULT_LANES,
        carrier_credential: _CarrierCredential | None = None,
    ) -> Candidate:
        """An HTTP/3 request to an `https://` URL, sent to `addr`, a `(host,
        port)`, when given
        (kind `http3`, as `dial_http3`)."""
    @staticmethod
    def webtransport(
        url: str,
        *,
        tls: TlsConfig | None = None,
        lanes: int = DEFAULT_LANES,
        carrier_credential: _CarrierCredential | None = None,
    ) -> Candidate:
        """A WebTransport session to an `https://` URL (kind `webtransport`,
        as `dial_webtransport`)."""
    def with_variant(self, variant: str) -> Candidate:
        """A copy of this candidate with its carriers labelled `variant`: a
        kind with different variants makes different candidates, each with
        its own place in the cache, in the order given."""
    @property
    def kind(self) -> _t.CarrierKind | str:
        """The candidate's carrier kind."""
    @property
    def variant(self) -> str | None:
        """The candidate's variant, or `None`."""

@final
class CarrierChoice:
    """How a client chooses the carrier (`connect_choice`,
    `PipePool(choice=...)`)."""

    @staticmethod
    def explicit(candidate: Candidate) -> CarrierChoice:
        """That kind only: a failure is reported, never replaced."""
    @staticmethod
    def auto(candidates: list[Candidate]) -> CarrierChoice:
        """A choice among `candidates`, most preferred first."""
    @property
    def is_auto(self) -> bool:
        """Whether the choice is automatic."""

@final
class CarrierChoicePolicy:
    """How an automatic carrier choice orders, times and remembers its
    candidates; durations in seconds. `cache` remembers outcomes across
    dials under `key` (`None`: a cache private to the session). A
    candidate's timer is the round trip of opening its carrier times
    `timer_factor`, within `timer_min` and `timer_max`; a candidate whose
    transport parameters do not arrive within it is abandoned. A joined pipe
    of a preferred kind stays `settle` before the pipes it replaces retire;
    a kind whose pipes fail within `drop_window` of being chosen counts as
    failed. `no_join` tries the candidates one after another instead of
    establishing on the most robust and joining the preferred ones (it does
    not apply to a pool)."""

    def __init__(
        self,
        *,
        cache: CarrierCache | None = None,
        key: str = "",
        timer_factor: float = 3.0,
        timer_min: float = 1.0,
        timer_max: float = 3.0,
        settle: float = 1.0,
        drop_window: float = 30.0,
        no_join: bool = False,
    ) -> None: ...
    @property
    def key(self) -> str: ...
    @property
    def timer_factor(self) -> float: ...
    @property
    def timer_min(self) -> float: ...
    @property
    def timer_max(self) -> float: ...
    @property
    def settle(self) -> float: ...
    @property
    def drop_window(self) -> float: ...
    @property
    def no_join(self) -> bool: ...

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
    def is_usable(
        self, key: str, kind: _t.CarrierKind | str, *, variant: str | None = None
    ) -> bool:
        """Whether the carrier kind `kind` with `variant` is held as usable
        under `key`."""
    def is_failed(
        self, key: str, kind: _t.CarrierKind | str, *, variant: str | None = None
    ) -> bool:
        """Whether the carrier kind `kind` with `variant` is backing off
        under `key`."""
    def report(
        self,
        key: str,
        kind: _t.CarrierKind | str,
        outcome: _t.CacheOutcome | str,
        *,
        variant: str | None = None,
    ) -> None:
        """Records an outcome the host learnt after a dial, under the rules
        of the automatic results: `key` the key in use, `variant` the
        candidate's. An unknown name raises `ValueError`."""
    def snapshot(self) -> str:
        """What the cache knows as JSON text (versioned, each entry with its
        variant, times in RFC 3339 UTC, shared by every implementation), to `restore` later, such as
        in the next run of the process. Expired entries are left out."""
    def restore(self, snapshot: str) -> None:
        """Merges a `snapshot` in: of two entries for one key, kind and variant the
        newer is kept, a backoff outside this cache's bounds is brought
        within them, and expired entries, unknown fields and unknown kinds
        are dropped. Malformed text raises `ValueError` and changes nothing."""

async def connect_choice(
    choice: CarrierChoice,
    *,
    config: _t.Config | None = None,
    choice_policy: CarrierChoicePolicy | None = None,
) -> Session:
    """A client session over the carrier `choice` selects. An auto choice
    sends no early data and races no candidates: it skips kinds the cache
    holds as failed, abandons a candidate whose transport parameters do not
    arrive within its timer, and with `max_pipes` above 1 establishes on the
    most robust candidate and joins the preferred ones in the background,
    retiring the replaced pipes once a join has settled (see
    `CarrierChoicePolicy`). Every try and the choice are session events
    (`CarrierCandidate`, `CarrierChosen`) and in `Session.stats()`. Raises
    `CarrierChoiceError` when no candidate was usable, `ValueError` for an
    invalid choice or policy."""

@final
class ExchangeOptions:
    """The HTTP exchange carrier's options; both ends must agree on `psk` and
    `encoding`, the rest is local. A keyword left out keeps the library's
    default. A carrier is authenticated by `psk`; without one it must be
    declined explicitly with `unauthenticated=True` (the MACs then only bind
    responses to requests), else `dial_exchange` and `serve_http` raise
    ValueError."""

    def __init__(
        self,
        *,
        psk: bytes = b"",
        unauthenticated: bool = False,
        encoding: Literal["binary", "base64"] = "binary",
        path: str = "/zmux/exchange",
        down_path: str | _t.Auto = _t.AUTO,
        query: str = "n",
        down_requests: int = 2,
        up_requests: int = 2,
        up_piece: int | _t.Auto = _t.AUTO,
        max_down_piece: int | _t.Auto = _t.AUTO,
        backoff: _t.Backoff | None = None,
        request_timeout: float = 25.0,
        deadline: float = 30.0,
        hold: float = 20.0,
        coalesce: float = 0.002,
        down_piece: int | _t.Auto = _t.AUTO,
        down_window: int = 32,
        max_up_piece: int | _t.Auto = _t.AUTO,
        up_store: int = 4 << 20,
        idle_timeout: float = 60.0,
        gone_memory: float = 60.0,
        max_carriers: int | None = None,
        time_window: float = 60.0,
        max_recorded: int = 1 << 18,
    ) -> None:
        """`path` and `down_path` (`AUTO`: `path`) are client templates:
        `{instance}` becomes a per-carrier token, `{nonce}` a fresh value per
        request (else added as query parameter `query`); the server matches
        the part before the first placeholder. Client: outstanding
        `down_requests` and `up_requests`, `up_piece` and `max_down_piece`
        (`AUTO`: from the encoding, and the larger of 1 MiB and that), the
        repetition `backoff` (a `Backoff`; `None`: from 0.02 s doubling to 2 s,
        jitter 0.2),
        `request_timeout`, `deadline`. Server: `hold`, `coalesce`,
        `down_piece` and `max_up_piece` (`AUTO` as the client's),
        `down_window`, `up_store`, `idle_timeout`, `gone_memory`,
        `max_carriers` (`None`: no bound but the listener's memory budget),
        `time_window` (whole seconds; requests whose time differs more are
        not authenticated), `max_recorded` request nonces."""
    @property
    def encoding(self) -> Literal["binary", "base64"]: ...
    @property
    def path(self) -> str: ...
    @property
    def down_path(self) -> str | _t.Auto:
        """The fixed DOWN path, or `AUTO`."""

async def dial_exchange(
    host: str,
    port: int,
    *,
    options: ExchangeOptions | None = None,
    down_addr: tuple[str, int] | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _CarrierCredential | None = None,
) -> PipeIo:
    """A pipe input on the HTTP exchange carrier (kind `exchange`): plain
    HTTP/1.1 POST requests to `host` and `port`, DOWN requests to
    `down_addr`, a `(host, port)`, when given, over TLS with `tls`; with `carrier_credential`,
    its prefix starts the uplink, for a server's admission. Returns without
    a round trip."""

async def dial_http3(
    url: str,
    *,
    tls: TlsConfig | None = None,
    addr: tuple[str, int] | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _CarrierCredential | None = None,
) -> PipeIo:
    """A pipe input on an HTTP/3 request to `url` (`https://`; kind
    `http3`), sent to `addr`, a `(host, port)`, when given. With `carrier_credential`, its
    prefix is the first bytes of every request body."""

async def dial_webtransport(
    url: str,
    *,
    tls: TlsConfig | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _CarrierCredential | None = None,
) -> PipeIo:
    """A pipe input on a new WebTransport session to `url` (`https://`; kind
    `webtransport`); the carrier credential's header field goes on the
    session request."""

@final
class Http2Connection:
    """An HTTP/2 connection whose requests carry pipes: prior knowledge
    without `tls`, ALPN `h2` with it. Dial several pipe inputs on one
    connection. Over TLS 1.3 its bidirectional requests are secure carriers
    with the connection's exporter, the same for every request."""

    @staticmethod
    async def dial(
        host: str,
        port: int,
        *,
        path: str = "/zmux",
        tls: TlsConfig | None = None,
        server_name: str | None = None,
        carrier_credential: _CarrierCredential | None = None,
        pair_field: str | None = None,
    ) -> Http2Connection:
        """With `carrier_credential` (unbound), its prefix is the first bytes
        of every request body."""
    async def open_pipe(
        self, *, direction: _t.Direction | str = _t.Direction.BIDI
    ) -> PipeIo:
        """A pipe input on a new request of `direction` (see
        `dial_streaming`)."""
    async def open_split(self) -> PipeIo:
        """A split bootstrap on two new requests of the connection."""
    async def join_split(
        self, session: Session, *, options: PipeOptions | None = None
    ) -> list[Pipe]:
        """Joins a split carrier on two new requests of the connection to
        `session` as two further pipes (see `join_split`)."""

@final
class ZeroRtt:
    """What became of the QUIC 0-RTT data of a session (live: values may change until known)."""

    @property
    def sent(self) -> bool:
        """0-RTT data was sent: false when the handshake completed before the
        session's first stream was opened (the session then runs on 1-RTT)."""
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
        lanes: int = DEFAULT_LANES,
        zero_rtt: bool = False,
        memory_capacity: int | None = None,
        bind: tuple[str, int] = ("0.0.0.0", 0),
        carrier_credential: _CarrierCredential | None = None,
    ) -> None:
        """`memory_capacity` bounds the servers remembered (`None`: no
        bound); `bind` is the local `(host, port)`. With `carrier_credential`, its prefix is the first stream's
        first bytes and no 0-RTT data is sent."""
    async def dial(
        self, host: str, port: int, *, server_name: str | None = None
    ) -> PipeIo:
        """A pipe input on a new connection."""
    async def connect(
        self,
        host: str,
        port: int,
        *,
        server_name: str | None = None,
        config: _t.Config | None = None,
    ) -> Session:
        """A session on a new connection; see `Session.zero_rtt`."""
    def forget(self, server_name: str) -> None:
        """Forgets the parameters remembered for `server_name` (after
        `EarlyDataRejectedError`)."""
    def clear(self) -> None:
        """Forgets every remembered server."""
    def remembers(self, server_name: str) -> bool:
        """Whether parameters are remembered for `server_name`."""

@final
class SendStream:
    """The sending half of a stream.

    `finish()` ends it cleanly, `reset(code)` abandons it (unsent data is
    dropped). A later call fails with `StreamClosedError`. Use `async with`
    to finish on a normal exit and reset with `ZMUX_CANCELLED` on an
    exception; leaving a stream neither finished nor reset keeps it
    half-open until the session ends. One operation at a time: a second
    concurrent call raises `StreamBusyError`. The runtime settings
    `send_buffer`, `scheduler` and `redundant` are writable properties and
    read back as in force."""

    @property
    def id(self) -> int | None:
        """The stream ID; `None` until the stream is opened on the wire."""
    @property
    def priority(self) -> Priority:
        """The local scheduling priority (urgency 0..7, lower first);
        assigning a `Priority` or `(urgency, incremental)` changes it."""
    @priority.setter
    def priority(self, priority: _Prio) -> None: ...
    async def write(self, data: bytes) -> int:
        """Writes all of `data`, waiting for flow control, and returns the
        number of bytes taken (`len(data)`). Not cancellation-safe in the
        sense of leaving the stream unchanged: if cancelled, a prefix of
        `data` may have been sent and nothing says how much, so a stream
        whose write was cancelled is to be reset, not written to again."""
    async def flush(self) -> None:
        """Opens the stream now and waits until the opening frame and the data
        written so far left for a carrier: the peer sees the stream even with
        nothing written, for a protocol whose other side speaks first. Data
        written before goes in the opening frame. Before establishment the
        frame goes as soon as the stream may open. A cancelled call leaves the
        frame owed. Once the opening frame and all data left, a stop from the
        peer no longer fails the flush: the next `write` or `finish` reports
        it; a stop before that still fails the flush."""
    async def finish(self) -> None:
        """Ends the stream (FIN) after the written data."""
    def reset(self, code: int) -> None:
        """Abandons the stream with an application error code (< 2**62);
        never blocks, like `asyncio.Transport.abort`. While a write is in
        progress the reset follows once that write returns or is
        cancelled. During the read drain after the peer's close it raises
        the session's error; the exit of `async with` ignores it."""
    async def write_chunk(self, buffer: Buffer) -> int:
        """Writes any buffer-protocol object without copying it, and returns
        the number of bytes taken; the caller does not modify it afterwards.
        Cancelled, it may have sent a prefix, as `write`."""
    def set_reliable_boundary(self) -> None:
        """Marks the bytes written so far as delivered even if the stream is
        reset later (RESET_STREAM_AT Reliable Size)."""
    def send_capacity(self) -> int:
        """The bytes the part could transmit now: the smaller of its stream
        and session credit, minus what it holds unsent."""
    async def wait_send_capacity(self, minimum: int) -> int:
        """Waits until the send capacity is at least `minimum` (>= 1), or above 0
        while nothing is unsent, and returns it; the stream's error otherwise."""
    @property
    def send_buffer(self) -> int:
        """The written-but-unreleased bytes this part may hold: the last
        assignment, else the session's `Config.send_buffer`."""
    @send_buffer.setter
    def send_buffer(self, n: int) -> None: ...
    @property
    def scheduler(self) -> Scheduler | None:
        """The part's scheduling policy; `None` (the default, and assigned)
        follows the session's. A name is accepted when assigning."""
    @scheduler.setter
    def scheduler(self, scheduler: Scheduler | str | None) -> None: ...
    @property
    def redundant(self) -> bool | None:
        """Whether the part's chunks go redundantly on a second pipe of the
        tier (multipath): `True` on, `False` off, `None` (the default)
        following the session's `redundancy`."""
    @redundant.setter
    def redundant(self, on: bool | None) -> None: ...
    def max_datagram_size(self, context: int = 0) -> int | None:
        """The largest payload the peer currently accepts in a datagram of
        this stream with the context ID `context`; `None` without datagram
        flows."""
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
    loses no data. Leaving `async with` stops the stream with code 0 (a
    no-op once it ended; it returns at once). `async for` ends silently at the end of the stream and raises
    the stream's error otherwise. The runtime settings `receive_window` and
    `peer_priority` are writable properties and read back as last
    assigned."""

    @property
    def id(self) -> int | None:
        """The stream ID."""
    @property
    def requested_priority(self) -> Priority | None:
        """The PRIORITY the peer asked for in the stream's opening preamble
        (`open_bi(peer_priority=...)` at its end); `None`
        when it sent none or the stream was opened locally. Later priority
        updates are not reflected: see `priority` for the one in force."""
    @property
    def is_replayable(self) -> bool:
        """The stream's opening arrived as carrier early data (TLS 1.3 early
        data, QUIC 0-RTT), so an attacker may have replayed it: process only
        idempotent requests from it, or refuse with `stop()`. It tells how the
        stream arrived, for the stream's life: it stays true after the
        carrier's handshake completes. Always false unless the server allowed
        carrier early data."""
    @property
    def preamble(self) -> Preamble:
        """Metadata the opener attached (`info`, `tlvs`, `pipe_carrier`)."""
    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes; `b""` at the end of the stream. Raises
        `StreamResetError` if the peer reset it."""
    async def read_exact(self, n: int) -> bytes:
        """Exactly `n` bytes, or `IncompleteReadError` (its `partial` the
        bytes read) when the stream ends first. A cancelled call loses no
        byte."""
    async def read_to_end(self, limit: int = 16777216) -> bytes:
        """The rest of the stream; `LimitExceededError` beyond `limit` bytes.
        A cancelled call loses no byte."""
    def stop(self, code: int) -> None:
        """Asks the peer to stop sending (STOP_SENDING) with an application
        error code; never blocks. While a read is in progress the stop
        follows once that read returns or is cancelled. During the read
        drain after the peer's close it discards the unread data and raises
        the session's error; the exit of `async with` ignores it."""
    async def read_chunk(self, n: int = 65536) -> memoryview:
        """Up to `n` bytes as a read-only view of the received buffer,
        without a copy; empty at the end of the stream."""
    def reject(self) -> None:
        """Declines the stream before reading it (ZMUX_REJECTED); the handle,
        and the sending one of a stream not written to, are used up."""
    @property
    def receive_window(self) -> tuple[int, int]:
        """The stream's receive window, `(window, maximum)`: the window now
        advertised, which auto-tuning raises up to `maximum`."""
    @receive_window.setter
    def receive_window(self, window: tuple[int, int]) -> None: ...
    @property
    def peer_priority(self) -> Priority | None:
        """The priority last asked of the peer for the stream (assigned as a
        `Priority` or `(urgency, incremental)`, or given at opening); `None`
        when none was asked."""
    @peer_priority.setter
    def peer_priority(self, priority: _Prio) -> None: ...
    async def read_datagram(self) -> StreamDatagram:
        """The next datagram of the stream; ends with the stream's error."""
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
    normal exit and aborts on an exception; `await wait_closed()` waits for
    its end. Watch `Session.events()` for its state changes. Its runtime
    settings change only through `update`."""

    @property
    def id(self) -> _t.PipeId:
        """The pipe's ID."""
    @property
    def admitted(self) -> Any:
        """The value the listener's admission gave the carrier that brought
        the pipe (`AdmissionVerdict.accept(value=...)`): its join's carrier, the
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
        """The `Session` object the pipe was given by, always the same one."""
    async def joined(self) -> None:
        """Waits until the peer confirmed the join; `PipeError` if it failed."""
    async def attached(self) -> None:
        """Waits until the peer attached the pipe, so that it carries the
        session even if every other pipe goes: pipe 0 once established, a
        pipe the peer joined at once, one of this endpoint's joins once
        `joined()` returned and the peer acknowledged a byte of it (an
        inbound-only pipe: once a record arrived). `PipeError` if the join
        failed or the pipe ended first; bound it with `asyncio.timeout`."""
    async def wait_closed(self) -> None:
        """Waits until the pipe ended: returns once every direction closed
        (or the session released it); `PipeError` if it failed or the
        session ended first."""
    def update(
        self,
        *,
        send_priority: int | _t.Clear = ...,
        receive_priority: int | _t.Clear = ...,
        send_standby: bool | _t.Clear = ...,
        receive_standby: bool | _t.Clear = ...,
        weight: int | _t.Clear = ...,
        probation: float | _t.Auto | _t.Clear | None = ...,
        liveness: _t.PipeLiveness | _t.Clear = ...,
        quality_band: QualityBand | _t.Clear = ...,
    ) -> None:
        """Changes these settings together (both receive fields: one
        PIPE_STATUS). A keyword left out keeps its value; `zmux.CLEAR`
        clears it (the `send_*` fields then follow the peer's request, the
        `receive_*` fields request the default again, `weight` is 1,
        `probation`, `liveness` and `quality_band` follow the session's); a
        value sets it (`probation=None` turns probation off). A field fixed when the pipe
        is added or an unknown name raises `TypeError`; an invalid value
        raises `ValueError` and changes nothing. Nothing is sent for
        `liveness`."""
    def close(self) -> None:
        """Removes the pipe gracefully: PIPE_ABANDON and drain."""
    def abort(self) -> None:
        """Removes the pipe at once: its data is reinjected elsewhere."""
    def stats(self) -> PipeStats | None:
        """A snapshot; `None` once the pipe is retired or the session
        released it (reads never raise; operations then raise `PipeError`)."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...

@final
class EventStream:
    """`Session.events()`; ends with the session. It reads the same queue
    as `Session.next_event()`: each event goes to one reader."""

    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Event: ...

@final
class DatagramStream:
    """`Session.datagrams()`; ends with the session. It reads the same queue
    as `Session.read_datagram()`: each datagram goes to one reader."""

    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> bytes: ...

@final
class Session:
    """A zmux session: a cheap handle; the session runs on the binding's runtime.

    `close()` starts the graceful close (written data sent first, 1 s at
    most) and `abort(code, reason)` ends it at once; both return at once
    and are idempotent, and `await wait_closed()` waits for the end.
    `await shutdown()` sends GOAWAY and closes once the open streams ended.
    `async with` closes and waits on a normal exit; an exit by an exception
    starts a close with `ZMUX_CANCELLED` and an empty reason and returns at
    once, so the peer can tell it from a normal end. `async for send, recv in
    session` accepts bidirectional streams until the session ends: silently
    when it was closed by either application with code 0, with the session's
    error otherwise. The runtime settings `scheduler`, `quality_band`,
    `capacity_floor`, `shaper`, `shaping_limits` and `liveness` are writable
    properties; an invalid value raises `ValueError` and changes nothing."""

    @staticmethod
    async def connect(pipe: PipeIo, *, config: _t.Config | None = None) -> Session:
        """Establishes a session as the dialling side of `pipe`."""
    @staticmethod
    async def accept(pipe: PipeIo, *, config: _t.Config | None = None) -> Session:
        """Establishes a single-pipe session as the accepting side of `pipe`."""
    @staticmethod
    async def symmetric(pipe: PipeIo, *, config: _t.Config | None = None) -> Session:
        """Establishes a session over a symmetric carrier: the roles are
        negotiated (role auto)."""
    @property
    def admitted(self) -> Any:
        """The value the listener's admission gave the carrier that started
        the session (`AdmissionVerdict.accept(value=...)`; a split bootstrap's
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
    ) -> BiStream:
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
    ) -> BiStream:
        """Opens a bidirectional stream if stream credit is available now;
        `StreamError` of kind `Blocked` (retryable) otherwise. Never waits."""
    async def open_packet_stream(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        policy: SendPolicy | str = "prefer_datagram",
        max_packet: int = 65535,
    ) -> PacketStream:
        """Opens a bidirectional stream with the preamble (`info`, `tlvs`),
        waiting for stream credit as `open_bi` does, and wraps it as a
        `PacketStream`. A cancelled open leaves no stream behind."""
    async def open_stream_pair(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        priority: _Prio | None = None,
        peer_priority: _Prio | None = None,
        high_water: int = 65536,
        limit: int = 65536,
    ) -> tuple[StreamPairReader, StreamPairWriter]:
        """Opens a bidirectional stream as an asyncio-style pair: the reader
        offers `asyncio.StreamReader`'s reads (`limit` its buffer limit, as
        `asyncio.open_connection(limit=...)`), the writer
        `asyncio.StreamWriter`'s writes (`high_water` the queued bytes
        above which `drain` waits). The other keywords are `open_bi`'s."""
    async def open_pipe_stream(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
    ) -> PipeIo:
        """Opens a carrier stream (PIPE_CARRIER) with the open info `info`
        and the application TLVs `tlvs`, as the pipe input of a nested
        session."""
    @property
    def quality_band(self) -> QualityBand | None:
        """The default quality band of the session's pipes; `None` (the
        default): no reports."""
    @quality_band.setter
    def quality_band(self, band: QualityBand | None) -> None: ...
    @property
    def capacity_floor(self) -> CapacityFloor | None:
        """The floor under the session's outbound capacity; `None` (the
        default): none."""
    @capacity_floor.setter
    def capacity_floor(self, floor: CapacityFloor | None) -> None: ...
    @property
    def scheduler(self) -> Scheduler:
        """The default scheduling policy of new stream data: the
        configuration's until assigned (a name is accepted when assigning)."""
    @scheduler.setter
    def scheduler(self, scheduler: Scheduler | str) -> None: ...
    async def open_uni(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        priority: _Prio | None = None,
    ) -> SendStream:
        """Opens a unidirectional stream."""
    async def accept_bi(self) -> BiStream:
        """The next bidirectional stream the peer opened;
        `SessionClosedError` once the session ended."""
    async def accept_uni(self) -> RecvStream:
        """The next unidirectional stream the peer opened."""
    def send_datagram(self, data: bytes) -> None:
        """Queues an unreliable datagram; never waits. When the queue is full
        the oldest datagram is dropped. `DatagramError` if datagrams are not
        negotiated or `data` exceeds `max_datagram_size`."""
    async def read_datagram(self) -> bytes:
        """The next received datagram; `SessionClosedError` once the session
        ended."""
    def datagrams(self) -> DatagramStream:
        """Received datagrams as an async iterator over the queue
        `read_datagram` reads: each datagram goes to one reader."""
    @property
    def max_datagram_size(self) -> int | None:
        """The largest datagram payload; `None` without datagram support."""
    def close(self, code: int = 0, reason: bytes = b"") -> None:
        """Starts the graceful close with the application error `code` and
        `reason` (the defaults: a close without error) and returns without
        blocking the event loop: the data the streams wrote is sent first, so
        that the peer reads it ahead of the code, then CONNECTION_CLOSE is
        handed to every usable carrier, all within 1 s; streams still open are
        not waited for and fail with the session's error. An application that
        exits right after `close` awaits `wait_closed()` first. Idempotent
        with `abort`: the first call of either decides what is sent, code and
        reason included; an `abort` while the close is still flushing ends it
        at once. The peer's `wait_closed()` returns an `ApplicationClosedError` with
        `code`, `reason` and `remote=True`."""
    def abort(self, code: int, reason: bytes = b"") -> None:
        """Ends the session at once with the application error `code` and
        `reason`, draining nothing: unsent data is discarded and
        CONNECTION_CLOSE goes in the background. Returns at once. An abort
        while a close is still flushing discards what remains unsent; a
        later call of either sends nothing more."""
    async def shutdown(self, code: int = 0, reason: bytes = b"") -> None:
        """Graceful: GOAWAY, then close once the streams ended."""
    async def wait_closed(self) -> SessionClosedError:
        """Waits for the session's whole end and returns the
        `SessionClosedError` that describes it (it is not raised). It
        returns once every pipe's inbound side has ended (the peer read the
        close and ended its side) or the linger timeout has passed, so a
        return before the linger confirms that the peer read the close. For
        "delivered, or given up after d" bound it with the language's own
        timeout, not an option::

            try:
                async with asyncio.timeout(5):
                    await session.wait_closed()
            except TimeoutError:
                ...  # not confirmed within 5 s; the linger goes on

        A timeout changes nothing in the session."""
    async def ping(self) -> float:
        """A round trip; the RTT in seconds."""
    async def next_event(self) -> Event | None:
        """The next session event; `None` once the session ended."""
    def events(self) -> EventStream:
        """Session events as an async iterator over the queue `next_event`
        reads: each event goes to one reader."""
    def stats(self) -> SessionStats:
        """A snapshot of the session."""
    @property
    def shaper(self) -> InstalledShaper | None:
        """The shaper in force on every outbound pipe, the `Config`'s or the
        last one assigned, as an opaque `InstalledShaper`; `None` for no
        shaping. Assigning takes a `Shaper` (a JSON definition, or
        definitions by carrier kind and by variant, with limits, a seed and
        a budget), a `ShapingBundle`, an `InstalledShaper` or `None`; an
        invalid definition raises `ValueError` and changes nothing."""
    @shaper.setter
    def shaper(
        self, shaper: _t.Shaper | ShapingBundle | InstalledShaper | None
    ) -> None: ...
    @property
    def shaping_limits(self) -> _t.ShapingLimits:
        """The session's shaping limits. Assigning replaces them, also
        before a shaper is installed; what was spent stays spent. Invalid
        ones raise `ValueError` and change nothing."""
    @shaping_limits.setter
    def shaping_limits(self, limits: _t.ShapingLimits) -> None: ...
    def set_join_secret(self, psk: bytes) -> None:
        """Supplies the deferred pre-shared key (`PipeAuth.deferred_psk`), of
        at least 16 bytes, once. After establishment it derives the join keys
        and releases the peer's held joins. `PipeError` of kind
        `InvalidArgument`, or `JoinSecretSetError` or `NotNegotiatedError`."""
    @property
    def join_pending(self) -> bool:
        """Whether the joins wait for the deferred pre-shared key."""
    def declare_end_to_end(self) -> None:
        """States that the host has proven pipe 0 end to end, for a session whose first
        pipe is outside the secure carrier: the join keys are derived from then on."""
    @property
    def epoch(self) -> int | None:
        """The session epoch new local joins use: it rises once this end switches to a
        committed epoch. `None` outside a multipath session."""
    @property
    def weakest_record_mode(self) -> _t.RecordMode:
        """The weakest record mode among the session's pipes."""
    def export_keying_material(
        self, label: str, *, context: bytes = b"", length: int = 32
    ) -> bytes:
        """Keying material from the innermost end-to-end handshake of the
        bootstrap carrier, the same at both ends; a split bootstrap of two
        connections gives the uplink's value followed by the downlink's,
        `2 * length` bytes. `ExportError` without a value."""
    @property
    def session_binding(self) -> bytes | None:
        """The 32 bytes that identify this session, the same at both ends, for
        an application's authentication transcript; public, not a secret.
        `None` before establishment and without multipath."""
    @property
    def liveness(self) -> _t.Liveness:
        """The liveness settings in effect, defaults filled in. Assigning a
        `Liveness` replaces them as a whole (a field left at its default is
        the default) and rearms the timers; a pipe's own settings keep
        winning. Invalid ones raise `ValueError` and change nothing.
        Nothing is sent."""
    @liveness.setter
    def liveness(self, liveness: _t.Liveness) -> None: ...
    def raise_incoming_streams(self, *, bidi: int = 0, uni: int = 0) -> None:
        """Raises the streams the peer may have open and sends the credit. The
        credit only grows: a value at or below the current one, 0 included,
        leaves that type unchanged. A negative value or one above 2**60 raises
        `ValueError` and changes nothing."""
    def shaping_meters(self) -> dict[str, int]:
        """Shaping readings: wire_left and stall_left (2**64-1 when unbounded), wire_spent, stall_spent (microseconds), sent_bytes."""
    def shaping_stats(self) -> dict[str, int | float]:
        """Shaping counters: wire_spent, stall_spent (s), clamped, injected, inject_dropped, faults, handshake_unplanned."""
    async def add_pipe(
        self, pipe: PipeIo, *, options: PipeOptions | None = None
    ) -> Pipe:
        """Adds a carrier as a further pipe (multipath). Returns once the peer
        attached it, or with `options.return_on_reply` once the Reply was
        verified; `Config.join_timeout` bounds the call. A pipe not attached
        by then is aborted and `DeadlineExceededError` raised; one that fails or is
        removed first raises the pipe error, the session's end the session
        error; a cancelled call aborts the pipe. A failed call leaves no pipe."""
    def maintain_pipes(self, pool: PipePool) -> MaintainHandle:
        """Keeps `pool`'s pipes up (dials, redials with backoff, rotation, the
        pool policy's decisions); needs a running event loop, on which `dial` runs."""
    def revalidate_pipes(self) -> None:
        """Probes every live outbound pipe again, for example after a network change."""
    def advance_epoch(self) -> None:
        """Starts a session epoch exchange as soon as this end is stable: the session
        secret, the join keys and the Session Locators advance. Never waits;
        `EpochCommitted` and `EpochDeleted` report it. A session without multipath
        raises `PipeError`."""
    async def replace_pipes(self) -> None:
        """For a suspected leak of a session-level secret only: advances the
        epoch, waits until new joins use it, then replaces each pipe that
        existed when called through the `Config.redial` hook, make before
        break. Unbounded: bound it with `asyncio.timeout(seconds)`, a
        relative bound; cancelled, it stops where it is, the pipes already
        replaced staying replaced. While the previous epoch is still kept,
        the exchange waits until it is deleted. Without `redial` it raises
        `ValueError`; outside a multipath session `NotNegotiatedError`."""
    def pipes(self) -> list[Pipe]:
        """The session's pipes."""
    def pipe_stats(self) -> list[PipeStats]:
        """A snapshot of every pipe."""
    @property
    def zero_rtt(self) -> ZeroRtt | None:
        """For sessions from `QuicClient.connect`: what became of the 0-RTT data."""
    @property
    def role(self) -> Role:
        """`Role.CLIENT` or `Role.SERVER`, negotiated when started as auto."""
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
    def is_established(self) -> bool:
        """Whether establishment has completed."""
    @property
    def qmux_version(self) -> str:
        """The QMux version in use: `"draft-02"`, the only one."""
    @property
    def tls(self) -> _t.TlsState | None:
        """The TLS or QUIC handshake this process ran for the bootstrap
        carrier; `None` where TLS ends outside the process or the carrier
        has none."""
    @property
    def datagram_support(self) -> _t.Support:
        """DATAGRAM support announced by each side (`Config.enable_datagrams`,
        the peer's `max_datagram_frame_size`)."""
    @property
    def reset_stream_at_support(self) -> _t.Support:
        """RESET_STREAM_AT support announced by each side."""
    @property
    def multipath(self) -> _t.Multipath:
        """What became of multipath, `JOIN_SECURITY_UNAVAILABLE` included."""
    @property
    def pipe_ack_in_use(self) -> bool:
        """Whether pipe acknowledgements are in use."""
    @property
    def resume_in_use(self) -> bool:
        """Whether resume is in use."""
    @property
    def goaway(self) -> _t.GoAwayReceived | None:
        """The watermarks of the latest GOAWAY received, or `None`."""
    @property
    def state(self) -> SessionState:
        """The session's lifecycle state."""
    @property
    def early_data(self) -> EarlyDataState:
        """What became of the early data: not sent, pending, accepted or rejected."""
    def release_first_flight(self) -> None:
        """Ends `Config(hold_first_flight=True)`: what is queued goes in one
        carrier write, as far as one batch holds it. Never blocks."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *exc: object) -> Literal[False]: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> BiStream: ...

@final
class Listener:
    """Accepts sessions (and multipath joins) from any number of carriers.
    Each `serve_*` binds `host` and `port` (port 0 picks one) and returns the
    bound address as `(host, port)`. `async for session in listener` until
    `close()` (the loop ends silently, as `accept` raises
    `ListenerClosedError`). `config` is the `Config` of its sessions,
    `listener_config` the `ListenerConfig`; each left out is the default."""

    def __init__(
        self,
        *,
        config: _t.Config | None = None,
        listener_config: _t.ListenerConfig | None = None,
    ) -> None: ...
    async def serve_tcp(self, host: str, port: int) -> tuple[str, int]:
        """Serves plain TCP on `host` and `port`; returns the bound address.
        With the listener's `admission`, a connection reaches it only once
        admitted."""
    async def serve_tls(
        self, host: str, port: int, *, tls: TlsConfig
    ) -> tuple[str, int]:
        """Without ALPN identifiers in `tls`, zmux's are accepted. The
        admission decides after the handshake, with its exporter."""
    async def serve_quic(
        self,
        host: str,
        port: int,
        *,
        tls: TlsConfig,
        lanes: int = DEFAULT_LANES,
        zero_rtt: bool = False,
    ) -> tuple[str, int]:
        """With `zero_rtt`, 0-RTT is accepted when `Config(carrier_early_data=True)`.
        With the listener's `admission`, the prefix is the first stream's
        first bytes; it excludes `zero_rtt` (ValueError)."""
    async def serve_http3(
        self, host: str, port: int, *, tls: TlsConfig, lanes: int = DEFAULT_LANES
    ) -> tuple[str, int]:
        """With the listener's `admission`, each request is decided on the
        first bytes of its body."""
    async def serve_webtransport(
        self, host: str, port: int, *, tls: TlsConfig, lanes: int = DEFAULT_LANES
    ) -> tuple[str, int]:
        """With the listener's `admission`, each session request is decided
        on its request head (no prefix), with the QUIC connection's exporter."""
    async def serve_websocket(
        self, host: str, port: int, *, tls: TlsConfig | None = None
    ) -> tuple[str, int]:
        """With the listener's `admission`, each upgrade is decided on its
        request head (no prefix), with the TLS exporter under `tls`."""
    async def serve_http(
        self,
        host: str,
        port: int,
        *,
        path: str = "/zmux",
        tls: TlsConfig | None = None,
        exchange: ExchangeOptions | None = None,
        websocket: bool = False,
        websocket_no_subprotocol: bool = False,
        pair_field: str | None = None,
    ) -> tuple[str, int]:
        """One HTTP endpoint for every HTTP carrier: HTTP/1.1 and HTTP/2
        (prior knowledge, or ALPN with `tls`), each request classified by its
        head: bidirectional, uplink and downlink requests and split
        bootstraps on `path`, with `exchange` the exchange carrier on its
        paths, with `websocket` WebSocket upgrades on `path` (with
        `websocket_no_subprotocol` also a request that offers no subprotocol).
        Split bootstrap halves are paired by the request field `pair_field`
        (default `Zmux-Pipe-Pair`; clients must use the same one). With the
        listener's `admission`, a request is decided on the first bytes of its
        body, or on its head when it has none (a credential's header form);
        a new exchange carrier is decided on the first bytes of its uplink. A
        carrier request forwarded from TLS early data (`Early-Data: 1`) is
        answered 425. Under TLS 1.3 with `tls`, bidirectional requests and
        WebSocket upgrades are secure carriers with their TLS connection's
        exporter (split halves and exchange carriers are not)."""
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
        """The next established session; `ListenerClosedError` once closed."""
    def close(self) -> None:
        """Closes at once: everything new is refused, joins and resumptions
        included, and the `serve_*` loops end."""
    def variant_stats(self) -> _t.AdmissionVariants:
        """The admission's verdicts on the carriers it labelled, per label."""
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
    abort: SpliceAbort | None = None,
) -> Spliced:
    """Forwards two bidirectional streams into each other until both
    directions ended; the handles are used up. Splicing a stream into
    itself raises `ValueError`; cancelling the task cancels the splice (the
    streams are reset with `ZMUX_CANCELLED`, stopped with 0, and there is no
    result). `abort.abort(code)` ends it with that code instead: both
    downstream parts are reset and both upstream parts stopped with it, and
    the directions still running report `SpliceEnd.CANCELLED` with `code`;
    a handle aborted before the start ends the splice at once."""

async def splice_packets(
    a: tuple[SendStream, RecvStream],
    b: tuple[SendStream, RecvStream],
    *,
    chunk: int = 65536,
    a_to_b: Limiter | None = None,
    b_to_a: Limiter | None = None,
    abort: SpliceAbort | None = None,
) -> Spliced:
    """Relays two packet streams as `splice` does: stream bytes pass through
    with only capsule headers parsed, and a stream datagram that does not fit
    the next hop's datagrams goes on as a DATAGRAM capsule at the next
    capsule boundary (`Forwarded.datagrams_as_capsules`). A capsule never
    becomes a datagram."""

@final
class SpliceAbort:
    """Aborts the splices (`splice`, `splice_packets`) given it as `abort=`
    with an application error code. One handle may serve several splices;
    the first `abort` decides the code and ends them all."""

    def __init__(self) -> None: ...
    def abort(self, code: int) -> None:
        """Aborts with `code` (< 2**62, 0 included); a later call changes
        nothing."""
    @property
    def code(self) -> int | None:
        """The code of the abort, `None` while not aborted."""

@final
class PacketStream:
    """Packets over a bidirectional stream, each as a datagram of the stream
    or as a DATAGRAM capsule in its bytes, as `policy` says. Packets are
    never fragmented and not ordered relative to each other; those in
    capsules arrive in order and reliably. Both endpoints wrap the stream
    once their application agreed it carries packets (by its preamble, for
    example); the two handles are used up. `max_packet` bounds the payload
    sent and accepted. `async for` yields packets until the peer closed its
    direction. Every coroutine is cancellation-safe: a cancelled send is
    completed by the next send or `close`, and a packet whose receive was
    cancelled is returned by the next one."""

    def __init__(
        self,
        send: SendStream,
        recv: RecvStream,
        *,
        policy: SendPolicy | str = "prefer_datagram",
        max_packet: int = 65535,
    ) -> None: ...
    async def send(self, payload: bytes, *, context: int = 0) -> Sent:
        """Sends a packet with Context ID `context` (below 2**62). A datagram
        never waits; a capsule waits for the stream's buffer.
        `PacketTooLargeError` above the bound, `InvalidArgumentError` for a
        Context ID out of range, `NotNegotiatedError` for
        `SendPolicy.DATAGRAM_ONLY` without datagrams."""
    async def recv(self) -> Packet | None:
        """The next packet, whichever way it came; `None` once the peer
        closed its direction at a capsule boundary. `MalformedPacketError`
        when the peer's bytes were malformed: the stream was reset and
        stopped with `ZMUX_PACKET_ERROR`."""
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Packet: ...
    async def close(self) -> None:
        """Ends the sending direction once a capsule in progress was
        written; the peer's `recv` then returns `None`."""
    def stats(self) -> PacketStats:
        """Both directions' counters."""
    def split(self) -> tuple[PacketSender, PacketReceiver]:
        """The sending and the receiving half, for two tasks; the stream is
        used up."""

@final
class PacketSender:
    """The sending half of a `PacketStream`."""

    async def send(self, payload: bytes, *, context: int = 0) -> Sent:
        """See `PacketStream.send`."""
    async def close(self) -> None:
        """See `PacketStream.close`."""
    def stats(self) -> PacketStats:
        """The counters of the sending direction."""

@final
class PacketReceiver:
    """The receiving half of a `PacketStream`."""

    async def recv(self) -> Packet | None:
        """See `PacketStream.recv`."""
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Packet: ...
    def stats(self) -> PacketStats:
        """The counters of the receiving direction."""

@final
class ReplayFilter:
    """A time-windowed single-use filter: a key stamped `stamp` (Unix
    milliseconds) is accepted when `|now - stamp| <= window` and it was not
    seen. At most `capacity` keys are held; a full filter accepts nothing
    new. Authenticate the key and its stamp together before checking them."""

    def __init__(
        self, window: float, capacity: int, *, not_before: float | None = None
    ) -> None:
        """`window` in seconds, at least 0.001; `capacity` at least 1 (`ValueError`
        otherwise); `not_before` (Unix seconds, typically the process start)
        rejects earlier stamps."""
    def check(self, key: bytes, stamp: int) -> ReplayVerdict:
        """Checks `key` by the system clock."""
    def check_at(self, key: bytes, stamp: int, now: int) -> ReplayVerdict:
        """Checks `key` with the clock at `now` (Unix milliseconds)."""
    def __len__(self) -> int:
        """The keys held now."""

def join_prefix(listener: Listener, prefix: bytes) -> tuple[_t.JoinPrefix, int]:
    """For an admission's `decide`: whether `prefix`, a byte-stream
    carrier's first bytes, begins a Join Hello whose Locator names a current
    session of `listener`: `(JoinPrefix, need)`, `need` the bytes wanted in
    all for `NEED_MORE` (ask for them with `AdmissionVerdict.more`; the
    admission's `max_peek` must allow it) and 0 otherwise. Advisory: the
    join still authenticates, and a session that ended meanwhile makes the
    Locator unknown."""

def join_ready(session: Session) -> bool:
    """Whether a pipe added to `session` now would join at once rather than
    wait: its join keys are in place, it has room for a join, and no join
    backoff is running."""

def classify_first_bytes(
    data: bytes, *, framing: _t.Framing | str = "byte_stream"
) -> tuple[_t.FirstBytes, int]:
    """Whether a carrier's first bytes can begin a first record, by syntax
    only: `(FirstBytes, need)`, `need` the bytes wanted in all for `NEED_MORE`
    (at most `MAX_FIRST_BYTES`) and 0 otherwise. In a message-framed carrier,
    `data` starts the first message. An unknown framing raises `ValueError`."""

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

type _Source = tuple[str, int] | None

def static_key_id(key: Buffer) -> bytes:
    """The 32-byte KeyId of a static key, for `PinVerifier`."""

def static_public(secret: Buffer) -> bytes:
    """The X25519 public key of a 32-byte static secret, as `static_key_id` names it;
    another length raises `ValueError`."""

def key_id(key_alg: _t.KeyAlg | int, key: Buffer) -> bytes:
    """The 32-byte KeyId of a key of `key_alg`: what a pin and a verdict name it by."""

def derive_handle_psk(
    secret: Buffer, domain: Buffer, context: Buffer = b""
) -> tuple[bytes, bytes]:
    """The Handle and the pre-shared key of a secret."""

def session_crypto(initiator: _t.SessionCrypto, responder: _t.SessionCrypto) -> bytes:
    """`session_crypto`: both endpoints' `SessionCrypto`, encoded, as the join keys
    take it. A set breaking the parameter's rules raises `ValueError`."""

# (the keyword is the public parameter name, shared with the function of that name)
# noinspection PyShadowingNames
def derive_join_psk(
    suite: int,
    epoch_secret: Buffer,
    *,
    role: _t.Role | str,
    session_crypto: Buffer,
) -> bytes:
    """`join_psk[e]_x` of `role` (`Role.CLIENT`, the initiator, or
    `Role.SERVER`) from an epoch secret and `session_crypto`, to the Suite's
    hash length. An unknown Suite raises `ValueError`."""

# (the keyword is the public parameter name, shared with the function of that name)
# noinspection PyShadowingNames
def expand_join_psk(
    suite: int,
    epoch_secret: Buffer,
    *,
    role: _t.Role | str,
    session_crypto: Buffer,
    length: int,
) -> bytes:
    """The Expand of `derive_join_psk` for any Suite value and an output length."""

class Verifier(Protocol):
    """Judges the peer once per Establish: returns a `VerifyVerdict`, or raises
    `VerifyRejectedError` (any other exception too) or `VerifyUnavailableError`. `verify` may be
    `async`. It does not see the transcript: the handshake checks the proof the verdict
    names."""

    def verify(
        self, input: _t.VerifyInput, /
    ) -> _t.VerifyVerdict | Awaitable[_t.VerifyVerdict]: ...

class Signer(Protocol):
    """Signs the transcript proof of a handshake once per handshake; it may live in an
    HSM or another process. `proof_key` is `(key_alg, public key)`; `sign` may be
    `async` and returns a signature of the algorithm's length."""

    @property
    def proof_key(self) -> tuple[int, bytes]: ...
    def sign(self, message: bytes, /) -> bytes | Awaitable[bytes]: ...

type AppDataSource = Callable[
    [int, _t.VerifyInput | None, _t.VerifyVerdict | None],
    bytes | Awaitable[bytes | None] | None,
]
"""Supplies the application data of a handshake message this end writes, called with
the message (1, 2 or 3), what is known of the peer by then (`None` for message 1) and,
for the client's message 3, its verifier's verdict on the server (`None` otherwise):
`None` or empty sends nothing. It may be `async`; an exception fails the handshake. An
unauthenticated peer can trigger it, so it is light and without side effects."""

class Gate(Protocol):
    """The server's host: who may establish. Each may be `async`, and raises
    `VerifyRejectedError` (any other exception too) or `VerifyUnavailableError` to refuse.
    `credential` chooses the server's credential by the Handle, the Profile and the
    local context; `commit` admits the client after message 3, and its result is the
    session's `admitted`."""

    def resolve(
        self, handle: bytes, source: _Source, /
    ) -> bytes | Awaitable[bytes]: ...
    def credential(
        self, handle: bytes, profile: int, local_context: bytes, source: _Source, /
    ) -> tuple[int, bytes] | Awaitable[tuple[int, bytes] | None] | None: ...
    def commit(
        self, handle: bytes, peer: _t.Peer, source: _Source, /
    ) -> Any | Awaitable[Any]: ...

type _Shaper = Callable[[_t.HandshakeView], _t.UnitPlan | None] | ShapingBundle

@final
class PinVerifier:
    """Trusts the one static key with this 32-byte KeyId (`static_key_id`): the key
    itself; a credential is not looked at. With `proof_key` (a KeyId) the peer must
    also prove the transcript with that key."""

    # (the keyword is the public parameter name, shared with the function `key_id`)
    # noinspection PyShadowingNames
    def __new__(cls, key_id: Buffer, *, proof_key: Buffer | None = None) -> Self: ...

@final
class SigningKey:
    """A signing key of this process for the transcript proof; it is a `Signer`."""

    @staticmethod
    def generate(key_alg: _t.KeyAlg | int = _t.KeyAlg.MLDSA44) -> SigningKey:
        """A new key of `key_alg`; an algorithm that cannot sign raises
        `ValueError`."""
    @staticmethod
    def from_seed(key_alg: _t.KeyAlg | int, seed: Buffer) -> SigningKey:
        """The key of `key_alg` from its seed."""
    @property
    def key_alg(self) -> int:
        """The key's algorithm (a `KeyAlg` value)."""
    @property
    def public(self) -> bytes:
        """The public key."""
    @property
    def key_id(self) -> bytes:
        """The KeyId a verdict names as its `proof_key`."""
    @property
    def proof_key(self) -> tuple[int, bytes]:
        """`(key_alg, public key)`."""
    def sign(self, message: Buffer) -> bytes:
        """The signature of `message`."""

@final
class SecureServer:
    """The server's side of Establish, for `ListenerConfig(secure_server=...)`. `shaper`, a
    `ShapingBundle` or a callable, is asked before a handshake message with a
    `HandshakeView` and returns a `UnitPlan`, or `None` for no plan.
    `accepted_profiles` (unset: 1 and 3; empty raises `ValueError`) is the only way to accept a
    Profile without a pre-shared key (4, 5). `client_verifier` verifies clients from
    message 3 (unset: only the gate's `commit` admits them); `local_context` is this
    listener's label for the gate and the verifier; `require_pq_auth` fails a client
    without post-quantum authentication; `signer` proves message 2 for clients whose
    verdict names its key; `app_data` supplies the data of message 2, and
    `max_app_data` bounds the client's (`DEFAULT_MAX_APP_DATA` bytes; `None`: no bound
    beyond the message). `allow_record_mode(mode, peer)` decides a mode other than
    Sealed. An unknown or reserved Profile, a key of zeros, or `require_pq_auth`
    without a verifier or with a pin of a static key alone raises `ValueError` here."""

    def __new__(
        cls,
        gate: Gate,
        static_key: Buffer,
        *,
        accepted_profiles: Iterable[int] | None = None,
        allow_record_mode: Callable[[_t.RecordMode, _t.Peer], bool] | None = None,
        shaper: _Shaper | None = None,
        shaping_limits: _t.ShapingLimits | None = None,
        client_verifier: Verifier | PinVerifier | None = None,
        local_context: Buffer = b"",
        require_pq_auth: bool = False,
        signer: Signer | SigningKey | None = None,
        app_data: AppDataSource | None = None,
        max_app_data: int | None = 256,
    ) -> Self: ...

async def establish(
    pipe: PipeIo,
    *,
    verifier: Verifier | PinVerifier | None = None,
    allow_psk_only: bool = False,
    handle: Buffer = b"",
    psk: Buffer = b"",
    static_secret: Buffer | _t.Auto = _t.AUTO,
    allowed_profiles: Iterable[int] | None = None,
    record_mode: _t.RecordMode | str = _t.RecordMode.SEALED,
    credential: tuple[int, bytes] | None = None,
    local_context: Buffer = b"",
    app_data: AppDataSource | None = None,
    max_app_data: int | None = 256,
    require_pq_auth: bool = False,
    signer: Signer | SigningKey | None = None,
    shaper: _Shaper | None = None,
    shaping_limits: _t.ShapingLimits | None = None,
    reply_timeout: float | None = 10.0,
) -> tuple[PipeIo, _t.Peer]:
    """Runs the client's handshake on `pipe`: the carrier for `Session.connect`, whose
    `pipe_auth` stays unset, and what it learned of the server. On a failure the
    carrier is closed; nothing is retried. A server that ends or stays silent until
    `reply_timeout` (`None`: none) raises `NoReplyError`; a rejected server raises
    `ZmuxError`; a configuration mistake raises `ValueError` naming it.
    `static_secret` is the client's 32-byte X25519 static secret (`AUTO`: a key
    generated once per process); `record_mode` the record mode of the session's
    first pipe.
    `allowed_profiles` `None` is both ciphers, AES-GCM first with AES hardware: 1 or
    3 with a pre-shared key, 4 or 5 without; an empty list raises `ValueError`. `credential` is sent in message 3;
    `local_context` is this dial's label for the verifier; `app_data` supplies the
    data of messages 1 (Profiles 1 and 3) and 3, and `max_app_data` bounds the
    server's (`DEFAULT_MAX_APP_DATA` bytes; `None`: no bound beyond the message);
    `require_pq_auth` fails a server without post-quantum authentication; `signer`
    proves message 3 for a server whose verdict names its key."""

@final
class InstalledShaper:
    """The shaper in force on a session's outbound pipes, as `Session.shaper`
    reads it: opaque, and assignable to the `Session.shaper` of another
    session (without a budget)."""

@final
class ShapingBundle:
    """A configuration bundle: per carrier kind, the machines, handshake plans, budget and pool."""

    @staticmethod
    def from_json(
        definition: str | bytes,
        *,
        features: list[str] = ...,
        allow_unshaped: bool = False,
        limits: _t.ShapingSizeLimits | None = None,
        seed: bytes | None = None,
    ) -> ShapingBundle:
        """Reads a bundle from its JSON `definition`; any error raises
        `ValueError`."""
    def selected(self, kind: str) -> int | None:
        """The index of the candidate chosen for `kind`, or `None`."""
    def unshaped(self) -> list[str]:
        """The carrier kinds left unshaped."""
    def plan(self, kind: str, handshake: str, message: str) -> _t.UnitPlan | None:
        """The plan of a handshake message of `kind`, or `None`."""
    def budget(self, kind: str) -> _t.ShapingBudget | None:
        """One draw of the budget of `kind`, or `None` without one."""
