"""Native layer. Every coroutine here is cancellation-safe unless noted:
cancelling the awaiting task drops the pending operation and leaves the
session, stream or pipe usable. Use `asyncio.timeout()` for per-call
deadlines; durations are seconds."""

import ipaddress
import os
from types import TracebackType
from collections.abc import (
    Awaitable,
    Buffer,
    Callable,
    Coroutine,
    Generator,
    Iterable,
    Mapping,
)
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
    ListenerLimits,
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
    SpliceResult,
    StreamDatagram,
    StreamStats,
    Tlv,
)

type _Pem = str | os.PathLike[str] | bytes
type _Prio = Priority | tuple[int, bool]
type _Headers = Mapping[str, str] | Iterable[tuple[str, str]]
type _Host = str | ipaddress.IPv4Address | ipaddress.IPv6Address
type _HostPort = tuple[_Host, int]

DEFAULT_MAX_PACKET: int
"""Default bound of a packet payload in bytes."""
DEFAULT_KEEP_ALIVE_PERIOD: float
"""Default keep-alive period, seconds (15)."""
DEFAULT_MAX_IDLE_TIMEOUT: float
"""Default idle timeout, seconds (30)."""
DEFAULT_MAX_LANES: int
"""Default `Config.max_lanes`, the lanes accepted on each inbound pipe (258).
Not `DEFAULT_LANES`, the QUIC adapter's lane count."""
DEFAULT_PROBE_JITTER: float
"""Default probe jitter (0.25)."""
DEFAULT_STANDBY_PROBE: float
"""Default standby probe interval, seconds (1)."""
DEFAULT_SUSPECT_FLOOR: float
"""Default floor of a pipe's suspicion, seconds."""
MAX_FIRST_BYTES: int
"""The most bytes `classify_first_bytes` needs (5)."""
PIPE_UNASSIGNED: int
"""JoinOutcome pipe ID for a failure before allocation."""
MAX_STREAM_CREDIT: int
"""The largest stream count the protocol can count, 2**60: the value that
grants the peer as many streams as it can, in effect no limit. It is the top
of the range of `Config.max_incoming_streams`,
`Config.max_incoming_uni_streams` and `Session.raise_incoming_streams`, a
value of that range and not a setting: 0 keeps meaning none."""
DIAL_TIMEOUT: float
"""The default bound of a TLS, QUIC, WebSocket, HTTP/3 or WebTransport dial,
seconds (10)."""
RESERVED_EXPORTER_PREFIX: str
"""The start of the exporter labels zmux itself uses."""
DEFAULT_MAX_RECORD_SIZE: int
"""Record size limit before the peer's parameters, bytes (16382)."""
MAX_ADMISSION_MESSAGE: int
"""The largest first message an `Admission` reads, its default
`max_message`: the largest record, bytes (65535)."""
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
DEFAULT_FIRST_RECORD_TIMEOUT: float
"""Default first-record timeout of a listener, seconds (2)."""
MIN_MAX_LEN: int
"""Smallest shaping `max_len` honoured, bytes (64)."""
"""Default longest delay a shaper may hold a record, seconds (1)."""
DEFAULT_MAX_APP_DATA: int
"""Default bound of the application data of a received handshake message, bytes (256)."""
DEFAULT_MAX_SLOTS: int
"""Default bound on the counters and timers of a shaping candidate (4096)."""
_KEYALG_X25519: int
_KEYALG_MLDSA44: int
DEFAULT_RECOVERY_RATIO: float
"""Default `CapacityFloor.recovery_ratio` (1.25)."""
DEFAULT_MIN_INTERVAL: float
"""Default `QualityBand.min_interval`, seconds (1)."""

def _pipe_option_defaults() -> dict[str, Any]:
    """Internal: the core defaults for the fields of PipeOptions."""

def _check_pipe_option_sentinels(options: _t.PipeOptions) -> None:
    """Internal: raises `TypeError` for an update sentinel in pipe options."""

def _check_shaping_account(o: _t.ShapingAccount) -> None:
    """Internal: raises `ValueError` for an invalid shaping account."""

def _check_shaping_profile(o: _t.ShapingProfileLimits) -> None:
    """Internal: raises `ValueError` for an invalid shaping profile."""

def _check_shaper_sources(v: _t.Shaper) -> None:
    """Internal: raises `ValueError` for conflicting shaping sources."""

def _check_epoch_policy(policy: _t.EpochPolicy) -> None:
    """Internal: raises `ValueError` for an invalid epoch policy."""

def _check_quality_band(b: _t.QualityBand) -> None:
    """Internal: raises `ValueError` for a `QualityBand` out of range."""

def _config_defaults() -> dict[str, Any]:
    """Internal: the library's defaults of the `zmux.Config` fields."""

@final
class _TestRevision:
    """Private observer of native commits, available in test builds."""

    async def changed(self) -> None:
        """Waits for an owner revision after the previous observation."""

def _with_backoff_jitter[T](
    sample: float, *, observe: Callable[[], T]
) -> tuple[T, int]:
    """Runs a test observation with a fixed jitter sample and counts the draws."""

@final
class _TestClock:
    """Native manually advanced clock for the test build."""

    @property
    def domain(self) -> ClockDomain:
        """The domain that uses this clock."""
    def advance(self, seconds: float) -> None:
        """Advances this clock by the given number of seconds."""
    async def wait_for_timer(self, delay: float, *, count: int = 1) -> None:
        """Waits for `count` timers at now + `delay` to register their wakeups."""

@final
class _MatrixWire:
    """Test-build observer for actual socket reads and writes."""

    def __init__(
        self,
        *,
        join: bool = False,
        client: bool = False,
        signal: _MatrixWire | None = None,
    ) -> None:
        """Observes bootstrap or Join traffic and optionally shares a change signal."""
    @property
    def revision(self) -> int:
        """The shared change watermark."""
    async def changed(self, observed: int) -> None:
        """Waits for a socket handoff after the observed watermark."""
    def snapshot(
        self,
    ) -> tuple[int, int, dict[int, int], dict[int, bool], int, int, int]:
        """Returns probe and eliciting ends, received ACKs, outbound streams, padding and datagrams."""
    def hold_reads(self, held: bool) -> int:
        """Holds or releases reads and returns the last complete inbound record position."""
    def hold_writes(self, held: bool) -> None:
        """Holds or releases writes while leaving the socket open."""

@final
class _MatrixTcp:
    """Test-build loopback listening socket."""

    @staticmethod
    async def bind() -> _MatrixTcp:
        """Binds on an ephemeral port."""
    @property
    def address(self) -> str:
        """The bound address as published to the driver."""
    async def accept(self, wire: _MatrixWire) -> tuple[PipeIo, tuple[str, int]]:
        """Accepts a TCP carrier and installs its observer."""
    async def upgrade(self, listener: Listener) -> _MatrixUpgrade:
        """Upgrades a WebSocket through the production head admission path."""

@final
class _MatrixUpgrade:
    """An upgraded WebSocket awaiting first-message admission in a test build."""

    async def admit(self) -> bool:
        """Runs admission to completion and attaches the carrier if accepted."""

async def _matrix_dial_tcp(address: str, *, wire: _MatrixWire) -> PipeIo:
    """Connects a TCP carrier and installs its observer."""

async def _matrix_write_messages(pipe: PipeIo, *, messages: list[bytes]) -> PipeIo:
    """Writes whole messages before returning the carrier for its next operation."""

async def _matrix_read_messages(pipe: PipeIo, *, count: int) -> list[bytes]:
    """Consumes the carrier and reads up to count messages or until it closes."""

async def _matrix_established(session: Session) -> None:
    """Waits for completed establishment on a test-build session."""

def _matrix_stall_evidence(
    session: Session, *, pipe: int, cost: float, waiting: bool
) -> None:
    """Installs deterministic ACK progress evidence through the core's fixture seam."""

def _matrix_fire_timers(session: Session) -> None:
    """Applies session timers at the current fixture-clock instant."""

async def _panic() -> None:
    """Internal, only in builds with the `test-hooks` feature: a future that
    panics (tests how a panic reaches its awaiter)."""

def _error_data() -> list[BaseException]:
    """Internal, only in test builds. Returns native errors for field tests."""

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

    def set_accounting_sources(
        self,
        *,
        send: _t.CarrierHalfSource | None = None,
        receive: _t.CarrierHalfSource | None = None,
    ) -> None:
        """Sets the host-provided attribution of the independent carrier halves."""

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
    def set_max_record(self, max: int) -> None:
        """Limits the largest record plaintext the carrier takes, applied
        beside the peer's `max_record_size` on every pipe this input
        becomes, the session's first included: the smaller of `max` and a
        limit already set holds, and a Sealed transform above keeps it less
        its overhead. 0 keeps the carrier's default; a value below 8192,
        the carrier record floor, raises `InvalidArgumentError` (it is never
        clamped). There is no upper bound: the peer's `max_record_size`
        reduces it. A pipe whose limit, less a Sealed transform's overhead,
        is below 8192 is refused when it is added or joined."""
    def declare_carrier_secure(self) -> None:
        """Declares the carrier secure: it meets the secure carrier's Bound
        contract, record confidentiality and integrity included, so a
        `record_policy` may choose `RecordMode.BOUND` on it
        (`RecordPolicy.secure`). An exporter alone is no such
        declaration; a carrier whose TLS ends outside the process is not
        secure."""
    @property
    def reports_failure(self) -> bool:
        """Whether the carrier reports its own failure: its reads or writes
        fail when the path under it fails (a stream of an outer session:
        `stream_pipe`, `Session.open_pipe_stream`, which report it). A
        stall then never fails the pipe unless its own
        `PipeLiveness.dead_timeout` says otherwise."""
    @reports_failure.setter
    def reports_failure(self, on: bool) -> None: ...
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
        loop (`NoRunningLoopError` without one). A layer's error raises
        `ConnectError`."""

@final
class CarrierStream:
    """A carrier's halves as one byte stream (`PipeIo.into_stream()`). On a
    carrier with message framing each write is one message and reads
    return the messages' bytes in order."""

    async def _release(self) -> None: ...
    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes; `b""` at the end (also without a receiving half)."""
    async def write(self, data: Buffer) -> None:
        """Exactly one write on the carrier; fails without a sending half.
        `data` is copied unless it is `bytes`."""
    async def shutdown(self) -> None:
        """Ends the sending half gracefully."""

@final
class _LayerEnd:
    """Internal: the Python side of the stream a `PipeIo.wrap` layer returns."""

    def _bridge_done(self) -> None: ...
    async def _released(self) -> None: ...
    async def read(self) -> bytes: ...
    async def write(self, data: Buffer) -> None: ...
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

    def _track_bridge(self, pipe: PipeIo) -> None: ...
    def _bridge_done(self) -> None: ...
    async def _released(self) -> None: ...
    async def read(self, n: int = 65536) -> bytes:
        """Up to `n` bytes the session wrote; `b""` once it closed."""
    async def write(self, data: Buffer) -> None:
        """Delivers `data` to the session (copied unless it is `bytes`);
        `b""` ends the pipe."""

def pipe_pair(
    *,
    carrier_kind: _t.CarrierKind | str | None = None,
    unsent: UnsentCount | None = None,
    max_record: int | None = None,
    exporter: Callable[[str, bytes, int], Awaitable[bytes | None] | bytes | None]
    | None = None,
) -> tuple[PipeIo, PipeEnd]:
    """An in-memory pipe: give the `PipeIo` to a session, drive the
    `PipeEnd` yourself. `carrier_kind` labels it with a carrier kind
    (`PipeIo.carrier_kind`). `unsent` is the carrier's unsent count, which
    the application keeps up to date with the bytes the carrier took and has
    not yet transmitted (it feeds `PipeStats.queued_bytes` and the
    scheduler's queue estimate; the session's driver reads it without the
    interpreter lock). `max_record` is the largest record plaintext the
    carrier takes (`PipeIo.set_max_record`: at least 8192, no upper
    bound, 0 the default). `exporter(label, context, length)` is the exporter of
    the carrier's innermost end-to-end handshake, the one source of
    `PipeAuth.exporter()`, carrier-bound joins and the session secret: it
    returns `length` bytes, or `None` while the handshake is incomplete
    (synchronously or `async`); an exception or another length gives no
    value and is reported as unraisable. It runs on the event loop running
    when `pipe_pair` is called (`NoRunningLoopError` without one): the
    values zmux reads are fetched there before the carrier's session, join
    or Establish needs them, bounded by its handshake or join deadline.
    `Session.export_keying_material` gives nothing for such a carrier.
    Never give an early exporter. A stream carrier ignores it."""

@final
class CarrierInfo:
    """The metadata of a carrier, given to an `Admission` decider and to a
    credential: a copy, usable for as long as it is kept."""

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
    def stage(self) -> _t.AdmissionStage:
        """What of the carrier the decision is taken on: `HEAD`, an HTTP
        request head (WebSocket, WebTransport, an HTTP request without a
        body: there is no prefix, and a credential travels in a request
        header field), or `CARRIER`, its first bytes or first message."""
    @property
    def framing(self) -> _t.Framing:
        """The carrier's framing at `AdmissionStage.CARRIER`: with
        `Framing.RECORDS` the prefix is its first message; `BYTE_STREAM` on
        a head."""
    @property
    def upgrade(self) -> bool:
        """The carrier of an HTTP upgrade (WebSocket, WebTransport), on its
        head and on the decision `AdmissionVerdict.DEFER` takes on the
        carrier."""
    def export(
        self, label: str, context: bytes = b"", length: int = 32
    ) -> bytes | None:
        """`length` bytes of the exporter of the carrier's completed
        handshake for `label` and `context`, as it answers without waiting;
        None without one, for a value it does not hold, or once the
        connection is gone. The metadata a TLS over TCP listener gives holds
        the values of zmux's own labels only (prefix authentication's among
        them), read at the handshake."""

@final
class AdmissionVerdict:
    """The outcome of an admission decision."""

    STALL: ClassVar[AdmissionVerdict]
    """Nothing is sent; what arrives is discarded until the stall interval
    has passed, then the carrier is closed."""
    CLOSE: ClassVar[AdmissionVerdict]
    """The carrier is closed at once."""
    DEFER: ClassVar[AdmissionVerdict]
    """On the head of an HTTP upgrade (`CarrierInfo.upgrade`, stage `HEAD`):
    completes the upgrade and decides again, with the same metadata at
    stage `CARRIER`, on the carrier's first message (WebSocket) or first
    `peek` bytes (a WebTransport session's first stream), within what
    remains of the peek timeout. Anywhere else it counts as `CLOSE`."""
    @staticmethod
    def accept(skip: int = 0, value: Any = None) -> AdmissionVerdict:
        """To the listener, without the first `skip` bytes of the prefix;
        `value`, any object, is the carrier's admitted value
        (`PipeHint.admitted`, `Session.admitted`, `Pipe.admitted`)."""
    @staticmethod
    def fallback(value: Any = None) -> AdmissionVerdict:
        """To the listener's fallback (`ListenerConfig.fallback`), what was
        read replayed; `value`, any object, is the host's routing of the
        carrier to a service of its own (`Takeover.value`). Without a
        fallback the carrier is stalled; an HTTP request decided on its
        head gets 404, and the value reaches no HTTP handler."""
    @staticmethod
    def takeover(value: Any = None) -> AdmissionVerdict:
        """Hand the carrier to the byte-stream fallback, or stall without one."""
    @staticmethod
    def more(need: int) -> AdmissionVerdict:
        """Reads until the prefix holds `need` bytes in all (or the carrier
        ends, or the peek timeout passes, all rounds sharing it), then decides
        again with the longer prefix. `need` exceeds the prefix and is at most
        `Admission.max_peek`, on a byte stream; otherwise (a first message, a
        request head), and on a carrier that ended short, it counts as
        `CLOSE`."""
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
        """An accept's or a fallback's value."""

@final
class Takeover:
    """A carrier the listener's admission handed to
    `ListenerConfig.fallback`, what was read of it replayed: the bytes of a
    byte stream, or the first message of a message-framed carrier (a whole,
    non-empty binary message).

    The carrier is the fallback's for its call: once the call returned,
    what it did not take (`into_pipe`, `into_messages`) is closed, and so is
    what the adapter holds beside it (the QUIC connection of a stream, the
    WebTransport session, the response of an HTTP request carrier, reset if
    not ended), unless the call detached it first (`detach`). A taken
    carrier is its holder's, closed when it is dropped or shut down; each
    half closes on its own."""

    @property
    def info(self) -> CarrierInfo:
        """The carrier's metadata, as the decision saw it."""
    @property
    def framing(self) -> _t.Framing:
        """The carrier's framing: `Framing.RECORDS` for a message-framed
        carrier (a WebSocket), whose replay is its first message."""
    @property
    def replayed(self) -> bytes:
        """What the admission read, replayed in front of the carrier."""
    @property
    def value(self) -> Any:
        """The value of the verdict that handed the carrier over
        (`AdmissionVerdict.fallback(value=...)`): the host's routing of it
        to a service of its own; `None` without one, and after a peek
        timeout."""
    @property
    def detached(self) -> bool:
        """Whether `detach` made the carrier the host's (`False` once it is
        taken)."""
    def detach(self) -> None:
        """Makes the carrier the host's for good: what the adapter holds of
        it stays open when the fallback returns, so that the host may serve
        it on another task; the host closes it once done. Call it before
        taking the carrier; a second call does nothing.
        `TakeoverReturnedError` once the fallback returned without it,
        `PipeUsedError` once the carrier was taken."""
    def into_pipe(self) -> PipeIo:
        """The carrier as a pipe input, what was read replayed first (on a
        message-framed carrier its first message is read again), with every
        capability an accepted carrier has (TLS state, exporter, secure
        declaration, failure reporting, ...): give it to a session or a
        listener, or read it as a stream (`PipeIo.into_stream`).
        `PipeUsedError` once taken, `TakeoverReturnedError` after the
        fallback returned without detaching it."""
    def into_messages(self) -> TakeoverMessages:
        """A message-framed carrier (`Framing.RECORDS`) read and written by
        whole messages, the first one read again first. `TypeError` for a
        byte stream (the takeover keeps its carrier); otherwise as
        `into_pipe`."""

@final
class TakeoverMessages:
    """A taken-over message-framed carrier (`Takeover.into_messages`): each
    read a whole message, each write one. Full duplex: a read waiting for a
    message never holds back a write, so one task may read while another
    writes; reads run one at a time, as do writes. A cancelled read may
    lose the message it was reading. Each half is closed once the object
    is dropped."""

    async def read_message(self, max: int = 65535) -> bytes | None:
        """The next message, of at most `max` bytes (a longer one is an
        error, raised as the carrier's, the replayed first one too); `None`
        at the carrier's end."""
    async def write_message(self, message: Buffer) -> None:
        """Writes `message` as one message."""
    async def shutdown(self) -> None:
        """Ends the sending half gracefully; the receiving half reads on."""

@final
class Decision:
    """A decision on a carrier: its verdict and the host's label of the kind
    of carrier."""

    def __init__(
        self, verdict: AdmissionVerdict, *, variant: str | None = None
    ) -> None:
        """A label counts the verdict in `Listener.variant_stats().variants` and, on an
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
    `async` and resolves to one. It runs on the event loop running when the
    admission is made, else on the one the `Listener` was made in, and is
    cancelled (`CancelledError`) when the peek timeout ends or the
    listener closes.
    An exception or another return value closes the carrier.
    `max_peek` is the largest prefix of a byte stream `AdmissionVerdict.more`
    may ask for (`peek` when larger). On a message-framed carrier the prefix
    is its first message, whole, read with a `peek` above 0 or after a
    `DEFER`: at most `max_message` bytes (0: `MAX_ADMISSION_MESSAGE`, the
    largest record; above it `ValueError`), a longer one closed undecided
    (`too_large`), and a carrier without one (ended, failed, a text or an
    empty message) closed undecided.
    `peek_timeout` (seconds, from the end of the outer handshake) bounds the
    reading of the prefix and the decision; `stall` is the `(min, max)`
    seconds a stalled carrier is held open; `AUTO` or `None` (the default) draws them
    at random. Within the interval, every carrier
    from one source is held open for the same duration during the listener's
    lifetime, and a held carrier counts against the listener's
    `max_pending_per_source` (beyond it, it is closed at once).
    A byte-stream carrier whose prefix has not arrived when the peek timeout
    ends is closed, or with `fallback_on_peek_timeout` taken to the fallback
    with the bytes read replayed, or stalled without a byte-stream target.
    The final outcome counts once in `AdmissionStats`. A message-framed
    carrier, an HTTP request carrier and a decision that does not return
    in time are closed either way."""

    def __init__(
        self,
        decide: Callable[
            [CarrierInfo, bytes],
            AdmissionVerdict | Decision | Awaitable[AdmissionVerdict | Decision],
        ],
        *,
        peek: int = 0,
        max_peek: int = 0,
        max_message: int = 0,
        peek_timeout: float | _t.Auto | None = None,
        stall: tuple[float, float] | _t.Auto | None = None,
        fallback_on_peek_timeout: bool = False,
    ) -> None: ...
    @staticmethod
    def prefix_auth(
        store: MemoryPrefixStore | _t.PrefixStore,
        *,
        binding: _t.PrefixBinding
        | Literal["bound", "encrypted", "allow_cleartext"] = "bound",
        header: str | None = None,
        reject: _t.PrefixRejection | Literal["close", "stall", "fallback"] = "close",
        max_skew: int | None = None,
        peek_timeout: float | _t.Auto | None = None,
        stall: tuple[float, float] | _t.Auto | None = None,
        fallback_on_peek_timeout: bool = False,
    ) -> Admission:
        """Redeem a 64-byte binary or request-header ticket through the authority."""
    @staticmethod
    def _fixture_first_message_ticket(
        store: MemoryPrefixStore, *, unix_seconds: int
    ) -> Admission:
        """Verifies cleartext first-message fixture tickets at a fixed Unix time."""
    @property
    def peek(self) -> int: ...
    @property
    def max_peek(self) -> int:
        """The largest prefix of a byte stream, at least `peek`."""
    @property
    def max_message(self) -> int:
        """The largest first message of a message-framed carrier decided on."""
    @property
    def fallback_on_peek_timeout(self) -> bool: ...
    @property
    def peek_timeout(self) -> float: ...
    @property
    def stall(self) -> tuple[float, float]: ...

PREFIX_TOKEN_LEN: int
"""Length of a binary ticket presentation in bytes."""

@final
class PrefixGeneration:
    """An outer key for an inclusive issue-slot interval."""

    def __init__(self, key: bytes, *, first_slot: int, last_slot: int) -> None:
        """Use a dedicated 32-byte key for this generation."""

@final
class PrefixSchedule:
    """Versioned outer key generations with disjoint issue intervals."""

    def __init__(
        self, generations: Iterable[PrefixGeneration], *, version: int = 1
    ) -> None:
        """Make a schedule for presenters or a custom authority."""
    @property
    def version(self) -> int:
        """The authority revision of the schedule."""

@final
class PrefixTicket:
    """A ticket record containing dedicated credentials and an inclusive lifetime."""

    def __init__(
        self,
        id: bytes,
        *,
        key: bytes,
        first_slot: int,
        last_slot: int,
        version: int = 1,
        single_use: bool = True,
    ) -> None:
        """Use an independently random 16-byte ID and dedicated 32-byte key."""

@final
class PrefixWindow:
    """Whole seconds per slot and permitted verifier clock skew."""

    def __init__(
        self, slot_seconds: int, *, skew: int = 0, skew_limit: int | None = None
    ) -> None:
        """Set the slot length and its skew bound."""
    @property
    def slot_seconds(self) -> int:
        """The slot length in whole seconds."""
    @property
    def skew(self) -> int:
        """Maximum clock difference in slots."""

@final
class MemoryPrefixStore:
    """In-process ticket authority. Retire the old domain after state loss."""

    def __init__(
        self,
        generations: Iterable[PrefixGeneration],
        *,
        window: PrefixWindow,
        capacity: int = 0,
    ) -> None:
        """Create an authority. Zero capacity selects the default."""
    def add_ticket(self, ticket: PrefixTicket) -> None:
        """Install a fresh ticket ID."""
    def revoke_ticket(self, id: bytes) -> None:
        """Revoke the ID and remember its tombstone."""
    def set_generations(self, generations: Iterable[PrefixGeneration]) -> None:
        """Publish a new schedule and invalidate the previous revision."""
    def expire(self, unix_seconds: int) -> None:
        """Retire expired claims and tickets at the given Unix time."""

@final
class PrefixDeadline:
    """Deadline and cancellation indicator for one authority operation."""

    @property
    def deadline(self) -> float | None:
        """Deadline on the monotonic clock, if set."""
    @property
    def ended(self) -> bool:
        """Whether the operation was cancelled or reached its deadline."""

@final
class PrefixAuth:
    """A client's ticket presenter, provisioned with a ticket and outer schedule."""

    def __init__(
        self,
        ticket: PrefixTicket,
        *,
        schedule: PrefixSchedule,
        slot_seconds: int,
        binding: _t.PrefixBinding
        | Literal["bound", "encrypted", "allow_cleartext"] = "bound",
        header: str | None = None,
    ) -> None:
        """Configure the same slot, binding and header policy as the verifier."""
    @property
    def binding(self) -> _t.PrefixBinding:
        """The carrier binding policy."""
    @property
    def header_name(self) -> str:
        """The field name used on head-admitted carriers."""
    def prefix(self, info: CarrierInfo) -> bytes:
        """Generate a fresh binary presentation for the carrier."""
    def header(self, info: CarrierInfo) -> tuple[str, str]:
        """Generate the field name and a fresh canonical base64url presentation."""
    def _fixture_token(self, unix_seconds: int, *, nonce: bytes) -> bytes:
        """Produces the unbound presentation for the given fixture time and nonce."""

type _CarrierCredential = PrefixAuth | _t.CarrierCredential

async def dial_tcp(
    host: _Host, port: int, *, carrier_credential: _CarrierCredential | None = None
) -> PipeIo:
    """A pipe input on a new TCP connection to `host` and `port`; with
    `carrier_credential`, its prefix is sent first (given no exporter)."""

async def dial_tls(
    host: _Host,
    port: int,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _CarrierCredential | None = None,
    timeout: float = DIAL_TIMEOUT,
) -> PipeIo:
    """A pipe input on TLS over TCP; `server_name` defaults to `host`.
    With `carrier_credential`, its prefix is sent after the handshake. Without ALPN
    identifiers in `tls`, zmux's are offered. `timeout` (seconds, positive)
    bounds the dial, from the TCP connect to the prefix written: past it
    the dial fails with `ConnectError`."""

async def dial_quic(
    host: _Host,
    port: int,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _CarrierCredential | None = None,
    timeout: float = DIAL_TIMEOUT,
) -> PipeIo:
    """A pipe input on a new QUIC connection using up to `lanes` QUIC
    streams. With `carrier_credential`, its prefix is the first stream's
    first bytes. `timeout` (seconds, positive) bounds the dial: past it
    the dial fails with `ConnectError`."""

async def dial_websocket(
    url: str,
    *,
    tls: TlsConfig | None = None,
    headers: _Headers | None = None,
    carrier_credential: _CarrierCredential | None = None,
    no_subprotocol: bool = False,
    timeout: float = DIAL_TIMEOUT,
) -> PipeIo:
    """A pipe input on a WebSocket (`ws://` or `wss://`); `headers` go on the upgrade
    request, with the carrier credential's header field (given the TLS exporter with `wss://`).
    With `no_subprotocol` the request offers no subprotocol, so the carrier has
    no application protocol identifier; the server must allow it
    (`serve_http(websocket_no_subprotocol=True)`). `timeout` (seconds,
    positive) bounds the dial, from the TCP connect to the upgrade's
    response, redirects included: past it the dial fails with
    `ConnectError`."""

async def dial_streaming(
    host: _Host,
    port: int,
    *,
    path: str | None = None,
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
    host: _Host,
    port: int,
    *,
    path: str | None = None,
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
    host: _Host,
    port: int,
    *,
    path: str | None = None,
    carrier_credential: _CarrierCredential | None = None,
    pair_field: str | None = None,
    options: PipeOptions | None = None,
) -> list[Pipe]:
    """Joins a split carrier over two HTTP/1.1 connections to `session`: one
    join across a POST and a GET paired by a token, one further pipe of the
    two directions, `options` choosing its direction; returns `[pipe]` as
    `add_pipe` does. A split bootstrap's carrier
    (`dial_split`) joins no session: `add_pipe` refuses it with
    `PipeError`."""

@final
class Candidate:
    """A controller candidate. Each constructor is named
    after the `dial_*` function that opens the same carrier. Carrier
    credentials go on the candidate; the exchange authenticates with its
    options' PSK."""

    @staticmethod
    def streaming(
        host: _Host,
        port: int,
        *,
        path: str | None = None,
        carrier_credential: _CarrierCredential | None = None,
        pair_field: str | None = None,
    ) -> Candidate:
        """A bidirectional streaming POST over HTTP/1.1 (kind `streaming`, as
        `dial_streaming`)."""
    @staticmethod
    def split(
        host: _Host,
        port: int,
        *,
        path: str | None = None,
        carrier_credential: _CarrierCredential | None = None,
        pair_field: str | None = None,
    ) -> Candidate:
        """A split bootstrap (kind `split`, as `dial_split`); as a
        further pipe, a downlink and an uplink. Its halves are paired by the
        request field `pair_field` (default `Zmux-Pipe-Pair`)."""
    @staticmethod
    def exchange(
        host: _Host, port: int, *, options: ExchangeOptions | None = None
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
        host: _Host,
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
        addr: _HostPort | None = None,
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
    @staticmethod
    def custom(
        kind: _t.CarrierKind | str,
        *,
        layout: Iterable[_t.AttachmentSpec],
        open: Callable[
            [_t.OpenRequest], Iterable[PipeIo] | Awaitable[Iterable[PipeIo]]
        ],
    ) -> Candidate:
        """Registers a host opener and its exact Join carrier layout."""
    def with_identity(self, id: str, *, cache_key: str) -> Candidate:
        """Registers this candidate's identity and the host's cache key."""
    def join_only(self) -> Candidate:
        """Makes this candidate available for Join only."""
    def with_preference(self, tier: int, *, standby: bool = False) -> Candidate:
        """Sets the candidate's tier and standby preference."""
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
class CarrierReportSource:
    """Authority to report sequenced observations for one cache key."""

@final
class WallClock:
    """An application-controlled UTC clock for anchoring carrier snapshots."""

    def __init__(self, timestamp_ns: int) -> None:
        """Starts at a signed Unix timestamp in nanoseconds."""
    def set(self, timestamp_ns: int) -> None:
        """Sets the timestamp, which may move backward."""
    @property
    def timestamp_ns(self) -> int:
        """Current signed Unix timestamp in nanoseconds."""

@final
class CarrierCache:
    """Shared scoring history and retry admission for carrier candidates."""

    def __init__(
        self,
        *,
        half_life: float | None = None,
        drop_window: float | None = None,
        performance_window: float | None = None,
        health_reset: float | None = None,
        backoff: _t.Backoff | None = None,
        retry_profile: _t.CarrierRetryProfile | None = None,
        kind_priors: dict[_t.CarrierKind | str, float] | None = None,
        import_limit: int | None = None,
        max_age: float | None = None,
        min_weight: float = 0.0,
        clock_domain: ClockDomain | None = None,
        wall_clock: WallClock | None = None,
    ) -> None:
        """Creates an empty cache with optional scoring and retry settings.

        A retry profile supplies its own settings in place of `backoff`.
        """
    def retry_metrics(
        self, key: str, *, kind: _t.CarrierKind | str, variant: str = ""
    ) -> _t.RetryMetrics:
        """Read candidate retry pacing and suppression counters."""
    def score(
        self, key: str, *, kind: _t.CarrierKind | str, variant: str = ""
    ) -> _t.CarrierScore:
        """Reads the current score, evidence and cooldown for a key."""
    def register_report_source(
        self,
        key: str,
        *,
        kind: _t.CarrierKind | str,
        variant: str = "",
    ) -> CarrierReportSource:
        """Registers an independent sequence space for observations."""
    def report(
        self,
        source: CarrierReportSource,
        *,
        sequence: int,
        outcome: _t.CacheOutcome | str,
        observation: _t.CarrierObservation | None = None,
    ) -> bool:
        """Applies a sequenced observation. Returns whether it was new."""
    def export(self) -> bytes:
        """Exports a versioned UTF-8 JSON snapshot."""
    def import_snapshot(self, snapshot: bytes) -> None:
        """Validates and atomically merges a v2 snapshot."""

@final
class ClockDomain:
    """A shared monotonic clock identity for sessions, controllers and caches."""

    def __init__(self) -> None:
        """Creates a distinct domain using the native monotonic clock."""
    def now(self) -> float:
        """Returns current time in seconds on the domain's monotonic clock."""

@final
class AccountingTicket:
    """An independently awaitable handle to final record accounting."""

    def __await__(self) -> Generator[Any, None, _t.PipeAccounting]:
        """Awaits the final totals without consuming them."""
    async def wait(self) -> _t.PipeAccounting:
        """Waits for final totals without consuming them or changing other waits."""

@final
class AccountingTickets:
    """An application-owned collection of tickets published at attachment handoff."""

    def __init__(self) -> None:
        """Creates an empty collection for use in a session or listener configuration."""
    def take(
        self, session: _t.SessionId, *, pipe: _t.PipeId
    ) -> AccountingTicket | None:
        """Takes the named ticket once, including after the pipe retires."""
    def drain(self) -> tuple[tuple[_t.SessionId, _t.PipeId, AccountingTicket], ...]:
        """Takes every published ticket, including retired attachments."""

@final
class Attempt:
    """Observation and cancellation of one carrier opening and confirmation."""

    def snapshot(self) -> _t.AttemptSnapshot:
        """Reads progress and the retained terminal result, if available."""
    async def wait(self) -> _t.AttemptResult:
        """Waits for the terminal result. Cancelling the wait leaves the attempt running."""
    def cancel(self) -> None:
        """Requests cancellation before ownership of the carriers has committed."""

@final
class CapacityChange:
    """An admitted batch of member additions and retirements."""

    def start_member(
        self,
        index: int,
        *,
        open: Callable[
            [_t.OpenRequest], Iterable[PipeIo] | Awaitable[Iterable[PipeIo]]
        ],
    ) -> Attempt:
        """Starts one reserved member's opener on the calling event loop."""
    def commit(self) -> _t.ChangeResult:
        """Commits confirmed additions and drains replaced members after the native checks."""
    def cancel(self) -> None:
        """Cancels a batch that has not committed."""

@final
class SessionController:
    """Owns a domain's carrier registrations, ranking and work bounds."""

    def __init__(
        self,
        domain: str,
        *,
        candidates: Iterable[Candidate],
        choice: Literal["static", "d160"] = "static",
        cache: CarrierCache | None = None,
        concurrent_openers: int | None = None,
        attempt_timeout: float | None = None,
        clock_domain: ClockDomain | None = None,
    ) -> None:
        """Registers candidates and retry policy for one controller domain."""
    async def open(
        self, target: _t.SessionTarget, *, config: _t.Config | None = None
    ) -> tuple[Session, SessionControl | None]:
        """Establishes a session. For an empty target, control is None when
        the client and peer did not negotiate multipath."""
    def manage(
        self,
        session: Session,
        *,
        target: _t.SessionTarget,
        bootstrap: str | None = None,
    ) -> SessionControl:
        """Takes ownership of convergence for an established session."""
    def take_over(
        self,
        previous: SessionControl,
        *,
        target: _t.SessionTarget,
        bootstrap: str | None = None,
    ) -> SessionControl:
        """Replace the exact current binding while retaining the session."""
    def close(self) -> None:
        """Requests shutdown of the controller and its bindings."""
    async def done(self) -> None:
        """Waits for the controller and all its bindings to stop."""

@final
class QualityEvidence:
    """An original path observation a replacement depends on."""

    @property
    def sampled_at(self) -> float:
        """Original observation time in monotonic seconds."""
    @property
    def valid_until(self) -> float | None:
        """Exclusive expiration in monotonic seconds, if the measurement expires."""

@final
class ControllerPath:
    """A path observation captured with the controller's member table."""

    @property
    def member(self) -> int | None:
        """The member that owns this attachment, if any."""
    @property
    def stats(self) -> _t.PipeStats:
        """The captured statistics and directional health."""
    def evidence(
        self,
        measurement: Literal[
            "health", "current_rtt", "baseline_rtt", "delivery", "loss"
        ] = "health",
        *,
        direction: _t.PipeHalf | Literal["Inbound", "Outbound"] = "Outbound",
    ) -> QualityEvidence:
        """Retains an observation and its original validity for a replacement.
        Raises ValueError if the snapshot lacks the selected evidence."""

@final
class SessionControl:
    """Control and progress for one managed session."""

    def set_target(self, target: _t.SessionTarget) -> None:
        """Installs a new target, or accepts the identical current revision."""
    def snapshot(self) -> _t.ControllerSnapshot:
        """Reads the latest committed controller plan and its coverage observation."""
    def release(self) -> None:
        """Release this binding and preserve confirmed coverage."""
    async def done(self) -> None:
        """Waits for the controller binding to stop."""

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
    host: _Host,
    port: int,
    *,
    options: ExchangeOptions | None = None,
    down_addr: _HostPort | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _CarrierCredential | None = None,
) -> PipeIo:
    """A pipe input on the HTTP exchange carrier (kind `exchange`): plain
    HTTP/1.1 POST requests to `host` and `port`, DOWN requests to
    `down_addr`, a `(host, port)`, when given, over TLS with `tls`; with `carrier_credential`,
    its prefix starts the uplink, for a server's admission. Returns without
    a round trip."""

@final
class Http3Connection:
    """One host-owned HTTP/3 connection for multiple request pipes."""

    @staticmethod
    async def dial(
        url: str,
        *,
        tls: TlsConfig | None = None,
        addr: tuple[_Host, int] | None = None,
        lanes: int = DEFAULT_LANES,
        carrier_credential: _CarrierCredential | None = None,
        timeout: float = DIAL_TIMEOUT,
    ) -> Http3Connection:
        """Establishes a QUIC connection and binds it to the URL's HTTPS authority."""
    async def open_pipe(self) -> PipeIo:
        """Opens another request on the shared connection."""
    @property
    def http_datagrams(self) -> bool:
        """Whether HTTP/3 and the QUIC transport negotiated native datagrams."""
    def close(self) -> None:
        """Closes the shared QUIC connection and its requests."""

async def dial_http3(
    url: str,
    *,
    tls: TlsConfig | None = None,
    addr: _HostPort | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _CarrierCredential | None = None,
    timeout: float = DIAL_TIMEOUT,
) -> PipeIo:
    """A pipe input on an HTTP/3 request to `url` (`https://`; kind
    `http3`), sent to `addr`, a `(host, port)`, when given. With `carrier_credential`, its
    prefix is the first bytes of every request body. `timeout` (seconds,
    positive) bounds the dial: past it the dial fails with
    `ConnectError`."""

async def dial_webtransport(
    url: str,
    *,
    tls: TlsConfig | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _CarrierCredential | None = None,
    timeout: float = DIAL_TIMEOUT,
) -> PipeIo:
    """A pipe input on a new WebTransport session to `url` (`https://`; kind
    `webtransport`); the carrier credential's header field goes on the
    session request. `timeout` (seconds, positive) bounds the dial, the
    QUIC handshake included: past it the dial fails with `ConnectError`."""

@final
class Http2Connection:
    """An HTTP/2 connection whose requests carry pipes: prior knowledge
    without `tls`, ALPN `h2` with it. Dial several pipe inputs on one
    connection. Over TLS 1.3 its bidirectional requests are secure carriers
    with the connection's exporter, the same for every request."""

    @staticmethod
    async def dial(
        host: _Host,
        port: int,
        *,
        path: str | None = None,
        tls: TlsConfig | None = None,
        server_name: str | None = None,
        carrier_credential: _CarrierCredential | None = None,
        pair_field: str | None = None,
    ) -> Http2Connection:
        """A shared HTTP/2 carrier connection. Ticket credentials use a
        binary prefix on a request body and the header form on a downlink."""

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
class QuicConnection:
    """An established QUIC connection shared by pipes and owned by its handle."""

    async def open_pipe(self) -> PipeIo:
        """Opens a zmux pipe. Closing the pipe leaves this connection open."""
    def close(self) -> None:
        """Closes this connection and its pipes. Dropping the handle also closes it."""

@final
class QuicServer:
    """A QUIC endpoint whose connections the application admits individually."""

    @staticmethod
    async def bind(
        host: _Host, *, port: int = 0, tls: TlsConfig, lanes: int = DEFAULT_LANES
    ) -> QuicServer:
        """Binds a QUIC endpoint for established connections."""
    @property
    def local_addr(self) -> tuple[str, int]:
        """The bound address and port."""
    async def accept(self, listener: Listener) -> QuicService | None:
        """Accepts one established connection and starts its listener service.
        Returns `None` if the listener refuses the connection at its limits."""
    def close(self) -> None:
        """Closes the endpoint and its connections."""

@final
class QuicService:
    """Admission and teardown of one QUIC connection on a listener."""

    def stop_admission(self) -> None:
        """Stops pipe admission and cancels setups still owned by the service.
        Handed-off pipes and their lanes continue. Dropping the handle also stops admission."""
    async def wait(self) -> None:
        """Waits for the service's pipe and lane receivers to finish.
        Cancelling the wait leaves the service running."""

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
        bind: _HostPort = ("0.0.0.0", 0),
        carrier_credential: _CarrierCredential | None = None,
    ) -> None:
        """`memory_capacity` bounds the servers remembered (`None`: no
        bound); `bind` is the local `(host, port)`. With `carrier_credential`, its prefix is the first stream's
        first bytes and no 0-RTT data is sent."""
    async def dial(
        self, host: _Host, port: int, *, server_name: str | None = None
    ) -> PipeIo:
        """A pipe input on a new connection."""
    async def open_connection(
        self, host: _Host, port: int, *, server_name: str | None = None
    ) -> QuicConnection:
        """Establishes a connection to reuse for zmux pipes."""
    async def connect(
        self,
        host: _Host,
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
    concurrent call raises `StreamBusyError`; `id` and `stats` read on
    while an operation is in progress. The runtime settings `priority`,
    `send_buffer`, `scheduler` and `redundant` are writable properties; each
    reads back the value the part holds (the last assigned, or for
    `priority` the peer's adjustment if it came later), `None` for a setting
    that follows the session. A reading never fails and never waits: it
    answers while a write, a flush or a wait holds the part, and after the
    stream ended with the value held last. An assignment does not take the
    part either: it works while a write, a flush or a wait is in progress, and
    fails only as the stream does (`StreamClosedError`)."""

    def send_datagram_with(
        self,
        payload: Buffer,
        *,
        options: _t.DatagramSendOptions,
        context: int = 0,
    ) -> None:
        """Admits a flow datagram with local send options."""
    def datagram_path(self, *, context: int = 0) -> _t.DatagramPath:
        """Reads the flow's original-copy and native payload limits during any write."""
    def set_datagram_options(self, options: _t.DatagramSendOptions) -> None:
        """Sets the default local datagram options for the flow."""

    @property
    def id(self) -> int | None:
        """The stream ID; `None` until the stream is opened on the wire."""
    @property
    def priority(self) -> Priority:
        """The local scheduling priority (urgency 0..7, lower first);
        assigning a `Priority` or `(urgency, incremental)` changes it. A new
        sending part holds `Priority.LOCAL_DEFAULT`."""
    @priority.setter
    def priority(self, priority: _Prio) -> None: ...
    async def write(self, data: Buffer) -> None:
        """Writes all of `data`, any buffer-protocol object, waiting for room.
        `bytes` (or a contiguous `memoryview` of `bytes`) is sent without a
        copy; any other buffer is copied when the call is made, so the caller
        may reuse it at once. Not cancellation-safe: a cancelled call may
        have taken a prefix of `data` and does not say how much, so a stream
        whose `write` was cancelled is to be reset, not written to again
        (`write_some` is the cancellation-safe write)."""
    async def write_some(self, data: Buffer) -> int:
        """Writes a prefix of `data` (copied as `write` says), waiting until
        the stream takes some, and returns the number of bytes taken (0 only
        for empty `data`). Cancellation-safe: the call only waits
        for `writable`, which takes nothing, and then writes synchronously, so
        a call that raises `CancelledError` took nothing of `data`."""
    async def writev(self, buffers: Iterable[Buffer]) -> int:
        """`write_some` over several buffers: writes a prefix of their
        concatenation (copied as `write` says) and returns the number of bytes
        taken; the same cancellation semantics."""
    def try_write(self, data: Buffer) -> int:
        """Writes as much of `data` as the stream takes now (copied as
        `write` says), without waiting: the number of bytes taken, 0 when there is
        no room (or `data` is empty); `StreamBusyError` while another
        operation holds the part. With `writable` it is the building
        block of `write_some`."""
    def try_writev(self, buffers: Iterable[Buffer]) -> int:
        """`try_write` over several buffers in order: the number of bytes
        taken."""
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
    def set_reliable_boundary(self) -> None:
        """Marks the bytes written so far as delivered even if the stream is
        reset later (RESET_STREAM_AT Reliable Size)."""
    async def writable(self) -> int:
        """Waits until `try_write` takes bytes (room in the send buffer, not
        credit) and returns how many it takes now; the stream's error once the
        part ended. Takes nothing, so a cancelled call has no effect."""
    def send_capacity(self) -> int:
        """The bytes the part could transmit now: the smaller of its stream
        and session credit, minus what it holds unsent."""
    async def wait_send_capacity(self, minimum: int) -> int:
        """The credit statistic's wait, not write readiness (see `writable`):
        waits until the send capacity is at least `minimum` (>= 1), or above 0
        while nothing is unsent, and returns it; the stream's error otherwise."""
    @property
    def send_buffer(self) -> int:
        """The written-but-unreleased bytes this part may hold: the last
        assignment, else the value the session's `Config.send_buffer` gave it
        when the stream was created (it does not follow the session after)."""
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
        flows. Never fails for a write in progress."""
    def path_datagram_size(self, context: int = 0) -> int | None:
        """The largest payload of a datagram of this stream with the
        context ID `context` that leaves as one carrier datagram instead of
        in a record (`Session.path_datagram_size` less the stream's flow),
        at most `max_datagram_size`; `None` without datagram flows."""
    def send_datagram(self, payload: Buffer, context: int = 0) -> None:
        """Sends a datagram of the stream with the context ID `context`;
        `payload` is any buffer-protocol object, copied unless it is `bytes`.
        Never waits and does not take the part: it works while a write, a
        flush or a wait is in progress."""
    def stats(self) -> StreamStats:
        """A snapshot of the stream; its final values once the session released it."""
    async def stopped(self) -> int | None:
        """Waits until the peer stops the stream (returns its code) or acknowledged all data (`None`)."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> Literal[False]: ...

@final
class RecvStream:
    """The receiving half of a stream; `async for chunk in stream` reads to the end.

    `stop(code)` asks the peer to stop sending. Cancelling a pending read
    loses no data. Leaving `async with` stops the stream with code 0 (a
    no-op once it ended; it returns at once). `async for` ends silently at the end of the stream and raises
    the stream's error otherwise. The runtime settings `receive_window` and
    `peer_priority` are writable properties and read back the value the part
    holds (`peer_priority`: `None` when none was asked); a reading never
    fails and never waits, and an assignment does not take the part: both
    work while a read is in progress. `id`, `stats`, `preamble`, `is_replayable` and
    `preamble_priority` read on while a read is in progress."""

    @property
    def id(self) -> int | None:
        """The stream ID."""
    @property
    def preamble_priority(self) -> Priority | None:
        """The PRIORITY the peer put in the stream's opening preamble
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
        without a copy. The view is empty at the end of the stream.
        `BorrowLimitError` leaves the bytes available for a copying read."""
    def _take(self, max: int, view: bool, /) -> bytes | memoryview | None: ...
    def _test_fail_read_allocation(self) -> None:
        """Makes the next read result allocation fail in the test-hooks build."""
    async def wait_readable(self) -> None:
        """Waits until the next read returns at once: data is readable, or the
        receiving part has ended (FIN, a reset, a stop by this endpoint, the
        session's end). It returns `None` in every one of these cases and
        takes nothing, so the read that follows reports the data or the end,
        once, in its own form; wait, then `try_read`. It fails only with the
        caller's own bound (`asyncio.timeout`); a cancelled call has no
        effect, and any number of tasks may wait at once."""
    def try_read(self, n: int = 65536) -> bytes | None:
        """Up to `n` bytes (at least 1) that are there now, without waiting:
        `None` when nothing is readable now, `b""` once the stream has ended
        with a FIN and everything was read. A reset, or the session's end,
        raises as a read does. `StreamBusyError` while another call holds
        the part."""
    def try_read_chunk(self, n: int = 65536) -> memoryview | None:
        """Read available bytes as a read-only view, or return None if it would wait."""
    def _put_back(self, chunks: list[bytes], /) -> None: ...
    def reject(self) -> None:
        """Declines the stream before reading it (ZMUX_REJECTED); the handle,
        and the sending one of a stream not written to, are used up."""
    @property
    def receive_window(self) -> tuple[int, int]:
        """The stream's receive window settings, `(initial, maximum)`: the
        initial window as set (or the session's), never the window
        auto-tuning has grown it to (that is `stats.recv_window`), and the
        cap on auto-tuning as set, 0 when it is automatic."""
    @receive_window.setter
    def receive_window(self, window: tuple[int, int]) -> None:
        """Assigns `(initial, maximum)`. The initial window is advertised at
        once when it is above the window in force; a maximum of 0 makes the
        cap on auto-tuning automatic, whatever the session's
        `max_stream_receive_window` is. Credit already advertised is never
        withdrawn: an initial below the window in force only changes what the
        getter reads back. An initial window below 4096 (the floor of
        `initial_stream_receive_window`) or a nonzero maximum below the
        initial window raises `InvalidArgumentError` and changes nothing."""
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
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> Literal[False]: ...

@final
class Pipe:
    """One pipe (carrier) of a multipath session. `close()` removes it
    gracefully (drain), `abort()` at once; `async with` closes it on a
    normal exit and aborts on an exception; `await wait_closed()` waits for
    its end. Watch `Session.events()` for its state changes. Its runtime
    settings change only through `update`."""

    def health(self) -> _t.PipeHealth | None:
        """Reads the committed health of both local attachment directions."""
    def observe_stability(self) -> None:
        """Requests evidence for the attachment's current stability round."""
    def accounting(self) -> AccountingTicket | None:
        """Acquires a handle to final record accounting when enabled."""

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
    def options(self) -> PipeOptions:
        """Every option as the pipe holds it: those it was added with, with each
        `update` applied, reading back exactly what an update set or cleared.
        A setting that follows the session, or is unset, reads as `INHERIT`;
        `direction`, `record_mode`, `key_group`, `label` and `fate_group` read
        as the pipe has them (the record mode and key group the join used),
        as given. A pipe the peer added reads as
        the join made it (`direction` from this endpoint's view, `record_mode`,
        `key_group`), the rest as `PipeOptions()` has it until an update sets
        it. The values in effect, which may follow the peer's request, are in
        `stats()`. It never fails: after the pipe ended it returns the options
        held last."""
    @property
    def state(self) -> OutboundState | InboundState | str | None:
        """The outbound direction's state (else the inbound one's); `None`
        once the pipe is retired or the session released it."""
    @property
    def session(self) -> Session:
        """The `Session` object the pipe was given by, always the same one."""
    async def joined(self) -> None:
        """Waits until the peer confirmed the join; `PipeError` if it failed."""
    async def wait_attached(self) -> None:
        """Waits until the peer attached the pipe, so that it carries the
        session even if every other pipe goes: pipe 0 once established, a
        pipe the peer joined at once, one of this endpoint's joins once
        `joined()` returned and the peer acknowledged a byte of it (an
        inbound-only pipe: once a record arrived). `PipeError` if the join
        failed or the pipe ended first; bound it with `asyncio.timeout`."""
    async def wait_closed(self) -> None:
        """Waits until the pipe ended: returns once every direction closed
        (or the session released it); `PipeError` if it failed or the
        session ended first. Completion also waits for release of the carrier,
        its lanes and its workers, including a stream bridge and its transport.
        The end is stable: a wait that starts after the
        pipe retired reports the same end as one registered before (after
        `abort()`, `PipeAbortedError`)."""
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
        quality_band: QualityBand | _t.Clear | None = ...,
    ) -> None:
        """Changes these settings together (both receive fields: one
        PIPE_STATUS). A keyword left out keeps its value; `zmux.CLEAR`
        clears it (the `send_*` fields then follow the peer's request, the
        `receive_*` fields request the default again, `weight` is 1,
        `probation`, `liveness` and `quality_band` follow the session's); a
        value sets it (`probation=None` turns probation off, `quality_band=None`
        turns the quality reports of this pipe off whatever the session's band
        is). A field fixed when the pipe
        is added or an unknown name raises `TypeError`; an invalid value
        raises `ValueError` and changes nothing. Nothing is sent for
        `liveness`."""
    def close(self) -> None:
        """Removes the pipe gracefully: PIPE_ABANDON and drain."""
    def abort(self) -> None:
        """Removes the pipe at once: its data is reinjected elsewhere."""
    def stats(self) -> PipeStats | None:
        """A snapshot, including the cached carrier sample. Reads never wait
        for a native statistics refresh. Receive-only pipes and carriers without a
        connection identity have no carrier sample. Returns `None` once retired or released."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> Literal[False]: ...

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

    def _test_revision(self) -> _TestRevision:
        """Subscribes to owner commits in the test-hooks build."""
    def _test_read_loan_slots(self, slots: int) -> None:
        """Sets the borrow slot limit before the first loan in the test-hooks build."""
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
    def capacity(self) -> _t.CapacitySnapshot:
        """Reads local occupancy and directional coverage in one snapshot."""
    async def capacity_changed(self, observed: int) -> _t.CapacitySnapshot:
        """Waits for capacity to change after the observation watermark."""
    def members(self) -> tuple[_t.MemberSnapshot, ...]:
        """Returns the members currently indexed by the session."""
    def member_for_pipe(self, pipe: int) -> int | None:
        """Looks up the member owning an indexed attachment."""
    def set_session_policy(self, policy: _t.SessionPolicy) -> None:
        """Installs a newer local capacity and authenticated Join policy."""
    def begin_change(self, request: _t.ChangeRequest) -> CapacityChange:
        """Reserves capacity for additions and retirements immediately."""
    async def queue_change(self, request: _t.ChangeRequest) -> CapacityChange:
        """Waits for admission. Cancelling the wait withdraws the request."""
    def subscribe_pipe_health(self) -> None:
        """Starts buffering directional service transitions with their evidence."""
    def send_datagram_with(
        self, data: Buffer, *, options: _t.DatagramSendOptions
    ) -> None:
        """Admits one session datagram with local send options."""
    def datagram_path(self) -> _t.DatagramPath:
        """Reads currently eligible original-copy and native payload limits."""
    def datagram_stats(self) -> _t.DatagramStats:
        """Reads the Rust scheduler's additional outcome counters."""
    def datagram_feedback(
        self, pipe: int, *, native: bool
    ) -> _t.DatagramFeedback | None:
        """Reads DATAGRAM_ACK feedback for an outbound attachment and carrier mode."""

    def datagram_arrivals(
        self, pipe: int, *, native: bool
    ) -> _t.DatagramArrivals | None:
        """Reads reportable arrivals for one inbound attachment and carrier mode."""

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
        default): no reports. A pipe can follow it, have a band of its own
        or be off (`PipeOptions.quality_band`)."""
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
        """Waits for unidirectional stream credit with `info` and `tlvs`
        fixed for the first frame. Cancellation withdraws the opener."""
    def try_open_uni(
        self,
        *,
        info: bytes | None = None,
        tlvs: list[Tlv] | list[tuple[int, bytes]] | None = None,
        priority: _Prio | None = None,
    ) -> SendStream:
        """Opens a unidirectional stream if stream credit is available now;
        `StreamError` of kind `Blocked` (retryable) otherwise. Never waits."""
    async def accept_bi(self) -> BiStream:
        """The next bidirectional stream the peer opened;
        `SessionClosedError` once the session ended."""
    async def accept_uni(self) -> RecvStream:
        """The next unidirectional stream the peer opened."""
    def send_datagram(self, data: Buffer) -> None:
        """Queues an unreliable datagram (copied unless it is `bytes`); never waits. At capacity, the oldest queued original makes room. If native carrier
        outcomes hold every slot, the new original raises `DatagramDroppedError`.
        Raises `DatagramError` if datagrams are not
        negotiated or `data` exceeds `max_datagram_size`."""
    async def send_datagram_wait(self, data: Buffer) -> None:
        """Queues a datagram, any buffer-protocol object (copied unless it is
        `bytes`), waiting for a free slot in the send queue; the
        same errors as `send_datagram`. Cancellation-safe: cancelled while
        it waits, it queued nothing (a cancellation that lands as it
        completes cannot take the datagram back)."""
    async def read_datagram(self) -> bytes:
        """The next received datagram; `SessionClosedError` once the session
        ended."""
    def datagrams(self) -> DatagramStream:
        """Received datagrams as an async iterator over the queue
        `read_datagram` reads: each datagram goes to one reader."""
    @property
    def max_datagram_size(self) -> int | None:
        """The largest datagram payload; `None` without datagram support."""
    @property
    def path_datagram_size(self) -> int | None:
        """The largest datagram payload that leaves as one datagram of the
        carrier instead of in a record: on a carrier with a datagram channel
        (QUIC, HTTP/3, WebTransport) what one of its datagrams takes as the
        carrier last reported it, path MTU discovery included; elsewhere
        `max_datagram_size`. A packet forwarder uses it as its MTU;
        `DatagramPathChanged` reports changes. `None` without datagram
        support."""
    def close(self, code: int = 0, reason: bytes = b"") -> None:
        """Starts the graceful close with the application error `code` and
        `reason` (the defaults: a close without error; a reason above 1024
        bytes is cut to at most 1024, never inside a UTF-8 character) and returns without
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
        `reason` (cut to 1024 bytes as in `close`), draining nothing: unsent data is discarded and
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
    def shaping_stats(self) -> _t.ShapingStats:
        """Shaping counters: wire_spent, stall_spent (s), clamped, injected, inject_dropped, faults, handshake_unplanned."""
    async def add_pipe(
        self, pipe: PipeIo, *, options: PipeOptions | None = None
    ) -> Pipe:
        """Adds a carrier and returns after the peer confirms its attachment.
        Cancelling before commit releases the carrier."""
    def revalidate_pipes(self) -> None:
        """Probes every live outbound pipe again, for example after a network change."""
    def advance_epoch(self) -> None:
        """Starts a session epoch exchange as soon as this end is stable: the session
        secret, the join keys and the Session Locators advance. Never waits;
        `EpochCommitted` and `EpochDeleted` report it. A session without multipath
        raises `PipeError`."""
    def pipes(self) -> list[Pipe]:
        """The session's pipes."""
    def pipe_stats(self) -> list[PipeStats]:
        """A snapshot of every pipe, with cached connection statistics."""
    @property
    def zero_rtt(self) -> ZeroRtt | None:
        """For sessions from `QuicClient.connect`: what became of the 0-RTT data."""
    @property
    def id(self) -> _t.SessionId:
        """The session's identifier in this process (unique while it runs,
        never reused): the one `Tracer` methods are given."""
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
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> Literal[False]: ...
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

    def _test_revision(self) -> _TestRevision:
        """Subscribes to counter commits in the test-hooks build."""
    def __init__(
        self,
        *,
        config: _t.Config | None = None,
        listener_config: _t.ListenerConfig | None = None,
    ) -> None: ...
    async def serve_tcp(self, host: _Host, port: int) -> tuple[str, int]:
        """Serves plain TCP on `host` and `port`; returns the bound address.
        With the listener's `admission`, a connection reaches it only once
        admitted."""
    async def serve_tls(
        self, host: _Host, port: int, *, tls: TlsConfig
    ) -> tuple[str, int]:
        """Without ALPN identifiers in `tls`, zmux's are accepted. The
        admission decides after the handshake, with its exporter."""
    async def serve_quic(
        self,
        host: _Host,
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
        self, host: _Host, port: int, *, tls: TlsConfig, lanes: int = DEFAULT_LANES
    ) -> tuple[str, int]:
        """With the listener's `admission`, each request is decided on the
        first bytes of its body."""
    async def serve_webtransport(
        self, host: _Host, port: int, *, tls: TlsConfig, lanes: int = DEFAULT_LANES
    ) -> tuple[str, int]:
        """With the listener's `admission`, each session request is decided
        on its request head (no prefix), with the QUIC connection's exporter."""
    async def serve_websocket(
        self, host: _Host, port: int, *, tls: TlsConfig | None = None
    ) -> tuple[str, int]:
        """With the listener's `admission`, each upgrade is decided on its
        request head (no prefix), with the TLS exporter under `tls`."""
    async def serve_http(
        self,
        host: _Host,
        port: int,
        *,
        path: str | None = None,
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
        peer: _HostPort | None = None,
        source: _HostPort | None = None,
    ) -> None:
        """Hands over a carrier the application accepted itself: `peer` is its
        directly connected peer, `source` the client the application resolved
        (unset, the peer; the peer unset, `127.0.0.1:0`). It takes a source
        slot and goes through the listener's admission, joins and
        resumptions too. Ownership transfers on entry. Returns once the session
        is queued or the join or lane attaches. Cancellation wins only before
        commit. A committed result is delivered even if the task cancels before delivery.
        The session owns the carrier after handoff. A dispatched fallback owns
        its callback interval even when this awaiter is cancelled. A normal
        fallback return completes setup successfully. A callback exception,
        a stall, or an admission close raises `ConnectError`."""
    def drain(self, reason: bytes) -> None:
        """Refuse subsequent bootstraps with these reason bytes."""
    def undrain(self) -> None:
        """Accept new sessions again unless shutdown has begun."""
    async def shutdown(self, code: int = 0, reason: bytes = b"") -> None:
        """Closes gracefully: new sessions are refused at once while joins
        and resumptions of the live sessions are still taken; every session
        is shut down with `code` and `reason`, and once they all ended the
        listener closes. Cancelled (a timeout), it closes at once."""
    async def accept(self) -> Session:
        """The next established session; `ListenerClosedError` once closed."""
    def close(self) -> None:
        """Closes at once: everything new is refused, joins and resumptions
        included, and the `serve_*` loops end. Accepted sessions retain their
        attached carriers."""
    def variant_stats(self) -> _t.AdmissionVariants:
        """The admission's verdicts on the carriers it labelled, per label."""
    def stats(self) -> ListenerStats:
        """What happened to the carriers handed to the listener: counts since it was made."""
    def limits(self) -> ListenerLimits:
        """The limits in effect."""
    def set_limits(self, limits: ListenerLimits, /) -> None:
        """Replaces the listener's limits; invalid ones raise
        `InvalidArgumentError` and change nothing. New carriers and the next
        decisions on held ones use them at once: lowered pending bounds
        refuse or displace new carriers but close none already held, a
        lowered `max_pending_per_session` applies to the next join, a
        lowered `max_suspended` closes the longest-suspended sessions beyond
        it, a changed `first_record_timeout` applies to carriers that
        arrive after the call, and a changed `memory_budget` applies at once,
        as if the sum crossed it."""
    async def __aenter__(self) -> Self: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> Literal[False]: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> Session: ...

def stream_pipe(send: SendStream, recv: RecvStream) -> PipeIo:
    """A bidirectional stream as a pipe input: one that carries
    PIPE_CARRIER, or any the application knows to be a carrier. The two
    handles are used up."""

def _splice_start(
    a: tuple[SendStream, RecvStream],
    b: tuple[SendStream, RecvStream],
    *,
    packets: bool,
    controlled: bool,
    chunk: int | None = None,
    a_to_b: Limiter | None = None,
    b_to_a: Limiter | None = None,
    abort: SpliceAbort | None = None,
    a_to_b_datagrams: _t.DatagramSendOptions | None = None,
    b_to_a_datagrams: _t.DatagramSendOptions | None = None,
    a_to_b_hooks: _t.SpliceHooks | None = None,
    b_to_a_hooks: _t.SpliceHooks | None = None,
    a_to_b_label: str = "",
    b_to_a_label: str = "",
    a_to_b_mirror: SpliceMirror | None = None,
    b_to_a_mirror: SpliceMirror | None = None,
    limits: _t.SpliceLimits | None = None,
    max_packet_payload: int | None = None,
    max_opaque_value: int | None = None,
    on_event: Callable[[_t.SpliceEvent], None] | None = None,
) -> tuple[SpliceController | None, Coroutine[Any, Any, SpliceResult]]:
    """Transfer the streams into the native relay and return its driver."""

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
class SpliceSignal:
    """A one-shot readiness signal shared by a hook and its resumer."""

    def __init__(self) -> None: ...
    def resume(self) -> None:
        """Set the signal, including before the relay begins waiting."""

@final
class SpliceDecision:
    """An immutable decision for the current hook's group."""

    @staticmethod
    def pass_(
        *,
        delay: float | None = None,
        timeout: float | None = None,
        resume: SpliceSignal | None = None,
    ) -> SpliceDecision:
        """Keep the group. Delay and timeout are seconds from the decision."""

    @staticmethod
    def replace(
        *,
        delay: float | None = None,
        timeout: float | None = None,
        resume: SpliceSignal | None = None,
    ) -> SpliceDecision:
        """Use the outputs built by the step, or drop if it built none."""

    @staticmethod
    def drop() -> SpliceDecision:
        """Discard the current group."""

    @staticmethod
    def reset(code: int) -> SpliceDecision:
        """Reset the target and stop the source, including with code zero."""

@final
class SpliceUnit:
    """Scoped payload reader and bounded replacement builder."""

    @property
    def meta(self) -> _t.SpliceMeta:
        """Immutable metadata that can be retained after the hook returns."""

    def __len__(self) -> int:
        """Return the number of items seen by this step."""

    def size(self, item: int = 0) -> int:
        """Return one item's payload size."""

    def byte_at(self, offset: int, *, item: int = 0) -> int:
        """Read one byte of an item by index without copying the payload."""

    def read(self, item: int = 0) -> bytes:
        """Copy one item to independent Python bytes."""

    def append_slice(
        self,
        start: int = 0,
        *,
        stop: int | None = None,
        item: int = 0,
    ) -> None:
        """Build one output sharing the selected immutable input bytes."""

    def append(self, data: bytes) -> None:
        """Build one output from immutable Python bytes."""

@final
class SpliceMirror:
    """Single-direction, bounded diagnostic tap."""

    def __init__(
        self,
        items: int,
        *,
        prefix: int = 0,
        mode: Literal["copy", "lease"] = "copy",
        backing_bytes: int | None = None,
    ) -> None:
        """Reserve a queue of copied or shared prefixes. Lease mode requires a backing limit."""

    async def recv(self) -> _t.SpliceSample | None:
        """Receive a sample, or None after the mirror closes."""

@final
class SpliceReceipt:
    """An admitted injection and its eventual local target disposition."""

    @property
    def sequence(self) -> int:
        """The direction-local input sequence."""

    @property
    def generation(self) -> int:
        """The hook generation used by this injection."""

    async def disposition(self) -> _t.SpliceDisposition:
        """Wait for the target disposition. A cancelled wait may be retried."""

@final
class SplicePause:
    """Owns one pause generation. Dropping the token also releases the pause."""

    @property
    def generation(self) -> int:
        """The direction-local pause generation."""

    async def acknowledged(self) -> None:
        """Wait for a safe output boundary. This wait can be retried."""

@final
class SpliceHandoffs:
    """Live settlement of bytes accepted by a splice direction."""

    def snapshot(self) -> _t.SpliceHandoffStats:
        """Read a consistent snapshot of local carrier handoffs and refunds."""

@final
class SpliceControl:
    """The ordered command channel of one controlled splice direction."""

    @property
    def handoffs(self) -> SpliceHandoffs:
        """Observe local carrier settlement during and after the direction."""

    @property
    def pre_admission_refunded_bytes(self) -> int:
        """Bytes the relay refunded before target acceptance, including late grants."""

    async def replace_hooks(self, chain: _t.SpliceHooks) -> int:
        """Install a new chain at an admission boundary and return its generation.

        A committed replacement remains installed after cancellation.
        """

    async def pause(self) -> SplicePause:
        """Request a pause and return the token that owns it."""

    async def resume(self, pause: SplicePause) -> None:
        """Resume using the current direction's pause token.

        A committed resume stays in effect after cancellation.
        """

    async def inject(
        self,
        payload: Buffer,
        *,
        kind: _t.SpliceKind = "stream",
        capsule_type: int | None = None,
        context: int | None = None,
    ) -> SpliceReceipt:
        """Admit an input to the current chain and return its local receipt.

        Once admitted, the input can be forwarded even if the awaiter is cancelled.
        """

    async def finished(self) -> tuple[_t.SpliceEnd, int | None]:
        """Wait for this direction's reliable end and optional application code."""

@final
class SpliceController:
    """The two direction handles and abort control of a controlled splice."""

    @property
    def a_to_b(self) -> SpliceControl:
        """Control the direction from the first stream to the second."""

    @property
    def b_to_a(self) -> SpliceControl:
        """Control the direction from the second stream to the first."""

    def abort(self, code: int) -> None:
        """Abort both remaining directions with this application code."""

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

    async def send_with(
        self,
        payload: bytes,
        *,
        options: _t.DatagramSendOptions,
        context: int = 0,
    ) -> _t.Sent:
        """Sends with local datagram options. Cancellation may write a capsule prefix."""

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
    async def send_with(
        self,
        payload: bytes,
        *,
        options: _t.DatagramSendOptions,
        context: int = 0,
    ) -> _t.Sent:
        """Sends with local datagram options. Cancellation may write a capsule prefix."""

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
    loop: `NoRunningLoopError` without one) to keep the loser's route as a
    pipe of the survivor. An
    undecidable pair or one with the same dialer raises
    `DuplicateUndecidedError` (a `ValueError`)."""

type _Source = tuple[str, int] | None

def static_key_id(key: Buffer) -> bytes:
    """The 32-byte KeyId of a static key, for `PinVerifier`."""

@final
class StaticKey:
    """A node's X25519 static private key: `establish(static_key=...)` for a client,
    `SecureServer(gate, static_key)` for a server. A client without one uses a key
    generated once per process."""

    @staticmethod
    def generate() -> StaticKey:
        """A new random key from the operating system's random source. When that fails
        (early boot, a sandbox without it), there is no fallback: `SecureCarrierError`
        with `kind == "random_failed"`."""
    @staticmethod
    def from_scalar(scalar: Buffer) -> StaticKey:
        """The key of a 32-byte X25519 private scalar; another length raises `ValueError`."""
    @property
    def public_key(self) -> bytes:
        """The X25519 public key (32 bytes): what `static_key_id` names for a peer's pin."""
    @property
    def scalar(self) -> bytes:
        """The private scalar (32 bytes)."""

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
    `ShapingBundle`, plans each handshake message.
    `accepted_profiles` (unset: 1 and 3; empty raises `ValueError`) is the only way to accept a
    Profile without a pre-shared key (4, 5). `client_verifier` verifies clients from
    message 3 (unset: only the gate's `commit` admits them); `local_context` is this
    listener's label for the gate and the verifier; `require_pq_auth` fails a client
    without post-quantum authentication; `signer` proves message 2 for clients whose
    verdict names its key; `app_data` supplies the data of message 2, and
    `max_app_data` bounds the client's (`DEFAULT_MAX_APP_DATA` bytes; `None`: no bound
    beyond the message). `allow_record_mode(mode, peer)` decides a mode other than
    Sealed; it may be `async` and runs on the event loop of the listener's
    creation, cancelled (refusing) at the handshake timeout. An unknown or reserved Profile, a key of zeros, or `require_pq_auth`
    without a verifier or with a pin of a static key alone raises `ValueError` here."""

    def __new__(
        cls,
        gate: Gate,
        static_key: StaticKey,
        *,
        accepted_profiles: Iterable[int] | None = None,
        allow_record_mode: Callable[[_t.RecordMode, _t.Peer], bool | Awaitable[bool]]
        | None = None,
        shaper: ShapingBundle | None = None,
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
    static_key: StaticKey = ...,
    allowed_profiles: Iterable[int] | None = None,
    record_mode: _t.RecordMode | str | None = None,
    credential: tuple[int, bytes] | None = None,
    local_context: Buffer = b"",
    app_data: AppDataSource | None = None,
    max_app_data: int | None = 256,
    require_pq_auth: bool = False,
    signer: Signer | SigningKey | None = None,
    shaper: ShapingBundle | None = None,
    shaping_limits: _t.ShapingLimits | None = None,
    reply_timeout: float | None = 10.0,
) -> tuple[PipeIo, _t.Peer]:
    """Runs the client's handshake on `pipe`: the carrier for `Session.connect`, whose
    `pipe_auth` stays unset, and what it learned of the server. On a failure the
    carrier is closed; nothing is retried. A server that ends or stays silent until
    `reply_timeout` (`None`: none) raises `NoReplyError`; a rejected server raises
    `CredentialsFailedError` (a `SecureCarrierError`, `kind == "credentials_failed"`; the
    verifier rejected it or could not decide, a proof failed, or `require_pq_auth` did not
    hold; only the side that judged raises it, so a server raises nothing: it closes the
    carrier and reports it to `on_reject`). A Python verifier exception is
    available as the credential error's `__cause__`. Another handshake failure
    raises `SecureCarrierError` with its `kind`; a configuration mistake raises
    `ValueError` naming it. If the client application-data callback raises, the
    original exception propagates.
    `static_key` is the client's `StaticKey` (left out: a key generated once per
    process, shared by this process's clients); `record_mode` the
    record mode of the session's first pipe (`None`: `RecordMode.SEALED`).
    `allowed_profiles` `None` is both ciphers, AES-GCM first with AES hardware: 1 or
    3 with a pre-shared key, 4 or 5 without; an empty list raises `ValueError`. `credential` is sent in message 3;
    `local_context` is this dial's label for the verifier; `app_data` supplies the
    data of messages 1 (Profiles 1 and 3) and 3, and `max_app_data` bounds the
    server's (`DEFAULT_MAX_APP_DATA` bytes; `None`: no bound beyond the message);
    `require_pq_auth` fails a server without post-quantum authentication; `signer`
    proves message 3 for a server whose verdict names its key. Its hooks run on
    the event loop running when it is called (`NoRunningLoopError` without one)."""

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
