"""Typed values exchanged with the native layer. Plain data; no protocol logic."""

from __future__ import annotations

import dataclasses
import enum
import logging
import math
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Final,
    Literal,
    NamedTuple,
    NewType,
    Protocol,
    TypedDict,
    runtime_checkable,
)

from . import _zmux
from ._errors import CredentialsFailedError

if TYPE_CHECKING:
    from ._zmux import (
        Admission,
        CarrierInfo,
        PipeHint,
        PipeIo,
        RecvStream,
        SecureServer,
        SendStream,
        ShapingBundle,
        Takeover,
        SpliceDecision,
        SpliceUnit,
    )


class _Enum(enum.StrEnum):
    """Base of the string enums: members compare equal to their wire text."""


def _enum_of[E: _Enum](cls: type[E], value: str) -> E | str:
    """`cls(value)`, or `value` itself when it names no member (a value a
    newer peer or native layer may send)."""
    try:
        return cls(value)
    except ValueError:
        return value


class _Setting(enum.Enum):
    """A setting of a field that is not a value of its range."""

    AUTO = "auto"
    STAGED = "staged"
    INHERIT = "inherit"
    CLEAR = "clear"

    def __repr__(self) -> str:
        return f"zmux.{self.name}"


AUTO: Final = _Setting.AUTO
"""The automatic setting: an automatic cap, a derived value, or a local
setting that follows the peer's request; the default where a field has
it."""
STAGED: Final = _Setting.STAGED
"""Staged unidirectional stream credit (`Config.max_incoming_uni_streams`,
the default)."""
INHERIT: Final = _Setting.INHERIT
"""A pipe or pool setting that follows the session's (the default of
those fields)."""
CLEAR: Final = _Setting.CLEAR
"""`Pipe.update`: clears a field to what it is when never set."""

Auto = Literal[_Setting.AUTO]
"""The type of `AUTO`."""
Staged = Literal[_Setting.STAGED]
"""The type of `STAGED`."""
Inherit = Literal[_Setting.INHERIT]
"""The type of `INHERIT`."""
Clear = Literal[_Setting.CLEAR]
"""The type of `CLEAR`."""

PipeId = NewType("PipeId", int)
"""The identifier of a pipe, unique for the life of its session (0 for the
bootstrap pipe)."""

SessionId = NewType("SessionId", int)
"""The identifier of a session, unique in the process while it runs and
never reused (`Session.id`, and what a `Tracer` is told). It is not sent."""

_DEFAULTS: Final[dict[str, Any]] = _zmux._config_defaults()


class RecordMode(_Enum):
    """How a pipe's records are protected."""

    SEALED = "sealed"
    BOUND = "bound"
    TRUSTED = "trusted"
    UNMANAGED = "unmanaged"
    """A first pipe outside the secure carrier; no join has this mode."""


class PrefixBinding(_Enum):
    """How a ticket presentation is bound to its carrier."""

    BOUND = "bound"
    """Bind to the carrier's 1-RTT TLS 1.3 or QUIC exporter."""
    ENCRYPTED = "encrypted"
    """Use a bearer ticket on an encrypted carrier."""
    ALLOW_CLEARTEXT = "allow_cleartext"
    """Also allow a bearer ticket as a binary prefix on cleartext carriers."""


class PrefixRejection(_Enum):
    """What the listener does with an invalid or unredeemable ticket."""

    CLOSE = "close"
    STALL = "stall"
    FALLBACK = "fallback"


class PrefixClaim(NamedTuple):
    """The exact transaction a ticket authority must commit or resolve."""

    id: bytes
    nonce: bytes
    commit_id: bytes
    version: int
    schedule: int
    generation: int
    issue_slot: int
    checked_slot: int
    local_slot: int


class PrefixStore(Protocol):
    """A shared, linearizable authority for one ticket admission domain.

    `local_schedule` is synchronous and may be called from a native worker.
    It returns a cached snapshot and a lower bound for the rollback floor.
    The other methods run on the admission's asyncio event loop.
    """

    @property
    def window(self) -> _zmux.PrefixWindow:
        """Immutable clock window of this admission domain."""
        ...

    def local_schedule(self) -> tuple[_zmux.PrefixSchedule, int]:
        """Return the published outer schedule and local floor hint."""
        ...

    def floor(self, attempt: _zmux.PrefixDeadline, /) -> int | Awaitable[int]:
        """Read the authoritative rollback floor."""
        ...

    def lookup(
        self, id: bytes, attempt: _zmux.PrefixDeadline, /
    ) -> _zmux.PrefixTicket | Awaitable[_zmux.PrefixTicket | None] | None:
        """Look up a ticket version without changing authority state."""
        ...

    def claim(
        self, claim: PrefixClaim, attempt: _zmux.PrefixDeadline, /
    ) -> bool | Awaitable[bool]:
        """Check the deadline, effective slot, schedule, generation, ticket and
        replay state atomically. Record the nonce, consume a single-use ticket
        and advance the floor in the same commit when accepting."""
        ...

    def resolve(
        self, claim: PrefixClaim, attempt: _zmux.PrefixDeadline, /
    ) -> bool | Awaitable[bool]:
        """Read the receipt of the original operation; raise if its outcome is unknown."""
        ...


class RejectAction(_Enum):
    """The answer of `ListenerConfig(on_reject=...)`. Neither sends anything."""

    CLOSE = "close"
    STALL = "stall"


class Role(_Enum):
    """The role of an endpoint: `CLIENT` is the initiator (the transport
    client of the bootstrap carrier), `SERVER` the responder, and `AUTO`
    negotiates the two with the peer."""

    CLIENT = "client"
    SERVER = "server"
    AUTO = "auto"


class SessionState(_Enum):
    """The session's lifecycle state."""

    ESTABLISHING = "Establishing"
    ACTIVE = "Active"
    DRAINING = "Draining"
    SUSPENDED = "Suspended"
    CLOSING = "Closing"
    CLOSED = "Closed"


class EarlyDataState(_Enum):
    """What became of a session's early data."""

    NOT_SENT = "NotSent"
    """No early stream data went out."""
    PENDING = "Pending"
    """Sent; the peer's parameters or the carrier's verdict are still due."""
    ACCEPTED = "Accepted"
    """The peer processed it."""
    REJECTED = "Rejected"
    """The peer processed none of it: after a carrier rejection the data
    went again once the handshake completed; after a zmux rejection the
    session ended with `EarlyDataRejectedError`."""


class Direction(_Enum):
    """Which directions a pipe carries, seen from this endpoint: `IN` it
    reads, `OUT` it writes, `BIDI` both."""

    IN = "in"
    OUT = "out"
    BIDI = "bidi"


class OutboundState(_Enum):
    """State of a pipe's outbound direction."""

    JOINING = "Joining"
    ACTIVE = "Active"
    SUSPECT = "Suspect"
    DRAINING = "Draining"
    FAILED = "Failed"
    CLOSED = "Closed"


class InboundState(_Enum):
    """State of a pipe's inbound direction."""

    JOINING = "Joining"
    OPEN = "Open"
    ENDED = "Ended"


class PipeHalf(_Enum):
    """A direction of a pipe: the one this endpoint reads or writes."""

    INBOUND = "Inbound"
    OUTBOUND = "Outbound"


class Multipath(_Enum):
    """`Session.multipath`: what became of multipath."""

    OFF = "off"
    """This endpoint did not offer it, or the session is not established yet."""
    IN_USE = "in_use"
    """In use: pipes can be added and resumption works when configured."""
    PEER_DECLINED = "peer_declined"
    """The peer did not offer it."""
    JOIN_SECURITY_UNAVAILABLE = "join_security_unavailable"
    """Both endpoints offered it, but no secret source of `pipe_auth` matched:
    the session runs on one pipe."""


class Support(NamedTuple):
    """Support of a protocol extension at each side, a negotiation result."""

    local: bool
    """Announced by this endpoint."""
    peer: bool
    """Announced by the peer."""


class PrioritySource(_Enum):
    """Where a pipe's effective priority comes from."""

    LOCAL = "Local"
    PEER = "Peer"
    DEFAULT = "Default"


class ErrorKind(_Enum):
    """`ZmuxError.kind`: the native error variant. Unknown variants stay plain `str`."""

    APPLICATION_CLOSED = "ApplicationClosed"
    CONNECTION_REFUSED = "ConnectionRefused"
    TRANSPORT_CLOSED = "TransportClosed"
    IDLE_TIMEOUT = "IdleTimeout"
    HANDSHAKE_TIMEOUT = "HandshakeTimeout"
    EARLY_DATA_REJECTED = "EarlyDataRejected"
    RESUME_TIMEOUT = "ResumeTimeout"
    RESUME_FAILED = "ResumeFailed"
    PIPES_LOST = "PipesLost"
    JOIN_REFUSED = "JoinRefused"
    JOIN_EVICTED = "JoinEvicted"
    JOIN_TIMEOUT = "JoinTimeout"
    RESET = "Reset"
    STOPPED = "Stopped"
    REJECTED = "Rejected"
    GOING_AWAY = "GoingAway"
    CLOSED_LOCALLY = "ClosedLocally"
    NOT_NEGOTIATED = "NotNegotiated"
    NOT_ESTABLISHED = "NotEstablished"
    BLOCKED = "Blocked"
    BORROW_LIMIT = "BorrowLimit"
    MEMORY_BUDGET = "MemoryBudget"
    DROPPED = "Dropped"
    SEQUENCE_EXHAUSTED = "SequenceExhausted"
    INVALID_OPTIONS = "InvalidOptions"
    TOO_LARGE = "TooLarge"
    INVALID_ARGUMENT = "InvalidArgument"
    CLOSED_STREAM = "ClosedStream"
    DEFERRED = "Deferred"
    UNKNOWN_PIPE = "UnknownPipe"
    FAILED = "Failed"
    CARRIER_LOOP = "CarrierLoop"
    INVALID_CONFIG = "InvalidConfig"
    FINISHED_EARLY = "FinishedEarly"
    TOO_LONG = "TooLong"
    LISTENER_CLOSED = "ListenerClosed"
    IO = "Io"
    JOIN_PENDING = "JoinPending"
    JOIN_SECRET_SET = "JoinSecretSet"
    NO_EXPORTER = "NoExporter"
    RESERVED_LABEL = "ReservedLabel"
    UNAVAILABLE = "Unavailable"
    INVALID_CONTEXT = "InvalidContext"
    MALFORMED = "Malformed"


class TransportErrorCode(enum.IntEnum):
    """The transport error codes of a `SessionClosedError.code` (kind
    `TRANSPORT_CLOSED`): QUIC's and zmux's."""

    NO_ERROR = 0x00
    INTERNAL_ERROR = 0x01
    CONNECTION_REFUSED = 0x02
    FLOW_CONTROL_ERROR = 0x03
    STREAM_LIMIT_ERROR = 0x04
    STREAM_STATE_ERROR = 0x05
    FINAL_SIZE_ERROR = 0x06
    FRAME_ENCODING_ERROR = 0x07
    TRANSPORT_PARAMETER_ERROR = 0x08
    PROTOCOL_VIOLATION = 0x0A
    NO_VIABLE_PATH = 0x10
    """A multipath session lost every pipe in a direction."""
    EXCESSIVE_LOAD = 0x25FF75EF
    ROLE_CONFLICT = 0x277DB2C3
    RESUME_TIMEOUT = 0x0EB87167
    """The resume grace period expired."""
    RESUME_FAILED = 0x0F05F74E
    """A resume could not be completed."""
    PIPE_FAILED = 0x296A5BF5
    PIPE_RESOURCE_LIMIT = 0x0B4FA113
    PIPE_AUTH_FAILED = 0x09613938
    """A join failed authentication; reported locally, never sent."""
    IDLE_TIMEOUT = 0x2736D55C


class ApplicationErrorCode(enum.IntEnum):
    """The application error codes zmux gives a meaning (the block
    0x5a4d0000 to 0x5a4d0fff); any other value below 2**62 is the
    application's own."""

    NO_ERROR = 0x00
    """No error; for a stop, "no more data wanted"."""
    ZMUX_CANCELLED = 0x5A4D0001
    """The endpoint abandoned the stream or session: what leaving an `async
    with` block by an exception sends."""
    ZMUX_REJECTED = 0x5A4D0002
    """The stream was not processed and may be retried."""
    ZMUX_CARRIER_FAILED = 0x5A4D0003
    """The stream carried something that failed; not safe to retry blindly."""
    ZMUX_PACKET_ERROR = 0x5A4D0004
    """The bytes of a packet stream were malformed: a capsule above the
    receiver's bound, or the stream ended inside a capsule."""
    ZMUX_PROXY_GENERAL_FAILURE = 0x5A4D0101
    ZMUX_PROXY_NOT_ALLOWED = 0x5A4D0102
    ZMUX_PROXY_NETWORK_UNREACHABLE = 0x5A4D0103
    ZMUX_PROXY_HOST_UNREACHABLE = 0x5A4D0104
    ZMUX_PROXY_CONNECTION_REFUSED = 0x5A4D0105
    ZMUX_PROXY_TTL_EXPIRED = 0x5A4D0106
    ZMUX_PROXY_COMMAND_NOT_SUPPORTED = 0x5A4D0107
    ZMUX_PROXY_ADDRESS_TYPE_NOT_SUPPORTED = 0x5A4D0108
    ZMUX_PROXY_DNS_FAILURE = 0x5A4D0110
    ZMUX_PROXY_CONNECT_TIMEOUT = 0x5A4D0111


class BiStream(NamedTuple):
    """A bidirectional stream: its two parts (`Session.open_bi`,
    `Session.accept_bi`); it unpacks as `send, recv`."""

    send: SendStream
    recv: RecvStream


class StreamDatagram(NamedTuple):
    """A datagram of a stream (`RecvStream.read_datagram`): its context ID
    and payload."""

    context: int
    payload: bytes


class _PriorityFields(NamedTuple):
    urgency: int
    incremental: bool = False


class Priority(_PriorityFields):
    """Stream scheduling priority: `urgency` 0 (highest) to 7, `incremental`
    interleaves equal urgencies (default: not incremental, as on the wire). A
    `(urgency, incremental)` tuple is accepted wherever a `Priority` is. There
    is no default priority without a name, so `urgency` is required:
    `LOCAL_DEFAULT` (3, incremental) is the local priority of a new sending
    part, `WIRE_DEFAULT` (3, not incremental) what the wire means when no
    priority was signalled."""

    __slots__ = ()
    LOCAL_DEFAULT: ClassVar[Priority]
    WIRE_DEFAULT: ClassVar[Priority]


Priority.LOCAL_DEFAULT = Priority(3, True)
Priority.WIRE_DEFAULT = Priority(3, False)


class Tlv(NamedTuple):
    """One preamble TLV: a varint `type` and its `value`."""

    type: int
    value: bytes


@dataclass(frozen=True, slots=True)
class Preamble:
    """Metadata the opener attached to a stream: its open info, its
    application TLVs in order, and whether it is a carrier stream
    (PIPE_CARRIER)."""

    info: bytes | None = None
    tlvs: tuple[Tlv, ...] = ()
    pipe_carrier: bool = False


class KeyGroup(enum.IntEnum):
    """The key-exchange group of a join and of the session epochs."""

    X25519 = 1
    X25519_MLKEM768 = 2


@dataclass(frozen=True, slots=True)
class SessionCrypto:
    """An endpoint's Join Suites and key groups, each ascending, holding
    Suite 1 and `KeyGroup.X25519_MLKEM768`, with no zero and no duplicate
    (`Config.session_crypto`; the default `SessionCrypto.LOCAL` is every
    Suite and key group of this build)."""

    suites: tuple[int, ...]
    groups: tuple[KeyGroup | int, ...]
    LOCAL: ClassVar[SessionCrypto]


SessionCrypto.LOCAL = SessionCrypto(
    tuple(_DEFAULTS["session_crypto"][0]),
    tuple(KeyGroup(g) for g in _DEFAULTS["session_crypto"][1]),
)


@dataclass(frozen=True, slots=True)
class RejectInfo:
    """An unauthenticated carrier that was refused: `profile` is 2 for a join and `None`
    when its first bytes named none. `reason` is the local reason, which the peer never
    sees. A secure carrier server's judgement of the client gives `"credentials_failed"`
    (its verifier rejected the client), `"proof"` (a required proof is missing or wrong)
    or `"pq_auth_required"` (the required post-quantum authentication does not hold);
    `"auth"` is for a failed AEAD or Confirm only. A verifier that could not decide
    closes the carrier without an `on_reject` call. Other reasons are an error class of
    the handshake or the refusal's name, for example `"unknown_locator"`.
    `error` carries the credential failure for verifier, proof and PQ refusals."""

    profile: int | None
    record_mode: RecordMode | None
    reason: str
    source: tuple[str, int] | None
    error: CredentialsFailedError | None = None


@dataclass(frozen=True, kw_only=True)
class RecordPolicy:
    """How a joiner chooses the record mode of a pipe it adds
    (`Config.record_policy`), when the pipe's options name none: the mode
    `by_label` gives the pipe's label, else `secure` for a carrier declared
    secure (`PipeIo.declare_carrier_secure`) when given, else `default`. It is data,
    chosen in the call that adds the pipe; an unmanaged mode raises
    `ValueError` when the `Config` is made."""

    default: RecordMode | str = RecordMode.SEALED
    secure: RecordMode | str | None = None
    by_label: Mapping[str, RecordMode | str] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "by_label", dict(self.by_label))


@dataclass(frozen=True, slots=True)
class RecordPolicyInput:
    """What `Config.allow_record_mode` knows of a carrier."""

    has_exporter: bool
    secure: bool
    label: str | None
    is_first_pipe: bool


@dataclass(frozen=True, slots=True)
class Principal:
    """Who a verified peer is: `kind` is `static_key` (`value` the peer's static key) or
    `other` (a host's own, with its `code`)."""

    kind: str
    value: bytes
    code: int = 0


@dataclass(frozen=True, slots=True)
class AppData:
    """Application handshake data of one message (1, 2 or 3). `forward_secret`: under
    keys with forward secrecy (message 1 is under the pre-shared key alone, and can be
    replayed). `authenticated`: the sender passed this end's verification; it is false
    in every `VerifyInput`. Act on message 3 data only after the server's `commit`."""

    message: int
    data: bytes
    forward_secret: bool
    authenticated: bool


@dataclass(frozen=True, slots=True)
class VerifyInput:
    """What a verifier is told about the peer: its role, the Profile, its static key,
    the Handle (`psk_identity`) when the Profile has one, its credential `(type, bytes)`
    when its message carried one, this end's `local_context`, and the application data
    the peer sent so far."""

    role: Role
    profile: int
    peer_static: bytes
    psk_identity: bytes | None
    credential: tuple[int, bytes] | None
    local_context: bytes
    peer_app_data: tuple[AppData, ...]


@dataclass(frozen=True, slots=True)
class VerifyVerdict:
    """A verifier's acceptance: who the peer is; `proof_key`, the KeyId of the key whose
    transcript signature the message must then carry; and `value`, the verifier's own
    result, which comes back on the `Peer`."""

    principal: Principal
    proof_key: bytes | None = None
    value: Any = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class Peer:
    """What an Establish learned of the other end: its static key and credential, the
    verdict (`None` when it was not verified), the Profile and the record mode, the
    application data it sent, and the two post-quantum facts: `pq_confidential` (the
    handshake resists a passive quantum adversary) and `pq_authenticated` (the verdict
    named a proof key, the proof verified, and its algorithm is post-quantum)."""

    static_key: bytes
    credential: tuple[int, bytes] | None
    verdict: VerifyVerdict | None
    profile: int
    record_mode: RecordMode
    app_data: tuple[AppData, ...]
    pq_confidential: bool
    pq_authenticated: bool


class RttSource(_Enum):
    """Where a pipe's RTT estimates come from."""

    ACK = "ack"
    KERNEL = "kernel"
    PING = "ping"


class PipeRequest(NamedTuple):
    """The peer's latest request for a pipe's outbound direction."""

    priority: int
    standby: bool


@dataclass(frozen=True, slots=True)
class LaneStats:
    """The positions of one lane of a pipe; `None` for a direction the lane
    does not have."""

    lane: int
    position_sent: int | None
    position_acked: int | None
    position_received: int | None


@dataclass(frozen=True, slots=True)
class CarrierId:
    """Opaque, process-local connection identity for equality and hashing."""

    _value: int = field(repr=False)


class CarrierSource(_Enum):
    """Provider of the carrier connection's statistics."""

    UNKNOWN = "unknown"
    LINUX_TCP_INFO = "linux_tcp_info"
    DARWIN_TCP_CONNECTION_INFO = "darwin_tcp_connection_info"
    WINDOWS_SIO_TCP_INFO = "windows_sio_tcp_info"
    QUINN = "quinn"


@dataclass(frozen=True, slots=True)
class TcpSegmentCounters:
    """TCP data segments sent and total segments retransmitted."""

    data_segs_out: int
    total_retrans: int


@dataclass(frozen=True, slots=True)
class TcpPacketCounters:
    """TCP packets transmitted and retransmitted."""

    packets_sent: int
    packets_retransmitted: int


@dataclass(frozen=True, slots=True)
class QuicCounters:
    """QUIC packets sent and declared lost by the provider."""

    packets_sent: int
    packets_lost: int


@dataclass(frozen=True, slots=True)
class CarrierSample:
    """A cached connection snapshot shared by its pipes."""

    carrier_id: CarrierId
    generation: int
    direction: Direction
    source: CarrierSource
    sampled_at: int
    """Monotonic nanoseconds. A cached read returns the same timestamp."""
    counts: TcpSegmentCounters | TcpPacketCounters | QuicCounters | None
    """The measured pair, or None when the provider cannot supply it."""


@dataclass(frozen=True, slots=True)
class PipeStats:
    """A snapshot of one attachment. Durations in seconds, rates in bytes per
    second, points in time on the `time.monotonic()` clock; estimates and
    the fields that need acknowledgements are `None` until known."""

    record_mode: RecordMode | None
    pipe: PipeId
    health: PipeHealth
    """Directional service and stability from the same capture."""
    accounting: PipeAccounting | None
    """Attribution and live or retired lane totals when enabled."""
    carrier_loss: CarrierLoss | None
    """A qualified loss interval scoped to the physical carrier, if available."""

    local: bool
    """This endpoint joined the attachment."""
    peer_attached: bool
    """The peer attached the pipe: it confirmed the join."""
    fate_group: int
    label: str | None
    carrier: CarrierKind | str | None
    """The carrier's kind, if the adapter declares one."""
    variant: str | None
    """The carrier's variant (`PipeIo.variant`, `Decision.variant`)."""
    inbound: InboundState | str | None
    outbound: OutboundState | str | None
    attached_for: float
    epoch: int | None
    """The session epoch the attachment joined in (0 for pipe 0)."""
    replace_by: float | None
    """When a carrier of an older epoch is to be replaced by a new join, by
    the epoch policy's period."""
    suspect_count: int
    failure_count: int
    failure: str | None
    send_priority: int
    send_priority_source: PrioritySource | str
    standby: bool
    standby_source: PrioritySource | str
    receive_priority: int
    receive_standby: bool
    request_seq: int
    """The sequence number of the last PIPE_STATUS request sent."""
    peer_request: PipeRequest | None
    weight: int
    probation_until: float | None
    in_probation: bool
    revalidating: bool
    eligible: bool
    writable: bool
    saturated: bool
    rtt_source: RttSource | str | None
    smoothed_rtt: float | None
    min_rtt: float | None
    rttvar: float | None
    one_way_delay: float | None
    delivery_rate: int | None
    queued_bytes: int | None
    """Bytes the outbound carrier holds unsent, summed over the lanes; `None`
    where its adapter reports no count. Only the carrier's part of the
    pipe's queue: bytes of write calls in progress are not included."""
    queue_delay: float | None
    bytes_in_flight: int | None
    bytes_sent: int
    bytes_received: int
    bytes_acked: int | None
    records_sent: int
    records_received: int
    bytes_reinjected: int
    bytes_lost: int | None
    """The outbound carrier bytes, framing included, sent and not
    acknowledged when the pipe failed (reinjection sends them again
    elsewhere, unlike `bytes_reinjected`, the stream payload sent again); 0
    before a failure, `None` until acknowledgements are known. zmux loses
    no record on a live pipe."""
    records_lost: int | None
    """`bytes_lost` in records, an estimate (rounded up)."""
    carrier_sample: CarrierSample | None
    """The carrier connection's most recent on-demand observation."""
    bytes_opportunistic: int
    bytes_redundant: int
    bytes_duplicate_received: int
    pings_sent: int
    pings_answered: int
    since_last_ack: float | None
    since_last_receive: float | None
    since_last_traffic: float | None
    """Seconds since a record with a traffic frame (STREAM, RESET_STREAM,
    RESET_STREAM_AT, STOP_SENDING or DATAGRAM) was sent or completely
    received on the pipe, or since it became live; probes,
    acknowledgements, other control frames and padding do not count.
    `None` while neither direction is live."""
    lanes_out: int
    lanes_in: int
    lanes_refused: int
    lanes: tuple[LaneStats, ...]
    """Per lane, for a pipe with lanes; empty without."""


@dataclass(frozen=True, slots=True)
class StreamStats:
    """A snapshot of a stream, in payload bytes (the preamble excluded); both
    parts of a bidirectional stream return the same one, and once the
    session released the stream it keeps its final values."""

    bytes_written: int
    bytes_sent: int
    """Payload bytes put into STREAM frames, each copy again."""
    bytes_acknowledged: int
    bytes_received: int
    """Distinct payload bytes received, read or not."""
    bytes_read: int
    datagrams_sent: int
    datagrams_received: int
    datagrams_dropped_recv: int
    datagram_bytes_sent: int
    datagram_bytes_received: int
    send_buffered: int
    recv_buffered: int
    recv_window: int
    pipe: PipeId | None
    """The pipe the sending direction is bound to under `affinity`."""


@dataclass(frozen=True, slots=True)
class AdmissionVariants:
    """`Listener.variant_stats()`: the admission's verdicts per label, at
    most 64 labels, the ones past that in `overflow`."""

    variants: Mapping[str, VariantStats] = field(default_factory=dict, hash=False)
    overflow: VariantStats = field(default_factory=lambda: VariantStats())


@dataclass(frozen=True, slots=True)
class VariantStats:
    """The admission's verdicts on the carriers it labelled with one
    variant. `takeover` counts dispatches to the byte-stream target.
    These carriers count in the totals of `AdmissionStats` as well."""

    accepted: int = 0
    fallback: int = 0
    stalled: int = 0
    closed: int = 0
    takeover: int = 0


@dataclass(frozen=True, slots=True)
class AdmissionStats:
    """What a listener's admission decided: counts since it was made, each
    carrier that took a source slot counted once its outcome is known; all 0
    without an admission. `accepted` carriers count once more in the other
    `ListenerStats` fields. `fallback` counts handoffs to a host, including
    those routed there after a peek timeout. `takeover` counts handoffs to
    the byte-stream target when the host callback begins. `stalled` counts
    stalls when they start and targetless HTTP fallbacks answered with 404.
    `closed` also counts
    a verdict where it does not apply (an `accept` beyond the prefix, a
    `more` or `DEFER` out of place), a failing decide, one cancelled by the
    listener's close, a message-framed carrier without a first message to
    decide on, an oversized first message on an ordinary carrier, and a
    deferred decision whose carrier ended first. `stall_overflow` counts
    a stall closed at once when its source already stalls
    `max_pending_per_source - 1` carriers, stalls occupy half of
    `max_pending`, or the listener closes. `too_large` counts a deferred
    first message after an upgrade that exceeds `Admission.max_message`.
    `peek_timed_out` counts admission that ends at the peek deadline.
    `handshake_failed` counts an outer handshake (TLS, HTTP
    upgrade, QUIC) that failed or timed out, counted here and not in
    `setup_failures`. A deferral is no outcome of its own."""

    accepted: int = 0
    fallback: int = 0
    stalled: int = 0
    closed: int = 0
    stall_overflow: int = 0
    too_large: int = 0
    peek_timed_out: int = 0
    handshake_failed: int = 0
    takeover: int = 0


@dataclass(frozen=True, slots=True)
class ListenerStats:
    """What happened to a listener's carriers: counts since it was made.
    `rejected` counts the listener's own rejections only (nothing sent for any);
    the admission's decisions are in `admission`."""

    sessions: int
    joins: int
    setup_failures: int
    rejected: int
    refused: int
    timed_out: int
    admission: AdmissionStats = AdmissionStats()


class CarrierKind(_Enum):
    """A carrier kind of a carrier mode (`Candidate.kind`)."""

    WEBSOCKET = "websocket"
    STREAMING = "streaming"
    SPLIT = "split"
    EXCHANGE = "exchange"
    QUIC = "quic"
    HTTP3 = "http3"
    WEBTRANSPORT = "webtransport"
    RAW = "raw"
    """A reliable ordered byte connection with no framing of its own (TCP, TLS)."""


class CarrierRetryProfile(_Enum):
    """Explicit deployment profiles for carrier retry."""

    SHORT_DROP_RESILIENT = "short_drop_resilient"
    """Uses 30 s to 30 min exponential backoff with symmetric jitter and a short-drop floor."""


class CacheOutcome(_Enum):
    """What a host learnt of a candidate after dialling it
    (`CarrierCache.report`)."""

    USABLE = "usable"
    """Usable, as a chosen candidate."""
    FAILED = "failed"
    """An ordinary failure: the backoff doubles."""
    REJECTED = "rejected"
    """A definitive path rejection."""
    SURVIVED = "survived"
    SHORT_DROP = "short_drop"
    LATE_DROP = "late_drop"
    LIFETIME = "lifetime"
    PERFORMANCE = "performance"
    RECOVERED = "recovered"


class ReplayVerdict(_Enum):
    """The result of `ReplayFilter.check`."""

    FRESH = "fresh"
    """Accepted, and recorded."""
    SEEN = "seen"
    """The key was seen within the window."""
    OUTSIDE = "outside"
    """The stamp is outside the window, or before `not_before`."""
    FULL = "full"
    """The filter holds its maximum of keys: nothing new is accepted."""


class Framing(_Enum):
    """How a carrier delivers records (`classify_first_bytes`)."""

    BYTE_STREAM = "byte_stream"
    """Concatenated records, each with its Size field."""
    RECORDS = "records"
    """Each carrier message is one record's frames."""


class AdmissionStage(_Enum):
    """What of a carrier an admission decides on (`CarrierInfo.stage`)."""

    HEAD = "head"
    """An HTTP request head: no prefix, a credential in a request header
    field."""
    CARRIER = "carrier"
    """The carrier's start: its first bytes, or its first message."""


class FirstBytes(_Enum):
    """What `classify_first_bytes` tells about a carrier's first bytes."""

    NEED_MORE = "need_more"
    """More bytes are needed to tell."""
    RECORD = "record"
    """They can begin a first record."""
    OTHER = "other"
    """They cannot."""


class JoinPrefix(_Enum):
    """What `Listener.join_prefix` tells about a carrier's prefix."""

    KNOWN = "known"
    """A Join Hello whose Locator names a current session."""
    UNKNOWN = "unknown"
    """A Join Hello whose Locator names no current session."""
    NOT_JOIN = "not_join"
    """Not a Join Hello, or a malformed one."""
    NEED_MORE = "need_more"
    """The prefix ends inside the Hello's head: more bytes are needed."""


@dataclass(frozen=True, slots=True)
class TlsState:
    """What the TLS or QUIC handshake this process ran for a carrier
    negotiated. No proof of an end-to-end handshake."""

    alpn: bytes | None = None
    server_name: str | None = None


@dataclass(frozen=True, slots=True)
class SessionCarrier:
    """What `ListenerConfig(session_config=...)` knows of a carrier that starts a
    session: `source` and `peer` as `(host, port)`, the handshake this
    process ran for it, and the admission's value."""

    source: tuple[str, int] | None
    peer: tuple[str, int] | None
    tls: TlsState | None
    admitted: Any


class CandidateOutcome(_Enum):
    """How one try of a candidate fared."""

    USABLE = "usable"
    TIMED_OUT = "timed_out"
    REFUSED = "refused"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """One try of a carrier mode's candidate: `joined` when it was tried as
    a further pipe of the established session; `error` unless usable;
    `variant` the candidate's."""

    carrier: CarrierKind | str
    outcome: CandidateOutcome | str
    joined: bool
    error: str | None
    variant: str | None = None


def _candidate_result(fields: dict[str, Any]) -> CandidateResult:
    return CandidateResult(
        _enum_of(CarrierKind, fields["carrier"]),
        _enum_of(CandidateOutcome, fields["outcome"]),
        fields["joined"],
        fields["error"],
        fields["variant"],
    )


@dataclass(frozen=True, slots=True)
class SessionStats:
    """A snapshot of the session's statistics. Carrier bytes count every byte
    of the records; the application bytes (`bytes_written`, `bytes_read`,
    `datagram_bytes_*`) are the session's totals. Durations in seconds;
    the RTT fields are `None` before the first sample."""

    bytes_sent: int
    bytes_received: int
    records_sent: int
    records_received: int
    bytes_written: int
    bytes_read: int
    datagram_bytes_sent: int
    datagram_bytes_received: int
    streams_opened_local: int
    streams_opened_remote: int
    streams_active: int
    stream_credit_waits: int
    datagrams_sent: int
    datagrams_received: int
    datagrams_sent_channel: int
    """Of `datagrams_sent`, those that went on a carrier datagram channel."""
    datagrams_received_channel: int
    datagrams_dropped_send: int
    datagrams_dropped_recv: int
    datagrams_dropped_limit: int
    no_effect_budget: int
    smoothed_rtt: float | None
    min_rtt: float | None
    latest_rtt: float | None
    mean_deviation: float | None
    bytes_reinjected: int
    bytes_opportunistic: int
    penalties: int
    reinjections: int
    bytes_redundant: int
    bytes_duplicate_received: int
    send_buffered: int
    recv_buffered: int
    retained: int
    pipes_active: int
    pipes_added: int
    pipe_failures: int
    join_auth_failures: int
    log_lines_dropped: int
    join_pending: int
    join_batch_dropped: int
    join_failures: int
    join_replays: int
    join_refusals: int
    suspensions: int
    suspended_time: float
    scheduler_answers: int
    scheduler_fallbacks: int
    first_flight_timeouts: int
    carrier: CarrierKind | str | None = None
    """The carrier kind a carrier mode chose (the latest after a switch)."""
    carrier_candidates: tuple[CandidateResult, ...] = ()
    """The tries of the mode's candidates, in order (the latest 64)."""

    def __post_init__(self) -> None:
        if self.carrier is not None:
            object.__setattr__(self, "carrier", _enum_of(CarrierKind, self.carrier))
        object.__setattr__(self, "carrier_candidates", tuple(self.carrier_candidates))


class EventKind(_Enum):
    """`Event.kind` values."""

    PIPE_HEALTH_CHANGED = "PipeHealthChanged"
    TARGET_CHANGED = "TargetChanged"
    BATCH_RESERVED = "BatchReserved"
    BATCH_ROLLED_BACK = "BatchRolledBack"
    DRAIN_COMMITTED = "DrainCommitted"
    ATTEMPT_STARTED = "AttemptStarted"
    ATTEMPT_FINISHED = "AttemptFinished"
    PIPE_ADDED = "PipeAdded"
    PIPE_JOINED = "PipeJoined"
    PIPE_SUSPECT = "PipeSuspect"
    PIPE_RECOVERED = "PipeRecovered"
    PIPE_FAILED = "PipeFailed"
    PIPE_CLOSED = "PipeClosed"
    JOIN_AUTH_FAILED = "JoinAuthFailed"
    PIPE_PRIORITY_CHANGED = "PipePriorityChanged"
    PIPE_QUALITY_CHANGED = "PipeQualityChanged"
    TIER_SATURATION = "TierSaturation"
    CAPACITY_BELOW = "CapacityBelow"
    CAPACITY_RESTORED = "CapacityRestored"
    GO_AWAY_RECEIVED = "GoAwayReceived"
    SESSION_SUSPENDED = "SessionSuspended"
    SESSION_RESUMED = "SessionResumed"
    RESUME_UNATTENDED = "ResumeUnattended"
    PIPES_RETIRED = "PipesRetired"
    CARRIER_CANDIDATE = "CarrierCandidate"
    CARRIER_CHOSEN = "CarrierChosen"
    EPOCH_COMMITTED = "EpochCommitted"
    EPOCH_DELETED = "EpochDeleted"
    DATAGRAM_PATH_CHANGED = "DatagramPathChanged"
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class Event:
    """Base of session events; match on the subclass or on `kind`."""

    kind: ClassVar[EventKind]


@dataclass(frozen=True, slots=True)
class PipeAdded(Event):
    """A local outbound pipe direction appeared (a join began, or pipe 0);
    `carrier` is the pipe's carrier kind."""

    kind: ClassVar[EventKind] = EventKind.PIPE_ADDED
    pipe: PipeId
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class PipeJoined(Event):
    """An outbound pipe direction became active."""

    kind: ClassVar[EventKind] = EventKind.PIPE_JOINED
    pipe: PipeId
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class PipeSuspect(Event):
    """An outbound pipe direction stopped making progress."""

    kind: ClassVar[EventKind] = EventKind.PIPE_SUSPECT
    pipe: PipeId
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class PipeRecovered(Event):
    """A suspect outbound pipe direction is active again."""

    kind: ClassVar[EventKind] = EventKind.PIPE_RECOVERED
    pipe: PipeId
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class PipeFailed(Event):
    """An outbound pipe direction failed, for the reason `failure`. Terminal."""

    kind: ClassVar[EventKind] = EventKind.PIPE_FAILED
    pipe: PipeId
    failure: str | None
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class PipeClosed(Event):
    """A pipe direction ended: the `OUTBOUND` one closed, or the `INBOUND`
    one ended. Terminal; retirement is reported by `PipesRetired`."""

    kind: ClassVar[EventKind] = EventKind.PIPE_CLOSED
    pipe: PipeId
    half: PipeHalf | str
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class JoinAuthFailed(Event):
    """`count` joins failed with this `reason` since the last such event was
    read (one event per reason, `count` at least 1; a `Tracer` gets one event
    per failure, with `count` 1)."""

    kind: ClassVar[EventKind] = EventKind.JOIN_AUTH_FAILED
    reason: str
    count: int


@dataclass(frozen=True, slots=True)
class PipePriorityChanged(Event):
    """A pipe's effective outbound priority, standby flag or weight changed."""

    kind: ClassVar[EventKind] = EventKind.PIPE_PRIORITY_CHANGED
    pipe: PipeId
    send_priority: int
    standby: bool
    weight: int
    source: PrioritySource


@dataclass(frozen=True, slots=True)
class PipeQualityChanged(Event):
    """A pipe's estimates left their band. Seconds; bytes per second."""

    kind: ClassVar[EventKind] = EventKind.PIPE_QUALITY_CHANGED
    pipe: PipeId
    smoothed_rtt: float | None
    delivery_rate: int | None


@dataclass(frozen=True, slots=True)
class TierSaturation(Event):
    """The outbound tier of `priority` entered or left saturation."""

    kind: ClassVar[EventKind] = EventKind.TIER_SATURATION
    priority: int
    saturated: bool


@dataclass(frozen=True, slots=True)
class CapacityBelow(Event):
    """Outbound capacity (bytes per second) fell below the configured floor."""

    kind: ClassVar[EventKind] = EventKind.CAPACITY_BELOW
    rate: int


@dataclass(frozen=True, slots=True)
class CapacityRestored(Event):
    """Outbound capacity (bytes per second) recovered."""

    kind: ClassVar[EventKind] = EventKind.CAPACITY_RESTORED
    rate: int


@dataclass(frozen=True, slots=True)
class GoAwayReceived(Event):
    """The peer sent GOAWAY: streams below the watermarks may be processed;
    `code` is the peer's application error code."""

    kind: ClassVar[EventKind] = EventKind.GO_AWAY_RECEIVED
    max_bidi: int
    max_uni: int
    code: int


@dataclass(frozen=True, slots=True)
class SessionSuspended(Event):
    """Every pipe in a direction was lost; the session waits for a pipe to resume."""

    kind: ClassVar[EventKind] = EventKind.SESSION_SUSPENDED


@dataclass(frozen=True, slots=True)
class SessionResumed(Event):
    """The session left the suspended state."""

    kind: ClassVar[EventKind] = EventKind.SESSION_RESUMED


@dataclass(frozen=True, slots=True)
class ResumeUnattended(Event):
    """The session can rejoin and suspended without a
    running pipe pool: nothing will dial, and it ends at the grace period unless the
    application adds a pipe. It follows `SessionSuspended` and is also logged as a
    warning."""

    kind: ClassVar[EventKind] = EventKind.RESUME_UNATTENDED


@dataclass(frozen=True, slots=True)
class PipesRetired(Event):
    """Pipes were retired since the last such event was read; `last` holds up
    to four of their IDs, oldest first. `failed` counts the retired pipes that
    ended failed and `closed` the others, those whose terminal state the
    application had not read (a `PipeFailed` or `PipeClosed` of the pipe; one
    never queued counts as unread). A `Tracer` gets one per retired pipe, with
    `retired` 1 and the pipe in `failed` or in `closed`."""

    kind: ClassVar[EventKind] = EventKind.PIPES_RETIRED
    retired: int
    failed: int
    closed: int
    last: tuple[PipeId, ...]


@dataclass(frozen=True, slots=True)
class CarrierCandidate(Event):
    """A carrier mode tried a candidate, as the session or (`joined`) as a
    further pipe; `variant` is the candidate's."""

    kind: ClassVar[EventKind] = EventKind.CARRIER_CANDIDATE
    carrier: CarrierKind | str
    outcome: CandidateOutcome | str
    joined: bool
    variant: str | None = None


@dataclass(frozen=True, slots=True)
class CarrierChosen(Event):
    """A carrier mode chose the session's carrier kind: when the session was
    established, and again on every switch; `variant` is the candidate's."""

    kind: ClassVar[EventKind] = EventKind.CARRIER_CHOSEN
    carrier: CarrierKind | str
    variant: str | None = None


@dataclass(frozen=True, slots=True)
class EpochCommitted(Event):
    """The session committed an epoch: its secret is known, and joins of it are
    accepted. The latest when several were not read."""

    kind: ClassVar[EventKind] = EventKind.EPOCH_COMMITTED
    epoch: int


@dataclass(frozen=True, slots=True)
class EpochDeleted(Event):
    """An epoch, its keys and its Locators were deleted. The latest when several were
    not read."""

    kind: ClassVar[EventKind] = EventKind.EPOCH_DELETED
    epoch: int


@dataclass(frozen=True, slots=True)
class DatagramPathChanged(Event):
    """The eligible original-copy or native channel datagram capacity changed."""

    kind: ClassVar[EventKind] = EventKind.DATAGRAM_PATH_CHANGED
    path: DatagramPath


@dataclass(frozen=True, slots=True)
class PipeHealthChanged(Event):
    """A committed health change for one local attachment direction."""

    kind: ClassVar[EventKind] = EventKind.PIPE_HEALTH_CHANGED
    change: PipeHealthChange


@dataclass(frozen=True, slots=True)
class TargetChanged(Event):
    """A managed session committed a controller binding or target revision."""

    kind: ClassVar[EventKind] = EventKind.TARGET_CHANGED
    generation: int
    """The session-local identity of the binding."""
    revision: int
    """The installed target revision."""
    initial: bool
    """Whether this is the binding's initial target."""
    predecessor: int | None
    """The replaced binding on takeover, when present."""


@dataclass(frozen=True, slots=True)
class BatchReserved(Event):
    """A controller reserved work for a target revision."""

    kind: ClassVar[EventKind] = EventKind.BATCH_RESERVED
    generation: int
    """The originating controller binding."""
    revision: int
    """The target revision."""
    batch: int
    """The session-local capacity batch identifier."""


@dataclass(frozen=True, slots=True)
class BatchRolledBack(Event):
    """A controller rolled back a capacity batch."""

    kind: ClassVar[EventKind] = EventKind.BATCH_ROLLED_BACK
    generation: int
    """The originating controller binding."""
    batch: int
    """The session-local capacity batch identifier."""


@dataclass(frozen=True, slots=True)
class DrainCommitted(Event):
    """A controller committed a member retirement."""

    kind: ClassVar[EventKind] = EventKind.DRAIN_COMMITTED
    generation: int
    """The originating controller binding."""
    batch: int
    """The session-local capacity batch identifier."""
    member: int
    """The retiring member."""


@dataclass(frozen=True, slots=True)
class AttemptStarted(Event):
    """A controller started a carrier opener."""

    kind: ClassVar[EventKind] = EventKind.ATTEMPT_STARTED
    generation: int
    """The originating controller binding."""
    batch: int
    """The session-local capacity batch identifier."""
    attempt: int
    """The session-local attempt identifier."""


@dataclass(frozen=True, slots=True)
class AttemptFinished(Event):
    """A controller settled one attempt. Attempt zero means refusal before opener entry."""

    kind: ClassVar[EventKind] = EventKind.ATTEMPT_FINISHED
    generation: int
    """The originating controller binding."""
    batch: int
    """The session-local capacity batch identifier."""
    attempt: int
    """The session-local attempt identifier."""
    reason: str
    """The terminal reason."""


@dataclass(frozen=True, slots=True)
class UnknownEvent(Event):
    """An event this binding does not model yet; `detail` is diagnostic text."""

    kind: ClassVar[EventKind] = EventKind.UNKNOWN
    detail: str


_EVENTS: dict[str, type[Event]] = {
    c.kind: c
    for c in (
        PipeAdded,
        PipeJoined,
        PipeSuspect,
        PipeRecovered,
        PipeFailed,
        PipeClosed,
        JoinAuthFailed,
        PipePriorityChanged,
        PipeQualityChanged,
        TierSaturation,
        CapacityBelow,
        CapacityRestored,
        GoAwayReceived,
        SessionSuspended,
        SessionResumed,
        ResumeUnattended,
        PipesRetired,
        CarrierCandidate,
        CarrierChosen,
        EpochCommitted,
        EpochDeleted,
        DatagramPathChanged,
        PipeHealthChanged,
        TargetChanged,
        BatchReserved,
        BatchRolledBack,
        DrainCommitted,
        AttemptStarted,
        AttemptFinished,
    )
}

_ENUM_FIELDS: dict[str, type[_Enum]] = {
    "half": PipeHalf,
    "source": PrioritySource,
    "carrier": CarrierKind,
    "outcome": CandidateOutcome,
}


def _event(kind: str, fields: dict[str, Any]) -> Event:
    cls = _EVENTS.get(kind)
    if cls is None:
        return UnknownEvent(fields.get("detail", kind))
    for k, e in _ENUM_FIELDS.items():
        if fields.get(k) is not None:
            fields[k] = _enum_of(e, fields[k])
    if "last" in fields:
        fields["last"] = tuple(fields["last"])
    return cls(**fields)


def _carrier_sample(
    carrier_id: int,
    generation: int,
    direction: Direction,
    source: str,
    sampled_at: int,
    pair: tuple[str, int, int] | None,
) -> CarrierSample:
    counts: TcpSegmentCounters | TcpPacketCounters | QuicCounters | None = None
    if pair is not None:
        kind, sent, lost = pair
        if kind == "tcp_segments":
            counts = TcpSegmentCounters(sent, lost)
        elif kind == "tcp_packets":
            counts = TcpPacketCounters(sent, lost)
        elif kind == "quic":
            counts = QuicCounters(sent, lost)
    return CarrierSample(
        CarrierId(carrier_id),
        generation,
        direction,
        CarrierSource(source),
        sampled_at,
        counts,
    )


def _pipe_stats(fields: dict[str, Any]) -> PipeStats:
    if fields["inbound"] is not None:
        fields["inbound"] = _enum_of(InboundState, fields["inbound"])
    if fields["outbound"] is not None:
        fields["outbound"] = _enum_of(OutboundState, fields["outbound"])
    if fields["carrier"] is not None:
        fields["carrier"] = _enum_of(CarrierKind, fields["carrier"])
    if fields["carrier_sample"] is not None:
        fields["carrier_sample"] = _carrier_sample(*fields["carrier_sample"])
    for k in ("send_priority_source", "standby_source"):
        fields[k] = _enum_of(PrioritySource, fields[k])
    if fields["rtt_source"] is not None:
        fields["rtt_source"] = _enum_of(RttSource, fields["rtt_source"])
    if fields["peer_request"] is not None:
        fields["peer_request"] = PipeRequest(*fields["peer_request"])
    fields["lanes"] = tuple(LaneStats(*lane) for lane in fields["lanes"])
    return PipeStats(**fields)


def _preamble(
    info: bytes | None, tlvs: list[tuple[int, bytes]], pipe_carrier: bool
) -> Preamble:
    return Preamble(info, tuple(Tlv(t, v) for t, v in tlvs), pipe_carrier)


@dataclass(frozen=True, slots=True)
class EpochPolicy:
    """When a multipath session starts an epoch exchange on its own
    (`Config.epoch_policy`): after `period` seconds in the stable state
    (one hour by default; `None`: never by time; a carrier lives at most
    twice as long before a new join replaces it), after `joins` joins in the
    epoch (2**16 by default; `None`: never by count), once after the first
    Sealed or Bound pipe of a session whose secret is a TLS exporter's or a
    pre-shared key's, and once after a suspension. `EpochPolicy.MANUAL`
    starts none: only `Session.advance_epoch` and `Session.replace_pipes`
    do. A `period` or `joins` of zero raises `ValueError`."""

    period: float | None = _DEFAULTS["epoch_policy"][0]
    joins: int | None = _DEFAULTS["epoch_policy"][1]
    after_first_pipe: bool = _DEFAULTS["epoch_policy"][2]
    after_resume: bool = _DEFAULTS["epoch_policy"][3]
    MANUAL: ClassVar[EpochPolicy]

    def __post_init__(self) -> None:
        _zmux._check_epoch_policy(self)


EpochPolicy.MANUAL = EpochPolicy(*_DEFAULTS["manual_epoch_policy"])


@dataclass(frozen=True, kw_only=True)
class ShapingAccount:
    """An allowance for injections, in bytes on the carrier; all fields zero: not set.
    Padding that goes with a record is never refused and does not draw on it. `initial` is
    at most 2**53, the others 2**43 (`ValueError` otherwise, at construction)."""

    ceiling: int = 0
    """Maximum balance, in bytes."""
    initial: int = 0
    """Available from the start."""
    per_mb: int = 0
    """Added per 10**6 bytes this endpoint sends of its own."""
    per_sec: int = 0
    """Added per second."""

    def __post_init__(self) -> None:
        _zmux._check_shaping_account(self)


def _count(k: str, v: object) -> None:
    if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
        raise ValueError(f"{k} is a non-negative integer")


class ShapingWindowStats(TypedDict):
    """Overhead recorded in one effective shaping window."""

    profile: ShapingProfileLimits
    baseline_bytes: int
    allowance_bytes: int
    consumed_bytes: int
    reserved_bytes: int
    history_complete: bool


class ShapingLedgerStats(TypedDict):
    """Outbound costs at zmux's adapter handoff."""

    boundary: Literal["zmux_handoff"]
    precision: Literal["exact", "unavailable"]
    measured_bytes: int
    baseline_bytes: int
    policy: ShapingWindowStats | None
    local: ShapingWindowStats | None


class ShapingStats(TypedDict):
    """Profile accounting and handoff statistics for outbound session shaping."""

    wire_spent: int
    stall_spent: float
    max_added_delay: float
    generation: int
    ledger: ShapingLedgerStats
    clamped: int
    faults: int
    handshake_unplanned: int
    handshake_measured_bytes: int
    handshake_reserved_bytes: int
    handshake_unresolved_bytes: int
    injection_accepted_bytes: int
    injection_sent_bytes: int
    injection_accepted_requests: int
    injection_rejected: int
    injection_rejected_by_reason: tuple[int, ...]
    runtime_reasons: tuple[int, ...]


@dataclass(frozen=True, kw_only=True)
class ShapingProfileLimits:
    """Outbound bounds."""

    window_seconds: int = _DEFAULTS["shaping_lightweight"][0]
    """Number of one-second buckets in the sliding window."""
    extra_bytes_ppm: int = _DEFAULTS["shaping_lightweight"][1]
    """Extra bytes per million proved baseline bytes."""
    floor_bytes: int = _DEFAULTS["shaping_lightweight"][2]
    """Minimum overhead allowance per window, in bytes."""
    max_added_delay: float = _DEFAULTS["shaping_lightweight"][3]
    """Maximum additional local wait per unit, in seconds."""

    def __post_init__(self) -> None:
        _zmux._check_shaping_profile(self)


@dataclass(frozen=True, kw_only=True)
class ShapingLimits:
    """Local bounds on shaping (`Config(shaping_limits=...)`), set by the application and
    never sent; a configuration cannot widen them. Durations are seconds."""

    wire: ShapingAccount | None = None
    """What cover injections may spend."""
    profile: ShapingProfileLimits | None = None
    """Additional local profile cap, if configured."""
    no_padding: bool = False
    """No padding at all, on handshakes and injections too."""
    no_pause: bool = False
    """No pause or delay."""
    no_injection: bool = False
    """No injection."""


@dataclass(frozen=True, kw_only=True)
class ShapingBudget:
    """What a shaping configuration allows for a session (`Config(shaping_budget=...)`,
    the same for every session; a `ShapingBundle` draws one per session). It cannot
    widen `ShapingLimits`."""

    wire: ShapingAccount | None = None
    """What cover injections may spend."""
    profile: ShapingProfileLimits | None = None
    """Optional profile limits."""
    no_injection: bool = False
    """The configuration allows no injection."""


@dataclass(frozen=True, kw_only=True)
class UnitPlan:
    """The size and timing of one unit written to a carrier. Lengths are bytes on the
    carrier, and `delay` is seconds."""

    pad_to: int = 0
    pad_multiple: int = 0
    pad: int = 0
    delay: float = 0.0


@dataclass(frozen=True, kw_only=True)
class ShapingSizeLimits:
    """Bounds of a shaping definition (`Shaper(limits=...)`);
    each field but `max_slots` is `None` by default, no bound, and a set one
    bounds as it is, 0 allowing none. A definition beyond one raises
    `ValueError`; so does a field that is not a non-negative integer, at
    construction."""

    max_bytes: int | None = None
    """Input bytes."""
    max_machines: int | None = None
    """Machines."""
    max_states: int | None = None
    """States per machine."""
    max_actions: int | None = None
    """Actions per state."""
    max_transitions: int | None = None
    """Transitions per state."""
    max_segments: int | None = None
    """Segments per value or table."""
    max_slots: int | None = _zmux.DEFAULT_MAX_SLOTS
    """Counters and timers of all machines of a candidate together (0
    allows none); `None`: no bound."""

    def __post_init__(self) -> None:
        for k in (
            "max_bytes",
            "max_machines",
            "max_states",
            "max_actions",
            "max_transitions",
            "max_segments",
        ):
            _count(k, getattr(self, k))
        _count("max_slots", self.max_slots)


class PipeAuth:
    """Join credentials for multipath, immutable: `PipeAuth.exporter()`
    (the exporter of the innermost end-to-end handshake, today TLS that
    this process terminates), `PipeAuth.psk(key)` (a
    pre-shared key of at least 16 bytes), and `auth.with_psk(key)`, a new
    value that adds a key. A session whose first pipe comes from `establish`
    (the secure carrier) takes its source from that handshake and leaves
    `pipe_auth` unset; a key or the exporter with it raises `ValueError`.
    `auth.with_end_to_end()` states in advance what `Session.declare_end_to_end`
    states; without it, a first pipe not on the secure carrier has no join
    keys. It is no source of its own, and on a secure first pipe it has no
    effect. `PipeAuth.deferred_psk()` offers a pre-shared key given later with
    `Session.set_join_secret`; `auth.with_deferred_psk()` adds that to the
    exporter. It excludes a static key (`ValueError` when the session
    starts). Multipath or resume without a source raises `ValueError`."""

    __slots__ = ("_deferred", "_end_to_end", "_exporter", "_psk")
    _exporter: bool
    _psk: bytes | None
    _end_to_end: bool
    _deferred: bool

    def __init__(
        self,
        *,
        exporter: bool = False,
        psk: bytes | None = None,
        end_to_end: bool = False,
        deferred_psk: bool = False,
    ) -> None:
        object.__setattr__(self, "_exporter", exporter)
        object.__setattr__(self, "_psk", None if psk is None else bytes(psk))
        object.__setattr__(self, "_end_to_end", end_to_end)
        object.__setattr__(self, "_deferred", deferred_psk)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PipeAuth is immutable")

    @staticmethod
    def exporter() -> PipeAuth:
        """The exporter of the innermost end-to-end handshake of the
        bootstrap carriers."""
        return PipeAuth(exporter=True)

    @staticmethod
    def psk(key: bytes) -> PipeAuth:
        """A pre-shared key."""
        return PipeAuth(psk=key)

    @staticmethod
    def deferred_psk() -> PipeAuth:
        """A pre-shared key given later with `Session.set_join_secret`, for
        example once the application authenticated the peer. Until then
        local joins fail with `JoinPendingError` and the
        peer's are held for at most the handshake timeout."""
        return PipeAuth(deferred_psk=True)

    def with_psk(self, key: bytes) -> PipeAuth:
        """These credentials with the pre-shared key `key` added."""
        return PipeAuth(
            exporter=self._exporter,
            psk=key,
            end_to_end=self._end_to_end,
            deferred_psk=self._deferred,
        )

    def with_end_to_end(self) -> PipeAuth:
        """These credentials, with pipe 0 stated to be proven end to end."""
        return PipeAuth(
            exporter=self._exporter,
            psk=self._psk,
            end_to_end=True,
            deferred_psk=self._deferred,
        )

    def with_deferred_psk(self) -> PipeAuth:
        """These credentials with a deferred pre-shared key added."""
        return PipeAuth(
            exporter=self._exporter,
            psk=self._psk,
            end_to_end=self._end_to_end,
            deferred_psk=True,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PipeAuth):
            return NotImplemented
        return (
            self._exporter,
            self._psk,
            self._end_to_end,
            self._deferred,
        ) == (
            other._exporter,
            other._psk,
            other._end_to_end,
            other._deferred,
        )

    def __hash__(self) -> int:
        return hash(
            (
                self._exporter,
                self._psk,
                self._end_to_end,
                self._deferred,
            )
        )

    def __repr__(self) -> str:
        parts = [
            n
            for n, on in (
                ("exporter", self._exporter),
                ("psk", self._psk is not None),
                ("end_to_end", self._end_to_end),
                ("deferred_psk", self._deferred),
            )
            if on
        ]
        return f"PipeAuth({', '.join(parts) or 'none'})"


_LIVENESS: Final[dict[str, Any]] = _DEFAULTS["liveness"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Liveness:
    """A session's liveness settings (`Config.liveness`), replaced as a whole
    by assigning `Session.liveness` (`dataclasses.replace(session.liveness,
    ...)` changes some). Durations are seconds; invalid values raise
    `ValueError` where they are used.

    `keep_alive_period` (15 s, at least 1; `None` off): QX_PING when idle,
    capped at half the effective idle timeout. `suspect_floor` (0.25 s, at
    least 0.05): the floor of the suspicion timer. `dead_timeout` (`AUTO`,
    derived; `None` turns stall-based failure off: a stalled pipe still
    turns suspect, is avoided, has its data reinjected and is probed, but
    only its carrier's error or end, its drain deadline or its removal fail
    it; else at least 1, any larger value safe): how long a suspect pipe
    stays suspect before it fails. It is off by default on a carrier that
    reports its own failure (`PipeIo.reports_failure`). `standby_probe` (1 s, at least 1; `None` off: standby pipes are
    probed at `probe_interval`). `probe_interval` (15 s, at least 1; `None`
    turns the idle probes off). `probe_jitter` (0.25, in [0, 1); 0 gives
    the fixed schedule tests use)."""

    keep_alive_period: float | None = _LIVENESS["keep_alive_period"]
    suspect_floor: float = _LIVENESS["suspect_floor"]
    dead_timeout: float | Auto | None = _LIVENESS["dead_timeout"]
    standby_probe: float | None = _LIVENESS["standby_probe"]
    probe_interval: float | None = _LIVENESS["probe_interval"]
    probe_jitter: float = _LIVENESS["probe_jitter"]


@dataclass(frozen=True, slots=True, kw_only=True)
class PipeLiveness:
    """A pipe's own liveness settings (`PipeOptions.liveness`, replaced with
    `Pipe.update(liveness=...)`): the `Liveness` fields of the same names
    that apply to one pipe, each `INHERIT` (the default, following the
    session's) or a value; `probe_interval=None` turns the pipe's idle
    probes off. `dead_timeout` `INHERIT` follows the carrier (off on one
    that reports its own failure, `PipeIo.reports_failure`), else the
    session's; `AUTO` (derived), `None` (stall-based failure off) or a
    value override both. Durations are seconds; invalid values raise
    `ValueError` where they are used."""

    suspect_floor: float | Inherit = INHERIT
    dead_timeout: float | Auto | Inherit | None = INHERIT
    probe_interval: float | Inherit | None = INHERIT
    probe_jitter: float | Inherit = INHERIT


@dataclass(frozen=True, slots=True, kw_only=True)
class QualityBand:
    """When to report a pipe's quality (`PipeQualityChanged`): once its
    smoothed RTT moved by more than `rtt` seconds (at least 1 ns), or its delivery
    rate by more than the factor `rate_ratio` (finite, at least 1; 1 reports
    every change), from the last reported values, at most once per
    `min_interval` seconds (at least 1 ns; `None`: no minimum; default
    `DEFAULT_MIN_INTERVAL`, 1 s). A half left at `None` reports nothing; a
    band with both halves `None` is not a band (to report nothing, set the
    session's band to `None`, or a pipe's). An `rtt` or `min_interval` below
    1 ns (zero and negative values included), a `rate_ratio` below 1, and a NaN or infinite value raise
    `ValueError`."""

    rtt: float | None = None
    rate_ratio: float | None = None
    min_interval: float | None = _zmux.DEFAULT_MIN_INTERVAL

    def __post_init__(self) -> None:
        _zmux._check_quality_band(self)


_PIPE_DEFAULTS: Final[dict[str, Any]] = _zmux._pipe_option_defaults()


@dataclass(frozen=True, slots=True, kw_only=True)
class PipeOptions:
    """Every option of a pipe (`Session.add_pipe`, `AttachmentSpec`); durations in
    seconds. Invalid values raise `ValueError` where the options are used.

    Fixed when the pipe is added: `direction` (`Direction.BIDI`), the
    directions the pipe carries; `record_mode` (`INHERIT`:
    `Config.record_policy`, else sealed); `key_group` (`INHERIT`: the local
    preference), the key group of the join; `label`, the application's name
    for the pipe (`None`: none); `fate_group` (0: independent), pipes that
    fail together.

    Changeable on a live pipe with `Pipe.update`: each is `INHERIT`, the
    default, which is the unset setting (`Pipe.update(field=CLEAR)` returns a
    field to it, and `Pipe.options` reads it back as `INHERIT`), or a value.
    `CLEAR` belongs to `Pipe.update`; in a `PipeOptions` it raises
    `TypeError`. `send_priority`, the tier of the local outbound direction,
    lower preferred (`INHERIT`: the peer's request, else 0);
    `receive_priority`, the tier requested for the peer's outbound direction
    (`INHERIT`: 0); `send_standby`, the local outbound direction takes data
    only on failover (`INHERIT`: the peer's request, else available);
    `receive_standby`, asks the peer to do so (`INHERIT`: no); `weight`, its
    share among the pipes of a tier (`INHERIT`: 1; 0 excludes the pipe);
    `probation` (`INHERIT`: the session's; `AUTO`: derived from the pipe's
    RTT; `None` off; else the base in seconds); `liveness` (a `PipeLiveness`,
    each of whose fields is `INHERIT` or a value; `INHERIT`: the session's);
    `quality_band` (a `QualityBand`; `INHERIT`: the session's; `None`: no
    reports for this pipe whatever the session's band is)."""

    direction: Direction = _PIPE_DEFAULTS["direction"]
    record_mode: RecordMode | str | Inherit = _PIPE_DEFAULTS["record_mode"]
    key_group: KeyGroup | int | Inherit = _PIPE_DEFAULTS["key_group"]
    send_priority: int | Inherit = _PIPE_DEFAULTS["send_priority"]
    receive_priority: int | Inherit = _PIPE_DEFAULTS["receive_priority"]
    send_standby: bool | Inherit = _PIPE_DEFAULTS["send_standby"]
    receive_standby: bool | Inherit = _PIPE_DEFAULTS["receive_standby"]
    weight: int | Inherit = _PIPE_DEFAULTS["weight"]
    probation: float | Auto | Inherit | None = _PIPE_DEFAULTS["probation"]
    liveness: PipeLiveness | Inherit = _PIPE_DEFAULTS["liveness"]
    quality_band: QualityBand | Inherit | None = _PIPE_DEFAULTS["quality_band"]
    label: str | None = _PIPE_DEFAULTS["label"]
    fate_group: int = _PIPE_DEFAULTS["fate_group"]

    def __post_init__(self) -> None:
        _zmux._check_pipe_option_sentinels(self)


class Directions(enum.IntFlag):
    """Local sending and receiving directions in a capacity observation."""

    NONE = 0
    SEND = 1
    RECEIVE = 2
    BOTH = SEND | RECEIVE


class DatagramCopyPolicy(_Enum):
    """Requests a single datagram or the session's adaptive replica policy."""

    SINGLE = "single"
    ADAPTIVE = "adaptive"


class DatagramCarrier(_Enum):
    """Chooses whether the datagram may use a reliable carrier."""

    PREFER_NATIVE = "prefer_native"
    REQUIRE_NATIVE = "require_native"


_DATAGRAM: Final[dict[str, Any]] = _DEFAULTS["datagram"]
_DATAGRAM_PRIORITY = Priority(*_DATAGRAM["priority"])


class DirectionHealth(NamedTuple):
    """Current service state and stability evidence for a local direction."""

    state: str
    reason: str
    since: float | None
    can_carry: bool
    """Whether the direction can provide service in this observation."""
    proof_kind: str | None
    settled: bool
    evidence: DirectionEvidence | None
    """The service generation and its start, including on a health event."""


class DirectionEvidence(NamedTuple):
    """Sequence and monotonic start time of a directional service interval."""

    generation: int
    since: float


class PipeHealth(NamedTuple):
    """Committed health of an attachment, including explicitly absent directions."""

    seq: int
    send: DirectionHealth
    receive: DirectionHealth
    peer_attached: bool
    joined_at: float | None
    attached_at: float | None
    send_evidence: DirectionEvidence | None
    receive_evidence: DirectionEvidence | None
    eligible_for_new_data: bool
    """Whether the outbound path can be scheduled for new data. A temporary
    scheduling penalty can clear this flag while `send.can_carry` stays true."""
    since_join: float
    failure: str | None
    settled: bool


class CarrierFailure(NamedTuple):
    """A physical connection failure committed by the session."""

    connection: int
    round: int
    kind: str
    retry_after: float | None
    at: float
    retry_at: float | None


class PipeHealthChange(NamedTuple):
    """One directional service transition with its before and after evidence.

    Scheduling penalties can change the current snapshot's eligibility while
    leaving the service generation intact. A sequence gap calls for a fresh
    health snapshot.
    """

    seq: int
    pipe: int
    half: PipeHalf
    before: DirectionHealth
    after: DirectionHealth
    reason: str
    at: float
    since_join: float
    failure: str | None
    physical_failure: CarrierFailure | None


class CarrierLoss(NamedTuple):
    """Paired counters for an actual carrier connection and observation interval."""

    connection: int
    generation: int
    source: CarrierSource
    unit: str
    since: float
    at: float
    sent: int
    lost: int


class CarrierHalfSource(NamedTuple):
    """Immutable attribution for one carrier half. An adapter supplies connection identity."""

    connection: int | None = None
    kind: CarrierKind | str | None = None
    route: str | None = None


class HalfTotals(NamedTuple):
    """Complete records and known partial bytes in one directional source segment."""

    source: CarrierHalfSource
    bytes: int
    records: int
    active_complete_record_bytes: int
    retired_complete_record_bytes: int
    partial_bytes: int
    imprecise: bool
    source_overflow: bool


class PipeAccounting(NamedTuple):
    """Record accounting of both halves, including retired lanes."""

    pipe: int
    send: tuple[HalfTotals, ...]
    receive: tuple[HalfTotals, ...]


class JoinFirstBatch(NamedTuple):
    """Structure of the authenticated batch, before flow control and stream checks."""

    encoded_bytes: int
    stream_frames: int
    stream_bytes: int
    malformed: bool


class JoinAuthorization(NamedTuple):
    """Authenticated Join facts captured before any state from this Join is committed."""

    session: int
    auth_generation: int
    join_epoch: int
    pipe_id: int
    direction: Direction
    record_mode: RecordMode
    carrier_kind: CarrierKind | str | None
    send: CarrierHalfSource
    receive: CarrierHalfSource
    principal: object | None
    admitted: object | None
    first_batch: JoinFirstBatch


class Cooldown(NamedTuple):
    """One active retry decision with nominal and sampled waits in seconds."""

    reason: str | None
    started_at: float | None
    nominal_wait: float
    sampled_wait: float | None
    retry_at: float
    remaining: float


class RetryMetrics(NamedTuple):
    """Candidate retry pacing and counters. Durations are in seconds."""

    attempted_starts: int
    recovery_nominal: float
    recovery_sampled: float
    recovery_retry_at: float | None
    faults: int
    suppressions: Mapping[str, int]
    elapsed: float | None
    remaining: float


class CarrierMeasurementSource(_Enum):
    """How the cache acquired a performance sample."""

    PROTOCOL = "protocol"
    """Observed on an attached member."""

    HOST_REPORT = "host_report"
    """Reported through a registered host source."""


class CarrierMeasurement(NamedTuple):
    """One performance sample with its original age and effective validity in seconds.

    The source is unknown for an imported version 2 sample. A sample with
    `age >= valid_for` has expired.
    """

    value: float
    age: float
    valid_for: float
    source: CarrierMeasurementSource | None


class CarrierScore(NamedTuple):
    """Current carrier score, decayed sample weights and local cooldown.

    `age` is the age of the scoring history in seconds, when known.
    `rtt.value` is in seconds and `rate.value` in bytes per second.
    """

    score: float
    attempts: int
    weight: float
    success_weight: float
    window_survived: float
    short_drops: float
    post_window_faults: float
    age: float | None
    cooldown: Cooldown | None
    post_window_seconds: float
    rtt: CarrierMeasurement | None
    rate: CarrierMeasurement | None


class DatagramPath(NamedTuple):
    """Current original-copy payload and native channel bounds in bytes."""

    payload: int | None
    native_payload: int | None
    native_room: int | None


class DatagramDrop(_Enum):
    """Why the sender dropped an original datagram."""

    NO_NATIVE_PATH = "no_native_path"
    QUEUE_OVERFLOW = "queue_overflow"
    LIMITER = "limiter"
    CODEL = "codel"
    DEADLINE = "deadline"
    SEQUENCE_EXHAUSTED = "sequence_exhausted"
    CLOSED_FLOW = "closed_flow"
    SIZE = "size"
    CARRIER_REJECTED = "carrier_rejected"
    CARRIER_CANCELLED = "carrier_cancelled"


class DatagramDrops(NamedTuple):
    """Outgoing originals dropped locally, grouped by Rust's decision."""

    no_native_path: int
    queue_overflow: int
    limiter: int
    codel: int
    deadline: int
    sequence_exhausted: int
    closed_flow: int
    size: int
    carrier_rejected: int
    carrier_cancelled: int


class DatagramReplicaDegradation(NamedTuple):
    """Extra copies that could not be sent."""

    budget: int
    no_eligible_pipe: int
    fate: int
    open_fence: int
    size: int
    deadline: int
    carrier_rejected: int
    carrier_cancelled: int


class DatagramDispatchStats(NamedTuple):
    """Original and replica dispatch and handoff counts for one representation."""

    originals: int
    original_bytes: int
    originals_accepted: int
    original_bytes_accepted: int
    originals_failed: int
    replicas: int
    replica_bytes: int
    replicas_accepted: int
    replica_bytes_accepted: int
    replicas_failed: int


class DatagramStats(NamedTuple):
    """Datagram drops, replica degradation, handoffs and deduplication counts."""

    duplicates_dropped: int
    stale_dropped: int
    drops: DatagramDrops
    replica_degradation: DatagramReplicaDegradation
    record: DatagramDispatchStats
    native: DatagramDispatchStats


class DatagramEvidenceSource(_Enum):
    """Source of a datagram path timing measurement."""

    DATAGRAM_ACK = "DatagramAck"


class DatagramFeedback(NamedTuple):
    """Bounded evidence for one outgoing pipe and carrier mode.

    Report RTT includes the return path. Missing or expired reports leave
    forward loss unknown. Times and durations use monotonic seconds.
    """

    tracking: int
    awaiting: int
    arrived: int
    expired: int
    report_rtt: float | None
    report_variation: float | None
    sampled_at: float | None
    sample_age: float | None
    samples: int
    sample_source: DatagramEvidenceSource | str | None


class DatagramArrivals(NamedTuple):
    """Reportable frames and payload bytes before deduplication and delivery."""

    frames: int
    bytes: int
    last_at: float


class MemberSnapshot(NamedTuple):
    """Current membership and confirmed directional coverage."""

    id: int
    candidate: str | None
    expected: Directions
    pipes: tuple[int, ...]
    covered: Directions
    stable: Directions
    complete: bool


class OpenRequest(NamedTuple):
    """The actual carrier opener invocation and its reserved layout."""

    attempt: int
    cause: str
    need: Directions
    stage: str
    layout: tuple[AttachmentSpec, ...]
    deadline: float


class AttemptResult(NamedTuple):
    """Terminal state, assigned attachments and their final accounting tickets."""

    id: int
    generation: int | None
    """The originating controller binding for managed work."""
    batch: int
    """The session-local capacity batch identifier."""
    reason: str
    error: BaseException | None
    open_error: BaseException | None
    member: int | None
    pipes: tuple[int, ...]
    tickets: tuple[_zmux.AccountingTicket, ...]


class AttemptSnapshot(NamedTuple):
    """Current progress and the retained terminal result, if any."""

    id: int
    cause: str
    need: Directions
    candidate: str | None
    member: int
    pipes: tuple[int, ...]
    replied: tuple[int, ...]
    confirmed: tuple[int, ...]
    started: float | None
    ended: float | None
    result: AttemptResult | None
    generation: int | None
    """The originating controller binding for managed work."""
    batch: int
    """The session-local capacity batch identifier."""


class QuotaDeficit(NamedTuple):
    """Count of missing complete members in a target quota."""

    group: str
    quota: str
    missing: int


class ChangeResult(NamedTuple):
    """Committed retirement identities and the resulting capacity observation."""

    draining: tuple[int, ...]
    capacity: CapacitySnapshot


class ControllerSnapshot(NamedTuple):
    """The controller's latest committed plan and associated core observation.

    A takeover snapshot identifies the previous binding in `predecessor`.
    `capacity.covered` and `capacity.stable` describe service observed at
    the same commit as `paths` and `members`.
    """

    generation: int
    predecessor: int | None
    revision: int
    capacity: CapacitySnapshot
    members: tuple[MemberSnapshot, ...]
    paths: tuple[_zmux.ControllerPath, ...]
    deficits: tuple[QuotaDeficit, ...]
    attempts: tuple[int, ...]
    last_attempt: AttemptResult | None
    blocked: str | None
    next_retry: float | None
    host_calls_in_flight: int
    """Opener slots still charged to this binding."""
    cleanup_in_flight: int
    """Attachment cleanup permits still charged to this binding."""
    domain_openers: int
    """Opener slots charged across the controller domain."""
    domain_cleanup: int
    """Attachment cleanup permits charged across the controller domain."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AccountingPolicy:
    """Opt-in final and live record accounting with an attribution limit."""

    enabled: bool = False
    source_limit: int = 0
    strict: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class CarrierObservation:
    """Original monotonic sample time, lifetime and protocol performance evidence."""

    at: float | None = None
    duration: float = 0.0
    rtt: float = 0.0
    rate: int = 0
    valid_for: float = 0.0


@dataclass(frozen=True, slots=True, kw_only=True)
class CapacityLimits:
    """Local attachment and carrier limits."""

    steady_attachments: int = 1
    join_headroom: int = 8
    local_carriers: int | None = None
    pending_peer_joins: int = 4
    recovery_burst: int = 4


@dataclass(frozen=True, slots=True, kw_only=True)
class CapacitySnapshot:
    """An atomic observation of session limits, reservations and coverage."""

    observed: int
    reserved_attachments: int
    policy_revision: int
    auth_generation: int
    protocol_envelope: int
    local_carrier_limit: int
    local_attachments: int
    peer_attachments: int
    pending_peer_joins: int
    peer_retry_at: float | None
    authorizing_peer_joins: int
    local_carriers: int
    limits: CapacityLimits
    required: Directions
    covered: Directions
    stable: Directions


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionPolicy:
    """Versioned local limits and authenticated Join authorization."""

    revision: int = 0
    auth_generation: int = 0
    limits: CapacityLimits = CapacityLimits()
    authorize_join: Callable[[JoinAuthorization], bool | Awaitable[bool]] | None = (
        field(default=None, compare=False, repr=False)
    )
    join_source_routes: tuple[str, ...] | None = None
    candidate_exclusions: tuple[tuple[str, Directions], ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class PathPreference:
    """Tier, standby flag and relative weight for one local direction."""

    tier: int = 0
    standby: bool = False
    weight: int = 1


@dataclass(frozen=True, slots=True)
class TargetCandidate:
    """A registered candidate and optional per-direction scheduling preferences."""

    id: str
    send: PathPreference | None = field(default=None, kw_only=True)
    receive: PathPreference | None = field(default=None, kw_only=True)


@dataclass(frozen=True, slots=True)
class MemberQuota:
    """Desired number of complete members with interchangeable candidates."""

    id: str
    count: int = field(kw_only=True)
    directions: Directions = field(kw_only=True)
    candidates: tuple[TargetCandidate, ...] = field(kw_only=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationPolicy:
    """Age or record-byte thresholds for replacing complete members."""

    max_age: float | None = None
    send_bytes: int | None = None
    receive_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class GroupTarget:
    """A named group of quotas that replaces one member at a time."""

    id: str
    quotas: tuple[MemberQuota, ...] = field(kw_only=True)
    rotation: RotationPolicy = field(default=RotationPolicy(), kw_only=True)


@dataclass(frozen=True, slots=True)
class ReplaceIntent:
    """Requests make-before-break replacement of a set of existing members."""

    id: str
    members: tuple[int, ...] = field(kw_only=True)
    min_epoch: int = field(default=0, kw_only=True)
    evidence: tuple[_zmux.QualityEvidence, ...] = field(default=(), kw_only=True)
    """Original path observations relied on for the replacement."""


@dataclass(frozen=True, slots=True)
class SessionTarget:
    """A revision of the desired member composition and explicit replacements."""

    revision: int = 0
    groups: tuple[GroupTarget, ...] = field(default=(), kw_only=True)
    replace: tuple[ReplaceIntent, ...] = field(default=(), kw_only=True)


@dataclass(frozen=True, slots=True)
class AttachmentSpec:
    """One carrier's expected local directions and Join options."""

    directions: Directions
    options: PipeOptions = field(default=PipeOptions(), kw_only=True)


@dataclass(frozen=True, slots=True)
class MemberSpec:
    """The exact attachment layout of a complete new member."""

    attachments: tuple[AttachmentSpec, ...]
    candidate: str | None = field(default=None, kw_only=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class ChangeRequest:
    """A capacity transaction based on a session observation."""

    policy_revision: int
    observed: int
    timeout: float = 0
    add: tuple[MemberSpec, ...] = ()
    drain: tuple[int, ...] = ()
    min_epoch: int = 0


@dataclass(frozen=True, slots=True)
class Duplicate:
    """Requests the given total copies, subject to the session's send budget."""

    count: int


@dataclass(frozen=True, slots=True)
class DatagramDeadline:
    """An absolute local monotonic deadline, in seconds."""

    at: float


@dataclass(frozen=True, slots=True, kw_only=True)
class DatagramSendOptions:
    """Local send overrides. A duration is a hop-local TTL. None explicitly clears the deadline."""

    copies: DatagramCopyPolicy | Duplicate | Literal["single", "adaptive"] | None = None
    urgent: bool | None = None
    independent_fate: bool | None = None
    deadline: float | DatagramDeadline | Inherit | None = INHERIT
    carrier: DatagramCarrier | Literal["prefer_native", "require_native"] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DatagramConfig:
    """Outgoing datagram defaults and queue bounds, plus the receive deduplication window."""

    dedup_window: int = _DATAGRAM["dedup_window"]
    send_bytes: int = _DATAGRAM["send_bytes"]
    send_flow_queue: int = _DATAGRAM["send_flow_queue"]
    send_flow_bytes: int = _DATAGRAM["send_flow_bytes"]
    stream_receive_bytes: int | None = _DATAGRAM["stream_receive_bytes"]
    hold_packets: int | None = _DATAGRAM["hold_packets"]
    hold_time: float | None = _DATAGRAM["hold_time"]
    copy_limit: int = _DATAGRAM["copy_limit"]
    replica_percent: int = _DATAGRAM["replica_percent"]
    replica_standby: bool = _DATAGRAM["replica_standby"]
    priority: Priority = _DATAGRAM_PRIORITY
    defaults: DatagramSendOptions = DatagramSendOptions()


@dataclass(frozen=True, slots=True)
class Backoff:
    """An exponential retry wait with nominal bounds and optional jitter on either side."""

    min: float = _zmux.DEFAULT_MIN_BACKOFF
    max: float = field(default=_zmux.DEFAULT_MAX_BACKOFF, kw_only=True)
    jitter: float = field(default=_zmux.DEFAULT_BACKOFF_JITTER, kw_only=True)
    jitter_up: float = field(default=0.0, kw_only=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class CapacityFloor:
    """The floor under the session's outbound capacity in bytes per second:
    `CapacityBelow` once below `rate` (at least 1), `CapacityRestored` once
    back at `rate * recovery_ratio` or more (a finite number of at least 1;
    1 is no hysteresis; default `DEFAULT_RECOVERY_RATIO`, 1.25). A zero
    `rate`, a `recovery_ratio` below 1 (0 included), and a NaN or infinite
    one raise `ValueError`."""

    rate: int
    recovery_ratio: float = _zmux.DEFAULT_RECOVERY_RATIO

    def __post_init__(self) -> None:
        if self.rate < 1:
            raise ValueError("rate is at least 1 byte per second")
        if not 1 <= self.recovery_ratio < math.inf:
            raise ValueError("recovery_ratio is a finite number of at least 1")


SpliceKind = Literal["stream"] | Literal["capsule"] | Literal["datagram"]
"""The shape of a splice input."""

SpliceRoute = Literal["a_to_b"] | Literal["b_to_a"]
"""The direction that owns a splice input."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SpliceMeta:
    """Snapshot of an input's metadata at admission."""

    route: SpliceRoute
    """Direction that admitted the input."""
    kind: SpliceKind
    """Input shape."""
    capsule_type: int | None
    """Protocol Type of a reliable capsule."""
    context: int | None
    """Context ID of a datagram or DATAGRAM capsule."""
    sequence: int
    """Direction-local input sequence."""
    generation: int
    """Hook generation at admission."""
    source_offset: int | None
    """Offset of the original reliable input, if applicable."""
    injected: bool
    """Whether the input came from the local control channel."""
    source_stream: int | None
    """Source hop's Stream ID, if assigned."""
    target_stream: int | None
    """Target hop's Stream ID, if assigned."""
    replayable: bool
    """Whether the source can carry replayable data."""
    preamble: Preamble
    """The inbound stream's opening metadata."""
    label: str
    """The application-supplied route label."""


class SpliceHook(Protocol):
    """A synchronous chain step on the splice's asyncio event loop."""

    def __call__(self, unit: SpliceUnit, /) -> SpliceDecision:
        """Inspect the group and decide how it proceeds."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class SpliceHooks:
    """One direction's hook chains. Entries run in tuple order."""

    stream: tuple[SpliceHook, ...] = ()
    """Steps for reliable byte blocks in byte mode."""
    capsule: tuple[SpliceHook, ...] = ()
    """Steps for complete reliable capsules in packet mode."""
    datagram: tuple[SpliceHook, ...] = ()
    """Steps for stream datagrams in either mode."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SpliceLimits:
    """Per-direction budgets for a controlled splice. None selects a size-derived
    default for byte budgets. Waits are measured from first admission."""

    hook_steps: int | None = None
    """Maximum steps in each chain."""
    group_items: int | None = None
    """Maximum outputs in a replacement group."""
    group_bytes: int | None = None
    """Maximum logical bytes per group including capsule headers."""
    group_backing_bytes: int | None = None
    """Maximum distinct backing capacity per group."""
    descriptors: int | None = None
    """Maximum payload fragments per unit or group."""
    queue_items: int | None = None
    """Maximum pending items per direction."""
    queue_bytes: int | None = None
    """Maximum distinct backing capacity per direction."""
    reliable_cleanup_slots: int | None = None
    """Maximum in-flight reliable limiter acquisitions per direction."""
    datagram_cleanup_slots: int | None = None
    """Maximum in-flight datagram limiter acquisitions per direction."""
    datagram_delay: bool = False
    """Allow hooks to defer datagrams."""
    wait_cap: float | None = 0
    """Safety cap in seconds. Zero selects the default and None disables it."""


class SpliceSample(NamedTuple):
    """A sampled input from a diagnostic mirror."""

    kind: SpliceKind
    """Input shape."""
    capsule_type: int | None
    """Protocol Type of a reliable capsule."""
    context: int | None
    """Context ID of a datagram or DATAGRAM capsule."""
    sequence: int
    """Direction-local input sequence."""
    generation: int
    """Hook generation at admission."""
    prefix: bytes | memoryview
    """Captured prefix of the input payload."""


class Limiter(Protocol):
    """A rate limiter of a splice direction (`zmux.splice(a_to_b=...)`),
    reserve then refund, in bytes. `acquire(min, max)` waits until it can
    grant and takes and returns n bytes, `min <= n <= max`; `try_acquire(min,
    max)` does the same without waiting, or returns 0 with nothing taken;
    `refund(n)` gives back unused bytes, including prepaid bytes that lose
    their final local carrier opportunity. The binding calls the acquire methods
    with `1 <= min <= max`. An empty datagram passes without a limiter call.
    `(n, n)` asks for a whole capsule or
    datagram. If the limiter cannot grant that amount, `acquire` raises and
    `try_acquire` returns 0.

    Each runs on the splice's event loop and must allow the loop to make
    progress. A plain method can also supply an immediate `acquire` result.
    `try_acquire` decides the current datagram. The parameters are
    positional-only.

    A limiter that fails is reported as unraisable: an `acquire` that raises
    or grants anything but an int in `min..=max` ends the direction with
    `SpliceEnd.LIMITER_FAILED`; a `try_acquire` that raises grants nothing;
    a `refund` that raises changes nothing. An invalid positive grant is
    refunded at once."""

    @property
    def max_burst_bytes(self) -> int:
        """Maximum atomic grant, regardless of the current balance."""
        ...

    def acquire(self, minimum: int, maximum: int, /) -> int | Awaitable[int]:
        """Waits for and takes a grant between the minimum and maximum."""
        ...

    def try_acquire(self, minimum: int, maximum: int, /) -> int:
        """Takes a grant between the minimum and maximum. Returns zero when it would wait."""
        ...

    def refund(self, n: int, /) -> None:
        """Returns `n` unused bytes. This method must never raise."""
        ...


class SpliceEnd(_Enum):
    """How one direction of a splice ended."""

    FINISHED = "finished"
    RESET = "reset"
    STOPPED = "stopped"
    UPSTREAM_LOST = "upstream_lost"
    DOWNSTREAM_LOST = "downstream_lost"
    CANCELLED = "cancelled"
    """Aborted with `SpliceAbort`; `SpliceDirection.code` is its code."""
    LIMITER_FAILED = "limiter_failed"
    """The direction's limiter failed (see `Limiter`): the downstream part
    was reset and the upstream part stopped with `ZMUX_CANCELLED`."""
    HOOK_RESET = "hook_reset"
    """A hook reset the target and stopped the source with its chosen code."""
    HOOK_FAILED = "hook_failed"
    """A hook failed or exceeded its output budget."""
    WAIT_TIMEOUT = "wait_timeout"
    """A reliable input expired while waiting."""
    PACKET_ERROR = "packet_error"
    """A malformed capsule ended the direction with `ZMUX_PACKET_ERROR`."""


class SpliceDropReason(_Enum):
    """Why the relay discarded an input before publication."""

    HOOK = "dropped_hook"
    EXPIRED = "dropped_expired"
    QUEUE_FULL = "dropped_queue_full"
    LIMITER = "dropped_limiter"
    BLOCKED = "dropped_blocked"
    TOO_LARGE = "dropped_too_large"
    NO_PATH = "dropped_no_path"
    SEQUENCE_EXHAUSTED = "dropped_sequence_exhausted"
    FLOW_CLOSED = "dropped_flow_closed"
    CODEL = "dropped_codel"


@dataclass(frozen=True, slots=True, kw_only=True)
class SpliceDrops:
    """Counts of datagram groups discarded before target publication."""

    dropped_hook: int
    dropped_expired: int
    dropped_queue_full: int
    dropped_limiter: int
    dropped_blocked: int
    dropped_too_large: int
    dropped_no_path: int
    dropped_sequence_exhausted: int
    dropped_flow_closed: int
    dropped_codel: int

    @property
    def total(self) -> int:
        """Number of groups discarded for all reasons."""
        return sum(dataclasses.astuple(self))


class SpliceHandoffStats(NamedTuple):
    """One snapshot of target acceptance and local carrier settlement."""

    accepted_bytes: int
    """Logical bytes accepted by the target."""
    first_carrier_bytes: int
    """Logical bytes handed off completely to a local carrier for the first time."""
    unsent_bytes: int
    """Accepted bytes that lost their final local carrier opportunity."""
    pending_bytes: int
    """Accepted bytes still waiting for their first local carrier outcome."""
    unsent_refunded_bytes: int
    """Prepaid bytes the relay returned after their final carrier opportunity."""
    native_count: int
    """Datagrams first handed off in native form."""
    record_count: int
    """Datagrams first handed off in a record."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SpliceDirection:
    """Forwarding and accounting for a finished splice direction."""

    bytes: int
    datagram_bytes: int
    datagrams_as_capsules: int
    input_units: int
    input_bytes: int
    enqueued_items: int
    replacements: int
    drops: SpliceDrops
    mirror_misses: int
    wait_time: float
    """Time spent waiting on hook readiness in seconds."""
    capsule_count: int
    accepted_bytes: int
    """Logical bytes accepted by the target, including capsule headers."""
    handoffs: _zmux.SpliceHandoffs | None
    """Live settlement for controlled or limited directions."""
    payload_copy_bytes: int
    encode_bytes: int
    mirror_copy_bytes: int
    pre_admission_refunded_bytes: int
    """Bytes refunded by the relay before target acceptance at direction end."""
    end: SpliceEnd
    code: int | None
    cause: str | None
    """Local budget failure, when it caused the direction to end."""


class SpliceDisposition(NamedTuple):
    """Local target outcome of an admitted injection.

    A submitted injection may still be pending in the direction's handoffs.
    """

    status: Literal["submitted", "dropped", "direction_ended"]
    sequence: int
    generation: int
    accepted_bytes: int
    """Logical bytes accepted by the target, including a partial write."""
    enqueued_items: int
    """Complete items accepted by the target."""
    drop_reason: SpliceDropReason | None
    end: SpliceEnd | None
    code: int | None


class SpliceEvent(NamedTuple):
    """A committed event from the direction owner."""

    route: SpliceRoute
    kind: Literal["hooks_replaced", "pause_acknowledged", "direction_finished"]
    generation: int | None
    token: int | None
    end: SpliceEnd | None
    code: int | None


@dataclass(frozen=True, slots=True)
class SpliceResult:
    """The two directions of a finished splice."""

    a_to_b: SpliceDirection
    b_to_a: SpliceDirection


class SendPolicy(_Enum):
    """How a packet stream sends a packet."""

    PREFER_DATAGRAM = "prefer_datagram"
    """As a datagram when the session's datagrams are in use and the packet
    fits the stream's largest datagram now, else as a capsule. A datagram a
    limiter refuses is dropped, never sent as a capsule instead."""
    STREAM_ONLY = "stream_only"
    """Always as a capsule: in order and reliably."""
    DATAGRAM_ONLY = "datagram_only"
    """Always as a datagram: a packet that does not fit fails."""


class Sent(_Enum):
    """How a packet left."""

    DATAGRAM = "datagram"
    CAPSULE = "capsule"


class Packet(NamedTuple):
    """A packet received: its Context ID and payload."""

    context: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class PacketStats:
    """The counters of a packet stream or of one of its halves."""

    sent_datagrams: int
    sent_capsules: int
    dropped_too_large: int
    """Not sent: too large for a datagram (`SendPolicy.DATAGRAM_ONLY`)."""
    dropped_limited: int
    """Not sent: a datagram limiter refused them."""
    received_datagrams: int
    received_capsules: int
    skipped_capsules: int
    """Capsules of unknown types skipped."""


class DuplicateRule(_Enum):
    """The value that decided between duplicate sessions."""

    IDENTITY = "identity"
    SESSION_NONCE = "session_nonce"
    ROLE_NONCE = "role_nonce"


@dataclass(frozen=True, slots=True, kw_only=True)
class Resolved:
    """The outcome of `resolve_duplicate`: the session kept, the one being
    drained, the rule that decided, and whether a rejoin was started."""

    survivor: _zmux.Session
    loser: _zmux.Session
    rule: DuplicateRule | str
    rejoin_started: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule", _enum_of(DuplicateRule, str(self.rule)))


class Scheduler(_Enum):
    """A built-in scheduling policy (`Config.scheduler`; its value, a
    string, is accepted too). The binding takes no policy written in
    Python: one would run on the driver's decision path under the
    interpreter lock."""

    AFFINITY = "affinity"
    SESSION_AFFINITY = "session-affinity"
    SPREAD_ETA = "spread-eta"
    SPREAD_ROUND_ROBIN = "spread-round-robin"
    SPREAD_RATE_WEIGHTED = "spread-rate-weighted"


class Redundancy(_Enum):
    """`Config.redundancy` (its value, a string, is accepted too): `URGENT`
    sends the stream directions of urgency 0 to 2 and the first chunk after
    an idle period redundantly on a second pipe; `OFF` sends nothing
    redundantly."""

    URGENT = "urgent"
    OFF = "off"


class KeyAlg(enum.IntEnum):
    """A key algorithm of the secure carrier: what a KeyId and a signing key
    are of."""

    X25519 = _zmux._KEYALG_X25519
    MLDSA44 = _zmux._KEYALG_MLDSA44


class Tracer:
    """`Config(tracer=...)`: observes a session's events without taking them
    from `Session.events()`. Subclass it and override what you need; each
    method runs on the `Config`'s event loop, in order
    (every session of the `Config` tells the one tracer, each session's
    calls in its own order), and an exception is reported as unraisable.
    Each session has a backlog of 256 events for the loop, fixed: an event
    that finds it full is dropped and counted in a `dropped` of that
    session, which is told before the next event delivered or before
    `closed`; `established`, `dropped` and `closed` take no room from the
    backlog and are never dropped, and `closed` is the last call. The one
    exception is a closed loop: nothing is delivered then, `established`
    and `closed` included, and nothing is reported afterwards."""

    def established(self, session: SessionId) -> None:
        """The session `session` (its `Session.id`) was established."""

    def event(self, session: SessionId, event: Event) -> None:
        """A session event."""

    def dropped(self, session: SessionId, count: int) -> None:
        """`count` events of the session `session` were dropped here, before
        the next event delivered or before `closed`: its backlog of 256
        events for the event loop was full."""

    def closed(self, session: SessionId, reason: BaseException) -> None:
        """The session ended, with the reason (the error `Session` calls
        raise from then on); nothing of it follows."""


_DEFAULT_SCHEDULER = _enum_of(Scheduler, _DEFAULTS["scheduler"])
_DEFAULT_REDUNDANCY = _enum_of(Redundancy, _DEFAULTS["redundancy"])


@dataclass(frozen=True, kw_only=True)
class Config:
    """Session configuration: one field per knob and knob parameter. A
    keyword left out keeps the library's default (the field's default);
    `None` is the off, no-timeout or unlimited setting of a field that has
    one and raises `ValueError` for any other. Durations are seconds.

    Timers: `handshake_timeout` (10 s; `None`: none) bounds establishment;
    `join_timeout` (10 s, positive, at most 60) bounds every join and
    `Session.add_pipe`; `max_idle_timeout` (30 s, at least 0.001; `None`
    announces none). `liveness` holds the keep-alive and probe settings.

    Windows and memory: `initial_stream_receive_window` (256 KiB, at least
    4 KiB), `max_stream_receive_window` (`AUTO`, or a fixed cap),
    `latency_budget` (100 us), `initial_connection_receive_window` (1 MiB,
    at least 16 KiB), `max_connection_receive_window` (`AUTO`, or a fixed
    cap), `memory_budget` (1 GiB; `None`: unlimited), `send_buffer` (4
    MiB), `send_buffer_max` (`AUTO`, or a fixed maximum).
    `max_send_record` (16382, one TLS record) is the largest Frames field
    of the records this endpoint sends before the peer's `max_record_size`
    caps it: at least 8192, the carrier record floor, with no upper bound.

    Streams: `max_incoming_streams` (256; 0: the peer may open none, else at
    least 4 and at most `MAX_STREAM_CREDIT`), `max_incoming_uni_streams`
    (`STAGED`: 16 at first and 256 once the application accepts one; or a
    count, 0 for none, at most `MAX_STREAM_CREDIT`).

    Enable datagrams with `enable_datagrams`. `datagram` configures the
    local send defaults, per-flow limits and receive deduplication.
    CoDel uses `datagram_queue_delay` for standing queue delay.

    `session_policy` sets local attachment limits, direction exclusions
    and authenticated Join authorization. `stability_hold` is the
    continuous healthy interval required to replace a member.
    `accounting` opts into live record totals and final accounting tickets
    on attachments. `accounting_tickets` collects tickets from attachment
    handoff, including bootstrap. `resume_timeout` allows the session to rejoin after
    losing all carriers. A `SessionController` can restore coverage.

    `scheduler`, `probation`, `overflow_delay` and `redundancy` govern local
    streams and pipes. Set `carrier_early_data` to allow replayable
    transport early data on carriers that support it. `hold_first_flight`
    stages a flight before it is released. The session's `protocols` are
    the supported application protocols.

    The `shaping_limits` and `shaping_budget` bound the effect of the
    configured shaping programs. A `Tracer` and logger observe activity
    on the configuration's event loop.
    """

    handshake_timeout: float | None = _DEFAULTS["handshake_timeout"]
    join_timeout: float = _DEFAULTS["join_timeout"]
    max_idle_timeout: float | None = _DEFAULTS["max_idle_timeout"]
    liveness: Liveness = Liveness()
    initial_stream_receive_window: int = _DEFAULTS["initial_stream_receive_window"]
    max_stream_receive_window: int | Auto = _DEFAULTS["max_stream_receive_window"]
    latency_budget: float = _DEFAULTS["latency_budget"]
    initial_connection_receive_window: int = _DEFAULTS[
        "initial_connection_receive_window"
    ]
    max_connection_receive_window: int | Auto = _DEFAULTS[
        "max_connection_receive_window"
    ]
    memory_budget: int | None = _DEFAULTS["memory_budget"]
    max_incoming_streams: int = _DEFAULTS["max_incoming_streams"]
    max_incoming_uni_streams: int | Staged = _DEFAULTS["max_incoming_uni_streams"]
    enable_datagrams: bool = _DEFAULTS["enable_datagrams"]
    datagram_send_queue: int = _DEFAULTS["datagram_send_queue"]
    datagram_receive_queue: int = _DEFAULTS["datagram_receive_queue"]
    datagram_stream_queue: int = _DEFAULTS["datagram_stream_queue"]
    datagram: DatagramConfig | None = None
    datagram_receive_bytes: int = _DEFAULTS["datagram_receive_bytes"]
    datagram_queue_delay: float | None = _DEFAULTS["datagram_queue_delay"]
    send_buffer: int = _DEFAULTS["send_buffer"]
    send_buffer_max: int | Auto = _DEFAULTS["send_buffer_max"]
    max_send_record: int = _DEFAULTS["max_send_record"]
    max_lanes: int = _DEFAULTS["max_lanes"]
    resume_timeout: float | None = _DEFAULTS["resume_timeout"]
    session_policy: SessionPolicy = SessionPolicy()
    clock_domain: _zmux.ClockDomain | None = None
    stability_hold: float = _DEFAULTS["stability_hold"]
    accounting: AccountingPolicy = AccountingPolicy()
    accounting_tickets: _zmux.AccountingTickets | None = field(
        default=None, repr=False, compare=False
    )
    scheduler: Scheduler | str = _DEFAULT_SCHEDULER
    spread_chunk: int = _DEFAULTS["spread_chunk"]
    probation: float | Auto | None = _DEFAULTS["probation"]
    overflow_delay: float = _DEFAULTS["overflow_delay"]
    redundancy: Redundancy | str = _DEFAULT_REDUNDANCY
    pipe_auth: PipeAuth | None = field(default=None, repr=False)
    join_early_hello: int | None = _DEFAULTS["join_early_hello"]
    session_crypto: SessionCrypto = SessionCrypto.LOCAL
    epoch_policy: EpochPolicy = EpochPolicy()
    record_policy: RecordPolicy | None = None
    allow_record_mode: (
        Callable[[RecordPolicyInput, RecordMode, Any], bool | Awaitable[bool]] | None
    ) = field(default=None, compare=False)
    allow_connection_window_increase: Callable[[int], bool | Awaitable[bool]] | None = (
        field(default=None, compare=False)
    )
    carrier_early_data: bool = _DEFAULTS["carrier_early_data"]
    hold_first_flight: bool = _DEFAULTS["hold_first_flight"]
    protocols: tuple[str, ...] | None = None
    logger: logging.Logger | None = field(default=None, repr=False, compare=False)
    tracer: Tracer | None = field(default=None, repr=False, compare=False)
    shaping_limits: ShapingLimits | None = None
    shaping_budget: ShapingBudget | None = None
    handshake_shaper: ShapingBundle | None = field(
        default=None, repr=False, compare=False
    )
    shaping_bundle: ShapingBundle | None = field(
        default=None, repr=False, compare=False
    )
    shaping: Mapping[CarrierKind | str | None, str] | None = field(
        default=None, compare=False
    )
    shaping_by_variant: Mapping[str, str] | None = field(default=None, compare=False)
    _native: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        kw = {f.name: getattr(self, f.name) for f in dataclasses.fields(self) if f.init}
        if kw["protocols"] is not None:
            object.__setattr__(self, "protocols", tuple(kw["protocols"]))
            kw["protocols"] = list(kw["protocols"])
        if kw["shaping"] is not None:
            kw["shaping"] = dict(kw["shaping"])
            object.__setattr__(self, "shaping", kw["shaping"])
        if kw["shaping_by_variant"] is not None:
            kw["shaping_by_variant"] = dict(kw["shaping_by_variant"])
            object.__setattr__(self, "shaping_by_variant", kw["shaping_by_variant"])
        object.__setattr__(self, "_native", _zmux.Config(**kw))

    def replace(self, **changes: Any) -> Config:
        """A copy with `changes` applied."""
        return dataclasses.replace(self, **changes)


_LISTENER: Final[dict[str, Any]] = _zmux._listener_defaults()


@dataclass(frozen=True, kw_only=True, slots=True)
class ListenerLimits:
    """The bounds of a `Listener` that `Listener.set_limits` changes while it
    runs; `ListenerConfig.limits` gives the initial values, and the listener
    holds the live ones. `max_pending` (1024; `None`: unlimited) bounds every
    carrier before it enters a session, from its source slot through the
    outer handshake, the admission, the transform, classification and join
    verification; when it is full the oldest stalled carrier makes room,
    else the new one is closed. `max_pending_per_source` (8, at least 2)
    bounds those of one source (counted as `ListenerConfig.source_prefix_v4`
    and `source_prefix_v6` say). `max_pending_per_session` (4) bounds the
    pending joins of one session. `max_suspended` (1024) bounds the
    suspended sessions. `first_record_timeout` (2 s; no off setting) bounds
    a carrier's first record. `memory_budget` (1 GiB; `None`: unlimited)
    bounds what the sessions hold together, in place of their own
    `Config.memory_budget`; a change applies at once, as if the sum crossed
    the new bound (the `on_memory_pressure` hook is told). The rest of the
    `ListenerConfig` is fixed for the listener's life; the bounds of a
    session are its `Config`, which `session_config` answers for every new
    session. Change one with `dataclasses.replace(listener.limits(), ...)`."""

    max_pending: int | None = _LISTENER["max_pending"]
    max_pending_per_source: int = _LISTENER["max_pending_per_source"]
    max_suspended: int = _LISTENER["max_suspended"]
    first_record_timeout: float = _LISTENER["first_record_timeout"]
    memory_budget: int | None = _LISTENER["memory_budget"]
    session_receive_growth_limit: int = _LISTENER["session_receive_growth_limit"]
    """Additional physical receive bytes per session above its bootstrap grant.
    Zero uses a quarter of the listener budget, or unlimited with no budget.
    A negative value removes the per-session cap. Updates affect new grants."""


@dataclass(frozen=True, kw_only=True)
class ListenerConfig:
    """The configuration of a `Listener` besides its sessions' `Config`:
    what it takes in, and how it judges carriers. A keyword left out keeps
    the library's default; durations are seconds.

    Bounds: `limits` (a `ListenerLimits`) holds the initial values of the
    bounds `Listener.set_limits` changes while it runs. A source is counted
    by its first `source_prefix_v4` bits (1 to 32, default 32: the address
    on its own) when IPv4 and its first `source_prefix_v6` bits (1 to 128,
    default 64) when IPv6, ports ignored and an IPv4-mapped IPv6 address
    counted as IPv4; the same aggregation serves the per-source bound, the
    source's stalled carriers, the stall duration and the limit on failed
    join verifications, and a value outside its range raises `ValueError`.
    `handshake_timeout` (10 s) bounds carriers that have not proved
    anything; it has no off setting. `max_record_size` (65535),
    `accept_sessions` (`True`).
    `instance_id` (at most 8 bytes) starts every session locator, for
    load-balancer stickiness. `on_memory_pressure(used, budget, active)` is
    called when memory pressure starts and ends.

    Behind reverse proxies, load balancers or CDNs, `trusted_proxies` lists
    their networks (`"10.0.0.0/8"`, a bare address): a carrier from one of
    them has as its source, for the per-source limits and the admission, the
    client the intermediary reports, in a PROXY protocol header with
    `proxy_protocol`, or in the HTTP header field `forwarded_header`
    (`Forwarded`, or a list such as `X-Forwarded-For`). Reports from other
    peers are ignored.

    Judgement: `admission` applies at every entry (every `serve_*` and
    `handle_pipe`), in one order: the carrier takes a slot of its source's
    `limits.max_pending_per_source` (refused at once beyond it), then its outer
    handshake (TLS, HTTP upgrade, QUIC), then the admission, then its first
    record. `inbound_transform(pipe, hint)` runs once for every carrier
    after its admission and before its first record, each half of a split
    bootstrap included, and returns the carrier the listener goes on with
    (typically `await pipe.wrap(layer, server_side=True)`, or `pipe`
    itself); `async`, it runs on the listener's event loop. It holds the
    carrier's source slot and `handshake_timeout` bounds it (then it is
    cancelled); the first-record timeout runs from its return. A carrier of
    another kind (other halves or framing), an exception or the bound closes
    the carrier as a setup failure; an exception other than a cancellation
    is reported as unraisable. `on_reject(info)` decides what happens to an
    unauthenticated carrier: an unknown Locator, a failed Hello, a refused
    Establish (it may be `async`; past the handshake timeout the carrier is
    closed). Nothing is sent either way. `fallback(takeover)` (it may be
    `async`) receives the carrier itself on an explicit
    `AdmissionVerdict.takeover(value=...)`. HTTP writes the accepted
    response head first and hands over the request and response bodies.
    Without a byte-stream target the carrier stalls. A
    `AdmissionVerdict.fallback(value=...)` or a prefix timeout configured
    for fallback uses the normal handler for that carrier: the HTTP
    adapter's fallback for requests, the byte-stream target for streams.
    The call runs to its end whatever the
    listener does (its close included); once it returned, what it neither
    took (`into_pipe`, `into_messages`) nor detached is closed, and so is
    what the adapter holds of the carrier (the QUIC connection, the
    WebTransport session, the HTTP response) unless it called
    `Takeover.detach()`. An exception is reported as unraisable and closes
    the carrier. Every Python hook of the
    listener runs on its event loop: the one running when the `Listener` is
    made, else the one running at its first use (`async with`, a `serve_*`,
    `handle_pipe`, `accept`); an admission decider runs on the loop running
    when the `Admission` is made, else on the listener's. Once that loop
    closes, hooks are answered without it as for a `Config` (a decider
    refuses at once), until a use from a running loop binds the listener
    to that loop. `secure_server` runs Establish on
    every new carrier; it is a transform, so not together with
    `inbound_transform`. `session_config(carrier)` runs once for every
    carrier that starts a session, never for a join, and returns its
    `Config`, or `None` for the listener's (or is `async` and resolves to
    one within the handshake timeout); joins verify with the session's own. The
    listener's memory budget and carrier-level bounds stay its own. An
    invalid configuration, an exception or another value closes the carrier
    without a byte, counted as `rejected`. `logger` receives the failures of
    the listener's own callbacks that it contains; its sessions log through
    their `Config.logger`. `logger` and `on_memory_pressure` run on the
    listener's event loop, through a queue of their own past which the
    item that arrives is dropped (counted in a warning to `logger`)."""

    limits: ListenerLimits = ListenerLimits()
    source_prefix_v4: int = _LISTENER["source_prefix_v4"]
    source_prefix_v6: int = _LISTENER["source_prefix_v6"]
    handshake_timeout: float = _LISTENER["handshake_timeout"]
    max_record_size: int = _LISTENER["max_record_size"]
    accept_sessions: bool = _LISTENER["accept_sessions"]
    instance_id: bytes = b""
    on_memory_pressure: Callable[[int, int, bool], object] | None = field(
        default=None, compare=False
    )
    trusted_proxies: Sequence[str] | None = None
    forwarded_header: str | None = None
    proxy_protocol: bool = False
    admission: Admission | None = field(default=None, compare=False)
    inbound_transform: (
        Callable[[PipeIo, PipeHint], Awaitable[PipeIo] | PipeIo] | None
    ) = field(default=None, compare=False)
    on_reject: (
        Callable[[RejectInfo], RejectAction | str | Awaitable[RejectAction | str]]
        | None
    ) = field(default=None, compare=False)
    secure_server: SecureServer | None = field(default=None, compare=False)
    fallback: Callable[[Takeover], Awaitable[None] | None] | None = field(
        default=None, compare=False
    )
    session_config: (
        Callable[[SessionCarrier], Config | Awaitable[Config | None] | None] | None
    ) = field(default=None, compare=False)
    logger: logging.Logger | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, kw_only=True)
class Shaper:
    """What `Session.shaper` is assigned to shape every outbound pipe: either
    the JSON `definition`, or `by_kind` (definitions by carrier kind, the
    `None` key the default, for a pipe of no kind or of a kind not listed)
    and `by_variant` (by carrier variant, which come first; a pipe without a
    definition is not shaped); not both. `limits` bounds the definitions,
    `seed` (for tests) makes every pipe draw the same deterministic sequence
    instead of the operating system's generator (never use it for real
    traffic), and `budget` is the spending
    budget. An invalid definition raises `ValueError` at assignment."""

    definition: str | None = None
    by_kind: Mapping[CarrierKind | str | None, str] | None = None
    by_variant: Mapping[str, str] | None = None
    limits: ShapingSizeLimits | None = None
    seed: bytes | None = None
    budget: ShapingBudget | None = None

    def __post_init__(self) -> None:
        _zmux._check_shaper_sources(self)


@runtime_checkable
class CarrierCredential(Protocol):
    """What a client presents to a server's admission on a new carrier, as
    `carrier_credential=` of the `dial_*` functions (`PrefixAuth` is one). Called
    once per carrier, after its handshake, on the library's thread that
    dials (the one hook that runs there: it must be quick and not block):
    `info.export()` gives the exporter of that handshake for a bound
    credential. An exception fails the dial."""

    def prefix(self, info: CarrierInfo) -> bytes:
        """The bytes a stream, HTTP request body or QUIC carrier starts with."""
        ...

    def header(self, info: CarrierInfo) -> tuple[str, str]:
        """The request header field `(name, value)` of a carrier decided on
        its HTTP request head (WebSocket, WebTransport)."""
        ...
