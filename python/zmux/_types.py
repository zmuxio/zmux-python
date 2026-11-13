"""Typed values exchanged with the native layer. Plain data; no protocol logic."""

from __future__ import annotations

import dataclasses
import enum
import logging
from collections.abc import Awaitable, Callable, Mapping
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
    runtime_checkable,
)

from . import _zmux

if TYPE_CHECKING:
    from typing import Self

    from ._errors import ZmuxError
    from ._zmux import CarrierInfo


class _Enum(enum.StrEnum):
    @classmethod
    def _of(cls, value: str) -> Self | str:
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

_DEFAULTS: Final[dict[str, Any]] = _zmux._config_defaults()


class RecordMode(_Enum):
    """How a pipe's records are protected."""

    SEALED = "sealed"
    BOUND = "bound"
    TRUSTED = "trusted"
    UNMANAGED = "unmanaged"
    """A first pipe outside the secure carrier; no join has this mode."""


class RejectAction(_Enum):
    """The answer of `Listener(on_reject=...)`. Neither sends anything."""

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
    TRANSPORT_CLOSED = "TransportClosed"
    IDLE_TIMEOUT = "IdleTimeout"
    HANDSHAKE_TIMEOUT = "HandshakeTimeout"
    EARLY_DATA_REJECTED = "EarlyDataRejected"
    RESUME_TIMEOUT = "ResumeTimeout"
    RESUME_FAILED = "ResumeFailed"
    PIPES_LOST = "PipesLost"
    JOIN_REFUSED = "JoinRefused"
    RESET = "Reset"
    STOPPED = "Stopped"
    REJECTED = "Rejected"
    GOING_AWAY = "GoingAway"
    CLOSED_LOCALLY = "ClosedLocally"
    NOT_NEGOTIATED = "NotNegotiated"
    NOT_ESTABLISHED = "NotEstablished"
    BLOCKED = "Blocked"
    TIMED_OUT = "TimedOut"
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
    ON_DRIVER_THREAD = "OnDriverThread"
    JOIN_PENDING = "JoinPending"
    JOIN_SECRET_SET = "JoinSecretSet"
    NO_EXPORTER = "NoExporter"
    RESERVED_LABEL = "ReservedLabel"
    UNAVAILABLE = "Unavailable"


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


class Priority(NamedTuple):
    """Stream scheduling priority: `urgency` 0 (highest) to 7, `incremental` interleaves equal urgencies."""

    urgency: int = 3
    incremental: bool = False


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
    when its first bytes named none; `reason` an error class or `unknown_locator`."""

    profile: int | None
    record_mode: RecordMode | None
    reason: str
    source: tuple[str, int] | None


@dataclass(frozen=True, slots=True)
class RecordPolicyInput:
    """What `Config.record_policy` and `Config.allow_record_mode` know of a
    carrier."""

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


@dataclass(frozen=True, slots=True)
class CloseInfo:
    """Why a session ended. `code`/`reason` are set for application and
    transport closes; `remote` tells whether the peer ended it; `error` is
    the exception an operation on the session raises now."""

    code: int | None
    reason: bytes | None
    remote: bool | None
    error: ZmuxError


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
class PipeStats:
    """A snapshot of one attachment. Durations in seconds, rates in bytes per
    second, points in time on the `time.monotonic()` clock; estimates and
    the fields that need acknowledgements are `None` until known."""

    record_mode: RecordMode | None
    pipe: PipeId
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
    bytes_retransmitted: int | None
    """The bytes the carrier itself retransmitted (TCP on Linux, Android,
    Apple platforms and Windows; QUIC, the connection's count on each of its
    pipes), queried at most once a second; `None` where it reports none."""
    loss_rate: float | None
    """The smoothed carrier loss rate, an estimate: the growth of
    `bytes_retransmitted` over that of `bytes_sent` (EWMA, gain 1/8),
    sampled at most once a second; `None` before the first sample."""
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
    pipe_id: int | None
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
    variant; they count in the totals of `AdmissionStats` as well."""

    accepted: int = 0
    fallback: int = 0
    stalled: int = 0
    closed: int = 0


@dataclass(frozen=True, slots=True)
class AdmissionStats:
    """What a listener's admission decided: counts since it was made, each
    carrier that took a source slot counted once its outcome is known; all 0
    without an admission. `accepted` carriers count once more in the other
    `ListenerStats` fields; `fallback` includes those stalled for want of a
    fallback; `stalled` counts when the stall starts; `closed` also counts
    an `accept` beyond the prefix, a failing decide and one cancelled by the
    listener's close; `stall_overflow` a stall closed at once, its source
    already stalling `max_pending_per_source - 1` carriers or the listener
    closing; `peek_timed_out` a decision past the peek timeout;
    `handshake_failed` an outer handshake (TLS, HTTP upgrade, QUIC) that
    failed or timed out, counted here and not in `setup_failures`."""

    accepted: int = 0
    fallback: int = 0
    stalled: int = 0
    closed: int = 0
    stall_overflow: int = 0
    peek_timed_out: int = 0
    handshake_failed: int = 0


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


class CacheOutcome(_Enum):
    """What a host learnt of a candidate after dialling it
    (`CarrierCache.report`)."""

    USABLE = "usable"
    """Usable, as a chosen candidate."""
    FAILED = "failed"
    """An ordinary failure: the backoff doubles."""
    REJECTED = "rejected"
    """A definite verdict of the host: skipped for the longest backoff."""


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
    """What `Listener(session_config=...)` knows of a carrier that starts a
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
        CarrierKind._of(fields["carrier"]),
        CandidateOutcome._of(fields["outcome"]),
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
            object.__setattr__(self, "carrier", CarrierKind._of(self.carrier))
        object.__setattr__(self, "carrier_candidates", tuple(self.carrier_candidates))


class EventKind(_Enum):
    """`Event.kind` values."""

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
    """`count` joins failed authentication since the last such event."""

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
    """The session, which can rejoin, suspended with neither a `redial` hook nor a
    running pipe pool: nothing will dial, and it ends at the grace period unless the
    application adds a pipe. It follows `SessionSuspended` and is also logged as a
    warning."""

    kind: ClassVar[EventKind] = EventKind.RESUME_UNATTENDED


@dataclass(frozen=True, slots=True)
class PipesRetired(Event):
    """Pipes were retired; `last` holds up to four of their IDs, oldest first."""

    kind: ClassVar[EventKind] = EventKind.PIPES_RETIRED
    retired: int
    failed: int
    closed: int
    dropped: int
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
            fields[k] = e._of(fields[k])
    if "last" in fields:
        fields["last"] = tuple(fields["last"])
    return cls(**fields)


def _pipe_stats(fields: dict[str, Any]) -> PipeStats:
    if fields["inbound"] is not None:
        fields["inbound"] = InboundState._of(fields["inbound"])
    if fields["outbound"] is not None:
        fields["outbound"] = OutboundState._of(fields["outbound"])
    if fields["carrier"] is not None:
        fields["carrier"] = CarrierKind._of(fields["carrier"])
    for k in ("send_priority_source", "standby_source"):
        fields[k] = PrioritySource._of(fields[k])
    if fields["rtt_source"] is not None:
        fields["rtt_source"] = RttSource._of(fields["rtt_source"])
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
    after_first_pipe: bool = True
    after_resume: bool = True
    MANUAL: ClassVar[EpochPolicy]

    def __post_init__(self) -> None:
        if self.period == 0:
            raise ValueError("epoch_policy.period is positive, or None for never")
        if self.joins == 0:
            raise ValueError("epoch_policy.joins is positive, or None for never")


EpochPolicy.MANUAL = EpochPolicy(None, None, False, False)


@dataclass(frozen=True, kw_only=True)
class ShapingAccount:
    """An allowance for injections, in bytes on the carrier; all fields zero: not set.
    Padding that goes with a record is never refused and does not draw on it. `initial` is
    at most 2**53, the others 2**43 (`ValueError` otherwise, at construction)."""

    initial: int = 0
    """Available from the start."""
    per_mb: int = 0
    """Added per 10**6 bytes this endpoint sends of its own."""
    per_sec: int = 0
    """Added per second."""

    def __post_init__(self) -> None:
        for k, most in (
            ("initial", 1 << 53),
            ("per_mb", 1 << 43),
            ("per_sec", 1 << 43),
        ):
            v = getattr(self, k)
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= most:
                raise ValueError(f"{k} is an integer in [0, {most}]")


def _count(k: str, v: object) -> None:
    if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
        raise ValueError(f"{k} is a non-negative integer")


def _wait(v: float | None) -> None:
    if v is not None and (
        not isinstance(v, (int, float)) or isinstance(v, bool) or not v > 0
    ):
        raise ValueError("max_delay is a positive number of seconds")


@dataclass(frozen=True, kw_only=True)
class ShapingLimits:
    """Local bounds on shaping (`Config(shaping_limits=...)`), set by the application and
    never sent; a configuration cannot widen them. Durations are seconds."""

    wire: ShapingAccount = ShapingAccount()
    """What injections may spend."""
    max_delay: float | None = _zmux.DEFAULT_MAX_DELAY
    """The bound on one wait, and so on the lowest rate of a gate (positive;
    `None`: no bound)."""
    no_padding: bool = False
    """No padding at all, on handshakes and injections too."""
    no_pause: bool = False
    """No pause or delay."""
    no_injection: bool = False
    """No injection."""

    def __post_init__(self) -> None:
        _wait(self.max_delay)


@dataclass(frozen=True, kw_only=True)
class ShapingBudget:
    """What a shaping configuration allows for a session (`Config(shaping_budget=...)`, a
    callable returning this, called once per session). It cannot widen `ShapingLimits`."""

    wire: ShapingAccount = ShapingAccount()
    """What injections may spend."""
    max_delay: float | None = None
    """The configuration's bound on one wait in seconds; `None`: none."""
    no_injection: bool = False
    """The configuration allows no injection."""

    def __post_init__(self) -> None:
        _wait(self.max_delay)


@dataclass(frozen=True, kw_only=True)
class UnitPlan:
    """The size and timing of one unit written to a carrier. Lengths are bytes on the
    carrier, and `delay` is seconds."""

    pad_to: int = 0
    pad_multiple: int = 0
    pad: int = 0
    delay: float = 0.0


@dataclass(frozen=True, kw_only=True)
class HandshakeView:
    """What a handshake shaper is told of a message: never a size."""

    kind: CarrierKind | None
    handshake: str
    message: str


@dataclass(frozen=True, kw_only=True)
class ShapingSizeLimits:
    """Bounds of a shaping definition (`Session.set_shaper(limits=...)`);
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
    derived; else at least 1): how long a suspect pipe stays suspect before
    it fails. `standby_probe` (1 s, at least 1; `None` off: standby pipes are
    probed at `probe_interval`). `probe_interval` (15 s, at least 1; `None`
    turns the idle probes off). `probe_jitter` (0.25, in [0, 1); 0 gives
    the fixed schedule tests use)."""

    keep_alive_period: float | None = _LIVENESS["keep_alive_period"]
    suspect_floor: float = _LIVENESS["suspect_floor"]
    dead_timeout: float | Auto = AUTO
    standby_probe: float | None = _LIVENESS["standby_probe"]
    probe_interval: float | None = _LIVENESS["probe_interval"]
    probe_jitter: float = _LIVENESS["probe_jitter"]


@dataclass(frozen=True, slots=True, kw_only=True)
class PipeLiveness:
    """A pipe's own liveness settings (`PipeOptions.liveness`, replaced with
    `Pipe.update(liveness=...)`): the `Liveness` fields of the same names
    that apply to one pipe, each `INHERIT` (the default, following the
    session's) or a value; `probe_interval=None` turns the pipe's idle
    probes off. Durations are seconds; invalid values raise `ValueError`
    where they are used."""

    suspect_floor: float | Inherit = INHERIT
    dead_timeout: float | Inherit = INHERIT
    probe_interval: float | Inherit | None = INHERIT
    probe_jitter: float | Inherit = INHERIT


@dataclass(frozen=True, slots=True, kw_only=True)
class PipeOptions:
    """Every option of a pipe (`Session.add_pipe`, `PipePool`); durations in
    seconds. Invalid values raise `ValueError` where the options are used.

    Fixed when the pipe is added: `direction` (`Direction.BIDI`), the
    directions the pipe carries; `record_mode` (`INHERIT`:
    `Config.record_policy`, else sealed); `key_group` (`INHERIT`: the local
    preference), the key group of the join; `label`, the application's name
    for the pipe (`None`: none); `fate_group` (0: independent), pipes that
    fail together; `return_on_reply` (`False`): `add_pipe` returns once the
    Reply is verified instead of once the peer attached the pipe (then wait
    with `Pipe.attached()` before closing the session's other pipes).

    Changed on a live pipe with `Pipe.update`: `send_priority` (`AUTO`: the
    peer's request, else 0), the tier of the local outbound direction, lower
    preferred; `receive_priority` (0), the tier requested for the peer's
    outbound direction; `send_standby` (`AUTO`: the peer's request, else
    available), the local outbound direction takes data only on failover;
    `receive_standby` (`False`), asks the peer to do so; `weight` (1, 0
    excludes the pipe), its share among the pipes of a tier; `probation`
    (`INHERIT`: the session's; `AUTO`: derived from the pipe's RTT; `None`
    off; else the base in seconds); `liveness` (a `PipeLiveness`)."""

    direction: Direction = Direction.BIDI
    record_mode: RecordMode | str | Inherit = INHERIT
    key_group: KeyGroup | int | Inherit = INHERIT
    send_priority: int | Auto = AUTO
    receive_priority: int = 0
    send_standby: bool | Auto = AUTO
    receive_standby: bool = False
    weight: int = 1
    probation: float | Auto | Inherit | None = INHERIT
    label: str | None = None
    fate_group: int = 0
    liveness: PipeLiveness = PipeLiveness()
    return_on_reply: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class QualityBand:
    """When to report a pipe's quality (`PipeQualityChanged`): once its
    smoothed RTT moved by more than `rtt` seconds (0: every change; `None`:
    never by RTT), or its delivery rate by more than the factor
    `rate_ratio` (1 or less: every change; `None`: never by rate), from
    the last reported values, at most once per `min_interval` seconds. A
    negative or NaN `rtt` or `rate_ratio` raises `ValueError`."""

    rtt: float | None = None
    rate_ratio: float | None = None
    min_interval: float = 1.0

    def __post_init__(self) -> None:
        for k in ("rtt", "rate_ratio"):
            v = getattr(self, k)
            if v is not None and not v >= 0:
                raise ValueError(f"{k} is a non-negative number, or None")


@dataclass(frozen=True, slots=True, kw_only=True)
class CapacityFloor:
    """The floor under the session's outbound capacity in bytes per second:
    `CapacityBelow` once below `rate`, `CapacityRestored` once back above
    `rate * rate_ratio` (a ratio below 1 counts as 1; a negative or NaN one
    raises `ValueError`)."""

    rate: int
    rate_ratio: float = 1.25

    def __post_init__(self) -> None:
        if not self.rate_ratio >= 0:
            raise ValueError("rate_ratio is a non-negative number")


class Limiter(Protocol):
    """A rate limiter of a splice direction (`zmux.splice(a_to_b=...)`):
    `ready(least, most)` waits until it allows at least `least` bytes (or
    its burst) and returns how many, at most `most`; `try_ready(most)` is
    the allowance now; `charge(n)` accounts for `n` bytes forwarded. The
    parameters are positional-only, so an implementation names them freely.
    An exception allows nothing."""

    async def ready(self, least: int, most: int, /) -> int:
        """Waits for an allowance of `least..=most` bytes."""
        ...

    def try_ready(self, most: int, /) -> int:
        """The allowance now, at most `most`; 0 when it would wait."""
        ...

    def charge(self, n: int, /) -> None:
        """Accounts for `n` bytes."""
        ...


class SpliceEnd(_Enum):
    """How one direction of a splice ended."""

    FINISHED = "finished"
    RESET = "reset"
    STOPPED = "stopped"
    UPSTREAM_LOST = "upstream_lost"
    DOWNSTREAM_LOST = "downstream_lost"


@dataclass(frozen=True, slots=True)
class Forwarded:
    """What one direction of a splice forwarded, and how it ended; `code` is
    the reset or stop code with `SpliceEnd.RESET` and `SpliceEnd.STOPPED`."""

    bytes: int
    datagram_bytes: int
    datagrams_dropped: int
    end: SpliceEnd | str
    code: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "end", SpliceEnd._of(str(self.end)))


@dataclass(frozen=True, slots=True)
class Spliced:
    """The two directions of a finished splice."""

    a_to_b: Forwarded
    b_to_a: Forwarded


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
        object.__setattr__(self, "rule", DuplicateRule._of(str(self.rule)))


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
    method runs in order, serially per session, on a native thread holding
    the GIL (quick, not blocking), and an exception is reported as
    unraisable."""

    def established(self) -> None:
        """The session was established."""

    def event(self, event: Event) -> None:
        """A session event."""

    def dropped(self, count: int) -> None:
        """`count` events were dropped since the previous call, before the
        next delivered."""

    def closed(self, reason: BaseException) -> None:
        """The session ended, with the reason (the error `Session` calls
        raise from then on); nothing follows."""


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

    Streams: `max_incoming_streams` (256; 0: the peer may open none, else at
    least 4 and at most `MAX_STREAM_CREDIT`), `max_incoming_uni_streams`
    (`STAGED`: 16 at first and 256 once the application accepts one; or a
    count, 0 for none, at most `MAX_STREAM_CREDIT`).

    Datagrams: `enable_datagrams` (`False`) and the queues
    `datagram_send_queue` (64), `datagram_receive_queue` (128),
    `datagram_stream_queue` (32 per stream), `datagram_receive_bytes`
    (1 MiB, the session queue and the datagrams held for streams not
    opened yet; stream queues do not count against it) and
    `datagram_stream_bytes` (512 KiB per stream; `None`: only the count
    bounds a stream queue), each at least 1; the oldest make room.

    Multipath: `max_pipes` (1, multipath off; 8 recommended),
    `pipe_headroom` (8), `replay_window` (`AUTO`, or at least `max_pipes +
    pipe_headroom`), `max_lanes` (258, at least 1). Multipath needs
    `pipe_auth` (a `PipeAuth`; `None`: no join credentials) unless the
    first pipe is on the secure carrier; `join_early_hello` (8 KiB;
    `None`: no first batch). `resume_timeout` (`None`: off; else at least
    0.001) with `redial`, an async callable given the direction that
    returns the `PipeIo` replacing a lost pipe, with backoff from
    `redial_min_backoff` (1 s) doubling up to `redial_max_backoff` (60 s);
    a `Config` with `redial` is made inside a running event loop.

    Scheduling: `scheduler` (`Scheduler.AFFINITY`), `spread_chunk`,
    `probation` (`AUTO`, derived from the pipe's RTT; `None` off; else the
    base in seconds), `overflow_delay` (1 s), `redundancy`
    (`Redundancy.URGENT`).

    Early data: `early_data` (`False`) declares the peer a zmux endpoint
    (stream data before its parameters), `carrier_early_data` (`False`)
    allows the carrier's own early data (replayable; see
    `RecvStream.is_replayable`), and `hold_first_flight` (`False`, a client
    with early data) keeps the bootstrap pipe's first write until
    `Session.release_first_flight()` or the handshake timeout.

    Security: `session_crypto` (`SessionCrypto.LOCAL`), `epoch_policy`
    (`EpochPolicy()`), `record_policy(input)` choosing a joined pipe's
    record mode and `allow_record_mode(input, mode, admitted)` admitting
    it, `authorize_join(pipe_id)` (on an acceptor, a further check of a
    join after its authentication and record mode: falsy or an exception
    refuses it). These run on a native thread holding the GIL.

    Hooks: `protocols`, the application protocols offered; `logger` (a
    `logging.Logger`) receives zmux's warnings; `tracer` (a `Tracer`)
    receives every event in order beside the event stream;
    `shaping_limits`, `shaping_budget`, `shaping` (definitions by carrier
    kind, `None` key the default), `shaping_by_variant` (by carrier variant,
    first), `handshake_shaper` and `shaping_bundle`. A hook left at `None`
    is not used. Use `config.replace(...)` to derive a variant.
    """

    handshake_timeout: float | None = _DEFAULTS["handshake_timeout"]
    join_timeout: float = _DEFAULTS["join_timeout"]
    max_idle_timeout: float | None = _DEFAULTS["max_idle_timeout"]
    liveness: Liveness = Liveness()
    initial_stream_receive_window: int = _DEFAULTS["initial_stream_receive_window"]
    max_stream_receive_window: int | Auto = AUTO
    latency_budget: float = _DEFAULTS["latency_budget"]
    initial_connection_receive_window: int = _DEFAULTS[
        "initial_connection_receive_window"
    ]
    max_connection_receive_window: int | Auto = AUTO
    memory_budget: int | None = _DEFAULTS["memory_budget"]
    max_incoming_streams: int = _DEFAULTS["max_incoming_streams"]
    max_incoming_uni_streams: int | Staged = STAGED
    enable_datagrams: bool = False
    datagram_send_queue: int = _DEFAULTS["datagram_send_queue"]
    datagram_receive_queue: int = _DEFAULTS["datagram_receive_queue"]
    datagram_stream_queue: int = _DEFAULTS["datagram_stream_queue"]
    datagram_receive_bytes: int = _DEFAULTS["datagram_receive_bytes"]
    datagram_stream_bytes: int | None = _DEFAULTS["datagram_stream_bytes"]
    send_buffer: int = _DEFAULTS["send_buffer"]
    send_buffer_max: int | Auto = AUTO
    max_pipes: int = _DEFAULTS["max_pipes"]
    pipe_headroom: int = _DEFAULTS["pipe_headroom"]
    replay_window: int | Auto = AUTO
    max_lanes: int = _DEFAULTS["max_lanes"]
    resume_timeout: float | None = None
    redial: Callable[[Direction], Awaitable[Any]] | None = field(
        default=None, compare=False
    )
    redial_min_backoff: float = _DEFAULTS["redial_min_backoff"]
    redial_max_backoff: float = _DEFAULTS["redial_max_backoff"]
    scheduler: Scheduler | str = Scheduler.AFFINITY
    spread_chunk: int = _DEFAULTS["spread_chunk"]
    probation: float | Auto | None = AUTO
    overflow_delay: float = _DEFAULTS["overflow_delay"]
    redundancy: Redundancy | str = Redundancy.URGENT
    pipe_auth: PipeAuth | None = field(default=None, repr=False)
    join_early_hello: int | None = _DEFAULTS["join_early_hello"]
    session_crypto: SessionCrypto = SessionCrypto.LOCAL
    epoch_policy: EpochPolicy = EpochPolicy()
    record_policy: Callable[[RecordPolicyInput], RecordMode | str] | None = field(
        default=None, compare=False
    )
    allow_record_mode: Callable[[RecordPolicyInput, RecordMode, Any], bool] | None = (
        field(default=None, compare=False)
    )
    authorize_join: Callable[[PipeId], bool] | None = field(default=None, compare=False)
    early_data: bool = False
    carrier_early_data: bool = False
    hold_first_flight: bool = False
    protocols: tuple[str, ...] | None = None
    logger: logging.Logger | None = field(default=None, repr=False, compare=False)
    tracer: Tracer | None = field(default=None, repr=False, compare=False)
    shaping_limits: ShapingLimits = ShapingLimits()
    shaping_budget: Callable[[], ShapingBudget] | None = None
    handshake_shaper: object | None = field(default=None, repr=False, compare=False)
    shaping_bundle: object | None = field(default=None, repr=False, compare=False)
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
            object.__setattr__(self, "shaping", dict(kw["shaping"]))
            kw["shaping"] = {
                k.value if isinstance(k, CarrierKind) else k: v
                for k, v in kw["shaping"].items()
            }
        if kw["shaping_by_variant"] is not None:
            kw["shaping_by_variant"] = dict(kw["shaping_by_variant"])
            object.__setattr__(self, "shaping_by_variant", kw["shaping_by_variant"])
        object.__setattr__(self, "_native", _zmux.Config(**kw))

    def replace(self, **changes: Any) -> Config:
        """A copy with `changes` applied."""
        return dataclasses.replace(self, **changes)


@runtime_checkable
class CarrierCredential(Protocol):
    """What a client presents to a server's admission on a new carrier, as
    `carrier_credential=` of the `dial_*` functions (`PrefixAuth` is one). Called on
    a native thread holding the GIL, once per carrier, after its handshake:
    `info.export()` gives the exporter of that handshake for a bound
    credential. An exception fails the dial."""

    def prefix(self, info: CarrierInfo) -> bytes:
        """The bytes a stream, HTTP request body or QUIC carrier starts with."""
        ...

    def header(self, info: CarrierInfo) -> tuple[str, str]:
        """The request header field `(name, value)` of a carrier decided on
        its HTTP request head (WebSocket, WebTransport)."""
        ...
