"""Typed values exchanged with the native layer. Plain data; no protocol logic."""

from __future__ import annotations

import dataclasses
import datetime
import enum
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Literal,
    NamedTuple,
    Protocol,
    runtime_checkable,
)

from . import _zmux

if TYPE_CHECKING:
    from typing import Self

    from ._zmux import CarrierInfo, ZmuxError


class _Enum(enum.StrEnum):
    @classmethod
    def _of(cls, value: str) -> Self | str:
        try:
            return cls(value)
        except ValueError:
            return value


class Role(_Enum):
    """The negotiated session role."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


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
    session ended with `EarlyDataRejected`."""


class Direction(_Enum):
    """Which directions a reserved pipe carries."""

    IN = "in"
    OUT = "out"
    BIDI = "bidi"


class OutboundState(_Enum):
    """State of a pipe's outbound direction (STATE_MACHINE.md Section 3.1)."""

    JOINING = "Joining"
    ACTIVE = "Active"
    SUSPECT = "Suspect"
    DRAINING = "Draining"
    FAILED = "Failed"
    CLOSED = "Closed"


class InboundState(_Enum):
    """State of a pipe's inbound direction (STATE_MACHINE.md Section 3.2)."""

    JOINING = "Joining"
    OPEN = "Open"
    ENDED = "Ended"


class PipeHalf(_Enum):
    """A direction of a pipe: the one this endpoint reads or writes."""

    INBOUND = "Inbound"
    OUTBOUND = "Outbound"


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
    PIPES_LOST = "PipesLost"
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


class TransportErrorCode(enum.IntEnum):
    """The transport error codes of a `SessionClosed.code` (kind
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
    """A resume could not be completed: also the answer of a listener with
    `answer_unknown_joins` to a join that names no session there, which
    ends a suspended session at once."""
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


@dataclass(frozen=True, slots=True, kw_only=True)
class PipeOptions:
    """Every option of a pipe; `None` is unset (the default). Durations in
    seconds.

    `send_priority`: the tier of the local outbound direction, lower
    preferred (unset: the peer's request, else 0). `receive_priority`: the
    tier requested for the peer's outbound direction (0). `send_standby`:
    the local outbound direction takes data only on failover (unset: the
    peer's request, else no). `receive_standby`: asks the peer to do so
    (no). `weight`: share among pipes of a tier (1). `probation`: base of
    the pipe's probation (0 turns it off). `label`: the application's name
    for the pipe. `fate_group`: pipes that fail together (0: independent).
    `suspect_floor` (at least 0.05), `dead_timeout` (at least 1),
    `probe_interval` (at least 1; a one-way attachment uses at most 15) and
    `probe_jitter` (0 <= j < 1): the detection settings, the session's when
    unset. `idle_probes=False` turns the pipe's idle probes off (without
    `probe_interval`). Invalid values raise `ValueError` where the options are used.
    A live pipe changes the first six with `Pipe.update`.
    """

    send_priority: int | None = None
    receive_priority: int | None = None
    send_standby: bool | None = None
    receive_standby: bool | None = None
    weight: int | None = None
    probation: float | None = None
    label: str | None = None
    fate_group: int | None = None
    suspect_floor: float | None = None
    dead_timeout: float | None = None
    probe_interval: float | None = None
    idle_probes: bool | None = None
    probe_jitter: float | None = None


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

    pipe: int
    local: bool
    """This endpoint joined the attachment."""
    fate_group: int
    label: str | None
    carrier: CarrierKind | str | None
    """The carrier's kind, if the adapter declares one."""
    inbound: InboundState | str | None
    outbound: OutboundState | str | None
    attached_for: float
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
    `rejected` counts the listener's own indistinguishable rejections only;
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


class CandidateOutcome(_Enum):
    """How one try of a candidate fared."""

    USABLE = "usable"
    TIMED_OUT = "timed_out"
    REFUSED = "refused"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """One try of a carrier mode's candidate: `joined` when it was tried as
    a further pipe of the established session; `error` unless usable."""

    carrier: CarrierKind | str
    outcome: CandidateOutcome | str
    joined: bool
    error: str | None


def _candidate_result(fields: dict[str, Any]) -> CandidateResult:
    return CandidateResult(
        CarrierKind._of(fields["carrier"]),
        CandidateOutcome._of(fields["outcome"]),
        fields["joined"],
        fields["error"],
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
    join_replays: int
    join_refusals: int
    suspensions: int
    suspended_time: float
    scheduler_answers: int
    scheduler_fallbacks: int
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

    PIPE_STATE = "PipeState"
    JOIN_AUTH_FAILED = "JoinAuthFailed"
    JOIN_SECURITY_UNAVAILABLE = "JoinSecurityUnavailable"
    PIPE_PRIORITY_CHANGED = "PipePriorityChanged"
    PIPE_QUALITY_CHANGED = "PipeQualityChanged"
    TIER_SATURATION = "TierSaturation"
    CAPACITY_BELOW = "CapacityBelow"
    CAPACITY_RESTORED = "CapacityRestored"
    GO_AWAY = "GoAway"
    SUSPENDED = "Suspended"
    RESUMED = "Resumed"
    PIPES_RETIRED = "PipesRetired"
    CARRIER_CANDIDATE = "CarrierCandidate"
    CARRIER_CHOSEN = "CarrierChosen"
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class Event:
    """Base of session events; match on the subclass or on `kind`."""

    kind: ClassVar[EventKind]


@dataclass(frozen=True, slots=True)
class PipeStateChanged(Event):
    """A pipe direction changed state: an `OutboundState` for the
    `OUTBOUND` half, an `InboundState` for the `INBOUND` one; `failure` is
    set with `OutboundState.FAILED`; `carrier` is the pipe's carrier kind."""

    kind: ClassVar[EventKind] = EventKind.PIPE_STATE
    pipe: int
    half: PipeHalf | str
    state: OutboundState | InboundState | str
    failure: str | None
    carrier: CarrierKind | str | None = None


@dataclass(frozen=True, slots=True)
class JoinAuthFailed(Event):
    """`count` joins failed authentication since the last such event."""

    kind: ClassVar[EventKind] = EventKind.JOIN_AUTH_FAILED
    carrier_bound: bool
    count: int


@dataclass(frozen=True, slots=True)
class JoinSecurityUnavailable(Event):
    """Both sides offered multipath without a matching pipe secret; the session stays on one pipe."""

    kind: ClassVar[EventKind] = EventKind.JOIN_SECURITY_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class PipePriorityChanged(Event):
    """A pipe's effective outbound priority, standby flag or weight changed."""

    kind: ClassVar[EventKind] = EventKind.PIPE_PRIORITY_CHANGED
    pipe: int
    send_priority: int
    standby: bool
    weight: int
    source: PrioritySource


@dataclass(frozen=True, slots=True)
class PipeQualityChanged(Event):
    """A pipe's estimates left their band. Seconds; bytes per second."""

    kind: ClassVar[EventKind] = EventKind.PIPE_QUALITY_CHANGED
    pipe: int
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
class GoAway(Event):
    """The peer sent GOAWAY: streams below the watermarks may be processed."""

    kind: ClassVar[EventKind] = EventKind.GO_AWAY
    max_bidi: int
    max_uni: int
    code: int


@dataclass(frozen=True, slots=True)
class Suspended(Event):
    """Every pipe in a direction was lost; the session waits for a pipe to resume."""

    kind: ClassVar[EventKind] = EventKind.SUSPENDED


@dataclass(frozen=True, slots=True)
class Resumed(Event):
    """The session left the suspended state."""

    kind: ClassVar[EventKind] = EventKind.RESUMED


@dataclass(frozen=True, slots=True)
class PipesRetired(Event):
    """Pipes were retired; `last` holds up to four of their IDs, oldest first."""

    kind: ClassVar[EventKind] = EventKind.PIPES_RETIRED
    retired: int
    failed: int
    closed: int
    dropped: int
    last: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CarrierCandidate(Event):
    """A carrier mode tried a candidate, as the session or (`joined`) as a
    further pipe."""

    kind: ClassVar[EventKind] = EventKind.CARRIER_CANDIDATE
    carrier: CarrierKind | str
    outcome: CandidateOutcome | str
    joined: bool


@dataclass(frozen=True, slots=True)
class CarrierChosen(Event):
    """A carrier mode chose the session's carrier kind: when the session was
    established, and again on every switch."""

    kind: ClassVar[EventKind] = EventKind.CARRIER_CHOSEN
    carrier: CarrierKind | str


@dataclass(frozen=True, slots=True)
class UnknownEvent(Event):
    """An event this binding does not model yet; `detail` is diagnostic text."""

    kind: ClassVar[EventKind] = EventKind.UNKNOWN
    detail: str


_EVENTS: dict[str, type[Event]] = {
    c.kind: c
    for c in (
        PipeStateChanged,
        JoinAuthFailed,
        JoinSecurityUnavailable,
        PipePriorityChanged,
        PipeQualityChanged,
        TierSaturation,
        CapacityBelow,
        CapacityRestored,
        GoAway,
        Suspended,
        Resumed,
        PipesRetired,
        CarrierCandidate,
        CarrierChosen,
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
    if cls is PipeStateChanged:
        states = InboundState if fields["half"] == PipeHalf.INBOUND else OutboundState
        fields["state"] = states._of(fields["state"])
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


Seconds = float | datetime.timedelta


def _secs(v: Seconds | None) -> float | None:
    return v.total_seconds() if isinstance(v, datetime.timedelta) else v


@dataclass(frozen=True, kw_only=True)
class ShapingLimits:
    """Bounds a session puts on its shaper (`Config(shaping_limits=...)`);
    each field is `None` by default, no bound, and a set one bounds as it
    is, 0 allowing none. Durations are seconds (`float`) or `timedelta`; a
    decision beyond a bound is reduced to it and counted as `clamped`.
    A set field is finite and non-negative and `max_padding_ratio` at most 1
    (`ValueError` otherwise, at construction). Under a set ratio, at least
    `STARTUP_ALLOWANCE` bytes of PADDING are allowed; without one only
    `max_padding_bytes` bounds PADDING."""

    max_padding_bytes: int | None = None
    """PADDING bytes added."""
    max_padding_ratio: float | None = None
    """PADDING bytes added over the other bytes sent."""
    max_injected: int | None = None
    """Records of PADDING only."""
    max_pause_total: Seconds | None = None
    """Sum of pauses and delays."""
    max_delay: Seconds | None = None
    """One pause or delay."""

    def __post_init__(self) -> None:
        for k in ("max_pause_total", "max_delay"):
            object.__setattr__(self, k, _secs(getattr(self, k)))
        for k in ("max_padding_bytes", "max_injected"):
            _count(k, getattr(self, k))
        for k in ("max_pause_total", "max_delay"):
            v = getattr(self, k)
            if v is not None and (
                not isinstance(v, (int, float))
                or isinstance(v, bool)
                or not 0 <= v < math.inf
            ):
                raise ValueError(f"{k} is a finite non-negative number of seconds")
        r = self.max_padding_ratio
        if r is not None and (
            not isinstance(r, (int, float)) or isinstance(r, bool) or not 0 <= r <= 1
        ):
            raise ValueError("max_padding_ratio is a number in [0, 1]")


def _count(k: str, v: object) -> None:
    if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
        raise ValueError(f"{k} is a non-negative integer")


@dataclass(frozen=True, kw_only=True)
class ShapingSizeLimits:
    """Bounds of a shaping definition (`Session.set_shaper(limits=...)`);
    each field is `None` by default, no bound, and a set one bounds as it
    is, 0 allowing none. A definition beyond one raises `ValueError`; so
    does a field that is not a non-negative integer, at construction."""

    max_bytes: int | None = None
    """Input bytes (JSON or sequence form)."""
    max_machines: int | None = None
    """Machines."""
    max_states: int | None = None
    """States per machine."""
    max_actions: int | None = None
    """Actions per state."""
    max_transitions: int | None = None
    """Transitions per state."""
    max_points: int | None = None
    """Points or components per distribution."""

    def __post_init__(self) -> None:
        for k in (
            "max_bytes",
            "max_machines",
            "max_states",
            "max_actions",
            "max_transitions",
            "max_points",
        ):
            _count(k, getattr(self, k))


class PipeAuth:
    """Join credentials for multipath, immutable: `PipeAuth.exporter()`
    (the exporter of the innermost end-to-end handshake, today TLS that
    this process terminates), `PipeAuth.psk(key)` (a
    pre-shared key of at least 16 bytes), `PipeAuth.insecure()` (no
    secret; only where other means protect the joins), and
    `auth.with_psk(key)`, a new value that adds a key."""

    __slots__ = ("_exporter", "_insecure", "_psk")
    _exporter: bool
    _psk: bytes | None
    _insecure: bool

    def __init__(
        self,
        *,
        exporter: bool = False,
        psk: bytes | None = None,
        insecure: bool = False,
    ) -> None:
        object.__setattr__(self, "_exporter", exporter)
        object.__setattr__(self, "_psk", None if psk is None else bytes(psk))
        object.__setattr__(self, "_insecure", insecure)

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
    def insecure() -> PipeAuth:
        """Insecure joins."""
        return PipeAuth(insecure=True)

    def with_psk(self, key: bytes) -> PipeAuth:
        """These credentials with the pre-shared key `key` added."""
        return PipeAuth(exporter=self._exporter, psk=key, insecure=self._insecure)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PipeAuth):
            return NotImplemented
        return (self._exporter, self._psk, self._insecure) == (
            other._exporter,
            other._psk,
            other._insecure,
        )

    def __hash__(self) -> int:
        return hash((self._exporter, self._psk, self._insecure))

    def __repr__(self) -> str:
        parts = [
            n
            for n, on in (
                ("exporter", self._exporter),
                ("psk", self._psk is not None),
                ("insecure", self._insecure),
            )
            if on
        ]
        return f"PipeAuth({', '.join(parts) or 'none'})"


@dataclass(frozen=True, slots=True, kw_only=True)
class QualityBand:
    """When to report a pipe's quality (`PipeQualityChanged`): once its
    smoothed RTT moved by more than `rtt` seconds (0: never), or its
    delivery rate by more than the factor `rate_ratio` (0: never), from the
    last reported values, at most once per `min_interval` seconds. A
    negative or NaN `rate_ratio` raises `ValueError`."""

    rtt: Seconds = 0.0
    rate_ratio: float = 0.0
    min_interval: Seconds = 1.0

    def __post_init__(self) -> None:
        for k in ("rtt", "min_interval"):
            object.__setattr__(self, k, _secs(getattr(self, k)))
        if not self.rate_ratio >= 0:
            raise ValueError("rate_ratio is a non-negative number")


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
    `ready(min, max)` waits until it allows at least `min` bytes (or its
    burst) and returns how many, at most `max`; `try_ready(max)` is the
    allowance now; `charge(n)` accounts for `n` bytes forwarded. An
    exception allows nothing."""

    async def ready(self, min: int, max: int, /) -> int:
        """Waits for an allowance of `min..=max` bytes."""
        ...

    def try_ready(self, max: int, /) -> int:
        """The allowance now, at most `max`; 0 when it would wait."""
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


Scheduler = Literal[
    "affinity",
    "session-affinity",
    "spread-eta",
    "spread-round-robin",
    "spread-rate-weighted",
]
"""A built-in scheduling policy by name. The binding takes no policy
written in Python: one would run on the driver's decision path under the
interpreter lock."""


@dataclass(frozen=True, kw_only=True)
class Config:
    """Session configuration: one field per knob and knob parameter.
    Durations are seconds (`float`) or `timedelta`.

    The timers and periods hold their defaults, and `None` is no timeout or
    off: `handshake_timeout` (10 s), `max_idle_timeout` (30 s, at least
    0.001; `None` announces none), `keep_alive_period` (15 s, at least 1),
    `standby_probe` (1 s) and `probe_interval` (15 s). Every other field
    keeps the default when `None`; `math.inf` makes `memory_budget` (1 GiB)
    unlimited, and 0 is a budget of no byte. A negative value raises.
    `keep_alive_period` is capped at half the
    effective idle timeout. `max_stream_receive_window`,
    `max_connection_receive_window` and `send_buffer_max` are auto when
    `None`; `max_incoming_uni_streams`
    `None` is staged credit. `standby_probe` (1 s; off leaves standby pipes
    at the probe interval) and `probe_interval` (15 s) are at least 1. Multipath needs `max_pipes` above 1 and
    `pipe_auth`. The datagram queues hold 64 datagrams waiting to be sent,
    128 received session datagrams and 32 per stream, within 1 MiB of
    received datagrams in all (`datagram_*`, each at least 1); the oldest
    make room. `scheduler` is a built-in `Scheduler` name; `redundancy` is
    `"urgent"` or `"off"`. `early_data` declares the peer a zmux endpoint
    (stream data before its parameters), `carrier_early_data` allows the
    carrier's own early data (replayable; see `RecvStream.is_replayable`).
    `protocols`, `shaping_limits` and `shaping` are hooks: the
    application protocols offered, the bounds of each session's shaper,
    and the shaping definitions by carrier kind (`None` key: the default).
    Use `config.replace(...)` to derive a variant.
    """

    handshake_timeout: Seconds | None = 10.0
    max_idle_timeout: Seconds | None = 30.0
    keep_alive_period: Seconds | None = 15.0
    initial_stream_receive_window: int | None = None
    max_stream_receive_window: int | None = None
    latency_budget: Seconds | None = None
    initial_connection_receive_window: int | None = None
    max_connection_receive_window: int | None = None
    memory_budget: int | float | None = None
    max_incoming_streams: int | None = None
    max_incoming_uni_streams: int | None = None
    enable_datagrams: bool | None = None
    datagram_send_queue: int | None = None
    datagram_receive_queue: int | None = None
    datagram_stream_queue: int | None = None
    datagram_receive_bytes: int | None = None
    send_buffer: int | None = None
    send_buffer_max: int | None = None
    max_pipes: int | None = None
    pipe_headroom: int | None = None
    replay_window: int | None = None
    max_lanes: int | None = None
    resume_timeout: Seconds | None = None
    scheduler: Scheduler | None = None
    spread_chunk: int | None = None
    suspect_floor: Seconds | None = None
    dead_timeout: Seconds | None = None
    probation: Seconds | None = None
    overflow_delay: Seconds | None = None
    standby_probe: Seconds | None = 1.0
    probe_interval: Seconds | None = 15.0
    probe_jitter: float | None = None
    redundancy: str | None = None
    pipe_auth: PipeAuth | None = field(default=None, repr=False)
    early_data: bool | None = None
    carrier_early_data: bool | None = None
    protocols: tuple[str, ...] | None = None
    shaping_limits: ShapingLimits | None = None
    shaping: Mapping[CarrierKind | str | None, str] | None = field(
        default=None, compare=False
    )
    _native: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        kw = {f.name: getattr(self, f.name) for f in dataclasses.fields(self) if f.init}
        for k, v in kw.items():
            if isinstance(v, datetime.timedelta):
                kw[k] = _secs(v)
        if kw["protocols"] is not None:
            object.__setattr__(self, "protocols", tuple(kw["protocols"]))
            kw["protocols"] = list(kw["protocols"])
        if kw["shaping"] is not None:
            object.__setattr__(self, "shaping", dict(kw["shaping"]))
            kw["shaping"] = {
                k.value if isinstance(k, CarrierKind) else k: v
                for k, v in kw["shaping"].items()
            }
        object.__setattr__(self, "_native", _zmux.Config(**kw))

    def replace(self, **changes: Any) -> Config:
        """A copy with `changes` applied."""
        return dataclasses.replace(self, **changes)


@runtime_checkable
class Credential(Protocol):
    """What a client presents to a server's admission on a new carrier, as
    `credential=` of the `dial_*` functions (`PrefixAuth` is one). Called on
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
