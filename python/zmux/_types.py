"""Typed values exchanged with the native layer. Plain data; no protocol logic."""

from __future__ import annotations

import dataclasses
import datetime
import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple

from . import _zmux

if TYPE_CHECKING:
    from typing import Self

    from ._zmux import ZmuxError


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


class PipeState(_Enum):
    """State of one direction of a pipe."""

    JOINING = "Joining"
    ACTIVE = "Active"
    SUSPECT = "Suspect"
    DRAINING = "Draining"
    FAILED = "Failed"
    CLOSED = "Closed"
    OPEN = "Open"
    ENDED = "Ended"
    RETIRED = "Retired"


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
    """Metadata the opener attached to a stream."""

    info: bytes | None = None
    tlvs: tuple[Tlv, ...] = ()


@dataclass(frozen=True, slots=True)
class PipePolicy:
    """How a pipe is scheduled; `None` fields keep the current or default value.

    `priority`: lower is preferred (default 0). `standby`: used only when no
    non-standby pipe is usable. `weight`: share among pipes of equal priority.
    """

    priority: int | None = None
    standby: bool | None = None
    weight: int | None = None


@dataclass(frozen=True, slots=True)
class CloseInfo:
    """Why a session ended. `code`/`reason` are set for application and
    transport closes; `remote` tells whether the peer ended it; `error` is
    the exception an operation on the session raises now."""

    code: int | None
    reason: bytes | None
    remote: bool | None
    error: ZmuxError


@dataclass(frozen=True, slots=True)
class PipeStats:
    """A snapshot of one pipe. Durations in seconds, rates in bytes per second;
    estimates are `None` until measured."""

    pipe: int
    local: bool
    label: str | None
    inbound: PipeState | None
    outbound: PipeState | None
    failure: str | None
    failure_count: int
    suspect_count: int
    attached_for: float
    send_priority: int
    standby: bool
    weight: int
    receive_priority: int
    receive_standby: bool
    in_probation: bool
    eligible: bool
    smoothed_rtt: float | None
    min_rtt: float | None
    delivery_rate: int | None
    bytes_in_flight: int | None
    queued_bytes: int
    bytes_sent: int
    bytes_received: int
    records_sent: int
    records_received: int


@dataclass(frozen=True, slots=True)
class SessionStats:
    """A snapshot of the session's transport counters (carrier bytes, not
    application bytes). Durations in seconds."""

    bytes_sent: int
    bytes_received: int
    records_sent: int
    records_received: int
    streams_opened_local: int
    streams_opened_remote: int
    streams_active: int
    datagrams_sent: int
    datagrams_received: int
    datagrams_dropped_send: int
    datagrams_dropped_recv: int
    smoothed_rtt: float | None
    min_rtt: float | None
    latest_rtt: float | None
    bytes_reinjected: int
    pipes_active: int
    pipes_added: int
    pipe_failures: int
    suspensions: int
    suspended_time: float


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
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class Event:
    """Base of session events; match on the subclass or on `kind`."""

    kind: ClassVar[EventKind]


@dataclass(frozen=True, slots=True)
class PipeStateChanged(Event):
    """A pipe direction changed state; `failure` is set with `PipeState.FAILED`."""

    kind: ClassVar[EventKind] = EventKind.PIPE_STATE
    pipe: int
    half: PipeHalf
    state: PipeState
    failure: str | None


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
class UnknownEvent(Event):
    """An event this binding does not model yet; `detail` is diagnostic text."""

    kind: ClassVar[EventKind] = EventKind.UNKNOWN
    detail: str


_EVENTS: dict[str, type[Event]] = {
    c.kind: c
    for c in (
        PipeStateChanged, JoinAuthFailed, JoinSecurityUnavailable, PipePriorityChanged,
        PipeQualityChanged, TierSaturation, CapacityBelow, CapacityRestored, GoAway,
        Suspended, Resumed, PipesRetired,
    )
}

_ENUM_FIELDS = {"half": PipeHalf, "state": PipeState, "source": PrioritySource}


def _event(kind: str, fields: dict[str, Any]) -> Event:
    cls = _EVENTS.get(kind)
    if cls is None:
        return UnknownEvent(fields.get("detail", kind))
    for k, e in _ENUM_FIELDS.items():
        if k in fields:
            fields[k] = e._of(fields[k])
    if "last" in fields:
        fields["last"] = tuple(fields["last"])
    return cls(**fields)


def _pipe_stats(fields: dict[str, Any]) -> PipeStats:
    for k in ("inbound", "outbound"):
        if fields[k] is not None:
            fields[k] = PipeState._of(fields[k])
    return PipeStats(**fields)


def _preamble(info: bytes | None, tlvs: list[tuple[int, bytes]]) -> Preamble:
    return Preamble(info, tuple(Tlv(t, v) for t, v in tlvs))


Seconds = float | datetime.timedelta


def _secs(v: Seconds | None) -> float | None:
    return v.total_seconds() if isinstance(v, datetime.timedelta) else v


@dataclass(frozen=True, kw_only=True)
class Config:
    """Session configuration; `None` keeps the native default. Durations are
    seconds (`float`) or `timedelta`.

    `datagrams`: `None` uses the default (off), `True`/`False` force it.
    `psk` and `tls_auth` select how multipath joins authenticate: a
    pre-shared key, the TLS exporter, or both combined; either enables
    multipath (`max_pipes` 8 unless set). `early_data` lets the first
    streams travel before the handshake completes (replayable; see
    `RecvStream.is_replayable`); `carrier_early_data` also allows the
    carrier's own 0-RTT. Use `dataclasses.replace(config, ...)` or
    `config.replace(...)` to derive a variant.
    """

    handshake_timeout: Seconds | None = None
    idle_timeout: Seconds | None = None
    keep_alive: Seconds | None = None
    datagrams: bool | None = None
    max_incoming_streams: int | None = None
    max_pipes: int | None = None
    psk: bytes | None = field(default=None, repr=False)
    tls_auth: bool = False
    resume_timeout: Seconds | None = None
    early_data: bool = False
    carrier_early_data: bool = False
    protocols: tuple[str, ...] | None = None
    dead_timeout: Seconds | None = None
    suspect_floor: Seconds | None = None
    probation: Seconds | None = None
    _native: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        kw = {f.name: getattr(self, f.name) for f in dataclasses.fields(self) if f.init}
        for k, v in kw.items():
            if isinstance(v, datetime.timedelta):
                kw[k] = _secs(v)
        if kw["protocols"] is not None:
            object.__setattr__(self, "protocols", tuple(kw["protocols"]))
            kw["protocols"] = list(kw["protocols"])
        object.__setattr__(self, "_native", _zmux.Config(**kw))

    def replace(self, **changes: Any) -> Config:
        """A copy with `changes` applied."""
        return dataclasses.replace(self, **changes)
