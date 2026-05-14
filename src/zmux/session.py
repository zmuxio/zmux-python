"""Public session protocols and lifecycle values."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType, TracebackType
from typing import Mapping, Optional, Protocol, Type, runtime_checkable

from .config import OpenOptions, Settings
from .errors import (
    ApplicationError,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    SessionClosed,
    TerminationKind,
)
from .preface import Negotiated, Preface
from .protocol import Role
from .streams import (
    AsyncRecvStream,
    AsyncSendStream,
    AsyncStream,
    ReadableBuffer,
    RecvStream,
    SendStream,
    Stream,
)

_MAX_UINT64 = (1 << 64) - 1


class SessionState(str, Enum):
    """Stable public session lifecycle state."""

    INVALID = "invalid"
    READY = "ready"
    DRAINING = "draining"
    CLOSING = "closing"
    CLOSED = "closed"
    FAILED = "failed"

    def __str__(self) -> str:
        return self.value

    def valid(self) -> bool:
        """Return whether this is a usable public session state."""

        return self is not SessionState.INVALID

    def terminal(self) -> bool:
        """Return whether this is a final state."""

        return self in (SessionState.CLOSED, SessionState.FAILED)


@dataclass(frozen=True)
class ActiveStreamStats:
    """Snapshot of active streams grouped by opener and direction."""

    local_bidi: int = 0
    local_uni: int = 0
    peer_bidi: int = 0
    peer_uni: int = 0
    total: int = 0

    def __post_init__(self) -> None:
        local_bidi = _nonnegative_int(self.local_bidi, "local_bidi")
        local_uni = _nonnegative_int(self.local_uni, "local_uni")
        peer_bidi = _nonnegative_int(self.peer_bidi, "peer_bidi")
        peer_uni = _nonnegative_int(self.peer_uni, "peer_uni")
        object.__setattr__(self, "local_bidi", local_bidi)
        object.__setattr__(self, "local_uni", local_uni)
        object.__setattr__(self, "peer_bidi", peer_bidi)
        object.__setattr__(self, "peer_uni", peer_uni)
        object.__setattr__(
            self,
            "total",
            _saturating_add(
                _saturating_add(local_bidi, local_uni),
                _saturating_add(peer_bidi, peer_uni),
            ),
        )


@dataclass(frozen=True)
class QueueStats:
    """Snapshot of writer queue depth."""

    urgent: int = 0
    advisory: int = 0
    ordinary: int = 0
    total: int = 0

    def __post_init__(self) -> None:
        urgent = _nonnegative_int(self.urgent, "urgent")
        advisory = _nonnegative_int(self.advisory, "advisory")
        ordinary = _nonnegative_int(self.ordinary, "ordinary")
        object.__setattr__(self, "urgent", urgent)
        object.__setattr__(self, "advisory", advisory)
        object.__setattr__(self, "ordinary", ordinary)
        object.__setattr__(
            self,
            "total",
            _saturating_add(_saturating_add(urgent, advisory), ordinary),
        )


@dataclass(frozen=True)
class FlushStats:
    """Snapshot of writer flush activity."""

    count: int = 0
    last_at: Optional[float] = None
    last_frames: int = 0
    last_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "count", _nonnegative_int(self.count, "count"))
        object.__setattr__(
            self, "last_frames", _nonnegative_int(self.last_frames, "last_frames")
        )
        object.__setattr__(
            self, "last_bytes", _nonnegative_int(self.last_bytes, "last_bytes")
        )


@dataclass(frozen=True)
class TelemetryStats:
    """Runtime telemetry values that are useful but not protocol state."""

    last_open_latency: Optional[float] = None
    send_rate_estimate_bytes_per_second: int = 0

    def __post_init__(self) -> None:
        if self.last_open_latency is not None:
            object.__setattr__(
                self,
                "last_open_latency",
                _nonnegative_float(self.last_open_latency, "last_open_latency"),
            )
        object.__setattr__(
            self,
            "send_rate_estimate_bytes_per_second",
            _nonnegative_int(
                self.send_rate_estimate_bytes_per_second,
                "send_rate_estimate_bytes_per_second",
            ),
        )


@dataclass(frozen=True)
class LivenessStats:
    """Keepalive and idle liveness snapshot."""

    keepalive_interval: float = 0.0
    keepalive_max_ping_interval: float = 0.0
    keepalive_timeout: float = 0.0
    ping_outstanding: bool = False
    ping_stalled: bool = False
    last_ping_rtt: Optional[float] = None
    inbound_idle_for: float = 0.0
    outbound_idle_for: float = 0.0

    def __post_init__(self) -> None:
        for name in (
                "keepalive_interval",
                "keepalive_max_ping_interval",
                "keepalive_timeout",
                "inbound_idle_for",
                "outbound_idle_for",
        ):
            object.__setattr__(
                self, name, _nonnegative_float(getattr(self, name), name)
            )
        object.__setattr__(
            self,
            "ping_outstanding",
            _require_bool(self.ping_outstanding, "ping_outstanding"),
        )
        object.__setattr__(
            self, "ping_stalled", _require_bool(self.ping_stalled, "ping_stalled")
        )
        if self.last_ping_rtt is not None:
            object.__setattr__(
                self,
                "last_ping_rtt",
                _nonnegative_float(self.last_ping_rtt, "last_ping_rtt"),
            )


@dataclass(frozen=True)
class WriterQueueStats:
    """Detailed writer queue accounting."""

    urgent_jobs: int = 0
    advisory_jobs: int = 0
    ordinary_jobs: int = 0
    queued_bytes: int = 0
    max_bytes: int = 0
    urgent_queued_bytes: int = 0
    urgent_max_bytes: int = 0
    advisory_queued_bytes: int = 0
    data_queued_bytes: int = 0
    session_data_high_watermark: int = 0
    per_stream_data_high_watermark: int = 0
    pending_control_bytes: int = 0
    pending_control_bytes_budget: int = 0
    pending_priority_bytes: int = 0
    pending_priority_bytes_budget: int = 0
    max_batch_frames: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))


@dataclass(frozen=True)
class RetentionStats:
    """Retained stream-state and diagnostic retention snapshot."""

    tombstones: int = 0
    tombstone_limit: int = 0
    marker_only_used_streams: int = 0
    marker_only_used_stream_ranges: int = 0
    marker_only_used_stream_limit: int = 0
    retained_open_info_bytes: int = 0
    retained_open_info_bytes_budget: int = 0
    retained_peer_reason_bytes: int = 0
    retained_peer_reason_bytes_budget: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))


@dataclass(frozen=True)
class MemoryStats:
    """Tracked session memory cap snapshot."""

    tracked_bytes: int = 0
    hard_cap: int = 0
    over_cap: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tracked_bytes", _nonnegative_int(self.tracked_bytes, "tracked_bytes")
        )
        object.__setattr__(self, "hard_cap", _nonnegative_int(self.hard_cap, "hard_cap"))
        object.__setattr__(self, "over_cap", _require_bool(self.over_cap, "over_cap"))


@dataclass(frozen=True)
class AbuseStats:
    """Inbound abuse and no-op budget accounting."""

    ignored_control: int = 0
    ignored_control_budget: int = 0
    no_op_zero_data: int = 0
    no_op_zero_data_budget: int = 0
    inbound_ping: int = 0
    inbound_ping_budget: int = 0
    no_op_max_data: int = 0
    no_op_max_data_budget: int = 0
    no_op_blocked: int = 0
    no_op_blocked_budget: int = 0
    no_op_priority_update: int = 0
    no_op_priority_update_budget: int = 0
    dropped_priority_update: int = 0
    inbound_control_frames: int = 0
    inbound_control_frame_budget: int = 0
    inbound_control_bytes: int = 0
    inbound_control_bytes_budget: int = 0
    inbound_ext_frames: int = 0
    inbound_ext_frame_budget: int = 0
    inbound_ext_bytes: int = 0
    inbound_ext_bytes_budget: int = 0
    inbound_mixed_frames: int = 0
    inbound_mixed_frame_budget: int = 0
    inbound_mixed_bytes: int = 0
    inbound_mixed_bytes_budget: int = 0
    group_rebucket_churn: int = 0
    group_rebucket_churn_budget: int = 0
    hidden_abort_churn: int = 0
    hidden_abort_churn_budget: int = 0
    visible_terminal_churn: int = 0
    visible_terminal_churn_budget: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))


@dataclass(frozen=True)
class ProgressStats:
    """Recent runtime progress timestamps.

    Values are implementation-defined timestamps, usually epoch or monotonic
    seconds. Adapters should be consistent within one stats snapshot.
    """

    inbound_frame_at: Optional[float] = None
    control_progress_at: Optional[float] = None
    transport_write_at: Optional[float] = None
    stream_progress_at: Optional[float] = None
    application_progress_at: Optional[float] = None
    ping_sent_at: Optional[float] = None
    pong_at: Optional[float] = None


@dataclass(frozen=True)
class RetainedBucketStats:
    """Retained item and byte counts for a bounded state bucket."""

    count: int = 0
    bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "count", _nonnegative_int(self.count, "count"))
        object.__setattr__(self, "bytes", _nonnegative_int(self.bytes, "bytes"))


@dataclass(frozen=True)
class RetainedStateBreakdownStats:
    """Retained session state grouped by the Go runtime bucket model."""

    hidden_control: RetainedBucketStats = field(default_factory=RetainedBucketStats)
    accept_backlog: RetainedBucketStats = field(default_factory=RetainedBucketStats)
    provisionals: RetainedBucketStats = field(default_factory=RetainedBucketStats)
    visible_tombstone: RetainedBucketStats = field(default_factory=RetainedBucketStats)
    marker_only: RetainedBucketStats = field(default_factory=RetainedBucketStats)

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(
                self,
                name,
                _coerce_stat(getattr(self, name), RetainedBucketStats, name),
            )

    @property
    def total_bytes(self) -> int:
        total = self.hidden_control.bytes
        total = _saturating_add(total, self.accept_backlog.bytes)
        total = _saturating_add(total, self.provisionals.bytes)
        total = _saturating_add(total, self.visible_tombstone.bytes)
        return _saturating_add(total, self.marker_only.bytes)


@dataclass(frozen=True)
class PressureStats:
    """Snapshot of buffered memory and receive pressure."""

    receive_backlog_bytes: int = 0
    receive_backlog_high: bool = False
    aggregate_late_data_bytes: int = 0
    aggregate_late_data_at_cap: bool = False
    retained_state_bytes: int = 0
    retained_buckets: RetainedStateBreakdownStats = field(
        default_factory=RetainedStateBreakdownStats
    )
    retained_open_info_bytes: int = 0
    retained_peer_reason_bytes: int = 0
    tracked_buffered_bytes: int = 0
    tracked_buffered_limit: int = 0
    tracked_buffered_high: bool = False
    tracked_buffered_at_cap: bool = False
    ordinary_queued_bytes: int = 0
    advisory_queued_bytes: int = 0
    urgent_queued_bytes: int = 0
    pending_control_bytes: int = 0
    pending_advisory_bytes: int = 0
    prepared_advisory_bytes: int = 0
    pending_terminal_bytes: int = 0
    pending_terminal_count: int = 0
    pending_protocol_jobs: int = 0
    buffered_receive_bytes: int = 0
    buffered_receive_storage_bytes: int = 0
    recv_session_advertised_bytes: int = 0
    recv_session_received_bytes: int = 0
    recv_session_pending_bytes: int = 0
    outstanding_ping_bytes: int = 0

    def __post_init__(self) -> None:
        retained_buckets = self.retained_buckets
        if retained_buckets is None:
            retained_buckets = RetainedStateBreakdownStats()
        if not isinstance(retained_buckets, RetainedStateBreakdownStats):
            raise TypeError("retained_buckets must be a RetainedStateBreakdownStats")
        object.__setattr__(self, "retained_buckets", retained_buckets)
        if self.retained_state_bytes == 0 and retained_buckets.total_bytes:
            object.__setattr__(
                self, "retained_state_bytes", retained_buckets.total_bytes
            )
        for name in (
                "receive_backlog_bytes",
                "aggregate_late_data_bytes",
                "retained_state_bytes",
                "retained_open_info_bytes",
                "retained_peer_reason_bytes",
                "tracked_buffered_bytes",
                "tracked_buffered_limit",
                "ordinary_queued_bytes",
                "advisory_queued_bytes",
                "urgent_queued_bytes",
                "pending_control_bytes",
                "pending_advisory_bytes",
                "prepared_advisory_bytes",
                "pending_terminal_bytes",
                "pending_terminal_count",
                "pending_protocol_jobs",
                "buffered_receive_bytes",
                "buffered_receive_storage_bytes",
                "recv_session_advertised_bytes",
                "recv_session_received_bytes",
                "recv_session_pending_bytes",
                "outstanding_ping_bytes",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))
        for name in (
                "receive_backlog_high",
                "aggregate_late_data_at_cap",
                "tracked_buffered_high",
                "tracked_buffered_at_cap",
        ):
            object.__setattr__(self, name, _require_bool(getattr(self, name), name))

    @property
    def tracked_session_memory_bytes(self) -> int:
        return self.tracked_buffered_bytes

    @property
    def tracked_retained_state_memory_bytes(self) -> int:
        return self.retained_state_bytes

    @property
    def retained_state_breakdown(self) -> RetainedStateBreakdownStats:
        return self.retained_buckets

    @property
    def session_memory_high_threshold_bytes(self) -> int:
        if self.tracked_buffered_limit <= 4:
            return self.tracked_buffered_limit
        return self.tracked_buffered_limit - self.tracked_buffered_limit // 4

    @property
    def session_memory_hard_cap_bytes(self) -> int:
        return self.tracked_buffered_limit

    @property
    def memory_pressure_high(self) -> bool:
        return self.tracked_buffered_high


@dataclass(frozen=True)
class HiddenStats:
    """Snapshot of non-application-visible retained stream state."""

    retained: int = 0
    soft_cap: int = 0
    hard_cap: int = 0
    at_soft_cap: bool = False
    at_hard_cap: bool = False
    refused: int = 0
    reaped: int = 0
    unread_bytes_discarded: int = 0

    def __post_init__(self) -> None:
        for name in (
                "retained",
                "soft_cap",
                "hard_cap",
                "refused",
                "reaped",
                "unread_bytes_discarded",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))
        for name in ("at_soft_cap", "at_hard_cap"):
            object.__setattr__(self, name, _require_bool(getattr(self, name), name))


@dataclass(frozen=True)
class AcceptBacklogStats:
    """Snapshot of peer-opened streams waiting for application acceptance."""

    count: int = 0
    count_limit: int = 0
    at_count_cap: bool = False
    bytes: int = 0
    bytes_limit: int = 0
    at_bytes_cap: bool = False
    refused: int = 0

    def __post_init__(self) -> None:
        for name in (
                "count",
                "count_limit",
                "bytes",
                "bytes_limit",
                "refused",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))
        object.__setattr__(
            self,
            "at_count_cap",
            _require_bool(self.at_count_cap, "at_count_cap")
            or (self.count_limit != 0 and self.count >= self.count_limit),
        )
        object.__setattr__(
            self,
            "at_bytes_cap",
            _require_bool(self.at_bytes_cap, "at_bytes_cap")
            or (self.bytes_limit != 0 and self.bytes >= self.bytes_limit),
        )

    def at_count_limit(self) -> bool:
        return self.count_limit != 0 and self.count >= self.count_limit

    def at_bytes_limit(self) -> bool:
        return self.bytes_limit != 0 and self.bytes >= self.bytes_limit


@dataclass(frozen=True)
class ProvisionalStats:
    """Snapshot of locally-created streams waiting to become peer-visible."""

    bidi: int = 0
    uni: int = 0
    soft_cap: int = 0
    hard_cap: int = 0
    bidi_at_soft: bool = False
    uni_at_soft: bool = False
    bidi_at_hard: bool = False
    uni_at_hard: bool = False
    bidi_limit: int = 0
    uni_limit: int = 0
    limited: int = 0
    expired: int = 0

    def __post_init__(self) -> None:
        for name in (
                "bidi",
                "uni",
                "soft_cap",
                "hard_cap",
                "bidi_limit",
                "uni_limit",
                "limited",
                "expired",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))
        if self.soft_cap:
            soft_cap = self.soft_cap
        elif self.bidi_limit or self.uni_limit:
            soft_cap = min(
                value for value in (self.bidi_limit, self.uni_limit) if value
            )
        else:
            soft_cap = 0
        hard_cap = self.hard_cap or max(self.bidi_limit, self.uni_limit)
        object.__setattr__(self, "soft_cap", soft_cap)
        object.__setattr__(self, "hard_cap", hard_cap)
        object.__setattr__(
            self,
            "bidi_at_soft",
            _require_bool(self.bidi_at_soft, "bidi_at_soft")
            or (soft_cap != 0 and self.bidi >= soft_cap),
        )
        object.__setattr__(
            self,
            "uni_at_soft",
            _require_bool(self.uni_at_soft, "uni_at_soft")
            or (soft_cap != 0 and self.uni >= soft_cap),
        )
        object.__setattr__(
            self,
            "bidi_at_hard",
            _require_bool(self.bidi_at_hard, "bidi_at_hard")
            or (hard_cap != 0 and self.bidi >= hard_cap),
        )
        object.__setattr__(
            self,
            "uni_at_hard",
            _require_bool(self.uni_at_hard, "uni_at_hard")
            or (hard_cap != 0 and self.uni >= hard_cap),
        )

    def bidi_at_limit(self) -> bool:
        return self.bidi_limit != 0 and self.bidi >= self.bidi_limit

    def uni_at_limit(self) -> bool:
        return self.uni_limit != 0 and self.uni >= self.uni_limit

    def at_limit(self) -> bool:
        return self.bidi_at_limit() or self.uni_at_limit()


@dataclass(frozen=True)
class ReasonStats:
    """Snapshot of retained reset and abort reason code counts."""

    reset: Mapping[int, int] = field(default_factory=dict)
    reset_overflow: int = 0
    abort: Mapping[int, int] = field(default_factory=dict)
    abort_overflow: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "reset", _copy_reason_map(self.reset, "reset"))
        object.__setattr__(
            self,
            "reset_overflow",
            _nonnegative_int(self.reset_overflow, "reset_overflow"),
        )
        object.__setattr__(self, "abort", _copy_reason_map(self.abort, "abort"))
        object.__setattr__(
            self,
            "abort_overflow",
            _nonnegative_int(self.abort_overflow, "abort_overflow"),
        )


@dataclass(frozen=True)
class DiagnosticStats:
    """Snapshot of protocol/runtime diagnostic counters."""

    dropped_priority_updates: int = 0
    dropped_local_priority_updates: int = 0
    late_data_after_close_read: int = 0
    late_data_after_reset: int = 0
    late_data_after_abort: int = 0
    coalesced_terminal_signals: int = 0
    superseded_terminal_signals: int = 0
    visible_terminal_churn_events: int = 0
    group_rebucket_events: int = 0
    hidden_abort_churn_events: int = 0
    skipped_close_on_dead_io: int = 0
    close_frame_admission_timeouts: int = 0
    close_frame_flush_timeouts: int = 0
    close_frame_flush_errors: int = 0
    close_completion_timeouts: int = 0
    graceful_close_timeouts: int = 0
    keepalive_timeouts: int = 0
    protocol_backlog_blocked: int = 0
    marker_only_range_count: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))


@dataclass(frozen=True)
class SessionStats:
    """Snapshot of public session state and runtime counters."""

    state: SessionState = SessionState.INVALID
    sent_frames: int = 0
    received_frames: int = 0
    sent_data_bytes: int = 0
    received_data_bytes: int = 0
    open_streams: int = 0
    accepted_streams: int = 0
    keepalive_interval: float = 0.0
    keepalive_max_ping_interval: float = 0.0
    keepalive_timeout: float = 0.0
    ping_outstanding: bool = False
    ping_stalled: bool = False
    progress: ProgressStats = field(default_factory=ProgressStats)
    last_inbound_frame_at: Optional[float] = None
    last_control_progress: Optional[float] = None
    last_transport_write: Optional[float] = None
    last_stream_progress: Optional[float] = None
    last_app_progress: Optional[float] = None
    last_ping_sent_at: Optional[float] = None
    last_pong_at: Optional[float] = None
    last_ping_rtt: float = 0.0
    active_streams: ActiveStreamStats = field(default_factory=ActiveStreamStats)
    queues: QueueStats = field(default_factory=QueueStats)
    flush: FlushStats = field(default_factory=FlushStats)
    blocked_write_total: float = 0.0
    last_open_latency: float = 0.0
    pressure: PressureStats = field(default_factory=PressureStats)
    hidden: HiddenStats = field(default_factory=HiddenStats)
    accept_backlog: AcceptBacklogStats = field(default_factory=AcceptBacklogStats)
    provisionals: ProvisionalStats = field(default_factory=ProvisionalStats)
    reasons: ReasonStats = field(default_factory=ReasonStats)
    diagnostics: DiagnosticStats = field(default_factory=DiagnosticStats)
    telemetry: TelemetryStats = field(default_factory=TelemetryStats)
    writer_queue: WriterQueueStats = field(default_factory=WriterQueueStats)
    liveness: LivenessStats = field(default_factory=LivenessStats)
    retention: RetentionStats = field(default_factory=RetentionStats)
    memory: MemoryStats = field(default_factory=MemoryStats)
    abuse: AbuseStats = field(default_factory=AbuseStats)

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", _coerce_session_state(self.state))
        for name, stat_type in (
                ("progress", ProgressStats),
                ("active_streams", ActiveStreamStats),
                ("queues", QueueStats),
                ("flush", FlushStats),
                ("pressure", PressureStats),
                ("hidden", HiddenStats),
                ("accept_backlog", AcceptBacklogStats),
                ("provisionals", ProvisionalStats),
                ("reasons", ReasonStats),
                ("diagnostics", DiagnosticStats),
                ("telemetry", TelemetryStats),
                ("writer_queue", WriterQueueStats),
                ("liveness", LivenessStats),
                ("retention", RetentionStats),
                ("memory", MemoryStats),
                ("abuse", AbuseStats),
        ):
            object.__setattr__(
                self, name, _coerce_stat(getattr(self, name), stat_type, name)
            )
        for name in (
                "sent_frames",
                "received_frames",
                "sent_data_bytes",
                "received_data_bytes",
                "open_streams",
                "accepted_streams",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))
        for name in (
                "keepalive_interval",
                "keepalive_max_ping_interval",
                "keepalive_timeout",
                "last_ping_rtt",
                "blocked_write_total",
                "last_open_latency",
        ):
            object.__setattr__(
                self, name, _nonnegative_float(getattr(self, name), name)
            )
        object.__setattr__(
            self,
            "ping_outstanding",
            _require_bool(self.ping_outstanding, "ping_outstanding"),
        )
        object.__setattr__(
            self, "ping_stalled", _require_bool(self.ping_stalled, "ping_stalled")
        )
        object.__setattr__(
            self,
            "last_inbound_frame_at",
            self.last_inbound_frame_at
            if self.last_inbound_frame_at is not None
            else self.progress.inbound_frame_at,
        )
        object.__setattr__(
            self,
            "last_control_progress",
            self.last_control_progress
            if self.last_control_progress is not None
            else self.progress.control_progress_at,
        )
        object.__setattr__(
            self,
            "last_transport_write",
            self.last_transport_write
            if self.last_transport_write is not None
            else self.progress.transport_write_at,
        )
        object.__setattr__(
            self,
            "last_stream_progress",
            self.last_stream_progress
            if self.last_stream_progress is not None
            else self.progress.stream_progress_at,
        )
        object.__setattr__(
            self,
            "last_app_progress",
            self.last_app_progress
            if self.last_app_progress is not None
            else self.progress.application_progress_at,
        )
        object.__setattr__(
            self,
            "last_ping_sent_at",
            self.last_ping_sent_at
            if self.last_ping_sent_at is not None
            else self.progress.ping_sent_at,
        )
        object.__setattr__(
            self,
            "last_pong_at",
            self.last_pong_at
            if self.last_pong_at is not None
            else self.progress.pong_at,
        )


@runtime_checkable
class Session(Protocol):
    """Stable synchronous session surface used by native zmux and adapters."""

    def __enter__(self) -> "Session":
        """Return the session for ``with`` blocks."""

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        """Close the session when leaving a ``with`` block."""

    def accept_stream(self, timeout: Optional[float] = None) -> Stream:
        """Accept the next peer-opened bidirectional stream."""

    def accept_uni_stream(self, timeout: Optional[float] = None) -> RecvStream:
        """Accept the next peer-opened unidirectional receive stream."""

    def open_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> Stream:
        """Open a local bidirectional stream."""

    def open_uni_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> SendStream:
        """Open a local unidirectional send stream."""

    def open_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> Stream:
        """Open a bidirectional stream and send its first payload."""

    def open_uni_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> SendStream:
        """Open a unidirectional stream, send final payload, and close write."""

    def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        """Send a PING and return round-trip time in seconds."""

    def go_away(
            self,
            last_accepted_bidi: int,
            last_accepted_uni: int,
            code: int = 0,
            reason: str = "",
    ) -> None:
        """Start graceful drain by advertising the last accepted stream ids."""

    def close(self) -> None:
        """Gracefully close the session."""

    def close_with_error(self, code: int, reason: str = "") -> None:
        """Terminate the session with an application-defined code."""

    def wait(self, timeout: Optional[float] = None) -> None:
        """Wait for final session termination."""

    @property
    def closed(self) -> bool:
        """Return whether the session has terminated."""
        raise NotImplementedError

    @property
    def local_addr(self) -> Optional[object]:
        """Return the local transport address when known."""
        raise NotImplementedError

    @property
    def remote_addr(self) -> Optional[object]:
        """Return the peer transport address when known."""
        raise NotImplementedError

    @property
    def close_error(self) -> Optional[BaseException]:
        """Return the terminal close error if one is known."""
        raise NotImplementedError

    @property
    def state(self) -> SessionState:
        """Return the public lifecycle state."""
        raise NotImplementedError

    @property
    def stats(self) -> SessionStats:
        """Return a point-in-time stats snapshot."""
        raise NotImplementedError

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        """Return the peer GOAWAY application error when present."""
        raise NotImplementedError

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        """Return the peer CLOSE application error when present."""
        raise NotImplementedError

    def local_preface(self) -> Preface:
        """Return the local preface."""

    def peer_preface(self) -> Preface:
        """Return the peer preface."""

    def negotiated(self) -> Negotiated:
        """Return negotiated session parameters."""


@runtime_checkable
class AsyncSession(Protocol):
    """Stable asynchronous session surface used by adapters."""

    async def __aenter__(self) -> "AsyncSession":
        """Return the session for ``async with`` blocks."""

    async def __aexit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        """Close the session when leaving an ``async with`` block."""

    async def accept_stream(self, timeout: Optional[float] = None) -> AsyncStream:
        """Accept the next peer-opened bidirectional stream."""

    async def accept_uni_stream(
            self, timeout: Optional[float] = None
    ) -> AsyncRecvStream:
        """Accept the next peer-opened unidirectional receive stream."""

    async def open_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> AsyncStream:
        """Open a local bidirectional stream."""

    async def open_uni_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> AsyncSendStream:
        """Open a local unidirectional send stream."""

    async def open_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> AsyncStream:
        """Open a bidirectional stream and send its first payload."""

    async def open_uni_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> AsyncSendStream:
        """Open a unidirectional stream, send final payload, and close write."""

    async def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        """Send a PING and return round-trip time in seconds."""

    async def go_away(
            self,
            last_accepted_bidi: int,
            last_accepted_uni: int,
            code: int = 0,
            reason: str = "",
    ) -> None:
        """Start graceful drain by advertising the last accepted stream ids."""

    async def close(self) -> None:
        """Gracefully close the session."""

    async def close_with_error(self, code: int, reason: str = "") -> None:
        """Terminate the session with an application-defined code."""

    async def wait(self, timeout: Optional[float] = None) -> None:
        """Wait for final session termination."""

    @property
    def closed(self) -> bool:
        """Return whether the session has terminated."""
        raise NotImplementedError

    @property
    def local_addr(self) -> Optional[object]:
        """Return the local transport address when known."""
        raise NotImplementedError

    @property
    def remote_addr(self) -> Optional[object]:
        """Return the peer transport address when known."""
        raise NotImplementedError

    @property
    def close_error(self) -> Optional[BaseException]:
        """Return the terminal close error if one is known."""
        raise NotImplementedError

    @property
    def state(self) -> SessionState:
        """Return the public lifecycle state."""
        raise NotImplementedError

    @property
    def stats(self) -> SessionStats:
        """Return a point-in-time stats snapshot."""
        raise NotImplementedError

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        """Return the peer GOAWAY application error when present."""
        raise NotImplementedError

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        """Return the peer CLOSE application error when present."""
        raise NotImplementedError

    def local_preface(self) -> Preface:
        """Return the local preface."""

    def peer_preface(self) -> Preface:
        """Return the peer preface."""

    def negotiated(self) -> Negotiated:
        """Return negotiated session parameters."""


class ClosedSession:
    """A permanently closed synchronous session."""

    __slots__ = ()

    def __enter__(self) -> "ClosedSession":
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def accept_stream(self, timeout: Optional[float] = None) -> Stream:
        raise _closed_session_error(ErrorOperation.ACCEPT)

    def accept_uni_stream(self, timeout: Optional[float] = None) -> RecvStream:
        raise _closed_session_error(ErrorOperation.ACCEPT)

    def open_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> Stream:
        raise _closed_session_error(ErrorOperation.OPEN)

    def open_uni_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> SendStream:
        raise _closed_session_error(ErrorOperation.OPEN)

    def open_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> Stream:
        raise _closed_session_error(ErrorOperation.OPEN)

    def open_uni_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> SendStream:
        raise _closed_session_error(ErrorOperation.OPEN)

    def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        raise _closed_session_error(ErrorOperation.PING)

    def go_away(
            self,
            last_accepted_bidi: int,
            last_accepted_uni: int,
            code: int = 0,
            reason: str = "",
    ) -> None:
        raise _closed_session_error(ErrorOperation.CLOSE)

    @staticmethod
    def close() -> None:
        return None

    @staticmethod
    def close_with_error(code: int, reason: str = "") -> None:
        if code is None and reason is None:
            return None
        return None

    @staticmethod
    def wait(timeout: Optional[float] = None) -> None:
        if timeout is not None:
            return None
        return None

    @property
    def closed(self) -> bool:
        return True

    @property
    def local_addr(self) -> Optional[object]:
        return None

    @property
    def remote_addr(self) -> Optional[object]:
        return None

    @property
    def close_error(self) -> Optional[BaseException]:
        return None

    @property
    def state(self) -> SessionState:
        return SessionState.CLOSED

    @property
    def stats(self) -> SessionStats:
        return _CLOSED_STATS

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        return None

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        return None

    @staticmethod
    def local_preface() -> Preface:
        return _zero_preface()

    @staticmethod
    def peer_preface() -> Preface:
        return _zero_preface()

    @staticmethod
    def negotiated() -> Negotiated:
        return _zero_negotiated()


class InvalidSession(ClosedSession):
    """A closed placeholder for a missing native session wrapper."""

    __slots__ = ()

    @property
    def state(self) -> SessionState:
        return SessionState.INVALID

    @property
    def stats(self) -> SessionStats:
        return _INVALID_STATS


class AsyncClosedSession:
    """A permanently closed asynchronous session."""

    __slots__ = ()

    async def __aenter__(self) -> "AsyncClosedSession":
        return self

    async def __aexit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        await self.close()

    async def accept_stream(self, timeout: Optional[float] = None) -> AsyncStream:
        raise _closed_session_error(ErrorOperation.ACCEPT)

    async def accept_uni_stream(
            self, timeout: Optional[float] = None
    ) -> AsyncRecvStream:
        raise _closed_session_error(ErrorOperation.ACCEPT)

    async def open_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> AsyncStream:
        raise _closed_session_error(ErrorOperation.OPEN)

    async def open_uni_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> AsyncSendStream:
        raise _closed_session_error(ErrorOperation.OPEN)

    async def open_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> AsyncStream:
        raise _closed_session_error(ErrorOperation.OPEN)

    async def open_uni_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> AsyncSendStream:
        raise _closed_session_error(ErrorOperation.OPEN)

    async def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        raise _closed_session_error(ErrorOperation.PING)

    async def go_away(
            self,
            last_accepted_bidi: int,
            last_accepted_uni: int,
            code: int = 0,
            reason: str = "",
    ) -> None:
        raise _closed_session_error(ErrorOperation.CLOSE)

    @staticmethod
    async def close() -> None:
        return None

    @staticmethod
    async def close_with_error(code: int, reason: str = "") -> None:
        if code is None and reason is None:
            return None
        return None

    @staticmethod
    async def wait(timeout: Optional[float] = None) -> None:
        if timeout is not None:
            return None
        return None

    @property
    def closed(self) -> bool:
        return True

    @property
    def local_addr(self) -> Optional[object]:
        return None

    @property
    def remote_addr(self) -> Optional[object]:
        return None

    @property
    def close_error(self) -> Optional[BaseException]:
        return None

    @property
    def state(self) -> SessionState:
        return SessionState.CLOSED

    @property
    def stats(self) -> SessionStats:
        return _CLOSED_STATS

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        return None

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        return None

    @staticmethod
    def local_preface() -> Preface:
        return _zero_preface()

    @staticmethod
    def peer_preface() -> Preface:
        return _zero_preface()

    @staticmethod
    def negotiated() -> Negotiated:
        return _zero_negotiated()


class AsyncInvalidSession(AsyncClosedSession):
    """A closed async placeholder for a missing async session wrapper."""

    __slots__ = ()

    @property
    def state(self) -> SessionState:
        return SessionState.INVALID

    @property
    def stats(self) -> SessionStats:
        return _INVALID_STATS


def closed_session() -> ClosedSession:
    """Return a permanently closed synchronous session handle."""

    return _CLOSED_SESSION


def async_closed_session() -> AsyncClosedSession:
    """Return a permanently closed asynchronous session handle."""

    return _ASYNC_CLOSED_SESSION


def as_session(session: Optional[Session]) -> Session:
    """Return ``session`` or an invalid placeholder handle."""

    return _INVALID_SESSION if session is None else session


def as_async_session(session: Optional[AsyncSession]) -> AsyncSession:
    """Return ``session`` or an invalid async placeholder handle."""

    return _ASYNC_INVALID_SESSION if session is None else session


def _closed_session_error(operation: ErrorOperation) -> SessionClosed:
    return (
        SessionClosed()
        .with_scope(ErrorScope.SESSION)
        .with_operation(operation)
        .with_source(ErrorSource.LOCAL)
        .with_direction(ErrorDirection.BOTH)
        .with_termination_kind(TerminationKind.SESSION_TERMINATION)
    )


def _zero_settings() -> Settings:
    return _ZERO_SETTINGS


def _zero_preface() -> Preface:
    return _ZERO_PREFACE


def _zero_negotiated() -> Negotiated:
    return _ZERO_NEGOTIATED


def _coerce_session_state(value: SessionState) -> SessionState:
    if isinstance(value, SessionState):
        return value
    if isinstance(value, str):
        return SessionState(value)
    raise TypeError("session state must be a SessionState or string")


def _nonnegative_int(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    return max(0, value)


def _saturating_add(left: int, right: int) -> int:
    left = _nonnegative_int(left, "left")
    right = _nonnegative_int(right, "right")
    return min(_MAX_UINT64, left + right)


def _nonnegative_float(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a number" % field_name)
    value = float(value)
    if value < 0.0 or not math.isfinite(value):
        return 0.0
    return value


def _require_bool(value: bool, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % field_name)
    return value


def _copy_reason_map(
        source: Mapping[int, int], field_name: str
) -> Mapping[int, int]:
    if source is None:
        return MappingProxyType({})
    copied = {}
    for key, value in source.items():
        code = _nonnegative_int(key, field_name + " code")
        count = _nonnegative_int(value, field_name + " count")
        copied[code] = count
    return MappingProxyType(copied)


def _coerce_stat(value, stat_type, field_name: str):
    if isinstance(value, stat_type):
        return value
    raise TypeError("%s must be a %s" % (field_name, stat_type.__name__))


_ZERO_SETTINGS = Settings(
    initial_max_stream_data_bidi_locally_opened=0,
    initial_max_stream_data_bidi_peer_opened=0,
    initial_max_stream_data_uni=0,
    initial_max_data=0,
    max_incoming_streams_bidi=0,
    max_incoming_streams_uni=0,
    max_frame_payload=0,
    max_control_payload_bytes=0,
    max_extension_payload_bytes=0,
    ping_padding_key=0,
)
_ZERO_PREFACE = Preface(
    preface_version=0,
    role=Role.INITIATOR,
    tie_breaker_nonce=0,
    min_proto=0,
    max_proto=0,
    capabilities=0,
    settings=_ZERO_SETTINGS,
)
_ZERO_NEGOTIATED = Negotiated(
    proto=0,
    capabilities=0,
    local_role=Role.INITIATOR,
    peer_role=Role.INITIATOR,
    peer_settings=_ZERO_SETTINGS,
)
_CLOSED_STATS = SessionStats(state=SessionState.CLOSED)
_INVALID_STATS = SessionStats(state=SessionState.INVALID)
_CLOSED_SESSION = ClosedSession()
_INVALID_SESSION = InvalidSession()
_ASYNC_CLOSED_SESSION = AsyncClosedSession()
_ASYNC_INVALID_SESSION = AsyncInvalidSession()

__all__ = [
    "AcceptBacklogStats",
    "ActiveStreamStats",
    "AbuseStats",
    "AsyncClosedSession",
    "AsyncInvalidSession",
    "AsyncSession",
    "ClosedSession",
    "DiagnosticStats",
    "FlushStats",
    "HiddenStats",
    "InvalidSession",
    "LivenessStats",
    "MemoryStats",
    "PressureStats",
    "ProgressStats",
    "ProvisionalStats",
    "QueueStats",
    "ReasonStats",
    "RetentionStats",
    "RetainedBucketStats",
    "RetainedStateBreakdownStats",
    "Session",
    "SessionState",
    "SessionStats",
    "TelemetryStats",
    "WriterQueueStats",
    "as_async_session",
    "as_session",
    "async_closed_session",
    "closed_session",
]
