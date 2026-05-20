"""Session-runtime policy and bookkeeping helpers.

The native session object will own locks, transport I/O, streams, and writer
threads.  This module holds the deterministic pieces copied from the Go
``session.go`` shape and cross-checked against the Java/Rust splits: lifecycle
planning, stream-id watermarks, establishment CLOSE payloads, policy derivation,
memory/retention accounting, provisional local-open queues, and ping/keepalive
payload helpers.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from threading import RLock
from typing import Any, Callable, Dict, Generic, Optional, TypeVar

from .._validation import require_varint62
from .control import MIN_PENDING_CONTROL_BUDGET, MIN_PENDING_PRIORITY_BUDGET
from .flow import repo_default_urgent_lane_cap
from .keepalive import (
    DEFAULT_KEEPALIVE_TIMEOUT_MAX,
    DEFAULT_KEEPALIVE_TIMEOUT_MIN,
    PING_NONCE_BYTES,
    PING_PADDING_TAG_BYTES,
    RTT_ADAPTIVE_SLACK,
    PingPayloadFingerprint,
    adaptive_rtt_timeout,
    average_u64_floor,
    build_padded_ping_echo,
    build_ping_payload,
    build_ping_payload_capped_with_nonce,
    effective_keepalive_timeout,
    fill_ping_padding_from_state,
    has_ping_padding_tag,
    init_keepalive_jitter_state,
    init_session_nonce_state,
    keepalive_lead_jittered_delay,
    make_ping_padding,
    next_keepalive_jitter,
    next_session_nonce,
    next_uint64n_from_state,
    ping_padding_bounds,
    ping_padding_tag,
    ping_payload_hash,
    ping_payload_len,
    ping_payload_limit,
    pong_payload_for_ping,
    pong_payload_matches_ping,
    keepalive_timeout_rtt_floor,
    rate_bytes_per_second,
    send_rate_sample,
    saturating_duration_mul_add,
)
from .read_loop import (
    ReadLoopAbuseConfig,
    aggregate_late_data_cap,
    first_local_stream_id,
    first_peer_stream_id,
    late_data_per_stream_cap,
    min_nonzero,
    negotiated_frame_payload,
    repo_default_per_stream_data_hwm,
    repo_default_session_data_hwm,
    saturating_add,
    saturating_mul,
    session_window_target,
    validate_go_away_watermark_creator,
    validate_go_away_watermark_for_direction,
)
from .stop_sending import stop_sending_drain_window
from .._state.open import (
    DEFAULT_ADMISSION_HARD_CAP,
    DEFAULT_ADMISSION_SOFT_CAP,
    PROVISIONAL_OPEN_MAX_AGE,
    admission_hard_cap,
    admission_soft_cap,
    projected_local_open_id,
    provisional_available_count,
    provisional_expired,
    provisional_open_hard_cap,
    provisional_open_soft_cap,
)
from .._state.session import (
    BeginCloseOutcome,
    BeginClosePlan,
    LocalOpenOutcome,
    PeerClosePlan,
    PeerGoAwayPlan,
    advance_session_on_go_away,
    allow_local_non_close_control,
    begin_session_closing,
    can_open_locally,
    close_session_state,
    ignore_peer_close,
    ignore_peer_non_close_frame,
    is_benign_session_error,
    is_session_finished,
    plan_begin_close,
    plan_local_open,
    plan_peer_close,
    plan_peer_go_away,
    visible_session_error,
)
from .._wire.payload import build_go_away_payload_capped
from ..config import (
    DEFAULT_ACCEPT_BACKLOG_LIMIT,
    DEFAULT_GO_AWAY_DRAIN_INTERVAL,
    DEFAULT_KEEPALIVE_INTERVAL,
    DEFAULT_KEEPALIVE_MAX_PING_INTERVAL,
    DEFAULT_PING_PADDING_MAX_BYTES,
    DEFAULT_PING_PADDING_MIN_BYTES,
    DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET,
    DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET,
    DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR,
    DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW,
    Config,
    Settings,
    default_accept_backlog_bytes_limit,
    default_config,
    default_settings,
)
from ..errors import (
    ApplicationError,
    OpenExpired,
    SessionClosed,
    error_code,
    error_reason,
)
from ..events import Event, EventType, StreamEventInfo
from ..frame import Frame, marshal_frame
from ..payload import StreamMetadata, build_error_payload
from ..preface import Negotiated, Preface
from ..protocol import ErrorCode, FrameType, MAX_VARINT62, Role

QueueT = TypeVar("QueueT")

MAX_UINT64 = (1 << 64) - 1

CONN_READ_BUFFER_SIZE = 512
WRITER_LANE_BUFFER = 128
ADVISORY_LANE_BUFFER = 32
MAX_BATCH_FRAMES = 32
SESSION_GO_AWAY_DRAIN_INTERVAL = DEFAULT_GO_AWAY_DRAIN_INTERVAL
SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT = 0.500
SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT_MAX = 5.0
SESSION_CLOSE_FRAME_SEND_TIMEOUT = 0.100
SESSION_CLOSE_FRAME_SEND_TIMEOUT_MAX = 2.0
ESTABLISHMENT_FAILURE_WRITE_WAIT = 0.250
ESTABLISHMENT_SUCCESS_WRITE_WAIT = 1.000
ESTABLISHMENT_CLOSE_DRAIN_DELAY = 0.010
SESSION_GO_AWAY_DRAIN_INTERVAL_MAX = 0.250

PROVISIONAL_OPEN_MAX_AGE_ADAPTIVE_CAP = 20.0
PROVISIONAL_OPEN_RTT_ADAPTIVE_SLACK = 0.250
PROVISIONAL_OPEN_RTT_MULTIPLIER = 6
PROVISIONAL_QUEUE_COMPACT_MIN_HEAD = 64
ACCEPT_QUEUE_COMPACT_MIN_HEAD = 64

MIN_SESSION_MEMORY_HARD_CAP = DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR
MIN_RETAINED_OPEN_INFO_BUDGET = DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET
MIN_RETAINED_PEER_REASON_BUDGET = DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET
MIN_RETAINED_STATE_UNIT = 4 << 10
MIN_COMPACT_TERMINAL_STATE_UNIT = 64
REASON_CODE_MAP_LIMIT = 1024

_DEFAULT_SETTINGS = default_settings()


class StreamArity(IntEnum):
    """Local/peer stream-id class."""

    UNI = 0
    BIDI = 1

    def is_bidi(self) -> bool:
        return self is StreamArity.BIDI

    def first_local_id(self, role: Role) -> int:
        return first_local_stream_id(role, self.is_bidi())

    def first_peer_id(self, role: Role) -> int:
        return first_peer_stream_id(role, self.is_bidi())

    def next_local_id(self, registry: "RegistryState") -> int:
        return registry.next_local_bidi if self.is_bidi() else registry.next_local_uni

    def set_next_local_id(self, registry: "RegistryState", value: int) -> None:
        if self.is_bidi():
            registry.next_local_bidi = _clamp_u64(value)
        else:
            registry.next_local_uni = _clamp_u64(value)

    def advance_local_id(self, registry: "RegistryState", assigned_id: int) -> int:
        next_id = saturating_add(assigned_id, 4)
        self.set_next_local_id(registry, next_id)
        return next_id

    @classmethod
    def from_bidi(cls, bidi: bool) -> "StreamArity":
        if not isinstance(bidi, bool):
            raise TypeError("bidi must be a boolean")
        return cls.BIDI if bidi else cls.UNI


@dataclass(frozen=True)
class KeepaliveAction(object):
    delay: float = 0.0
    send_ping: bool = False
    timed_out: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "delay", _nonnegative_float(self.delay, "delay"))
        object.__setattr__(self, "send_ping", _require_bool(self.send_ping, "send_ping"))
        object.__setattr__(self, "timed_out", _require_bool(self.timed_out, "timed_out"))

    def should_send_ping(self) -> bool:
        return self.send_ping

    def should_close(self) -> bool:
        return self.timed_out


def accepted_peer_go_away_watermark(
        local_role: Role,
        arity: StreamArity,
        next_peer_id: int,
) -> int:
    first_peer_id = first_peer_stream_id(local_role, arity.is_bidi())
    if next_peer_id <= first_peer_id:
        return 0
    return next_peer_id - 4


def max_peer_go_away_watermark(local_role: Role, arity: StreamArity) -> int:
    first_peer_id = first_peer_stream_id(local_role, arity.is_bidi())
    if first_peer_id == 0 or first_peer_id > MAX_VARINT62:
        return 0
    return first_peer_id + ((MAX_VARINT62 - first_peer_id) // 4) * 4


def effective_go_away_send_watermark(local_role: Role, arity: StreamArity, watermark: int) -> int:
    if watermark == MAX_VARINT62:
        return max_peer_go_away_watermark(local_role, arity)
    return watermark


def min_go_away_watermark(a: int, b: int) -> int:
    return a if a < b else b


def provisional_open_max_age(last_ping_rtt: Optional[float] = None) -> float:
    timeout = PROVISIONAL_OPEN_MAX_AGE
    rtt = 0.0 if last_ping_rtt is None else _nonnegative_float(last_ping_rtt, "last_ping_rtt")
    if rtt > 0:
        timeout = max(
            timeout,
            saturating_duration_mul_add(
                rtt,
                PROVISIONAL_OPEN_RTT_MULTIPLIER,
                PROVISIONAL_OPEN_RTT_ADAPTIVE_SLACK,
            ),
        )
    return min(timeout, PROVISIONAL_OPEN_MAX_AGE_ADAPTIVE_CAP)


def validate_local_go_away(
        local_role: Role,
        peer_role: Role,
        last_accepted_bidi: int,
        last_accepted_uni: int,
) -> None:
    validate_go_away_watermark_for_direction(last_accepted_bidi, True)
    validate_go_away_watermark_creator(peer_role, last_accepted_bidi)
    validate_go_away_watermark_for_direction(last_accepted_uni, False)
    validate_go_away_watermark_creator(peer_role, last_accepted_uni)
    _ = local_role


def default_urgent_queue_max_bytes(local: Settings, peer: Settings) -> int:
    payload = min_nonzero(local.max_control_payload_bytes, peer.max_control_payload_bytes)
    return repo_default_urgent_lane_cap(payload)


def default_hidden_control_opened_limit(pending_limit: int) -> int:
    return admission_hard_cap(pending_limit)


def hidden_control_soft_limit(hard_limit: int) -> int:
    hard_limit = _nonnegative_int(hard_limit, "hard_limit")
    if hard_limit <= 1:
        return hard_limit
    return max(1, hard_limit // 2)


def default_pending_control_bytes_budget(peer: Settings, local: Settings) -> int:
    payload = (
            peer.max_control_payload_bytes
            or local.max_control_payload_bytes
            or _DEFAULT_SETTINGS.max_control_payload_bytes
    )
    return max(MIN_PENDING_CONTROL_BUDGET, saturating_mul(payload, 8))


def default_pending_priority_bytes_budget(peer: Settings, local: Settings) -> int:
    payload = (
            peer.max_extension_payload_bytes
            or local.max_extension_payload_bytes
            or _DEFAULT_SETTINGS.max_extension_payload_bytes
    )
    return max(MIN_PENDING_PRIORITY_BUDGET, saturating_mul(payload, 8))


def retained_open_info_budget(
        local: Settings,
        peer: Settings,
        configured: Optional[int] = None,
) -> int:
    if configured:
        return _nonnegative_int(configured, "configured")
    max_payload = max(local.max_frame_payload, peer.max_frame_payload)
    if max_payload == 0:
        max_payload = _DEFAULT_SETTINGS.max_frame_payload
    return max(MIN_RETAINED_OPEN_INFO_BUDGET, saturating_mul(max_payload, 8))


def retained_peer_reason_budget(local: Settings, configured: Optional[int] = None) -> int:
    if configured:
        return _nonnegative_int(configured, "configured")
    max_payload = (
            local.max_control_payload_bytes or _DEFAULT_SETTINGS.max_control_payload_bytes
    )
    return max(MIN_RETAINED_PEER_REASON_BUDGET, saturating_mul(max_payload, 8))


def retained_state_unit(settings: Settings) -> int:
    unit = max(
        settings.max_frame_payload,
        settings.max_control_payload_bytes,
        settings.max_extension_payload_bytes,
    )
    if unit == 0:
        unit = max(
            _DEFAULT_SETTINGS.max_frame_payload,
            _DEFAULT_SETTINGS.max_control_payload_bytes,
            _DEFAULT_SETTINGS.max_extension_payload_bytes,
        )
    return max(unit, MIN_RETAINED_STATE_UNIT)


def compact_terminal_state_unit() -> int:
    return MIN_COMPACT_TERMINAL_STATE_UNIT


def session_memory_high_threshold(hard_cap: int) -> int:
    hard_cap = _nonnegative_int(hard_cap, "hard_cap")
    if hard_cap <= 4:
        return hard_cap
    return hard_cap - hard_cap // 4


def session_memory_hard_cap(
        local_settings: Settings,
        policy: "RuntimePolicy",
) -> int:
    if policy.session_memory_cap:
        return policy.session_memory_cap
    hard_cap = session_window_target(local_settings, policy.session_queued_data_hwm)
    hard_cap = saturating_add(hard_cap, policy.session_queued_data_hwm)
    hard_cap = saturating_add(hard_cap, policy.urgent_queued_bytes_cap)
    hard_cap = saturating_add(hard_cap, policy.pending_control_bytes_budget)
    hard_cap = saturating_add(hard_cap, policy.pending_priority_bytes_budget)
    hard_cap = saturating_add(hard_cap, policy.retained_open_info_bytes_budget)
    hard_cap = saturating_add(hard_cap, policy.retained_peer_reason_bytes_budget)
    return max(hard_cap, MIN_SESSION_MEMORY_HARD_CAP)


def session_memory_cap_error(tracked: int, hard_cap: int) -> Optional[RuntimeError]:
    if tracked <= hard_cap:
        return None
    return RuntimeError("session memory cap exceeded: tracked=%d cap=%d" % (tracked, hard_cap))


def retained_bucket_stats(count: int, unit: int) -> tuple[int, int]:
    count = _nonnegative_int(count, "count")
    unit = _nonnegative_int(unit, "unit")
    if count == 0 or unit == 0:
        return 0, 0
    return count, saturating_mul(count, unit)


def truncate_string_to_bytes(value: str, limit: int) -> str:
    if value is None:
        return ""
    value = str(value)
    limit = _nonnegative_int(limit, "limit")
    if limit == 0:
        return ""
    if len(value) <= limit and value.isascii():
        return value

    used = 0
    out: list[str] = []
    truncated = False
    for char in value:
        size = len(char.encode("utf-8"))
        if used + size > limit:
            truncated = True
            break
        out.append(char)
        used += size
    return "".join(out) if truncated else value


def build_close_payload(err: Optional[BaseException], max_payload: int) -> bytes:
    if err is None:
        return build_error_payload(int(ErrorCode.NO_ERROR), "", max_payload)
    app_err = close_mapped_application_error(err)
    return build_error_payload(app_err.code or 0, app_err.reason, max_payload)


def close_mapped_application_error(err: BaseException) -> ApplicationError:
    if isinstance(err, ApplicationError):
        return err.clone()
    code = error_code(err)
    if code is None:
        code = int(ErrorCode.INTERNAL)
    return ApplicationError(code, error_reason(err) or str(err))


def establishment_close_max_payload(local: Preface, peer: Optional[Preface]) -> int:
    if peer is not None and peer.settings.max_control_payload_bytes:
        return peer.settings.max_control_payload_bytes
    if local.settings.max_control_payload_bytes:
        return local.settings.max_control_payload_bytes
    return _DEFAULT_SETTINGS.max_control_payload_bytes


def build_establishment_close_frame(
        local: Preface,
        peer: Optional[Preface],
        err: Optional[BaseException],
) -> bytes:
    payload = build_close_payload(err, establishment_close_max_payload(local, peer))
    return marshal_frame(Frame(FrameType.CLOSE, 0, 0, payload))


def establishment_close_drain_delay(err: Optional[BaseException]) -> float:
    return 0.0 if err is None else ESTABLISHMENT_CLOSE_DRAIN_DELAY


@dataclass(frozen=True)
class RuntimePolicy(object):
    """Config-derived runtime constants for an established session."""

    write_queue_max_bytes: int
    write_batch_max_frames: int
    session_memory_cap: Optional[int]
    per_stream_queued_data_hwm: int
    session_queued_data_hwm: int
    urgent_queued_bytes_cap: int
    pending_control_bytes_budget: int
    pending_priority_bytes_budget: int
    accept_backlog_limit: int
    accept_backlog_bytes_limit: int
    hidden_control_opened_limit: int
    tombstone_limit: int
    marker_only_used_stream_limit: int
    retained_open_info_bytes_budget: int
    retained_peer_reason_bytes_budget: int
    aggregate_late_data_cap: int
    late_data_per_stream_cap: Optional[int]
    max_provisional_streams_bidi: int
    max_provisional_streams_uni: int
    provisional_open_max_age: float
    stop_sending_graceful_drain_window: float
    stop_sending_graceful_tail_cap: int
    graceful_close_drain_timeout: float
    go_away_drain_interval: float
    keepalive_interval: float
    keepalive_max_ping_interval: float
    keepalive_timeout: Optional[float]
    ping_padding: bool
    ping_padding_min_bytes: int
    ping_padding_max_bytes: int
    abuse: ReadLoopAbuseConfig = field(default_factory=ReadLoopAbuseConfig)

    @classmethod
    def from_config(
            cls,
            config: Optional[Config],
            local: Optional[Preface] = None,
            peer: Optional[Preface] = None,
            negotiated: Optional[Negotiated] = None,
    ) -> "RuntimePolicy":
        config = default_config() if config is None else config
        local = config.local_preface() if local is None else local
        peer_settings = negotiated.peer_settings if negotiated is not None else config.settings
        peer = (
            Preface(
                preface_version=local.preface_version,
                role=Role.RESPONDER if local.role == Role.INITIATOR else Role.INITIATOR,
                tie_breaker_nonce=0,
                min_proto=local.min_proto,
                max_proto=local.max_proto,
                capabilities=local.capabilities,
                settings=peer_settings,
            )
            if peer is None
            else peer
        )
        payload = negotiated_frame_payload(local.settings, peer.settings)
        per_stream_hwm = (
            config.per_stream_queued_data_hwm
            if config.per_stream_queued_data_hwm is not None
            else repo_default_per_stream_data_hwm(payload)
        )
        per_stream_hwm = max(1, per_stream_hwm)
        session_hwm = (
            config.session_queued_data_hwm
            if config.session_queued_data_hwm is not None
            else repo_default_session_data_hwm(per_stream_hwm)
        )
        session_hwm = max(1, session_hwm)
        accept_limit = (
            config.accept_backlog_limit
            if config.accept_backlog_limit is not None
            else DEFAULT_ACCEPT_BACKLOG_LIMIT
        )
        accept_bytes = (
            config.accept_backlog_bytes_limit
            if config.accept_backlog_bytes_limit is not None
            else default_accept_backlog_bytes_limit(local.settings.max_frame_payload)
        )
        hidden_control_limit = (
            config.hidden_control_opened_limit
            if config.hidden_control_opened_limit is not None
            else default_hidden_control_opened_limit(accept_limit)
        )
        marker_only_limit = (
            config.marker_only_used_stream_limit
            if config.marker_only_used_stream_limit is not None
            else config.used_marker_limit
        )
        return cls(
            write_queue_max_bytes=max(0, config.write_queue_max_bytes),
            write_batch_max_frames=max(0, config.write_batch_max_frames or MAX_BATCH_FRAMES),
            session_memory_cap=config.session_memory_cap,
            per_stream_queued_data_hwm=per_stream_hwm,
            session_queued_data_hwm=session_hwm,
            urgent_queued_bytes_cap=(
                config.urgent_queued_bytes_cap
                if config.urgent_queued_bytes_cap is not None
                else default_urgent_queue_max_bytes(local.settings, peer.settings)
            ),
            pending_control_bytes_budget=(
                config.pending_control_bytes_budget
                if config.pending_control_bytes_budget is not None
                else default_pending_control_bytes_budget(peer.settings, local.settings)
            ),
            pending_priority_bytes_budget=(
                config.pending_priority_bytes_budget
                if config.pending_priority_bytes_budget is not None
                else default_pending_priority_bytes_budget(peer.settings, local.settings)
            ),
            accept_backlog_limit=max(0, accept_limit),
            accept_backlog_bytes_limit=max(0, accept_bytes),
            hidden_control_opened_limit=max(0, hidden_control_limit),
            tombstone_limit=max(0, config.tombstone_limit),
            marker_only_used_stream_limit=max(0, marker_only_limit),
            retained_open_info_bytes_budget=retained_open_info_budget(
                local.settings, peer.settings, config.retained_open_info_bytes_budget
            ),
            retained_peer_reason_bytes_budget=retained_peer_reason_budget(
                local.settings, config.retained_peer_reason_bytes_budget
            ),
            aggregate_late_data_cap=(
                config.aggregate_late_data_cap
                if config.aggregate_late_data_cap is not None
                else aggregate_late_data_cap(local.settings.max_frame_payload)
            ),
            late_data_per_stream_cap=config.late_data_per_stream_cap,
            max_provisional_streams_bidi=max(0, config.max_provisional_streams_bidi),
            max_provisional_streams_uni=max(0, config.max_provisional_streams_uni),
            provisional_open_max_age=PROVISIONAL_OPEN_MAX_AGE,
            stop_sending_graceful_drain_window=(
                config.stop_sending_graceful_drain_window
                if config.stop_sending_graceful_drain_window is not None
                else DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
            ),
            stop_sending_graceful_tail_cap=(
                0
                if config.stop_sending_graceful_tail_cap is None
                else config.stop_sending_graceful_tail_cap
            ),
            graceful_close_drain_timeout=(
                SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT
                if config.graceful_close_drain_timeout is None
                else config.graceful_close_drain_timeout
            ),
            go_away_drain_interval=(
                SESSION_GO_AWAY_DRAIN_INTERVAL
                if config.go_away_drain_interval is None
                else config.go_away_drain_interval
            ),
            keepalive_interval=(
                0.0 if config.keepalive_interval is None else config.keepalive_interval
            ),
            keepalive_max_ping_interval=(
                0.0
                if config.keepalive_max_ping_interval is None
                else config.keepalive_max_ping_interval
            ),
            keepalive_timeout=config.keepalive_timeout,
            ping_padding=config.ping_padding,
            ping_padding_min_bytes=config.ping_padding_min_bytes,
            ping_padding_max_bytes=config.ping_padding_max_bytes,
            abuse=ReadLoopAbuseConfig.from_config(config),
        )


@dataclass
class RegistryState(object):
    """Stream id and live-stream counters owned by an established session."""

    next_local_bidi: int
    next_local_uni: int
    next_peer_bidi: int
    next_peer_uni: int
    active_local_bidi: int = 0
    active_local_uni: int = 0
    active_peer_bidi: int = 0
    active_peer_uni: int = 0
    live_stream_count: int = 0
    tombstone_limit: int = 0

    @classmethod
    def for_role(cls, role: Role, tombstone_limit: int = 0) -> "RegistryState":
        return cls(
            next_local_bidi=first_local_stream_id(role, True),
            next_local_uni=first_local_stream_id(role, False),
            next_peer_bidi=first_peer_stream_id(role, True),
            next_peer_uni=first_peer_stream_id(role, False),
            tombstone_limit=max(0, tombstone_limit),
        )

    def active_stats(self):
        from ..session import ActiveStreamStats

        return ActiveStreamStats(
            local_bidi=self.active_local_bidi,
            local_uni=self.active_local_uni,
            peer_bidi=self.active_peer_bidi,
            peer_uni=self.active_peer_uni,
        )


@dataclass
class FlowState(object):
    recv_session_advertised: int = 0
    recv_session_received: int = 0
    recv_session_used: int = 0
    recv_session_pending: int = 0
    send_session_max: int = 0
    send_session_used: int = 0
    queued_data_bytes: int = 0
    urgent_queued_bytes: int = 0
    read_buffer_overhead: int = 0

    def release_send(self, amount: int) -> bool:
        amount = _nonnegative_int(amount, "amount")
        before = self.send_session_credit()
        self.send_session_used = max(0, self.send_session_used - amount)
        return before == 0 and self.send_session_credit() > 0

    def send_session_credit(self) -> int:
        if self.send_session_used >= self.send_session_max:
            return 0
        return self.send_session_max - self.send_session_used


@dataclass
class RetentionState(object):
    retained_open_info_bytes: int = 0
    retained_peer_reason_bytes: int = 0
    reset_reasons: "ReasonCounter" = field(
        default_factory=lambda: ReasonCounter(REASON_CODE_MAP_LIMIT)
    )
    abort_reasons: "ReasonCounter" = field(
        default_factory=lambda: ReasonCounter(REASON_CODE_MAP_LIMIT)
    )
    hidden_control_retained: int = 0
    visible_tombstone_retained: int = 0
    marker_only_retained: int = 0
    marker_only_range_count: int = 0

    def retained_state_breakdown(self, settings: Settings) -> "RetainedStateBreakdown":
        retained_unit = retained_state_unit(settings)
        compact_unit = compact_terminal_state_unit()
        return RetainedStateBreakdown(
            hidden_control=RetainedBucket.from_count(self.hidden_control_retained, retained_unit),
            visible_tombstone=RetainedBucket.from_count(
                self.visible_tombstone_retained,
                compact_unit,
            ),
            marker_only=RetainedBucket.from_count(self.marker_only_retained, compact_unit),
        )

    def retain_peer_reason(
            self,
            old_bytes: int,
            reason: str,
            budget: int,
            hard_cap_available: int,
    ) -> tuple[str, int]:
        old_bytes = _nonnegative_int(old_bytes, "old_bytes")
        base = max(0, self.retained_peer_reason_bytes - old_bytes)
        if not reason or budget == 0 or base >= budget or hard_cap_available == 0:
            self.retained_peer_reason_bytes = base
            return "", 0
        available = min(budget - base, hard_cap_available)
        trimmed = truncate_string_to_bytes(reason, available)
        new_bytes = len(trimmed.encode("utf-8"))
        self.retained_peer_reason_bytes = saturating_add(base, new_bytes)
        return trimmed, new_bytes


@dataclass(frozen=True)
class RetainedBucket(object):
    count: int = 0
    bytes: int = 0

    @classmethod
    def from_count(cls, count: int, unit: int) -> "RetainedBucket":
        count, bytes_value = retained_bucket_stats(count, unit)
        return cls(count=count, bytes=bytes_value)


@dataclass(frozen=True)
class RetainedStateBreakdown(object):
    hidden_control: RetainedBucket = field(default_factory=RetainedBucket)
    accept_backlog: RetainedBucket = field(default_factory=RetainedBucket)
    provisionals: RetainedBucket = field(default_factory=RetainedBucket)
    visible_tombstone: RetainedBucket = field(default_factory=RetainedBucket)
    marker_only: RetainedBucket = field(default_factory=RetainedBucket)

    @property
    def total_bytes(self) -> int:
        total = self.hidden_control.bytes
        total = saturating_add(total, self.accept_backlog.bytes)
        total = saturating_add(total, self.provisionals.bytes)
        total = saturating_add(total, self.visible_tombstone.bytes)
        return saturating_add(total, self.marker_only.bytes)


@dataclass
class ReasonCounter(object):
    """Bounded reason-code count map with Go-compatible overflow behavior."""

    limit: int = REASON_CODE_MAP_LIMIT
    counts: Dict[int, int] = field(default_factory=dict)
    overflow: int = 0

    def __post_init__(self) -> None:
        self.limit = _strict_nonnegative_int(self.limit, "limit")
        overflow = _strict_nonnegative_int(self.overflow, "overflow")
        counts: Dict[int, int] = {}
        for raw_code, raw_count in self.counts.items():
            code = _strict_nonnegative_int(raw_code, "reason code")
            count = _strict_nonnegative_int(raw_count, "reason count")
            if count == 0:
                continue
            if code in counts:
                counts[code] = saturating_add(counts[code], count)
            elif len(counts) < self.limit:
                counts[code] = count
            else:
                overflow = saturating_add(overflow, count)
        self.counts = counts
        self.overflow = overflow

    def note(self, code: int) -> None:
        code = _strict_nonnegative_int(code, "code")
        if code in self.counts:
            self.counts[code] = saturating_add(self.counts[code], 1)
            return
        if len(self.counts) >= self.limit:
            self.overflow = saturating_add(self.overflow, 1)
            return
        self.counts[code] = 1

    def snapshot(self) -> tuple[Dict[int, int], int]:
        return dict(self.counts), self.overflow


@dataclass
class IngressState(object):
    aggregate_late_data: int = 0
    aggregate_late_data_cap: int = 0
    late_data_per_stream_cap: int = 0
    late_data_after_close: int = 0
    late_data_after_reset: int = 0
    late_data_after_abort: int = 0
    dropped_priority_update: int = 0
    dropped_local_priority: int = 0
    hidden_streams_refused: int = 0
    hidden_streams_reaped: int = 0
    hidden_unread_bytes_discarded: int = 0
    provisional_limited: int = 0
    provisional_expired: int = 0


@dataclass
class RuntimeMetrics(object):
    sent_frames: int = 0
    received_frames: int = 0
    sent_data_bytes: int = 0
    received_data_bytes: int = 0
    accepted_streams: int = 0
    flush_count: int = 0
    last_flush_at: Optional[float] = None
    last_batch_frames: int = 0
    last_batch_bytes: int = 0
    send_rate_estimate: int = 0
    blocked_write_time: float = 0.0
    last_open_latency: float = 0.0
    coalesced_terminal_signals: int = 0
    dropped_superseded_controls: int = 0
    skipped_close_on_dead_io: int = 0
    protocol_backlog_blocked: int = 0
    close_frame_admission_timeout: int = 0
    close_frame_flush_timeout: int = 0
    close_frame_flush_error: int = 0
    close_completion_timeout: int = 0
    graceful_close_timeout: int = 0
    keepalive_timeout: int = 0
    visible_terminal_churn_events: int = 0
    group_rebucket_events: int = 0
    hidden_abort_churn_events: int = 0

    def note_flush(
            self,
            byte_count: int,
            frame_count: int,
            data_bytes: int = 0,
            elapsed: float = 0.0,
            now: Optional[float] = None,
    ) -> None:
        byte_count = _nonnegative_int(byte_count, "byte_count")
        frame_count = _nonnegative_int(frame_count, "frame_count")
        data_bytes = _nonnegative_int(data_bytes, "data_bytes")
        self.sent_frames = saturating_add(self.sent_frames, frame_count)
        self.sent_data_bytes = saturating_add(self.sent_data_bytes, data_bytes)
        self.flush_count = saturating_add(self.flush_count, 1)
        self.last_flush_at = time.monotonic() if now is None else float(now)
        self.last_batch_frames = frame_count
        self.last_batch_bytes = byte_count
        sample = send_rate_sample(byte_count, elapsed)
        if sample:
            if self.send_rate_estimate == 0:
                self.send_rate_estimate = sample
            else:
                self.send_rate_estimate = average_u64_floor(
                    self.send_rate_estimate,
                    sample,
                )

    def note_blocked_write(self, blocked: float) -> None:
        if blocked > 0:
            self.blocked_write_time = self.blocked_write_time + float(blocked)

    def note_writer_failure(self, close_frame_attempted: bool = False) -> None:
        close_frame_attempted = _require_bool(close_frame_attempted, "close_frame_attempted")
        if close_frame_attempted:
            self.close_frame_flush_error = saturating_add(self.close_frame_flush_error, 1)
        else:
            self.skipped_close_on_dead_io = saturating_add(self.skipped_close_on_dead_io, 1)


@dataclass
class LivenessState(object):
    keepalive_interval: float = DEFAULT_KEEPALIVE_INTERVAL
    keepalive_max_ping_interval: float = DEFAULT_KEEPALIVE_MAX_PING_INTERVAL
    keepalive_timeout: Optional[float] = None
    ping_padding: bool = False
    ping_padding_min: int = DEFAULT_PING_PADDING_MIN_BYTES
    ping_padding_max: int = DEFAULT_PING_PADDING_MAX_BYTES
    keepalive_jitter_state: int = 0
    ping_nonce_state: int = 0
    read_idle_ping_due_at: Optional[float] = None
    write_idle_ping_due_at: Optional[float] = None
    max_ping_due_at: Optional[float] = None
    last_inbound_frame_at: Optional[float] = None
    last_control_progress_at: Optional[float] = None
    last_transport_write_at: Optional[float] = None
    last_stream_progress_at: Optional[float] = None
    last_app_progress_at: Optional[float] = None
    last_ping_sent_at: Optional[float] = None
    last_pong_at: Optional[float] = None
    last_ping_rtt: float = 0.0
    ping_outstanding: bool = False
    ping_accepts_padded_pong: bool = False
    ping_payload: bytes = b""
    canceled_ping: "PingPayloadFingerprint" = field(
        default_factory=lambda: PingPayloadFingerprint()
    )
    last_ping_padding_len: int = 0

    @classmethod
    def from_policy(
            cls,
            policy: RuntimePolicy,
            local: Preface,
            peer: Preface,
            now: Optional[float] = None,
    ) -> "LivenessState":
        now = time.monotonic() if now is None else float(now)
        state = cls(
            keepalive_interval=policy.keepalive_interval,
            keepalive_max_ping_interval=policy.keepalive_max_ping_interval,
            keepalive_timeout=policy.keepalive_timeout,
            keepalive_jitter_state=init_keepalive_jitter_state(
                local.tie_breaker_nonce ^ peer.tie_breaker_nonce
            ),
            ping_nonce_state=init_session_nonce_state(
                (local.tie_breaker_nonce << 1) ^ peer.tie_breaker_nonce
            ),
            ping_padding=policy.ping_padding,
            ping_padding_min=policy.ping_padding_min_bytes,
            ping_padding_max=policy.ping_padding_max_bytes,
            last_inbound_frame_at=now,
            last_control_progress_at=now,
            last_transport_write_at=now,
        )
        state.reset_keepalive_schedules(now)
        return state

    def note_inbound_frame(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else float(now)
        self.last_inbound_frame_at = now
        self.last_control_progress_at = now
        self.reset_read_idle_ping_due(now)

    def note_transport_write(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else float(now)
        self.last_transport_write_at = now
        self.reset_write_idle_ping_due(now)

    def note_stream_progress(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else float(now)
        self.last_stream_progress_at = now
        self.last_app_progress_at = now

    def reset_keepalive_schedules(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else float(now)
        self.reset_read_idle_ping_due(now)
        self.reset_write_idle_ping_due(now)
        self.reset_max_ping_due(now)

    def ensure_keepalive_schedules(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else float(now)
        if self.keepalive_interval <= 0:
            self.read_idle_ping_due_at = None
            self.write_idle_ping_due_at = None
            self.max_ping_due_at = None
            return
        if self.read_idle_ping_due_at is None:
            self.reset_read_idle_ping_due(self.last_inbound_frame_at or now)
        if self.write_idle_ping_due_at is None:
            self.reset_write_idle_ping_due(self.last_transport_write_at or now)
        if self.max_ping_due_at is None:
            self.reset_max_ping_due(now)

    def reset_read_idle_ping_due(self, now: float) -> None:
        if self.keepalive_interval <= 0:
            self.read_idle_ping_due_at = None
            return
        self.read_idle_ping_due_at = now + keepalive_lead_jittered_delay(
            self.keepalive_interval, self
        )

    def reset_write_idle_ping_due(self, now: float) -> None:
        if self.keepalive_interval <= 0:
            self.write_idle_ping_due_at = None
            return
        self.write_idle_ping_due_at = now + keepalive_lead_jittered_delay(
            self.keepalive_interval, self
        )

    def reset_max_ping_due(self, now: float) -> None:
        if self.keepalive_interval <= 0 or self.keepalive_max_ping_interval <= 0:
            self.max_ping_due_at = None
            return
        self.max_ping_due_at = now + keepalive_lead_jittered_delay(
            self.keepalive_max_ping_interval, self
        )

    def effective_keepalive_timeout(self) -> float:
        return effective_keepalive_timeout(
            self.keepalive_interval,
            self.keepalive_timeout or 0.0,
            self.last_ping_rtt,
        )

    def next_keepalive_action(self, now: Optional[float] = None) -> KeepaliveAction:
        now = time.monotonic() if now is None else float(now)
        if self.keepalive_interval <= 0:
            return KeepaliveAction()
        if self.ping_outstanding:
            timeout = self.effective_keepalive_timeout()
            if timeout > 0 and self.last_ping_sent_at is not None:
                elapsed = max(0.0, now - self.last_ping_sent_at)
                if elapsed > timeout:
                    return KeepaliveAction(timed_out=True)
                remaining = timeout - elapsed
                if remaining > 0:
                    return KeepaliveAction(delay=remaining)
            return KeepaliveAction(delay=self.keepalive_interval)
        self.ensure_keepalive_schedules(now)
        due = earliest_nonzero_time(
            self.read_idle_ping_due_at,
            self.write_idle_ping_due_at,
            self.max_ping_due_at,
        )
        if due is None:
            return KeepaliveAction()
        if due <= now:
            return KeepaliveAction(send_ping=True)
        return KeepaliveAction(delay=due - now)

    def begin_ping_payload(
            self,
            payload: bytes,
            sent_at: Optional[float] = None,
            accepts_padded_pong: bool = False,
    ) -> None:
        if self.ping_outstanding:
            raise RuntimeError("zmux: ping already outstanding")
        if not isinstance(accepts_padded_pong, bool):
            raise TypeError("accepts_padded_pong must be a bool")
        self.ping_payload = _bytes_like(payload, "payload")
        self.ping_outstanding = True
        self.ping_accepts_padded_pong = accepts_padded_pong
        self.last_ping_sent_at = time.monotonic() if sent_at is None else float(sent_at)
        self.reset_max_ping_due(self.last_ping_sent_at)

    def clear_ping(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else float(now)
        self.ping_outstanding = False
        self.ping_accepts_padded_pong = False
        self.ping_payload = b""
        self.reset_read_idle_ping_due(now)
        self.reset_write_idle_ping_due(now)

    def cancel_ping(self, now: Optional[float] = None) -> None:
        self.canceled_ping = PingPayloadFingerprint.from_payload(
            self.ping_payload, self.ping_accepts_padded_pong
        )
        self.clear_ping(now)

    def handle_pong_payload(self, payload: bytes, now: Optional[float] = None) -> bool:
        payload = _bytes_like(payload, "payload")
        now = time.monotonic() if now is None else float(now)
        self.last_pong_at = now
        if self.ping_outstanding and (
                payload == self.ping_payload
                or (
                        self.ping_accepts_padded_pong
                        and pong_payload_matches_ping(
                    payload,
                    self.ping_payload,
                    allow_padding=True,
                )
                )
        ):
            if self.last_ping_sent_at is not None:
                self.last_ping_rtt = max(0.0, now - self.last_ping_sent_at)
            self.clear_ping(now)
            return True
        if self.canceled_ping.matches(payload):
            self.canceled_ping = PingPayloadFingerprint()
            return True
        return False


@dataclass
class SessionControlState(object):
    peer_go_away_bidi: int = MAX_VARINT62
    peer_go_away_uni: int = MAX_VARINT62
    local_go_away_bidi: int = MAX_VARINT62
    local_go_away_uni: int = MAX_VARINT62
    peer_go_away_error: Optional[ApplicationError] = None
    peer_close_error: Optional[ApplicationError] = None
    sent_go_away_bidi: int = 0
    sent_go_away_uni: int = 0
    has_sent_go_away: bool = False
    pending_go_away_bidi: int = 0
    pending_go_away_uni: int = 0
    pending_go_away_payload: bytes = b""
    has_pending_go_away: bool = False
    go_away_send_active: bool = False

    def set_pending_go_away(self, bidi: int, uni: int, payload: bytes) -> None:
        self.pending_go_away_bidi = _require_varint62(bidi, "bidi")
        self.pending_go_away_uni = _require_varint62(uni, "uni")
        self.pending_go_away_payload = _bytes_like(payload, "payload")
        self.has_pending_go_away = True

    def clear_pending_go_away(self) -> None:
        self.pending_go_away_bidi = 0
        self.pending_go_away_uni = 0
        self.pending_go_away_payload = b""
        self.has_pending_go_away = False


@dataclass
class ShutdownState(object):
    graceful_close_active: bool = False
    close_frame_pending: bool = False
    close_frame_sent: bool = False

    def close_frame_outstanding(self) -> bool:
        return self.close_frame_pending or self.close_frame_sent

    def finish_close_frame_enqueue(self, sent: bool) -> None:
        sent = _require_bool(sent, "sent")
        self.close_frame_pending = False
        if sent:
            self.close_frame_sent = True


@dataclass
class SessionRuntimeState(object):
    """In-memory state bundle used by future native sync/async sessions."""

    local_preface: Preface
    peer_preface: Preface
    negotiated: Negotiated
    policy: RuntimePolicy
    state: Any
    registry: RegistryState
    flow: FlowState
    retention: RetentionState = field(default_factory=RetentionState)
    ingress: IngressState = field(default_factory=IngressState)
    metrics: RuntimeMetrics = field(default_factory=RuntimeMetrics)
    liveness: LivenessState = field(default_factory=LivenessState)
    control: SessionControlState = field(default_factory=SessionControlState)
    shutdown: ShutdownState = field(default_factory=ShutdownState)
    inflight_data_by_stream: Dict[int, int] = field(default_factory=dict)
    open_streams: int = 0
    close_error: Optional[BaseException] = None

    @classmethod
    def established(
            cls,
            local: Preface,
            peer: Preface,
            negotiated: Negotiated,
            config: Optional[Config] = None,
            now: Optional[float] = None,
    ) -> "SessionRuntimeState":
        policy = RuntimePolicy.from_config(config, local, peer, negotiated)
        registry = RegistryState.for_role(negotiated.local_role, policy.tombstone_limit)
        flow = FlowState(
            recv_session_advertised=local.settings.initial_max_data,
            send_session_max=peer.settings.initial_max_data,
        )
        ingress = IngressState(
            aggregate_late_data_cap=policy.aggregate_late_data_cap,
            late_data_per_stream_cap=policy.late_data_per_stream_cap or 0,
        )
        return cls(
            local_preface=local,
            peer_preface=peer,
            negotiated=negotiated,
            policy=policy,
            state=_session_state("ready"),
            registry=registry,
            flow=flow,
            ingress=ingress,
            liveness=LivenessState.from_policy(policy, local, peer, now),
        )

    def tracked_session_memory(self, retained_state_bytes: Optional[int] = None) -> int:
        if retained_state_bytes is None:
            retained_state_bytes = self.retained_state_breakdown().total_bytes
        total = self.flow.recv_session_used
        total = saturating_add(total, self.flow.queued_data_bytes)
        total = saturating_add(total, self.flow.urgent_queued_bytes)
        total = saturating_add(total, self.flow.read_buffer_overhead)
        total = saturating_add(total, self.retention.retained_open_info_bytes)
        total = saturating_add(total, self.retention.retained_peer_reason_bytes)
        total = saturating_add(total, len(self.liveness.ping_payload))
        return saturating_add(total, retained_state_bytes)

    def add_inflight_data(self, data: Any) -> None:
        for stream_id, byte_count in _stream_value_items(data):
            self.inflight_data_by_stream[stream_id] = saturating_add(
                self.inflight_data_by_stream.get(stream_id, 0),
                byte_count,
            )

    def remove_inflight_data(self, data: Any) -> None:
        for stream_id, byte_count in _stream_value_items(data):
            remaining = max(0, self.inflight_data_by_stream.get(stream_id, 0) - byte_count)
            if remaining:
                self.inflight_data_by_stream[stream_id] = remaining
            else:
                self.inflight_data_by_stream.pop(stream_id, None)

    def inflight_data_for_stream(self, stream_id: int) -> int:
        stream_id = _positive_int(stream_id, "stream_id")
        return self.inflight_data_by_stream.get(stream_id, 0)

    def hard_cap(self) -> int:
        return session_memory_hard_cap(self.local_preface.settings, self.policy)

    def high_threshold(self) -> int:
        return session_memory_high_threshold(self.hard_cap())

    def memory_pressure_high(self) -> bool:
        return self.tracked_session_memory() >= self.high_threshold()

    def marker_only_used_stream_hard_cap(self, hard_cap: Optional[int] = None) -> int:
        return self.policy.marker_only_used_stream_limit

    def retained_state_breakdown(self) -> RetainedStateBreakdown:
        retained_unit = retained_state_unit(self.local_preface.settings)
        compact_unit = compact_terminal_state_unit()
        return RetainedStateBreakdown(
            hidden_control=RetainedBucket.from_count(
                self.retention.hidden_control_retained,
                retained_unit,
            ),
            accept_backlog=RetainedBucket.from_count(self.accept_backlog_count(), retained_unit),
            provisionals=RetainedBucket.from_count(self.provisional_count(), retained_unit),
            visible_tombstone=RetainedBucket.from_count(
                self.retention.visible_tombstone_retained,
                compact_unit,
            ),
            marker_only=RetainedBucket.from_count(
                self.retention.marker_only_retained,
                compact_unit,
            ),
        )

    @staticmethod
    def provisional_count() -> int:
        return 0

    @staticmethod
    def accept_backlog_count() -> int:
        return 0

    def note_reset_reason(self, code: int) -> None:
        self.retention.reset_reasons.note(code)

    def note_abort_reason(self, code: int) -> None:
        self.retention.abort_reasons.note(code)

    def begin_close(self, has_open_streams: bool = False) -> BeginClosePlan:
        has_open_streams = _require_bool(has_open_streams, "has_open_streams")
        plan = plan_begin_close(
            self.state,
            self.shutdown.graceful_close_active,
            self.close_error is not None,
            has_open_streams,
        )
        self.state = plan.next_state
        if plan.outcome is BeginCloseOutcome.GRACEFUL:
            self.shutdown.graceful_close_active = True
        return plan

    def close_with_error(self, err: Optional[BaseException]) -> None:
        self.close_error = err or SessionClosed()
        self.state = close_session_state(self.state, self.close_error)
        self.shutdown.graceful_close_active = False
        self.liveness.ping_outstanding = False
        self.liveness.ping_payload = b""

    def effective_late_data_per_stream_cap(self, initial_stream_window: int) -> int:
        if self.policy.late_data_per_stream_cap is not None:
            return self.policy.late_data_per_stream_cap
        payload = negotiated_frame_payload(self.local_preface.settings, self.peer_preface.settings)
        return late_data_per_stream_cap(initial_stream_window, payload)

    def go_away_payload(self, bidi: int, uni: int, code: int = 0, reason: str = "") -> bytes:
        validate_local_go_away(
            self.negotiated.local_role,
            self.negotiated.peer_role,
            bidi,
            uni,
        )
        max_payload = (
                self.peer_preface.settings.max_control_payload_bytes
                or _DEFAULT_SETTINGS.max_control_payload_bytes
        )
        return build_go_away_payload_capped(bidi, uni, code, reason, max_payload)

    def stats(self):
        from ..session import (
            AcceptBacklogStats,
            AbuseStats,
            DiagnosticStats,
            FlushStats,
            HiddenStats,
            LivenessStats,
            MemoryStats,
            PressureStats,
            ProgressStats,
            ProvisionalStats,
            QueueStats,
            ReasonStats,
            RetentionStats,
            RetainedBucketStats,
            RetainedStateBreakdownStats,
            SessionStats,
            TelemetryStats,
            WriterQueueStats,
        )

        now = time.monotonic()
        terminal = _coerce_public_state(self.state).terminal()
        retained_breakdown = self.retained_state_breakdown()
        tracked = self.tracked_session_memory(retained_breakdown.total_bytes)
        hard_cap = self.hard_cap()
        high_threshold = session_memory_high_threshold(hard_cap)
        reset, reset_overflow = self.retention.reset_reasons.snapshot()
        abort, abort_overflow = self.retention.abort_reasons.snapshot()
        keepalive_timeout = self.liveness.effective_keepalive_timeout()
        retained_buckets = RetainedStateBreakdownStats(
            hidden_control=RetainedBucketStats(
                retained_breakdown.hidden_control.count,
                retained_breakdown.hidden_control.bytes,
            ),
            accept_backlog=RetainedBucketStats(
                retained_breakdown.accept_backlog.count,
                retained_breakdown.accept_backlog.bytes,
            ),
            provisionals=RetainedBucketStats(
                retained_breakdown.provisionals.count,
                retained_breakdown.provisionals.bytes,
            ),
            visible_tombstone=RetainedBucketStats(
                retained_breakdown.visible_tombstone.count,
                retained_breakdown.visible_tombstone.bytes,
            ),
            marker_only=RetainedBucketStats(
                retained_breakdown.marker_only.count,
                retained_breakdown.marker_only.bytes,
            ),
        )
        ping_stalled = (
                not terminal
                and self.liveness.ping_outstanding
                and self.liveness.last_ping_sent_at is not None
                and keepalive_timeout > 0
                and now - self.liveness.last_ping_sent_at > keepalive_timeout / 2
        )
        inbound_idle_for = 0.0
        if not terminal and self.liveness.last_inbound_frame_at is not None:
            inbound_idle_for = max(0.0, now - self.liveness.last_inbound_frame_at)
        outbound_idle_for = 0.0
        if not terminal and self.liveness.last_transport_write_at is not None:
            outbound_idle_for = max(0.0, now - self.liveness.last_transport_write_at)
        queued_bytes = saturating_add(self.flow.queued_data_bytes, self.flow.urgent_queued_bytes)
        abuse = self.policy.abuse
        accept_backlog_count = retained_breakdown.accept_backlog.count
        accept_backlog_bytes = retained_breakdown.accept_backlog.bytes
        hidden_retained = self.retention.hidden_control_retained
        hidden_hard_cap = self.policy.hidden_control_opened_limit
        hidden_soft_cap = hidden_control_soft_limit(hidden_hard_cap)
        return SessionStats(
            state=self.state,
            sent_frames=self.metrics.sent_frames,
            received_frames=self.metrics.received_frames,
            sent_data_bytes=self.metrics.sent_data_bytes,
            received_data_bytes=self.metrics.received_data_bytes,
            open_streams=self.open_streams,
            accepted_streams=self.metrics.accepted_streams,
            keepalive_interval=0.0 if terminal else self.liveness.keepalive_interval,
            keepalive_max_ping_interval=(
                0.0 if terminal else self.liveness.keepalive_max_ping_interval
            ),
            keepalive_timeout=keepalive_timeout,
            ping_outstanding=False if terminal else self.liveness.ping_outstanding,
            ping_stalled=ping_stalled,
            progress=ProgressStats(
                inbound_frame_at=self.liveness.last_inbound_frame_at,
                control_progress_at=self.liveness.last_control_progress_at,
                transport_write_at=self.liveness.last_transport_write_at,
                stream_progress_at=self.liveness.last_stream_progress_at,
                application_progress_at=self.liveness.last_app_progress_at,
                ping_sent_at=None if terminal else self.liveness.last_ping_sent_at,
                pong_at=None if terminal else self.liveness.last_pong_at,
            ),
            last_ping_rtt=0.0 if terminal else self.liveness.last_ping_rtt,
            active_streams=self.registry.active_stats(),
            queues=QueueStats(),
            flush=FlushStats(
                count=self.metrics.flush_count,
                last_at=self.metrics.last_flush_at,
                last_frames=self.metrics.last_batch_frames,
                last_bytes=self.metrics.last_batch_bytes,
            ),
            blocked_write_total=self.metrics.blocked_write_time,
            last_open_latency=self.metrics.last_open_latency,
            pressure=PressureStats(
                receive_backlog_bytes=self.flow.recv_session_used,
                receive_backlog_high=(
                        self.flow.recv_session_advertised > 0
                        and self.flow.recv_session_used >= self.flow.recv_session_advertised // 2
                ),
                aggregate_late_data_bytes=self.ingress.aggregate_late_data,
                aggregate_late_data_at_cap=(
                        0
                        < self.ingress.aggregate_late_data_cap
                        <= self.ingress.aggregate_late_data
                ),
                retained_state_bytes=retained_breakdown.total_bytes,
                retained_buckets=retained_buckets,
                retained_open_info_bytes=self.retention.retained_open_info_bytes,
                retained_peer_reason_bytes=self.retention.retained_peer_reason_bytes,
                tracked_buffered_bytes=tracked,
                tracked_buffered_limit=hard_cap,
                tracked_buffered_high=tracked >= high_threshold,
                tracked_buffered_at_cap=tracked >= hard_cap,
                buffered_receive_bytes=self.flow.recv_session_used,
                buffered_receive_storage_bytes=self.flow.read_buffer_overhead,
                recv_session_advertised_bytes=self.flow.recv_session_advertised,
                recv_session_received_bytes=self.flow.recv_session_received,
                recv_session_pending_bytes=self.flow.recv_session_pending,
                outstanding_ping_bytes=0 if terminal else len(self.liveness.ping_payload),
            ),
            hidden=HiddenStats(
                retained=hidden_retained,
                soft_cap=hidden_soft_cap,
                hard_cap=hidden_hard_cap,
                at_soft_cap=hidden_soft_cap != 0 and hidden_retained >= hidden_soft_cap,
                at_hard_cap=hidden_hard_cap != 0 and hidden_retained >= hidden_hard_cap,
                refused=self.ingress.hidden_streams_refused,
                reaped=self.ingress.hidden_streams_reaped,
                unread_bytes_discarded=self.ingress.hidden_unread_bytes_discarded,
            ),
            accept_backlog=AcceptBacklogStats(
                count=accept_backlog_count,
                count_limit=self.policy.accept_backlog_limit,
                bytes=accept_backlog_bytes,
                bytes_limit=self.policy.accept_backlog_bytes_limit,
            ),
            provisionals=ProvisionalStats(
                soft_cap=provisional_open_soft_cap(self.policy.accept_backlog_limit),
                hard_cap=provisional_open_hard_cap(self.policy.accept_backlog_limit),
                bidi_limit=self.policy.max_provisional_streams_bidi,
                uni_limit=self.policy.max_provisional_streams_uni,
                limited=self.ingress.provisional_limited,
                expired=self.ingress.provisional_expired,
            ),
            reasons=ReasonStats(
                reset=reset,
                reset_overflow=reset_overflow,
                abort=abort,
                abort_overflow=abort_overflow,
            ),
            diagnostics=DiagnosticStats(
                dropped_priority_updates=self.ingress.dropped_priority_update,
                dropped_local_priority_updates=self.ingress.dropped_local_priority,
                late_data_after_close_read=self.ingress.late_data_after_close,
                late_data_after_reset=self.ingress.late_data_after_reset,
                late_data_after_abort=self.ingress.late_data_after_abort,
                visible_terminal_churn_events=self.metrics.visible_terminal_churn_events,
                group_rebucket_events=self.metrics.group_rebucket_events,
                hidden_abort_churn_events=self.metrics.hidden_abort_churn_events,
                coalesced_terminal_signals=self.metrics.coalesced_terminal_signals,
                superseded_terminal_signals=self.metrics.dropped_superseded_controls,
                skipped_close_on_dead_io=self.metrics.skipped_close_on_dead_io,
                close_frame_admission_timeouts=self.metrics.close_frame_admission_timeout,
                close_frame_flush_timeouts=self.metrics.close_frame_flush_timeout,
                close_frame_flush_errors=self.metrics.close_frame_flush_error,
                close_completion_timeouts=self.metrics.close_completion_timeout,
                graceful_close_timeouts=self.metrics.graceful_close_timeout,
                keepalive_timeouts=self.metrics.keepalive_timeout,
                protocol_backlog_blocked=self.metrics.protocol_backlog_blocked,
                marker_only_range_count=self.retention.marker_only_range_count,
            ),
            telemetry=TelemetryStats(
                last_open_latency=(
                    self.metrics.last_open_latency
                    if self.metrics.last_open_latency > 0
                    else None
                ),
                send_rate_estimate_bytes_per_second=self.metrics.send_rate_estimate,
            ),
            writer_queue=WriterQueueStats(
                queued_bytes=queued_bytes,
                max_bytes=self.policy.write_queue_max_bytes,
                urgent_queued_bytes=self.flow.urgent_queued_bytes,
                urgent_max_bytes=self.policy.urgent_queued_bytes_cap,
                data_queued_bytes=self.flow.queued_data_bytes,
                session_data_high_watermark=self.policy.session_queued_data_hwm,
                per_stream_data_high_watermark=self.policy.per_stream_queued_data_hwm,
                pending_control_bytes_budget=self.policy.pending_control_bytes_budget,
                pending_priority_bytes_budget=self.policy.pending_priority_bytes_budget,
                max_batch_frames=self.policy.write_batch_max_frames,
            ),
            liveness=LivenessStats(
                keepalive_interval=0.0 if terminal else self.liveness.keepalive_interval,
                keepalive_max_ping_interval=(
                    0.0 if terminal else self.liveness.keepalive_max_ping_interval
                ),
                keepalive_timeout=keepalive_timeout,
                ping_outstanding=False if terminal else self.liveness.ping_outstanding,
                ping_stalled=ping_stalled,
                last_ping_rtt=None if terminal else self.liveness.last_ping_rtt,
                inbound_idle_for=inbound_idle_for,
                outbound_idle_for=outbound_idle_for,
            ),
            retention=RetentionStats(
                tombstones=self.retention.visible_tombstone_retained,
                tombstone_limit=self.policy.tombstone_limit,
                marker_only_used_streams=self.retention.marker_only_retained,
                marker_only_used_stream_ranges=self.retention.marker_only_range_count,
                marker_only_used_stream_limit=self.marker_only_used_stream_hard_cap(
                    hard_cap
                ),
                retained_open_info_bytes=self.retention.retained_open_info_bytes,
                retained_open_info_bytes_budget=self.policy.retained_open_info_bytes_budget,
                retained_peer_reason_bytes=self.retention.retained_peer_reason_bytes,
                retained_peer_reason_bytes_budget=self.policy.retained_peer_reason_bytes_budget,
            ),
            memory=MemoryStats(
                tracked_bytes=tracked,
                hard_cap=hard_cap,
                over_cap=tracked >= hard_cap,
            ),
            abuse=AbuseStats(
                ignored_control_budget=abuse.ignored_control_budget,
                no_op_zero_data_budget=abuse.no_op_zero_data_budget,
                inbound_ping_budget=abuse.inbound_ping_budget,
                no_op_max_data_budget=abuse.no_op_max_data_budget,
                no_op_blocked_budget=abuse.no_op_blocked_budget,
                no_op_priority_update_budget=abuse.no_op_priority_update_budget,
                dropped_priority_update=self.ingress.dropped_priority_update,
                inbound_control_frame_budget=abuse.inbound_control_frame_budget,
                inbound_control_bytes_budget=abuse.inbound_control_bytes_budget,
                inbound_ext_frame_budget=abuse.inbound_ext_frame_budget,
                inbound_ext_bytes_budget=abuse.inbound_ext_bytes_budget,
                inbound_mixed_frame_budget=abuse.inbound_mixed_frame_budget,
                inbound_mixed_bytes_budget=abuse.inbound_mixed_bytes_budget,
                group_rebucket_churn_budget=abuse.group_rebucket_churn_budget,
                hidden_abort_churn_budget=abuse.hidden_abort_churn_budget,
                visible_terminal_churn_budget=abuse.visible_terminal_churn_budget,
            ),
        )


# noinspection PyTypeHints
@dataclass
class SparseQueue(Generic[QueueT]):
    """List-backed sparse queue with Go-compatible head/count compaction."""

    compact_min_head: int = PROVISIONAL_QUEUE_COMPACT_MIN_HEAD
    items: list[QueueT | None] = field(default_factory=list)
    head: int = 0
    count: int = 0
    init: bool = True

    def __post_init__(self) -> None:
        self.compact_min_head = _nonnegative_int(self.compact_min_head, "compact_min_head")
        self.head = _nonnegative_int(self.head, "head")
        self.count = _nonnegative_int(self.count, "count")
        self.init = _require_bool(self.init, "init")

    def __len__(self) -> int:
        return self.count

    def append(self, item: QueueT) -> int:
        idx = len(self.items)
        self.items.append(item)
        self.count += 1
        if self.count == 1:
            self.head = idx
        self.init = True
        return idx

    def head_item(self) -> QueueT | None:
        if self.count == 0:
            return None
        self.head = self._advance_head(self.head)
        if self.head >= len(self.items):
            return None
        return self.items[self.head]

    def tail_item(self) -> QueueT | None:
        if self.count == 0:
            return None
        for idx in range(len(self.items) - 1, self.head - 1, -1):
            item = self.items[idx]
            if item is not None:
                return item
        return None

    def remove_index(self, idx: int) -> QueueT | None:
        if idx < 0 or idx >= len(self.items) or self.count == 0:
            return None
        item = self.items[idx]
        if item is None:
            return None
        self.items[idx] = None
        self.count -= 1
        if self.count < 0:
            self.count = 0
        if idx == self.head:
            self.head = self._advance_head(self.head)
        return item

    def pop_head(self) -> QueueT | None:
        item = self.head_item()
        if item is None:
            return None
        self.remove_index(self.head)
        self.maybe_compact()
        return item

    def pop_tail(self) -> QueueT | None:
        if self.count == 0:
            return None
        for idx in range(len(self.items) - 1, self.head - 1, -1):
            if self.items[idx] is not None:
                item = self.items[idx]
                self.remove_index(idx)
                self.maybe_compact()
                return item
        return None

    def clear(self, visit: Callable[[QueueT], None] | None = None) -> None:
        if visit is not None:
            for item in self.items:
                if item is not None:
                    visit(item)
        self.items = []
        self.head = 0
        self.count = 0
        self.init = False

    def maybe_compact(self) -> None:
        if self.count == 0:
            self.clear()
            return
        holes = len(self.items) - self.head - self.count
        if self.head < self.compact_min_head and holes < self.count:
            return
        kept = [item for item in self.items[self.head:] if item is not None]
        self.items = kept
        self.head = 0
        self.count = len(kept)
        self.init = True

    def _advance_head(self, head: int) -> int:
        while head < len(self.items) and self.items[head] is None:
            head += 1
        return head


@dataclass
class QueueItem(object):
    """Minimal queue item used by IndexedQueue and local-open trackers."""

    value: Any
    index: int = -1
    created_at: Optional[float] = None
    id_set: bool = False
    stream_id: int = 0
    bidi: bool = True
    failed: Optional[BaseException] = None

    def __post_init__(self) -> None:
        self.index = _signed_int(self.index, "index")
        self.created_at = (
            None
            if self.created_at is None
            else _nonnegative_float(self.created_at, "created_at")
        )
        self.id_set = _require_bool(self.id_set, "id_set")
        self.stream_id = _require_varint62(self.stream_id, "stream_id")
        if self.id_set and self.stream_id == 0:
            raise ValueError("stream_id must be non-zero when id_set is true")
        self.bidi = _require_bool(self.bidi, "bidi")


# noinspection PyTypeHints
@dataclass
class IndexedQueue(Generic[QueueT]):
    state: SparseQueue[QueueT]
    get_index: Callable[[QueueT], int]
    set_index: Callable[[QueueT, int], None]

    def append(self, item: QueueT) -> None:
        current = self.get_index(item)
        if self.holds(item, current):
            return
        idx = self.state.append(item)
        self.set_index(item, idx)

    def head_item(self) -> QueueT | None:
        return self.state.head_item()

    def tail_item(self) -> QueueT | None:
        return self.state.tail_item()

    def holds(self, item: QueueT, current_index: int) -> bool:
        if current_index < 0 or current_index >= len(self.state.items):
            return False
        return self.state.items[current_index] is item

    def remove(self, item: QueueT) -> bool:
        idx = self.get_index(item)
        if not self.holds(item, idx):
            idx = -1
            for pos in range(self.state.head, len(self.state.items)):
                if self.state.items[pos] is item:
                    idx = pos
                    break
        if idx < 0:
            self.set_index(item, -1)
            return False
        removed = self.state.remove_index(idx)
        self.set_index(item, -1)
        self.state.maybe_compact()
        return removed is not None

    def clear(self, visit: Callable[[QueueT], None] | None = None) -> None:
        def clear_index(item: QueueT) -> None:
            self.set_index(item, -1)
            if visit is not None:
                visit(item)

        self.state.clear(clear_index)


@dataclass
class LocalOpenTracker(object):
    """Provisional local-open and unseen-local stream bookkeeping."""

    provisional_bidi: SparseQueue[QueueItem] = field(default_factory=SparseQueue)
    provisional_uni: SparseQueue[QueueItem] = field(default_factory=SparseQueue)
    unseen_local_bidi: SparseQueue[QueueItem] = field(default_factory=SparseQueue)
    unseen_local_uni: SparseQueue[QueueItem] = field(default_factory=SparseQueue)
    limited_count: int = 0
    expired_count: int = 0

    def provisional_queue(self, arity: StreamArity) -> SparseQueue[QueueItem]:
        arity = _coerce_stream_arity(arity)
        return self.provisional_bidi if arity.is_bidi() else self.provisional_uni

    def unseen_queue(self, arity: StreamArity) -> SparseQueue[QueueItem]:
        arity = _coerce_stream_arity(arity)
        return self.unseen_local_bidi if arity.is_bidi() else self.unseen_local_uni

    def provisional_count(self, arity: StreamArity) -> int:
        return len(self.provisional_queue(arity))

    def total_provisional_count(self) -> int:
        return len(self.provisional_bidi) + len(self.provisional_uni)

    def append_provisional(self, item: QueueItem, now: Optional[float] = None) -> None:
        if not isinstance(item, QueueItem):
            raise TypeError("item must be QueueItem")
        queue = self.provisional_queue(StreamArity.from_bidi(item.bidi))
        if 0 <= item.index < len(queue.items) and queue.items[item.index] is item:
            return
        item.created_at = time.monotonic() if now is None else _nonnegative_float(now, "now")
        item.index = queue.append(item)

    def remove_provisional(self, item: QueueItem) -> bool:
        if not isinstance(item, QueueItem):
            raise TypeError("item must be QueueItem")
        queue = self.provisional_queue(StreamArity.from_bidi(item.bidi))
        removed = queue.remove_index(item.index)
        item.index = -1
        queue.maybe_compact()
        return removed is not None

    def reap_expired(
            self,
            arity: StreamArity,
            now: Optional[float] = None,
            max_age: float = PROVISIONAL_OPEN_MAX_AGE,
    ) -> tuple[QueueItem, ...]:
        arity = _coerce_stream_arity(arity)
        now = time.monotonic() if now is None else _nonnegative_float(now, "now")
        max_age = _nonnegative_float(max_age, "max_age")
        queue = self.provisional_queue(arity)
        expired: list[QueueItem] = []
        while True:
            item = queue.head_item()
            if item is None or not provisional_expired(item.id_set, item.created_at, now, max_age):
                break
            queue.pop_head()
            item.index = -1
            item.failed = OpenExpired()
            expired.append(item)
            self.expired_count = saturating_add(self.expired_count, 1)
        return tuple(expired)

    def reclaim_by_goaway(
            self, arity: StreamArity, next_local_id: int, peer_watermark: int
    ) -> tuple[QueueItem, ...]:
        arity = _coerce_stream_arity(arity)
        next_local_id = _nonnegative_int(next_local_id, "next_local_id")
        peer_watermark = _require_varint62(peer_watermark, "peer_watermark")
        queue = self.provisional_queue(arity)
        available = provisional_available_count(next_local_id, peer_watermark)
        reclaimed: list[QueueItem] = []
        while len(queue) > available:
            item = queue.pop_tail()
            if item is None:
                break
            item.index = -1
            item.failed = ApplicationError(int(ErrorCode.REFUSED_STREAM), "")
            reclaimed.append(item)
        return tuple(reclaimed)

    def can_open(
            self,
            arity: StreamArity,
            registry: RegistryState,
            peer_goaway: int,
            peer_stream_limit: int,
            configured_cap: int,
    ) -> bool:
        arity = _coerce_stream_arity(arity)
        peer_goaway = _require_varint62(peer_goaway, "peer_goaway")
        peer_stream_limit = _nonnegative_int(peer_stream_limit, "peer_stream_limit")
        configured_cap = _nonnegative_int(configured_cap, "configured_cap")
        queue_len = self.provisional_count(arity)
        projected = projected_local_open_id(arity.next_local_id(registry), queue_len)
        if projected > MAX_VARINT62 or projected > peer_goaway:
            return False
        available = provisional_available_count(arity.next_local_id(registry), peer_goaway)
        if queue_len >= min(configured_cap, available):
            self.limited_count = saturating_add(self.limited_count, 1)
            return False
        active = registry.active_local_bidi if arity.is_bidi() else registry.active_local_uni
        if active >= peer_stream_limit or saturating_add(active, queue_len) >= peer_stream_limit:
            return False
        return True


# noinspection PyTypeHints
@dataclass
class EventDispatcher(object):
    """Synchronous event emitter with re-entrant queueing and exception capture."""

    handler: Optional[Callable[[Event], None]] = None
    emitting: bool = False
    queue: deque[Event] = field(default_factory=deque)
    dropped_handler_exceptions: int = 0
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    def emit(self, event: Optional[Event]) -> None:
        if event is None:
            return
        with self._lock:
            handler = self.handler
            if handler is None:
                return
            if self.emitting:
                self.queue.append(event)
                return
            self.emitting = True
        try:
            current: Optional[Event] = event
            while current is not None:
                try:
                    handler(current)
                except Exception:
                    with self._lock:
                        self.dropped_handler_exceptions = saturating_add(
                            self.dropped_handler_exceptions, 1
                        )
                with self._lock:
                    if self.queue:
                        current = self.queue.popleft()
                    else:
                        self.emitting = False
                        return
        except BaseException:
            with self._lock:
                self.emitting = False
            raise


def stream_event(
        event_type: EventType,
        stream_id: int,
        opened_locally: bool,
        bidirectional: bool,
        application_visible: bool = False,
        timestamp: Optional[float] = None,
        metadata: Optional[StreamMetadata] = None,
        session_state: Optional[object] = None,
        error: Optional[BaseException] = None,
        local_addr: Optional[object] = None,
        remote_addr: Optional[object] = None,
) -> Event:
    opened_locally = _require_bool(opened_locally, "opened_locally")
    bidirectional = _require_bool(bidirectional, "bidirectional")
    application_visible = _require_bool(application_visible, "application_visible")
    return Event(
        event_type=event_type,
        session_state=session_state,
        stream=StreamEventInfo(
            stream_id=stream_id,
            metadata=metadata or StreamMetadata(),
            local=opened_locally,
            bidirectional=bidirectional,
            application_visible=application_visible,
            local_addr=local_addr,
            remote_addr=remote_addr,
        ),
        time=time.time() if timestamp is None else timestamp,
        error=error,
    )


def session_closed_event(
        timestamp: Optional[float] = None,
        session_state: Optional[object] = None,
        error: Optional[BaseException] = None,
) -> Event:
    return Event(
        event_type=EventType.SESSION_CLOSED,
        session_state=session_state,
        time=time.time() if timestamp is None else timestamp,
        error=error,
    )


def go_away_drain_interval(configured: float, last_ping_rtt: float) -> float:
    configured = _nonnegative_float(configured, "configured")
    last_ping_rtt = _nonnegative_float(last_ping_rtt, "last_ping_rtt")
    if configured == 0:
        return 0.0
    if configured != SESSION_GO_AWAY_DRAIN_INTERVAL:
        return configured
    interval = configured
    if last_ping_rtt > 0:
        interval = max(interval, last_ping_rtt / 4.0)
    return min(interval, SESSION_GO_AWAY_DRAIN_INTERVAL_MAX)


def graceful_close_drain_timeout(configured: float, last_ping_rtt: float) -> float:
    configured = _nonnegative_float(configured, "configured")
    last_ping_rtt = _nonnegative_float(last_ping_rtt, "last_ping_rtt")
    if configured == 0.0 or configured != SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT:
        return configured
    return adaptive_rtt_timeout(
        last_ping_rtt,
        configured,
        SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT_MAX,
        4,
        0.100,
    )


def close_frame_send_timeout(last_ping_rtt: float = 0.0) -> float:
    return adaptive_rtt_timeout(
        _nonnegative_float(last_ping_rtt, "last_ping_rtt"),
        SESSION_CLOSE_FRAME_SEND_TIMEOUT,
        SESSION_CLOSE_FRAME_SEND_TIMEOUT_MAX,
        4,
        RTT_ADAPTIVE_SLACK,
    )


def earliest_nonzero_time(*values: Optional[float]) -> Optional[float]:
    earliest: Optional[float] = None
    for value in values:
        if value is None or value <= 0:
            continue
        if earliest is None or value < earliest:
            earliest = value
    return earliest


def _session_state(value: str) -> Any:
    from ..session import SessionState

    return SessionState(value)


def _coerce_public_state(value: Any) -> Any:
    from ..session import SessionState

    if isinstance(value, SessionState):
        return value
    if isinstance(value, str):
        return SessionState(value)
    raise TypeError("session state must be a SessionState or string")


def _coerce_stream_arity(value: StreamArity) -> StreamArity:
    if isinstance(value, StreamArity):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("arity must be StreamArity or integer")
    return StreamArity(value)


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return max(0, value)


def _signed_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value


def _strict_nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


def _positive_int(value: int, name: str) -> int:
    value = _strict_nonnegative_int(value, name)
    if value == 0:
        raise ValueError("%s must be > 0" % name)
    return value


def _stream_value_items(data: Any) -> tuple[tuple[int, int], ...]:
    if data is None:
        return ()
    values = data.items() if isinstance(data, dict) else data
    out = []
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise TypeError("data must be a mapping or iterable of pairs") from exc
    for item in iterator:
        try:
            stream_id, byte_count = item
        except (TypeError, ValueError) as exc:
            raise TypeError("data entries must be stream/byte pairs") from exc
        stream_id = _positive_int(stream_id, "stream_id")
        byte_count = _strict_nonnegative_int(byte_count, "byte_count")
        if byte_count:
            out.append((stream_id, byte_count))
    return tuple(out)


def _require_varint62(value: int, name: str) -> int:
    return require_varint62(value, name)


def _nonnegative_float(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a duration in seconds" % name)
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError("%s must be a finite value >= 0" % name)
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


def _clamp_u64(value: int) -> int:
    return min(_nonnegative_int(value, "value"), MAX_UINT64)


def _bytes_like(value: bytes, name: str) -> bytes:
    if isinstance(value, (bool, int, str)):
        raise TypeError("%s must be bytes-like" % name)
    try:
        view = memoryview(value)
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % name) from exc
    if view.ndim != 1 or view.format != "B":
        view = view.cast("B")
    return view.tobytes()


__all__ = (
    "ACCEPT_QUEUE_COMPACT_MIN_HEAD",
    "ADVISORY_LANE_BUFFER",
    "CONN_READ_BUFFER_SIZE",
    "DEFAULT_ADMISSION_HARD_CAP",
    "DEFAULT_ADMISSION_SOFT_CAP",
    "DEFAULT_KEEPALIVE_TIMEOUT_MAX",
    "DEFAULT_KEEPALIVE_TIMEOUT_MIN",
    "ESTABLISHMENT_CLOSE_DRAIN_DELAY",
    "ESTABLISHMENT_FAILURE_WRITE_WAIT",
    "ESTABLISHMENT_SUCCESS_WRITE_WAIT",
    "EventDispatcher",
    "BeginCloseOutcome",
    "BeginClosePlan",
    "FlowState",
    "IngressState",
    "IndexedQueue",
    "KeepaliveAction",
    "LivenessState",
    "LocalOpenOutcome",
    "LocalOpenTracker",
    "MAX_BATCH_FRAMES",
    "MAX_UINT64",
    "MIN_COMPACT_TERMINAL_STATE_UNIT",
    "MIN_RETAINED_OPEN_INFO_BUDGET",
    "MIN_RETAINED_PEER_REASON_BUDGET",
    "MIN_RETAINED_STATE_UNIT",
    "MIN_SESSION_MEMORY_HARD_CAP",
    "PING_NONCE_BYTES",
    "PING_PADDING_TAG_BYTES",
    "PROVISIONAL_OPEN_MAX_AGE",
    "PROVISIONAL_OPEN_MAX_AGE_ADAPTIVE_CAP",
    "PROVISIONAL_OPEN_RTT_ADAPTIVE_SLACK",
    "PROVISIONAL_OPEN_RTT_MULTIPLIER",
    "PeerClosePlan",
    "PeerGoAwayPlan",
    "PingPayloadFingerprint",
    "QueueItem",
    "REASON_CODE_MAP_LIMIT",
    "RTT_ADAPTIVE_SLACK",
    "ReasonCounter",
    "RegistryState",
    "RetainedBucket",
    "RetainedStateBreakdown",
    "RetentionState",
    "RuntimeMetrics",
    "RuntimePolicy",
    "SESSION_GO_AWAY_DRAIN_INTERVAL",
    "SESSION_GO_AWAY_DRAIN_INTERVAL_MAX",
    "SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT",
    "SESSION_GRACEFUL_CLOSE_DRAIN_TIMEOUT_MAX",
    "SESSION_CLOSE_FRAME_SEND_TIMEOUT",
    "SESSION_CLOSE_FRAME_SEND_TIMEOUT_MAX",
    "SessionControlState",
    "SessionRuntimeState",
    "ShutdownState",
    "SparseQueue",
    "StreamArity",
    "WRITER_LANE_BUFFER",
    "accepted_peer_go_away_watermark",
    "adaptive_rtt_timeout",
    "admission_hard_cap",
    "admission_soft_cap",
    "advance_session_on_go_away",
    "allow_local_non_close_control",
    "average_u64_floor",
    "begin_session_closing",
    "build_close_payload",
    "build_establishment_close_frame",
    "build_padded_ping_echo",
    "build_ping_payload",
    "build_ping_payload_capped_with_nonce",
    "can_open_locally",
    "close_frame_send_timeout",
    "close_mapped_application_error",
    "close_session_state",
    "compact_terminal_state_unit",
    "default_pending_control_bytes_budget",
    "default_pending_priority_bytes_budget",
    "default_hidden_control_opened_limit",
    "default_urgent_queue_max_bytes",
    "earliest_nonzero_time",
    "effective_keepalive_timeout",
    "effective_go_away_send_watermark",
    "establishment_close_drain_delay",
    "establishment_close_max_payload",
    "fill_ping_padding_from_state",
    "go_away_drain_interval",
    "graceful_close_drain_timeout",
    "has_ping_padding_tag",
    "hidden_control_soft_limit",
    "ignore_peer_non_close_frame",
    "ignore_peer_close",
    "init_keepalive_jitter_state",
    "init_session_nonce_state",
    "is_benign_session_error",
    "is_session_finished",
    "keepalive_lead_jittered_delay",
    "keepalive_timeout_rtt_floor",
    "make_ping_padding",
    "max_peer_go_away_watermark",
    "min_go_away_watermark",
    "next_keepalive_jitter",
    "next_session_nonce",
    "next_uint64n_from_state",
    "ping_padding_bounds",
    "ping_padding_tag",
    "ping_payload_hash",
    "ping_payload_len",
    "ping_payload_limit",
    "plan_begin_close",
    "plan_local_open",
    "plan_peer_close",
    "plan_peer_go_away",
    "pong_payload_for_ping",
    "pong_payload_matches_ping",
    "projected_local_open_id",
    "provisional_available_count",
    "provisional_expired",
    "provisional_open_max_age",
    "provisional_open_hard_cap",
    "provisional_open_soft_cap",
    "retained_bucket_stats",
    "retained_open_info_budget",
    "retained_peer_reason_budget",
    "retained_state_unit",
    "rate_bytes_per_second",
    "send_rate_sample",
    "session_closed_event",
    "session_memory_cap_error",
    "session_memory_hard_cap",
    "session_memory_high_threshold",
    "stop_sending_drain_window",
    "stream_event",
    "truncate_string_to_bytes",
    "validate_local_go_away",
    "visible_session_error",
)
