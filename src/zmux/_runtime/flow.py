"""Runtime flow-control, watermark, and wake-planning policy helpers."""

from __future__ import annotations

from dataclasses import dataclass

from .._validation import (
    require_bool as _require_bool,
    require_nonnegative_int as _nonnegative_int,
)
from ..config import Settings, default_settings
from ..protocol import MAX_VARINT62

MAX_UINT64 = (1 << 64) - 1

REPO_DEFAULT_PER_STREAM_DATA_HWM_MIN = 256 << 10
REPO_DEFAULT_SESSION_DATA_HWM_MIN = 4 << 20
REPO_DEFAULT_URGENT_LANE_CAP_MIN = 64 << 10

DEFAULT_VISIBLE_ACCEPT_BACKLOG_LIMIT = 128
VISIBLE_ACCEPT_BACKLOG_BYTES_MIN = 4 << 20
VISIBLE_ACCEPT_PER_STREAM_HWM_MIN = 256 << 10
VISIBLE_ACCEPT_PER_STREAM_HWM_FRAMES = 16
VISIBLE_ACCEPT_SESSION_HWM_FACTOR = 4

MIN_LATE_DATA_PER_STREAM_CAP = 1024
MIN_AGGREGATE_LATE_DATA_CAP = 64 << 10


@dataclass(frozen=True)
class ReleaseWakePlan(object):
    """Wake decisions after queued bytes or prepared write state are released."""

    broadcast: bool = False
    stream_wake: bool = False
    control: bool = False
    memory_wake: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "broadcast", _require_bool(self.broadcast, "broadcast"))
        object.__setattr__(
            self,
            "stream_wake",
            _require_bool(self.stream_wake, "stream_wake"),
        )
        object.__setattr__(self, "control", _require_bool(self.control, "control"))
        object.__setattr__(
            self,
            "memory_wake",
            _require_bool(self.memory_wake, "memory_wake"),
        )


def quarter_threshold(value: int) -> int:
    value = _nonnegative_int(value, "value")
    if value <= 4:
        return 1
    return value // 4


def window_remaining(limit: int, received: int) -> int:
    limit = _nonnegative_int(limit, "limit")
    received = _nonnegative_int(received, "received")
    if received >= limit:
        return 0
    return limit - received


def receive_window_exceeded(received: int, advertised: int, amount: int) -> bool:
    amount = _nonnegative_int(amount, "amount")
    return amount > window_remaining(advertised, received)


def negotiated_frame_payload(local: Settings, peer: Settings) -> int:
    payload = min_nonzero(local.max_frame_payload, peer.max_frame_payload)
    if payload == 0:
        payload = default_settings().max_frame_payload
    return payload


def repo_default_per_stream_data_hwm(max_frame_payload: int) -> int:
    return max(
        REPO_DEFAULT_PER_STREAM_DATA_HWM_MIN,
        saturating_mul(_nonnegative_int(max_frame_payload, "max_frame_payload"), 16),
    )


def repo_default_session_data_hwm(per_stream_data_hwm: int) -> int:
    return max(
        REPO_DEFAULT_SESSION_DATA_HWM_MIN,
        saturating_mul(_nonnegative_int(per_stream_data_hwm, "per_stream_data_hwm"), 4),
    )


def repo_default_urgent_lane_cap(max_control_payload: int) -> int:
    return max(
        REPO_DEFAULT_URGENT_LANE_CAP_MIN,
        saturating_mul(_nonnegative_int(max_control_payload, "max_control_payload"), 8),
    )


def min_nonzero(a: int, b: int) -> int:
    a = _nonnegative_int(a, "a")
    b = _nonnegative_int(b, "b")
    if a == 0:
        return b
    if b == 0:
        return a
    return min(a, b)


def max_uint64(a: int, b: int) -> int:
    return max(_nonnegative_int(a, "a"), _nonnegative_int(b, "b"))


def elapsed_nanos(later: int, earlier: int) -> int:
    later = _nonnegative_int(later, "later")
    earlier = _nonnegative_int(earlier, "earlier")
    if later <= earlier:
        return 0
    return min(later - earlier, MAX_UINT64)


def positive_elapsed_nanos(later: int, earlier: int) -> int:
    elapsed = elapsed_nanos(later, earlier)
    return 1 if elapsed == 0 else elapsed


def elapsed_exceeds(later: int, earlier: int, threshold: int) -> bool:
    threshold = _nonnegative_int(threshold, "threshold")
    return elapsed_nanos(later, earlier) > threshold


def saturating_add(a: int, b: int, limit: int = MAX_UINT64) -> int:
    a = _nonnegative_int(a, "a")
    b = _nonnegative_int(b, "b")
    limit = _nonnegative_int(limit, "limit")
    if a >= limit or b > limit - a:
        return limit
    return a + b


def saturating_mul(value: int, factor: int, limit: int = MAX_UINT64) -> int:
    value = _nonnegative_int(value, "value")
    factor = _nonnegative_int(factor, "factor")
    limit = _nonnegative_int(limit, "limit")
    if value == 0 or factor == 0:
        return 0
    if value > limit // factor:
        return limit
    return value * factor


def saturating_mul_div_floor(x: int, y: int, d: int) -> int:
    x = _nonnegative_int(x, "x")
    y = _nonnegative_int(y, "y")
    d = _nonnegative_int(d, "d")
    if x == 0 or y == 0:
        return 0
    if d == 0:
        return MAX_UINT64
    return min(MAX_UINT64, (x * y) // d)


def saturating_mul_div_ceil(x: int, y: int, d: int) -> int:
    x = _nonnegative_int(x, "x")
    y = _nonnegative_int(y, "y")
    d = _nonnegative_int(d, "d")
    if x == 0 or y == 0:
        return 0
    if d == 0:
        return MAX_UINT64
    return min(MAX_UINT64, -(-(x * y) // d))


def low_watermark(high: int) -> int:
    return _nonnegative_int(high, "high") // 2


def queue_would_block(
        session_memory_blocked: bool,
        session_queued: int,
        stream_queued: int,
        req_bytes: int,
        session_hwm: int,
        stream_hwm: int,
) -> bool:
    if not isinstance(session_memory_blocked, bool):
        raise TypeError("session_memory_blocked must be a bool")
    req_bytes = _nonnegative_int(req_bytes, "req_bytes")
    if session_memory_blocked or req_bytes == 0:
        return session_memory_blocked
    return (
            saturating_add(_nonnegative_int(session_queued, "session_queued"), req_bytes)
            > _nonnegative_int(session_hwm, "session_hwm")
            or saturating_add(_nonnegative_int(stream_queued, "stream_queued"), req_bytes)
            > _nonnegative_int(stream_hwm, "stream_hwm")
    )


def crossed_low_watermark(prev: int, next_value: int, low_watermark_value: int) -> bool:
    prev = _nonnegative_int(prev, "prev")
    next_value = _nonnegative_int(next_value, "next_value")
    low_watermark_value = _nonnegative_int(low_watermark_value, "low_watermark")
    return next_value <= low_watermark_value < prev


def gained_credit(prev: int, next_value: int) -> bool:
    prev = _nonnegative_int(prev, "prev")
    next_value = _nonnegative_int(next_value, "next_value")
    return prev == 0 and next_value > 0


def memory_wake_needed(prev_tracked: int, next_tracked: int, threshold: int) -> bool:
    prev_tracked = _nonnegative_int(prev_tracked, "prev_tracked")
    next_tracked = _nonnegative_int(next_tracked, "next_tracked")
    threshold = _nonnegative_int(threshold, "threshold")
    if next_tracked >= prev_tracked:
        return False
    return next_tracked < threshold


def projected_exceeds_threshold(current: int, additional: int, threshold: int) -> bool:
    return saturating_add(current, additional) > _nonnegative_int(threshold, "threshold")


def visible_accept_backlog_bytes_hard_cap(max_frame_payload: int) -> int:
    max_frame_payload = _nonnegative_int(max_frame_payload, "max_frame_payload")
    if max_frame_payload == 0:
        max_frame_payload = default_settings().max_frame_payload
    per_stream = saturating_mul(VISIBLE_ACCEPT_PER_STREAM_HWM_FRAMES, max_frame_payload)
    per_stream = max(per_stream, VISIBLE_ACCEPT_PER_STREAM_HWM_MIN)
    limit = saturating_mul(VISIBLE_ACCEPT_SESSION_HWM_FACTOR, per_stream)
    return max(limit, VISIBLE_ACCEPT_BACKLOG_BYTES_MIN)


def late_data_per_stream_cap(initial_stream_window: int, max_frame_payload: int) -> int:
    max_frame_payload = _nonnegative_int(max_frame_payload, "max_frame_payload")
    if max_frame_payload == 0:
        max_frame_payload = default_settings().max_frame_payload
    limit = saturating_mul(max_frame_payload, 2)
    window_cap = _nonnegative_int(initial_stream_window, "initial_stream_window") // 8
    if window_cap < limit:
        limit = window_cap
    return max(MIN_LATE_DATA_PER_STREAM_CAP, limit)


def aggregate_late_data_cap(max_frame_payload: int) -> int:
    max_frame_payload = _nonnegative_int(max_frame_payload, "max_frame_payload")
    if max_frame_payload == 0:
        max_frame_payload = default_settings().max_frame_payload
    return max(
        MIN_AGGREGATE_LATE_DATA_CAP,
        saturating_mul(max_frame_payload, 4),
    )


def session_window_target(local: Settings, session_data_high_watermark: int) -> int:
    return max(
        local.initial_max_data,
        saturating_mul(
            _nonnegative_int(
                session_data_high_watermark, "session_data_high_watermark"
            ),
            4,
            MAX_VARINT62,
        ),
    )


def stream_window_target(
        initial_receive_window_value: int, per_stream_data_high_watermark: int
) -> int:
    return max(
        _nonnegative_int(initial_receive_window_value, "initial_receive_window"),
        saturating_mul(
            _nonnegative_int(
                per_stream_data_high_watermark, "per_stream_data_high_watermark"
            ),
            2,
            MAX_VARINT62,
        ),
    )


def session_emergency_threshold(payload: int) -> int:
    return saturating_mul(_nonnegative_int(payload, "payload"), 2)


def stream_emergency_threshold(target: int, payload: int) -> int:
    payload = _nonnegative_int(payload, "payload")
    threshold = quarter_threshold(target)
    if payload == 0:
        return threshold
    return min(payload, threshold)


def replenish_min_pending(target: int, payload: int) -> int:
    min_pending = quarter_threshold(target)
    payload = _nonnegative_int(payload, "payload")
    if payload > 0:
        min_pending = min(min_pending, payload)
    return max(1, min_pending)


def should_replenish_pending_window(
        remaining: int,
        target: int,
        advertised: int,
        pending: int,
        emergency_threshold: int,
        min_pending: int,
        *,
        force: bool = False,
) -> bool:
    pending = _nonnegative_int(pending, "pending")
    if pending == 0:
        return False
    force = _require_bool(force, "force")
    if force:
        return True
    remaining = _nonnegative_int(remaining, "remaining")
    target = _nonnegative_int(target, "target")
    advertised = _nonnegative_int(advertised, "advertised")
    if remaining <= _nonnegative_int(emergency_threshold, "emergency_threshold"):
        return True
    if remaining <= quarter_threshold(target) and advertised >= target:
        return True
    return pending >= _nonnegative_int(min_pending, "min_pending")


def should_flush_receive_credit(
        advertised: int,
        received: int,
        pending: int,
        target: int,
        emergency_threshold: int,
        min_pending: int,
        force: bool = False,
) -> bool:
    force = _require_bool(force, "force")
    return should_replenish_pending_window(
        window_remaining(advertised, received),
        target,
        advertised,
        pending,
        emergency_threshold,
        min_pending,
        force=force,
    )


def next_credit_limit(
        advertised: int,
        pending: int,
        received: int,
        target: int,
        allow_standing_growth: bool,
) -> int:
    allow_standing_growth = _require_bool(
        allow_standing_growth,
        "allow_standing_growth",
    )
    floor = saturating_add(advertised, pending)
    desired = floor
    if allow_standing_growth:
        desired = max(desired, saturating_add(received, target))
    return min(desired, MAX_VARINT62)


def session_standing_growth_allowed(
        memory_pressure_high: bool,
        buffered: int,
        pending: int,
        session_data_high_watermark: int,
) -> bool:
    return standing_growth_allowed(
        memory_pressure_high, buffered, pending, session_data_high_watermark
    )


def stream_standing_growth_allowed(
        memory_pressure_high: bool,
        buffered: int,
        pending: int,
        per_stream_data_high_watermark: int,
) -> bool:
    return standing_growth_allowed(
        memory_pressure_high, buffered, pending, per_stream_data_high_watermark
    )


def standing_growth_allowed(
        memory_pressure_high: bool, buffered: int, pending: int, high_watermark: int
) -> bool:
    memory_pressure_high = _require_bool(memory_pressure_high, "memory_pressure_high")
    if memory_pressure_high:
        return False
    buffered = _nonnegative_int(buffered, "buffered")
    pending = _nonnegative_int(pending, "pending")
    high_watermark = _nonnegative_int(high_watermark, "high_watermark")
    if buffered >= high_watermark:
        return False
    return pending < high_watermark - buffered


def plan_queue_release_wake(
        prev_tracked: int,
        next_tracked: int,
        memory_threshold: int,
        prev_session_queued: int,
        next_session_queued: int,
        session_lwm: int,
        prev_stream_queued: int,
        next_stream_queued: int,
        stream_lwm: int,
        urgent_released: bool,
) -> ReleaseWakePlan:
    urgent_released = _require_bool(urgent_released, "urgent_released")
    memory_wake = memory_wake_needed(prev_tracked, next_tracked, memory_threshold)
    session_wake = crossed_low_watermark(
        prev_session_queued, next_session_queued, session_lwm
    )
    broadcast = session_wake or memory_wake
    stream_wake = not session_wake and crossed_low_watermark(
        prev_stream_queued, next_stream_queued, stream_lwm
    )
    return ReleaseWakePlan(
        broadcast=broadcast,
        stream_wake=stream_wake,
        control=memory_wake or urgent_released,
        memory_wake=memory_wake,
    )


def plan_prepared_release_wake(
        prev_tracked: int,
        next_tracked: int,
        memory_threshold: int,
        prev_session_queued: int,
        next_session_queued: int,
        session_lwm: int,
        prev_stream_queued: int,
        next_stream_queued: int,
        stream_lwm: int,
        prev_session_credit: int,
        next_session_credit: int,
        prev_stream_credit: int,
        next_stream_credit: int,
        urgent_released: bool,
) -> ReleaseWakePlan:
    urgent_released = _require_bool(urgent_released, "urgent_released")
    memory_wake = memory_wake_needed(prev_tracked, next_tracked, memory_threshold)
    session_wake = crossed_low_watermark(
        prev_session_queued, next_session_queued, session_lwm
    ) or gained_credit(prev_session_credit, next_session_credit)
    broadcast = session_wake or memory_wake
    stream_wake = not session_wake and (
            crossed_low_watermark(prev_stream_queued, next_stream_queued, stream_lwm)
            or gained_credit(prev_stream_credit, next_stream_credit)
    )
    return ReleaseWakePlan(
        broadcast=broadcast,
        stream_wake=stream_wake,
        control=memory_wake or urgent_released,
        memory_wake=memory_wake,
    )


def plan_lane_release_wake(
        prev_tracked: int,
        next_tracked: int,
        memory_threshold: int,
        control_released: bool,
) -> ReleaseWakePlan:
    control_released = _require_bool(control_released, "control_released")
    memory_wake = memory_wake_needed(prev_tracked, next_tracked, memory_threshold)
    return ReleaseWakePlan(
        broadcast=memory_wake,
        stream_wake=False,
        control=memory_wake or control_released,
        memory_wake=memory_wake,
    )


__all__ = (
    "DEFAULT_VISIBLE_ACCEPT_BACKLOG_LIMIT",
    "MAX_UINT64",
    "MIN_AGGREGATE_LATE_DATA_CAP",
    "MIN_LATE_DATA_PER_STREAM_CAP",
    "REPO_DEFAULT_PER_STREAM_DATA_HWM_MIN",
    "REPO_DEFAULT_SESSION_DATA_HWM_MIN",
    "REPO_DEFAULT_URGENT_LANE_CAP_MIN",
    "ReleaseWakePlan",
    "VISIBLE_ACCEPT_BACKLOG_BYTES_MIN",
    "VISIBLE_ACCEPT_PER_STREAM_HWM_FRAMES",
    "VISIBLE_ACCEPT_PER_STREAM_HWM_MIN",
    "VISIBLE_ACCEPT_SESSION_HWM_FACTOR",
    "aggregate_late_data_cap",
    "crossed_low_watermark",
    "elapsed_exceeds",
    "elapsed_nanos",
    "gained_credit",
    "late_data_per_stream_cap",
    "low_watermark",
    "max_uint64",
    "memory_wake_needed",
    "min_nonzero",
    "negotiated_frame_payload",
    "next_credit_limit",
    "plan_lane_release_wake",
    "plan_prepared_release_wake",
    "plan_queue_release_wake",
    "positive_elapsed_nanos",
    "projected_exceeds_threshold",
    "quarter_threshold",
    "queue_would_block",
    "receive_window_exceeded",
    "replenish_min_pending",
    "repo_default_per_stream_data_hwm",
    "repo_default_session_data_hwm",
    "repo_default_urgent_lane_cap",
    "saturating_add",
    "saturating_mul",
    "saturating_mul_div_ceil",
    "saturating_mul_div_floor",
    "session_emergency_threshold",
    "session_standing_growth_allowed",
    "session_window_target",
    "should_flush_receive_credit",
    "should_replenish_pending_window",
    "standing_growth_allowed",
    "stream_emergency_threshold",
    "stream_standing_growth_allowed",
    "stream_window_target",
    "visible_accept_backlog_bytes_hard_cap",
    "window_remaining",
)
