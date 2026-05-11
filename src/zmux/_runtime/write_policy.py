"""Pure write-policy math for DATA fragmentation and burst sizing."""

from __future__ import annotations

from .flow import saturating_mul_div_floor
from ..config import default_settings
from ..protocol import SchedulerHint

DEFAULT_WRITE_BURST_FRAMES = 16
MILD_WRITE_BURST_FRAMES = 8
STRONG_WRITE_BURST_FRAMES = 4
SATURATED_WRITE_BURST_FRAMES = 2

DEFAULT_FRAGMENT_TIME_BUDGET = 0.200
MILD_FRAGMENT_TIME_BUDGET = 0.150
STRONG_FRAGMENT_TIME_BUDGET = 0.100
SATURATED_FRAGMENT_TIME_BUDGET = 0.050

DEFAULT_FRAGMENT_TIME_BUDGET_NANOS = 200_000_000
MILD_FRAGMENT_TIME_BUDGET_NANOS = 150_000_000
STRONG_FRAGMENT_TIME_BUDGET_NANOS = 100_000_000
SATURATED_FRAGMENT_TIME_BUDGET_NANOS = 50_000_000
NANOS_PER_SECOND = 1_000_000_000
_DEFAULT_MAX_FRAME_PAYLOAD = default_settings().max_frame_payload


def write_burst_limit(
        priority: int,
        hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED,
) -> int:
    priority = _nonnegative_int(priority, "priority")
    hint = _coerce_scheduler_hint(hint)
    if priority >= 16:
        return SATURATED_WRITE_BURST_FRAMES
    if priority >= 4:
        return STRONG_WRITE_BURST_FRAMES
    if priority >= 1:
        return MILD_WRITE_BURST_FRAMES
    if hint is SchedulerHint.LATENCY:
        return MILD_WRITE_BURST_FRAMES
    return DEFAULT_WRITE_BURST_FRAMES


def scaled_fragment_cap(max_value: int, numerator: int, denominator: int) -> int:
    max_value = _nonnegative_int(max_value, "max_value")
    numerator = _nonnegative_int(numerator, "numerator")
    denominator = _nonnegative_int(denominator, "denominator")
    if max_value == 0:
        return 0
    if denominator == 0:
        return max_value
    value = saturating_mul_div_floor(max_value, numerator, denominator)
    if value == 0:
        return 1
    return min(max_value, value)


def fragment_cap(
        max_payload: int,
        prefix_len: int,
        priority: int,
        hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED,
) -> int:
    max_payload = _nonnegative_int(max_payload, "max_payload")
    prefix_len = _nonnegative_int(prefix_len, "prefix_len")
    priority = _nonnegative_int(priority, "priority")
    hint = _coerce_scheduler_hint(hint)
    if max_payload == 0:
        max_payload = _DEFAULT_MAX_FRAME_PAYLOAD
    if prefix_len >= max_payload:
        return 0
    available = max_payload - prefix_len
    if priority >= 16:
        return scaled_fragment_cap(available, 1, 4)
    if priority >= 4:
        return scaled_fragment_cap(available, 1, 2)
    if priority >= 1:
        return scaled_fragment_cap(available, 3, 4)
    if hint is SchedulerHint.LATENCY:
        return scaled_fragment_cap(available, 1, 2)
    return available


def fragment_time_budget(
        priority: int,
        hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED,
) -> float:
    priority = _nonnegative_int(priority, "priority")
    hint = _coerce_scheduler_hint(hint)
    if priority >= 16:
        return SATURATED_FRAGMENT_TIME_BUDGET
    if priority >= 4:
        return STRONG_FRAGMENT_TIME_BUDGET
    if priority >= 1:
        return MILD_FRAGMENT_TIME_BUDGET
    if hint is SchedulerHint.LATENCY:
        return STRONG_FRAGMENT_TIME_BUDGET
    return DEFAULT_FRAGMENT_TIME_BUDGET


def fragment_time_budget_nanos(
        priority: int,
        hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED,
) -> int:
    priority = _nonnegative_int(priority, "priority")
    hint = _coerce_scheduler_hint(hint)
    if priority >= 16:
        return SATURATED_FRAGMENT_TIME_BUDGET_NANOS
    if priority >= 4:
        return STRONG_FRAGMENT_TIME_BUDGET_NANOS
    if priority >= 1:
        return MILD_FRAGMENT_TIME_BUDGET_NANOS
    if hint is SchedulerHint.LATENCY:
        return STRONG_FRAGMENT_TIME_BUDGET_NANOS
    return DEFAULT_FRAGMENT_TIME_BUDGET_NANOS


def rate_limited_fragment_cap(
        base_cap: int,
        estimated_send_rate_bps: int,
        priority: int,
        hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED,
) -> int:
    base_cap = _nonnegative_int(base_cap, "base_cap")
    estimated_send_rate_bps = _nonnegative_int(
        estimated_send_rate_bps,
        "estimated_send_rate_bps",
    )
    priority = _nonnegative_int(priority, "priority")
    hint = _coerce_scheduler_hint(hint)
    if base_cap == 0 or estimated_send_rate_bps == 0:
        return base_cap
    budget_nanos = fragment_time_budget_nanos(priority, hint)
    if budget_nanos <= 0:
        return base_cap
    rate_cap = saturating_mul_div_floor(
        estimated_send_rate_bps,
        budget_nanos,
        NANOS_PER_SECOND,
    )
    if rate_cap == 0:
        rate_cap = 1
    return min(base_cap, rate_cap)


def tx_fragment_cap(
        max_payload: int,
        prefix_len: int,
        priority: int,
        scheduler_hint: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED,
        send_rate_estimate: int = 0,
) -> int:
    base_cap = fragment_cap(max_payload, prefix_len, priority, scheduler_hint)
    return rate_limited_fragment_cap(
        base_cap,
        send_rate_estimate,
        priority,
        scheduler_hint,
    )


def _coerce_scheduler_hint(value: SchedulerHint) -> SchedulerHint:
    if isinstance(value, SchedulerHint):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("scheduler hint must be a SchedulerHint or integer")
    return SchedulerHint.from_code(value)


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


__all__ = (
    "DEFAULT_FRAGMENT_TIME_BUDGET",
    "DEFAULT_FRAGMENT_TIME_BUDGET_NANOS",
    "DEFAULT_WRITE_BURST_FRAMES",
    "MILD_FRAGMENT_TIME_BUDGET",
    "MILD_FRAGMENT_TIME_BUDGET_NANOS",
    "MILD_WRITE_BURST_FRAMES",
    "NANOS_PER_SECOND",
    "SATURATED_FRAGMENT_TIME_BUDGET",
    "SATURATED_FRAGMENT_TIME_BUDGET_NANOS",
    "SATURATED_WRITE_BURST_FRAMES",
    "STRONG_FRAGMENT_TIME_BUDGET",
    "STRONG_FRAGMENT_TIME_BUDGET_NANOS",
    "STRONG_WRITE_BURST_FRAMES",
    "fragment_cap",
    "fragment_time_budget",
    "fragment_time_budget_nanos",
    "rate_limited_fragment_cap",
    "scaled_fragment_cap",
    "tx_fragment_cap",
    "write_burst_limit",
)
