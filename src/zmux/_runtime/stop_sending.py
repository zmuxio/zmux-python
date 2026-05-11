"""STOP_SENDING graceful-drain policy helpers."""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .flow import MAX_UINT64, saturating_mul_div_floor
from .write_policy import scaled_fragment_cap
from ..config import (
    DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW,
    DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX,
)

REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW = DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW_MAX = DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX
NANOS_PER_SECOND = 1_000_000_000


class StopSendingGracefulDeadlineQueue:
    """Identity-keyed deadline queue for STOP_SENDING graceful drains.

    Streams can be updated repeatedly while old heap entries remain stale.
    The queue keeps an active id map and prunes stale heap entries lazily, which
    mirrors the Java coordinator while keeping long-running heap growth bounded.
    """

    __slots__ = ("_deadlines", "_heap", "_sequence")

    def __init__(self) -> None:
        self._deadlines: Dict[int, Tuple[object, float, int]] = {}
        self._heap: List[Tuple[float, int, int]] = []
        self._sequence = 0

    def __bool__(self) -> bool:
        return bool(self._deadlines)

    def __len__(self) -> int:
        return len(self._deadlines)

    def clear(self) -> None:
        self._deadlines.clear()
        self._heap.clear()
        self._sequence = 0

    def deadline_for(self, stream: object) -> Optional[float]:
        if stream is None:
            return None
        active = self._deadlines.get(id(stream))
        if active is None or active[0] is not stream:
            return None
        return active[1]

    def update(self, stream: object, deadline: Optional[float]) -> bool:
        if stream is None:
            return False
        deadline_seconds = _finite_seconds_or_zero(deadline, "deadline")
        if deadline_seconds <= 0:
            return self.discard(stream)

        stream_key = id(stream)
        active = self._deadlines.get(stream_key)
        if (
                active is not None
                and active[0] is stream
                and active[1] == deadline_seconds
        ):
            return False

        self._sequence += 1
        sequence = self._sequence
        self._deadlines[stream_key] = (stream, deadline_seconds, sequence)
        heapq.heappush(self._heap, (deadline_seconds, sequence, stream_key))
        self._compact_if_needed()
        return True

    def discard(self, stream: object) -> bool:
        if stream is None:
            return False
        active = self._deadlines.get(id(stream))
        if active is None or active[0] is not stream:
            return False
        del self._deadlines[id(stream)]
        self._compact_if_needed()
        return True

    def next_deadline(self) -> Optional[float]:
        self._prune_stale()
        if not self._heap:
            return None
        return self._heap[0][0]

    def pop_expired(self, now: float) -> Optional[object]:
        now_seconds = _finite_seconds(now, "now")
        while self._heap:
            deadline, sequence, stream_key = self._heap[0]
            active = self._deadlines.get(stream_key)
            if active is None or active[2] != sequence:
                heapq.heappop(self._heap)
                continue
            if deadline > now_seconds:
                return None
            heapq.heappop(self._heap)
            del self._deadlines[stream_key]
            return active[0]
        return None

    def _prune_stale(self) -> None:
        while self._heap:
            _, sequence, stream_key = self._heap[0]
            active = self._deadlines.get(stream_key)
            if active is not None and active[2] == sequence:
                return
            heapq.heappop(self._heap)

    def _compact_if_needed(self) -> None:
        active = len(self._deadlines)
        if len(self._heap) <= max(64, active * 2 + 64):
            return
        self._heap = []
        self._sequence = 0
        for stream_key, (stream, deadline, _) in list(self._deadlines.items()):
            self._sequence += 1
            sequence = self._sequence
            self._deadlines[stream_key] = (stream, deadline, sequence)
            self._heap.append((deadline, sequence, stream_key))
        heapq.heapify(self._heap)


@dataclass(frozen=True)
class StopSendingGracefulInput:
    recv_abortive: bool = False
    needs_local_opener: bool = False
    local_opened: bool = False
    send_committed: bool = False
    queued_data_bytes: int = 0
    inflight_queued: int = 0
    fragment_cap: int = 0
    send_rate_estimate: int = 0
    explicit_tail_cap: Optional[int] = None
    drain_window: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "recv_abortive",
            _require_bool(self.recv_abortive, "recv_abortive"),
        )
        object.__setattr__(
            self,
            "needs_local_opener",
            _require_bool(self.needs_local_opener, "needs_local_opener"),
        )
        object.__setattr__(
            self,
            "local_opened",
            _require_bool(self.local_opened, "local_opened"),
        )
        object.__setattr__(
            self,
            "send_committed",
            _require_bool(self.send_committed, "send_committed"),
        )
        object.__setattr__(
            self,
            "queued_data_bytes",
            _nonnegative_u64(self.queued_data_bytes, "queued_data_bytes"),
        )
        object.__setattr__(
            self,
            "inflight_queued",
            _nonnegative_u64(self.inflight_queued, "inflight_queued"),
        )
        object.__setattr__(
            self,
            "fragment_cap",
            _nonnegative_u64(self.fragment_cap, "fragment_cap"),
        )
        object.__setattr__(
            self,
            "send_rate_estimate",
            _nonnegative_u64(self.send_rate_estimate, "send_rate_estimate"),
        )
        explicit = (
            None
            if self.explicit_tail_cap is None
            else _nonnegative_u64(self.explicit_tail_cap, "explicit_tail_cap")
        )
        object.__setattr__(self, "explicit_tail_cap", explicit)
        object.__setattr__(
            self,
            "drain_window",
            _duration_seconds(self.drain_window, "drain_window"),
        )


@dataclass(frozen=True)
class StopSendingGracefulDecision:
    attempt: bool = False
    tail_budget: int = 0
    committed_tail: int = 0
    inflight_tail: int = 0
    queued_only_tail: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "attempt", _require_bool(self.attempt, "attempt"))
        object.__setattr__(
            self,
            "tail_budget",
            _nonnegative_u64(self.tail_budget, "tail_budget"),
        )
        object.__setattr__(
            self,
            "committed_tail",
            _nonnegative_u64(self.committed_tail, "committed_tail"),
        )
        object.__setattr__(
            self,
            "inflight_tail",
            _nonnegative_u64(self.inflight_tail, "inflight_tail"),
        )
        object.__setattr__(
            self,
            "queued_only_tail",
            _nonnegative_u64(self.queued_only_tail, "queued_only_tail"),
        )


def evaluate_stop_sending_graceful(
        policy_input: StopSendingGracefulInput,
) -> StopSendingGracefulDecision:
    if not isinstance(policy_input, StopSendingGracefulInput):
        raise TypeError("policy_input must be StopSendingGracefulInput")
    committed_tail = stop_sending_committed_tail(
        policy_input.queued_data_bytes,
        policy_input.inflight_queued,
    )
    inflight_tail = policy_input.inflight_queued
    queued_only_tail = stop_sending_queued_only_tail(
        policy_input.queued_data_bytes,
        policy_input.inflight_queued,
    )
    tail_budget = stop_sending_tail_budget(
        policy_input.fragment_cap,
        policy_input.explicit_tail_cap,
        policy_input.send_rate_estimate,
        policy_input.drain_window,
    )

    attempt = False
    if (
            not policy_input.recv_abortive
            and not policy_input.needs_local_opener
            and policy_input.send_committed
    ):
        if committed_tail == 0:
            attempt = policy_input.local_opened
        elif inflight_tail > 0:
            attempt = inflight_tail <= tail_budget
        else:
            attempt = queued_only_tail <= tail_budget

    return StopSendingGracefulDecision(
        attempt=attempt,
        tail_budget=tail_budget,
        committed_tail=committed_tail,
        inflight_tail=inflight_tail,
        queued_only_tail=queued_only_tail,
    )


def stop_sending_committed_tail(queued_data_bytes: int, inflight_queued: int) -> int:
    return max(
        _nonnegative_u64(queued_data_bytes, "queued_data_bytes"),
        _nonnegative_u64(inflight_queued, "inflight_queued"),
    )


def stop_sending_queued_only_tail(queued_data_bytes: int, inflight_queued: int) -> int:
    queued = _nonnegative_u64(queued_data_bytes, "queued_data_bytes")
    inflight = _nonnegative_u64(inflight_queued, "inflight_queued")
    if queued <= inflight:
        return 0
    return queued - inflight


def stop_sending_tail_budget(
        fragment_cap: int,
        explicit_tail_cap: Optional[int],
        send_rate_estimate: int,
        drain_window: float,
) -> int:
    explicit = (
        0
        if explicit_tail_cap is None
        else _nonnegative_u64(explicit_tail_cap, "explicit_tail_cap")
    )
    if explicit > 0:
        return explicit
    budget = stop_sending_static_tail_cap(fragment_cap)
    rate_budget = stop_sending_graceful_rate_budget(
        send_rate_estimate,
        stop_sending_drain_window(drain_window),
    )
    return max(budget, rate_budget)


def stop_sending_static_tail_cap(fragment_cap: int) -> int:
    limit = scaled_fragment_cap(_nonnegative_u64(fragment_cap, "fragment_cap"), 1, 4)
    if limit == 0:
        return 0
    return min(limit, 512)


def stop_sending_graceful_rate_budget(
        rate_bytes_per_second: int,
        window: float,
) -> int:
    rate = _nonnegative_u64(rate_bytes_per_second, "rate_bytes_per_second")
    seconds = _duration_seconds(window, "window")
    if rate == 0 or seconds <= 0:
        return 0
    nanos = _duration_to_nanos(seconds)
    if nanos >= MAX_UINT64:
        return MAX_UINT64
    budget = saturating_mul_div_floor(rate, nanos, NANOS_PER_SECOND)
    if budget == 0:
        return 1
    return min(budget, MAX_UINT64)


def stop_sending_drain_window(
        configured: Optional[float],
        last_ping_rtt: Optional[float] = None,
) -> float:
    configured_seconds = _duration_seconds(configured, "configured")
    if configured_seconds > 0:
        return configured_seconds
    rtt_seconds = _duration_seconds(last_ping_rtt, "last_ping_rtt")
    if rtt_seconds > 0:
        adaptive = rtt_seconds * 2
        if not math.isfinite(adaptive):
            return REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW_MAX
        return min(
            max(adaptive, REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW),
            REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW_MAX,
        )
    return REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW


def _duration_seconds(value: Optional[float], name: str) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a duration in seconds" % name)
    seconds = float(value)
    if math.isnan(seconds):
        raise ValueError("%s must not be NaN" % name)
    if seconds < 0:
        raise ValueError("%s must be >= 0" % name)
    return seconds


def _finite_seconds(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a timestamp in seconds" % name)
    seconds = float(value)
    if math.isnan(seconds):
        raise ValueError("%s must not be NaN" % name)
    if not math.isfinite(seconds):
        raise ValueError("%s must be finite" % name)
    return seconds


def _finite_seconds_or_zero(value: Optional[float], name: str) -> float:
    if value is None:
        return 0.0
    return _finite_seconds(value, name)


def _duration_to_nanos(seconds: float) -> int:
    if not math.isfinite(seconds):
        return MAX_UINT64
    nanos = seconds * NANOS_PER_SECOND
    if not math.isfinite(nanos) or nanos >= MAX_UINT64:
        return MAX_UINT64
    if nanos <= 0:
        return 0
    return max(1, int(nanos))


def _nonnegative_u64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    integer = value
    if integer < 0:
        raise ValueError("%s must be >= 0" % name)
    if integer == 0:
        return 0
    return min(integer, MAX_UINT64)


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


__all__ = (
    "NANOS_PER_SECOND",
    "REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW",
    "REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW_MAX",
    "StopSendingGracefulDeadlineQueue",
    "StopSendingGracefulDecision",
    "StopSendingGracefulInput",
    "evaluate_stop_sending_graceful",
    "stop_sending_committed_tail",
    "stop_sending_drain_window",
    "stop_sending_graceful_rate_budget",
    "stop_sending_queued_only_tail",
    "stop_sending_static_tail_cap",
    "stop_sending_tail_budget",
)
