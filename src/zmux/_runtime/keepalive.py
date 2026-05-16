"""Keepalive jitter and ping nonce helpers.

This module mirrors Go ``internal/runtime/keepalive.go``.  The helpers are
small but deliberately shared by keepalive scheduling and PING padding so both
paths advance the same SplitMix64-style state without depending on session I/O.
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass
from struct import pack_into
from threading import Lock
from typing import Any

from .flow import MAX_UINT64
from .._validation import (
    require_bool as _shared_require_bool,
    require_nonnegative_duration as _duration_seconds,
)
from ..config import DEFAULT_PING_PADDING_MAX_BYTES, DEFAULT_PING_PADDING_MIN_BYTES, Settings

KEEPALIVE_JITTER_GAMMA = 0x9E3779B97F4A7C15
SPLITMIX64_MUL1 = 0xBF58476D1CE4E5B9
SPLITMIX64_MUL2 = 0x94D049BB133111EB
RTT_ADAPTIVE_SLACK = 0.050
DEFAULT_KEEPALIVE_TIMEOUT_MIN = 5.0
DEFAULT_KEEPALIVE_TIMEOUT_MAX = 60.0
MIN_SEND_RATE_SAMPLE_BYTES = 4 << 10
MIN_SEND_RATE_SAMPLE_DURATION = 0.025
PING_NONCE_BYTES = 8
PING_PADDING_TAG_BYTES = 8
PING_PADDING_TAG_SALT = 0x6D1D9F6D33F9772D
PING_PAYLOAD_HASH_OFFSET64 = 14695981039346656037
PING_PAYLOAD_HASH_PRIME64 = 1099511628211
_JITTER_WINDOW_DIVISOR = 8.0
_NANOS_PER_SECOND = 1_000_000_000
_MAX_DURATION_SECONDS = ((1 << 63) - 1) / _NANOS_PER_SECOND
_PING_BLOCK_BYTES = 8
_DEFAULT_SETTINGS = Settings()

_seed_counter = 0
_seed_lock = Lock()


def splitmix64_from_state(state: int) -> int:
    """Return the SplitMix64 output for an already-advanced 64-bit state."""
    z = _uint64(state, "state")
    z = ((z ^ (z >> 30)) * SPLITMIX64_MUL1) & MAX_UINT64
    z = ((z ^ (z >> 27)) * SPLITMIX64_MUL2) & MAX_UINT64
    return (z ^ (z >> 31)) & MAX_UINT64


def init_keepalive_jitter_state(seed: int) -> int:
    """Preserve explicit non-zero seeds and allocate distinct default seeds."""
    seed = _uint64(seed, "seed")
    if seed == 0:
        global _seed_counter
        with _seed_lock:
            _seed_counter = (_seed_counter + KEEPALIVE_JITTER_GAMMA) & MAX_UINT64
            seed = _seed_counter
    return seed


def init_session_nonce_state(seed: int) -> int:
    return init_keepalive_jitter_state(seed)


def next_keepalive_jitter_value_from_state(state: int) -> tuple[int, int]:
    """Advance a raw state and return ``(new_state, mixed_value)``."""
    state = _uint64(state, "state")
    if state == 0:
        state = init_keepalive_jitter_state(0)
    state = (state + KEEPALIVE_JITTER_GAMMA) & MAX_UINT64
    return state, splitmix64_from_state(state)


def next_session_nonce(liveness: Any) -> int:
    state, value = next_keepalive_jitter_value_from_state(
        0 if liveness is None else getattr(liveness, "ping_nonce_state", 0)
    )
    if liveness is not None:
        liveness.ping_nonce_state = state
    return value


def next_keepalive_jitter(base: float, liveness: Any) -> float:
    base = _duration_seconds(base, "base")
    if math.isnan(base) or base <= 0:
        return 0.0
    if math.isinf(base):
        window_nanos = MAX_UINT64
    else:
        window_nanos = min(
            MAX_UINT64, int((base / _JITTER_WINDOW_DIVISOR) * _NANOS_PER_SECOND)
        )
    if window_nanos <= 0:
        return 0.0
    state, value = next_keepalive_jitter_value_from_state(
        0 if liveness is None else getattr(liveness, "keepalive_jitter_state", 0)
    )
    if liveness is not None:
        liveness.keepalive_jitter_state = state
    return (value % (window_nanos + 1)) / _NANOS_PER_SECOND


def keepalive_lead_jittered_delay(base: float, liveness: Any) -> float:
    base = _duration_seconds(base, "base")
    if math.isnan(base) or base <= 0:
        return 0.0
    delay = base - next_keepalive_jitter(base, liveness)
    return base if delay <= 0 else delay


def next_uint64n_from_state(liveness: Any, n: int) -> int:
    if isinstance(n, bool) or not isinstance(n, int):
        raise TypeError("n must be an integer")
    if n < 0:
        raise ValueError("n must be >= 0")
    if n <= 1:
        return 0
    if n > MAX_UINT64:
        raise OverflowError("n exceeds uint64")
    limit = MAX_UINT64 - (MAX_UINT64 % n)
    while True:
        value = next_session_nonce(liveness)
        if value < limit:
            return value % n


def fill_ping_padding_from_state(length: int, liveness: Any) -> bytes:
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 0:
        raise ValueError("length must be >= 0")
    out = bytearray(length)
    offset = 0
    full_end = length - (length % _PING_BLOCK_BYTES)
    while offset < full_end:
        pack_into(">Q", out, offset, next_session_nonce(liveness))
        offset += _PING_BLOCK_BYTES
    if offset < length:
        block = next_session_nonce(liveness).to_bytes(_PING_BLOCK_BYTES, "big")
        out[offset:] = block[: length - offset]
    return bytes(out)


@dataclass(frozen=True)
class PingPayloadFingerprint(object):
    """Hash one outstanding or recently canceled PING payload."""

    nonce: int = 0
    hash: int = 0
    length: int = 0
    allow_padding: bool = False
    set: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "nonce", _uint64(self.nonce, "nonce"))
        object.__setattr__(self, "hash", _uint64(self.hash, "hash"))
        object.__setattr__(self, "length", _nonnegative_int(self.length, "length"))
        object.__setattr__(
            self,
            "allow_padding",
            _require_bool(self.allow_padding, "allow_padding"),
        )
        object.__setattr__(self, "set", _require_bool(self.set, "set"))

    @classmethod
    def from_payload(
            cls,
            payload: bytes,
            allow_padding: bool = False,
    ) -> "PingPayloadFingerprint":
        allow_padding = _require_bool(allow_padding, "allow_padding")
        view = _byte_view(payload)
        if len(view) < PING_NONCE_BYTES:
            return cls()
        return cls(
            nonce=int.from_bytes(view[:PING_NONCE_BYTES], "big"),
            hash=ping_payload_hash(view),
            length=len(view),
            allow_padding=allow_padding,
            set=True,
        )

    def matches(self, payload: bytes) -> bool:
        view = _byte_view(payload)
        if not self.set or len(view) < PING_NONCE_BYTES:
            return False
        if int.from_bytes(view[:PING_NONCE_BYTES], "big") != self.nonce:
            return False
        if self.allow_padding:
            return (
                    len(view) >= self.length
                    and ping_payload_hash(view[: self.length]) == self.hash
            )
        return len(view) == self.length and ping_payload_hash(view) == self.hash


def effective_keepalive_timeout(
        interval: float,
        configured: float = 0.0,
        last_ping_rtt: float = 0.0,
) -> float:
    interval = _duration_seconds(interval, "interval")
    configured = _duration_seconds(configured, "configured")
    last_ping_rtt = _duration_seconds(last_ping_rtt, "last_ping_rtt")
    if configured > 0:
        timeout = configured
        if last_ping_rtt > 0:
            timeout = max(timeout, keepalive_timeout_rtt_floor(last_ping_rtt))
        return timeout
    if interval <= 0:
        return 0.0
    timeout = min(
        DEFAULT_KEEPALIVE_TIMEOUT_MAX,
        max(
            DEFAULT_KEEPALIVE_TIMEOUT_MIN,
            saturating_duration_mul_add(interval, 2, 0.0),
        ),
    )
    if last_ping_rtt > 0:
        timeout = min(
            DEFAULT_KEEPALIVE_TIMEOUT_MAX,
            max(timeout, keepalive_timeout_rtt_floor(last_ping_rtt)),
        )
    return timeout


def keepalive_timeout_rtt_floor(rtt: float) -> float:
    rtt = _duration_seconds(rtt, "rtt")
    if rtt <= 0:
        return 0.0
    return saturating_duration_mul_add(rtt, 4, RTT_ADAPTIVE_SLACK)


def ping_payload_hash(payload: bytes) -> int:
    value = PING_PAYLOAD_HASH_OFFSET64
    for byte in _byte_view(payload):
        value ^= byte
        value = (value * PING_PAYLOAD_HASH_PRIME64) & MAX_UINT64
    return value


def ping_payload_len(echo_len: int) -> int:
    echo_len = _nonnegative_int(echo_len, "echo_len")
    if echo_len > sys.maxsize - PING_NONCE_BYTES:
        raise OverflowError("PING payload length overflows platform int")
    return echo_len + PING_NONCE_BYTES


def build_ping_payload(echo: bytes, nonce: int) -> bytes:
    echo = _bytes_like(echo, "echo")
    ping_payload_len(len(echo))
    return _uint64(nonce, "nonce").to_bytes(PING_NONCE_BYTES, "big") + echo


def build_ping_payload_capped_with_nonce(
        echo: bytes,
        max_payload: int,
        nonce: int,
) -> bytes:
    echo = _bytes_like(echo, "echo")
    payload_len = ping_payload_len(len(echo))
    max_payload = _nonnegative_int(max_payload, "max_payload")
    if payload_len > max_payload:
        raise ValueError(
            "PING payload %d exceeds control payload limit %d"
            % (payload_len, max_payload)
        )
    return build_ping_payload(echo, nonce)


def pong_payload_matches_ping(
        pong: bytes,
        ping: bytes,
        *,
        allow_padding: bool = False,
) -> bool:
    allow_padding = _require_bool(allow_padding, "allow_padding")
    ping_view = _byte_view(ping)
    pong_view = _byte_view(pong)
    if allow_padding:
        return len(pong_view) >= len(ping_view) and pong_view[: len(ping_view)] == ping_view
    return pong_view == ping_view


def ping_payload_limit(local: Settings, peer: Settings) -> int:
    local_limit = local.max_control_payload_bytes or _DEFAULT_SETTINGS.max_control_payload_bytes
    peer_limit = peer.max_control_payload_bytes or _DEFAULT_SETTINGS.max_control_payload_bytes
    return min(local_limit, peer_limit)


def ping_padding_tag(key: int, nonce: int) -> int:
    value = (_uint64(key, "key") ^ _uint64(nonce, "nonce") ^ PING_PADDING_TAG_SALT)
    value &= MAX_UINT64
    value = ((value ^ (value >> 30)) * SPLITMIX64_MUL1) & MAX_UINT64
    value = ((value ^ (value >> 27)) * SPLITMIX64_MUL2) & MAX_UINT64
    return (value ^ (value >> 31)) & MAX_UINT64


def has_ping_padding_tag(payload: bytes, key: int) -> bool:
    key = _uint64(key, "key")
    view = _byte_view(payload)
    if key == 0 or len(view) < PING_NONCE_BYTES + PING_PADDING_TAG_BYTES:
        return False
    nonce = int.from_bytes(view[:PING_NONCE_BYTES], "big")
    tag = int.from_bytes(
        view[PING_NONCE_BYTES: PING_NONCE_BYTES + PING_PADDING_TAG_BYTES],
        "big",
    )
    return tag == ping_padding_tag(key, nonce)


def ping_padding_bounds(
        max_allowed: int,
        configured_min: int = 0,
        configured_max: int = 0,
) -> tuple[int, int]:
    max_allowed = min(
        _nonnegative_int(max_allowed, "max_allowed"),
        sys.maxsize - PING_NONCE_BYTES,
    )
    configured_min = _nonnegative_int(configured_min, "configured_min")
    configured_max = _nonnegative_int(configured_max, "configured_max")
    max_padding = configured_max or DEFAULT_PING_PADDING_MAX_BYTES
    max_padding = min(max_padding, max_allowed)
    if max_padding == 0:
        return 0, 0
    min_padding = configured_min or DEFAULT_PING_PADDING_MIN_BYTES
    min_padding = min(min_padding, max_padding)
    return min_padding, max_padding


def make_ping_padding(
        liveness: Any,
        max_allowed: int,
        min_required: int = 0,
) -> bytes:
    if not _liveness_ping_padding(liveness):
        return b""
    min_padding, max_padding = ping_padding_bounds(
        max_allowed,
        getattr(liveness, "ping_padding_min", 0),
        getattr(liveness, "ping_padding_max", 0),
    )
    min_required = _nonnegative_int(min_required, "min_required")
    if max_padding == 0 or min_required > max_padding:
        return b""
    if min_padding < min_required:
        min_padding = min_required
    padding_len = min_padding
    span = max_padding - min_padding + 1
    if span > 1:
        padding_len += next_uint64n_from_state(liveness, span)
        if padding_len == getattr(liveness, "last_ping_padding_len", 0):
            padding_len = min_padding + ((padding_len - min_padding + 1) % span)
    liveness.last_ping_padding_len = padding_len
    return fill_ping_padding_from_state(padding_len, liveness)


def build_padded_ping_echo(
        liveness: Any,
        local: Settings,
        peer: Settings,
        echo: bytes,
        nonce: int,
) -> tuple[bytes, bool]:
    echo = _bytes_like(echo, "echo")
    nonce = _uint64(nonce, "nonce")
    if not _liveness_ping_padding(liveness):
        return echo, False
    limit = ping_payload_limit(local, peer)
    min_payload_len = len(echo) + PING_NONCE_BYTES + PING_PADDING_TAG_BYTES
    if limit < min_payload_len or local.ping_padding_key == 0:
        return echo, False
    max_allowed = limit - len(echo) - PING_NONCE_BYTES
    _, max_padding = ping_padding_bounds(
        max_allowed,
        getattr(liveness, "ping_padding_min", 0),
        getattr(liveness, "ping_padding_max", 0),
    )
    if max_padding < PING_PADDING_TAG_BYTES:
        return echo, False
    padding = make_ping_padding(liveness, max_allowed, PING_PADDING_TAG_BYTES)
    if not padding:
        return echo, False
    tag = ping_padding_tag(local.ping_padding_key, nonce).to_bytes(
        PING_PADDING_TAG_BYTES,
        "big",
    )
    padding = tag + padding[PING_PADDING_TAG_BYTES:]
    return (
        padding[:PING_PADDING_TAG_BYTES] + echo + padding[PING_PADDING_TAG_BYTES:],
        True,
    )


def pong_payload_for_ping(
        liveness: Any,
        local: Settings,
        peer: Settings,
        payload: bytes,
) -> bytes:
    payload = _bytes_like(payload, "payload")
    if not has_ping_padding_tag(payload, peer.ping_padding_key):
        return payload
    max_payload = ping_payload_limit(local, peer)
    if len(payload) >= max_payload:
        return payload
    padding = make_ping_padding(liveness, max_payload - len(payload), 0)
    if not padding:
        return payload
    return payload + padding


def adaptive_rtt_timeout(
        rtt: float,
        base: float,
        maximum: float,
        multiplier: int,
        slack: float,
) -> float:
    rtt = _duration_seconds(rtt, "rtt")
    base = _duration_seconds(base, "base")
    maximum = _duration_seconds(maximum, "maximum")
    multiplier = _nonnegative_int(multiplier, "multiplier")
    slack = _duration_seconds(slack, "slack")
    if base <= 0:
        return 0.0
    timeout = base
    if rtt > 0 and multiplier > 0:
        timeout = max(timeout, saturating_duration_mul_add(rtt, multiplier, slack))
    if 0 < maximum < timeout:
        return maximum
    return timeout


def saturating_duration_mul_add(value: float, multiplier: int, add: float) -> float:
    value = _duration_seconds(value, "value")
    multiplier = _nonnegative_int(multiplier, "multiplier")
    add = _duration_seconds(add, "add")
    if value <= 0 or multiplier <= 0:
        return 0.0
    out = value * multiplier
    if math.isinf(out) or out > _MAX_DURATION_SECONDS:
        return _MAX_DURATION_SECONDS
    if add > 0:
        out += add
        if math.isinf(out) or out > _MAX_DURATION_SECONDS:
            return _MAX_DURATION_SECONDS
    return out


def send_rate_sample(byte_count: int, elapsed: float) -> int:
    byte_count = _nonnegative_int(byte_count, "byte_count")
    elapsed = _duration_seconds(elapsed, "elapsed")
    if byte_count == 0 or elapsed == 0.0:
        return 0
    if byte_count < MIN_SEND_RATE_SAMPLE_BYTES and elapsed < MIN_SEND_RATE_SAMPLE_DURATION:
        return 0
    return max(1, rate_bytes_per_second(byte_count, elapsed))


def rate_bytes_per_second(byte_count: int, elapsed: float) -> int:
    byte_count = _nonnegative_int(byte_count, "byte_count")
    elapsed = _duration_seconds(elapsed, "elapsed")
    if byte_count == 0 or elapsed == 0.0:
        return 0
    if math.isinf(elapsed):
        return 1
    nanos = max(1, int(math.ceil(elapsed * _NANOS_PER_SECOND)))
    rate = (byte_count * _NANOS_PER_SECOND) // nanos
    return min(MAX_UINT64, rate)


def average_u64_floor(a: int, b: int) -> int:
    a = _uint64(a, "a")
    b = _uint64(b, "b")
    if a <= b:
        return a + (b - a) // 2
    return b + (a - b) // 2


def _uint64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    if value > MAX_UINT64:
        raise OverflowError("%s exceeds uint64" % name)
    return value


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


def _require_bool(value: bool, name: str) -> bool:
    return _shared_require_bool(value, name)


def _byte_view(data: bytes) -> memoryview:
    view = memoryview(data)
    if view.ndim != 1 or view.format != "B":
        view = view.cast("B")
    return view


def _bytes_like(data: bytes, name: str) -> bytes:
    if isinstance(data, bytes):
        return data
    try:
        return _byte_view(data).tobytes()
    except TypeError:
        raise TypeError("%s must be bytes-like" % name) from None


def _liveness_ping_padding(liveness: Any) -> bool:
    return _require_bool(getattr(liveness, "ping_padding", False), "ping_padding")


_splitmix64_from_state = splitmix64_from_state

__all__ = (
    "DEFAULT_KEEPALIVE_TIMEOUT_MAX",
    "DEFAULT_KEEPALIVE_TIMEOUT_MIN",
    "KEEPALIVE_JITTER_GAMMA",
    "MIN_SEND_RATE_SAMPLE_BYTES",
    "MIN_SEND_RATE_SAMPLE_DURATION",
    "PING_NONCE_BYTES",
    "PING_PADDING_TAG_BYTES",
    "PING_PADDING_TAG_SALT",
    "PING_PAYLOAD_HASH_OFFSET64",
    "PING_PAYLOAD_HASH_PRIME64",
    "PingPayloadFingerprint",
    "RTT_ADAPTIVE_SLACK",
    "SPLITMIX64_MUL1",
    "SPLITMIX64_MUL2",
    "adaptive_rtt_timeout",
    "average_u64_floor",
    "build_padded_ping_echo",
    "build_ping_payload",
    "build_ping_payload_capped_with_nonce",
    "effective_keepalive_timeout",
    "fill_ping_padding_from_state",
    "has_ping_padding_tag",
    "init_keepalive_jitter_state",
    "init_session_nonce_state",
    "keepalive_lead_jittered_delay",
    "keepalive_timeout_rtt_floor",
    "make_ping_padding",
    "next_keepalive_jitter",
    "next_keepalive_jitter_value_from_state",
    "next_session_nonce",
    "next_uint64n_from_state",
    "ping_padding_bounds",
    "ping_padding_tag",
    "ping_payload_hash",
    "ping_payload_len",
    "ping_payload_limit",
    "pong_payload_for_ping",
    "pong_payload_matches_ping",
    "rate_bytes_per_second",
    "send_rate_sample",
    "saturating_duration_mul_add",
    "splitmix64_from_state",
)
