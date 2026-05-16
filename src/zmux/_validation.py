"""Shared validation helpers for small public and runtime value checks."""

from __future__ import annotations

import math
from typing import Optional

MAX_VARINT62_VALUE = (1 << 62) - 1


def require_nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


def require_varint62(value: int, name: str) -> int:
    value = require_nonnegative_int(value, name)
    if value > MAX_VARINT62_VALUE:
        raise ValueError("%s must be within varint62 range" % name)
    return value


def require_stream_id(value: int, name: str = "stream_id") -> int:
    value = require_varint62(value, name)
    if value == 0:
        raise ValueError("%s must be non-zero" % name)
    return value


def require_bool(value: bool, name: str, *, noun: str = "bool") -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a %s" % (name, noun))
    return value


def require_nonnegative_duration(value: float, name: str) -> float:
    if isinstance(value, bool):
        raise TypeError("%s must be a duration in seconds" % name)
    duration = float(value)
    if duration < 0:
        raise ValueError("%s must be >= 0" % name)
    return duration


def optional_seconds(
        value: object,
        name: str,
        *,
        description: str,
        clamp_negative: bool = False,
) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be %s or None" % (name, description))
    seconds = float(value)
    if math.isnan(seconds) or math.isinf(seconds):
        return None
    if clamp_negative and seconds < 0.0:
        return 0.0
    return seconds


def coerce_int_enum(value, enum_type, name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be a %s or integer" % (name, enum_type.__name__))
    return enum_type(value)
