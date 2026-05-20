"""Small validation and time helpers for the aioquic adapter."""

from __future__ import annotations

import sys
import time
from collections.abc import Iterable
from typing import Optional, Tuple

from zmux.config import OpenOptions
from zmux.errors import AdapterUnsupported
from zmux.protocol import ErrorCode, MAX_VARINT62


def _normalize_open_options(options: Optional[OpenOptions]) -> OpenOptions:
    if options is None:
        return OpenOptions()
    if isinstance(options, OpenOptions):
        return options
    raise TypeError("open options must be zmux.OpenOptions or None")


def _memoryview(data: object) -> memoryview:
    if data is None or isinstance(data, int):
        raise TypeError("data must be bytes-like")
    try:
        view = memoryview(data)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TypeError("data must be bytes-like") from exc
    if view.ndim != 1 or view.format not in ("B", "b", "c"):
        try:
            view = view.cast("B")
        except (TypeError, ValueError):
            view = memoryview(view.tobytes())
    return view


def _writable_memoryview(buffer: object) -> memoryview:
    view = _memoryview(buffer)
    if view.readonly:
        raise TypeError("buffer must be writable")
    return view


def _writable_memoryviews(parts: Iterable[object]) -> Tuple[Tuple[memoryview, ...], int]:
    if parts is None:
        raise TypeError("buffers must be an iterable of writable bytes-like objects")
    views = []
    total = 0
    for part in parts:
        view = _writable_memoryview(part)
        size = len(view)
        if size == 0:
            continue
        if size > sys.maxsize - total:
            raise OverflowError("vectored read buffers are too large")
        views.append(view)
        total += size
    return tuple(views), total


def _memoryviews(parts: Iterable[object]) -> Tuple[Tuple[memoryview, ...], int]:
    if parts is None:
        raise TypeError("parts must be an iterable of bytes-like objects")
    views = []
    total = 0
    for part in parts:
        view = _memoryview(part)
        size = len(view)
        if size == 0:
            continue
        if size > sys.maxsize - total:
            raise OverflowError("vectored payload is too large")
        views.append(view)
        total += size
    return tuple(views), total


def _remaining_deadline(
        specific_deadline: Optional[float], shared_deadline: Optional[float]
) -> Optional[float]:
    deadline = specific_deadline if specific_deadline is not None else shared_deadline
    if deadline is None:
        return None
    return max(0.0, _deadline_seconds(deadline, "deadline") - time.monotonic())


def _require_application_code(code: int) -> int:
    if isinstance(code, ErrorCode):
        code = int(code)
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError("QUIC application error code must be an integer")
    if code < 0 or code > MAX_VARINT62:
        raise AdapterUnsupported("zmux: QUIC application error code is out of range")
    return code


def _stream_id_value(stream_id: Optional[int]) -> int:
    if stream_id is None:
        return 0
    value = _nonnegative_int(stream_id, "stream_id")
    if value > MAX_VARINT62:
        raise AdapterUnsupported("zmux: QUIC stream id is out of range")
    return value


def _normalize_stream_group(group: Optional[int]) -> Optional[int]:
    if group is None:
        return None
    value = _nonnegative_int(group, "stream group")
    if value > MAX_VARINT62:
        raise AdapterUnsupported("zmux: stream group is out of range")
    return None if value == 0 else value


def _read_size(max_bytes: Optional[int]) -> int:
    if max_bytes is None:
        return -1
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("read size must be an integer")
    return max_bytes


def _deadline_from_timeout(timeout: Optional[float], name: str) -> Optional[float]:
    if timeout is None:
        return None
    value = _timeout_seconds(timeout, name)
    if value == float("inf"):
        return None
    return time.monotonic() + max(value, 0.0)


def _deadline_seconds(deadline: Optional[float], name: str) -> Optional[float]:
    if deadline is None:
        return None
    return _timeout_seconds(deadline, name)


def _timeout_seconds(timeout: float, name: str) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("%s must be a number of seconds" % name)
    value = float(timeout)
    if value != value:
        raise ValueError("%s must not be NaN" % name)
    return value


def _wait_timeout(timeout: Optional[float]) -> Optional[float]:
    if timeout is None:
        return None
    value = _timeout_seconds(timeout, "timeout")
    if value == float("inf"):
        return None
    return max(0.0, value)


def _signed_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value


def _nonnegative_int(value: int, name: str) -> int:
    value = _signed_int(value, name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


def _require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a boolean" % name)
    return value


def _reason_text(reason: str) -> str:
    if reason is None:
        return ""
    if not isinstance(reason, str):
        raise TypeError("reason must be a string")
    return reason
