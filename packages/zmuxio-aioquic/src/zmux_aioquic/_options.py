"""Adapter options and process-wide prelude defaults."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from ._constants import (
    DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT,
    DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT,
    MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT,
)
from ._validation import _signed_int, _timeout_seconds

_DEFAULT_MAX_CONCURRENT_LOCK = threading.RLock()
_default_accepted_prelude_max_concurrent = DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT


@dataclass(frozen=True)
class SessionOptions(object):
    """Adapter-local options for an aioquic-backed zmux session."""

    accepted_prelude_read_timeout: Optional[float] = (
        DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT
    )
    accepted_prelude_max_concurrent: Optional[int] = None
    local_addr: Optional[object] = None
    remote_addr: Optional[object] = None

    def __post_init__(self) -> None:
        if self.accepted_prelude_read_timeout is not None:
            object.__setattr__(
                self,
                "accepted_prelude_read_timeout",
                _timeout_seconds(
                    self.accepted_prelude_read_timeout,
                    "accepted_prelude_read_timeout",
                ),
            )
        if self.accepted_prelude_max_concurrent is not None:
            object.__setattr__(
                self,
                "accepted_prelude_max_concurrent",
                _signed_int(
                    self.accepted_prelude_max_concurrent,
                    "accepted_prelude_max_concurrent",
                ),
            )


def default_accepted_prelude_max_concurrent() -> int:
    """Return the process default accepted-prelude parsing concurrency."""

    with _DEFAULT_MAX_CONCURRENT_LOCK:
        current = _default_accepted_prelude_max_concurrent
    if current > 0:
        return min(current, MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT)
    return 1


def set_default_accepted_prelude_max_concurrent(max_concurrent: int) -> None:
    """Set the process default accepted-prelude parsing concurrency."""

    global _default_accepted_prelude_max_concurrent
    max_concurrent = _signed_int(max_concurrent, "max_concurrent")
    if max_concurrent <= 0:
        max_concurrent = DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT
    else:
        max_concurrent = min(max_concurrent, MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT)
    with _DEFAULT_MAX_CONCURRENT_LOCK:
        _default_accepted_prelude_max_concurrent = max_concurrent


def normalize_accepted_prelude_read_timeout(
        timeout: Optional[float],
) -> Optional[float]:
    """Normalize prelude read timeout seconds.

    ``None`` and negative numbers disable the adapter-managed timeout. Zero
    uses the built-in default, matching the Go adapter behavior.
    """

    if timeout is None:
        return None
    timeout = _timeout_seconds(timeout, "timeout")
    if timeout < 0:
        return None
    if timeout == 0:
        return DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT
    return timeout


def normalize_accepted_prelude_max_concurrent(max_concurrent: Optional[int]) -> int:
    if max_concurrent is not None:
        max_concurrent = _signed_int(max_concurrent, "max_concurrent")
        if max_concurrent > 0:
            return min(max_concurrent, MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT)
    return default_accepted_prelude_max_concurrent()
