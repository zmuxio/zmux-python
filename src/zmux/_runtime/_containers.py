"""Small container helpers for retained runtime state."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def clear_attrs(owner: object, names: Iterable[str]) -> None:
    for name in names:
        getattr(owner, name).clear()


def pop_attrs(owner: object, names: Iterable[str], key: Any) -> None:
    for name in names:
        getattr(owner, name).pop(key, None)
