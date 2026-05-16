"""Shared helpers for byte-oriented buffer views."""

from __future__ import annotations


def byte_view(data: object) -> memoryview:
    view = memoryview(data)
    if view.ndim == 1 and view.itemsize == 1 and view.format in ("B", "b", "c"):
        return view
    try:
        return view.cast("B")
    except (TypeError, ValueError):
        return memoryview(view.tobytes())
