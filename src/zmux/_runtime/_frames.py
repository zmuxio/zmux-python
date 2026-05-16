"""Shared runtime frame sequence helpers."""

from __future__ import annotations

from collections.abc import Iterable

from ..frame import Frame


def frame_tuple(frames: Iterable[Frame], name: str) -> tuple[Frame, ...]:
    if isinstance(frames, Frame):
        raise TypeError("%s must be a sequence of Frame objects" % name)
    try:
        values = tuple(frames)
    except TypeError as exc:
        raise TypeError("%s must be a sequence of Frame objects" % name) from exc
    for frame in values:
        if not isinstance(frame, Frame):
            raise TypeError("%s must contain only Frame objects" % name)
    return values
