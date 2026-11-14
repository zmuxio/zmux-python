"""Scheduling: the built-in policies that choose which pipe carries a chunk,
and the redundancy of urgent data. The binding takes no policy written in
Python: one would run on the driver's decision path under the interpreter
lock."""

from __future__ import annotations

from ._types import Redundancy, Scheduler

__all__ = [
    "Redundancy",
    "Scheduler",
]
