"""Batch scheduler facade for runtime writer ordering.

The implementation is split by semantic responsibility: ``sched_core`` owns the
transport-independent scheduler data model and algorithms; ``batch_scheduler``
owns the small mutable facade used by writer code.
"""

from __future__ import annotations

from .sched_core import __all__ as _CORE_ALL
from .sched_core import *  # noqa: F403
from .batch_scheduler import BatchScheduler, new_batch_scheduler

__all__ = _CORE_ALL + ("BatchScheduler", "new_batch_scheduler")
