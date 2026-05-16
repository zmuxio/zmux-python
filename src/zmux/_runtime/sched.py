"""Batch scheduler facade for runtime writer ordering.

The implementation is split by semantic responsibility: ``sched_core`` owns the
transport-independent scheduler data model and algorithms; ``batch_scheduler``
owns the small mutable facade used by writer code.
"""

from __future__ import annotations

from . import batch_scheduler as _batch_scheduler
from . import sched_core as _sched_core
from ._facade import export_modules

__all__ = export_modules(globals(), _sched_core, _batch_scheduler)

del export_modules, _batch_scheduler, _sched_core
