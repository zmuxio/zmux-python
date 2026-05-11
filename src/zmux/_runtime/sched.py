"""Batch scheduler facade for runtime writer ordering.

The implementation is split by semantic responsibility: ``sched_core`` owns the
transport-independent scheduler data model and algorithms; ``batch_scheduler``
owns the small mutable facade used by writer code.
"""

from __future__ import annotations

from typing import Tuple

from . import batch_scheduler as _batch_scheduler
from . import sched_core as _sched_core


def _export(module: object) -> Tuple[str, ...]:
    names = tuple(vars(module).get("__all__", ()))
    for name in names:
        globals()[name] = getattr(module, name)
    return names


__all__ = _export(_sched_core) + _export(_batch_scheduler)

del _export, _batch_scheduler, _sched_core
