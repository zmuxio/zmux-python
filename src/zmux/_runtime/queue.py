"""Internal writer queue facade for runtime modules.

The implementation is split by semantic responsibility: ``tx`` owns transmit
frames, write jobs, classification, coalescing, and cost helpers; ``write_queue``
owns the mutable blocking queue state.  This module intentionally re-exports the
combined internal surface used by the rest of the runtime and tests.
"""

from __future__ import annotations

from typing import Tuple

from . import tx as _tx
from . import write_queue as _write_queue


def _export(module: object) -> Tuple[str, ...]:
    names = tuple(vars(module).get("__all__", ()))
    for name in names:
        globals()[name] = getattr(module, name)
    return names


__all__ = _export(_tx) + _export(_write_queue)

del _export, _tx, _write_queue
