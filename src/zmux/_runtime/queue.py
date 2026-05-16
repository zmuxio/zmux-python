"""Internal writer queue facade for runtime modules.

The implementation is split by semantic responsibility: ``tx`` owns transmit
frames, write jobs, classification, coalescing, and cost helpers; ``write_queue``
owns the mutable blocking queue state.  This module intentionally re-exports the
combined internal surface used by the rest of the runtime and tests.
"""

from __future__ import annotations

from . import tx as _tx
from . import write_queue as _write_queue
from ._facade import export_modules

__all__ = export_modules(globals(), _tx, _write_queue)

del export_modules, _tx, _write_queue
