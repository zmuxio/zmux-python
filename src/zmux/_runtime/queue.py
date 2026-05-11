"""Internal writer queue facade for runtime modules.

The implementation is split by semantic responsibility: ``tx`` owns transmit
frames, write jobs, classification, coalescing, and cost helpers; ``write_queue``
owns the mutable blocking queue state.  This module intentionally re-exports the
combined internal surface used by the rest of the runtime and tests.
"""

from __future__ import annotations

from .tx import __all__ as _TX_ALL
from .tx import *  # noqa: F403
from .write_queue import __all__ as _WRITE_QUEUE_ALL
from .write_queue import *  # noqa: F403

__all__ = _TX_ALL + _WRITE_QUEUE_ALL
