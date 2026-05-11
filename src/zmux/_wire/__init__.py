"""Private zmux wire codec implementation.

This package contains the registry constants, varint/TLV codecs, frame
envelope handling, payload helpers, settings, and preface parsing used by the
public ``zmux`` modules. Import from the public modules unless a conformance
test needs exact wire internals; names under ``zmux._wire`` are implementation
details and may change between releases.
"""

from __future__ import annotations

__all__ = ()
