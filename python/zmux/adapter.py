"""What only the author of a carrier adapter or of an accept loop of their
own needs: carriers as asyncio streams, the first bytes of a carrier, the
join lookups of a listener and a session's join readiness, the in-memory
pipe, replay filtering and the join key derivation of the secure carrier.
An application that dials and serves with the entries of `zmux` uses none of
it."""

from __future__ import annotations

from ._layer import Layer, LayerWriter, open_carrier
from ._types import FirstBytes, Framing, JoinPrefix, ReplayVerdict
from ._zmux import (
    MAX_FIRST_BYTES,
    RESERVED_EXPORTER_PREFIX,
    CarrierStream,
    PipeEnd,
    PipeHint,
    ReplayFilter,
    UnsentCount,
    classify_first_bytes,
    derive_handle_psk,
    derive_join_psk,
    expand_join_psk,
    join_prefix,
    join_ready,
    pipe_pair,
    session_crypto,
    stream_pipe,
)

__all__ = [
    "MAX_FIRST_BYTES",
    "RESERVED_EXPORTER_PREFIX",
    "CarrierStream",
    "FirstBytes",
    "Framing",
    "JoinPrefix",
    "Layer",
    "LayerWriter",
    "PipeEnd",
    "PipeHint",
    "ReplayFilter",
    "ReplayVerdict",
    "UnsentCount",
    "classify_first_bytes",
    "derive_handle_psk",
    "derive_join_psk",
    "expand_join_psk",
    "join_prefix",
    "join_ready",
    "open_carrier",
    "pipe_pair",
    "session_crypto",
    "stream_pipe",
]
