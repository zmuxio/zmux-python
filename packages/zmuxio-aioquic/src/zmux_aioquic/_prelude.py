"""Stream metadata prelude handling for the aioquic adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import zmux
from zmux.config import OpenOptions
from zmux.errors import OpenMetadataTooLarge
from zmux.payload import StreamMetadata, parse_stream_metadata_bytes_view
from zmux.varint import encoded_len_from_first, parse_varint
from ._constants import (
    DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT,
    EMPTY_STREAM_PRELUDE,
    OPEN_METADATA_CAPABILITIES,
    STREAM_PRELUDE_MAX_PAYLOAD,
)
from ._errors import _protocol_prelude_error
from ._io import _read_exactly
from ._validation import _normalize_open_options, _require_bool


@dataclass(frozen=True)
class AcceptedStreamMetadata:
    """Decoded adapter prelude metadata for an accepted QUIC stream."""

    metadata: StreamMetadata = field(default_factory=StreamMetadata)
    metadata_valid: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, StreamMetadata):
            raise TypeError("metadata must be StreamMetadata")
        object.__setattr__(
            self,
            "metadata_valid",
            _require_bool(self.metadata_valid, "metadata_valid"),
        )

    @property
    def open_info(self) -> bytes:
        return self.metadata.open_info


def build_stream_prelude(options: Optional[OpenOptions] = None) -> bytes:
    """Build the QUIC stream adapter prelude for open-time metadata."""

    options = _normalize_open_options(options)
    prefix = zmux.build_open_metadata_prefix(
        OPEN_METADATA_CAPABILITIES,
        options.initial_priority,
        options.initial_group,
        options.open_info,
        STREAM_PRELUDE_MAX_PAYLOAD,
    )
    return prefix if prefix else EMPTY_STREAM_PRELUDE


async def read_stream_prelude(
        reader: object, timeout: Optional[float] = DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT
) -> AcceptedStreamMetadata:
    """Read and decode one accepted stream metadata prelude."""

    if reader is None:
        raise _protocol_prelude_error("missing stream prelude reader")
    first = await _read_exactly(reader, 1, timeout, "read stream prelude length")
    prefix_len = encoded_len_from_first(first[0])
    raw_prefix = first
    if prefix_len > 1:
        raw_prefix += await _read_exactly(
            reader, prefix_len - 1, timeout, "read stream prelude length"
        )
    try:
        metadata_len, consumed = parse_varint(raw_prefix)
    except Exception as exc:  # pragma: no cover - public codec normally catches this
        raise _protocol_prelude_error("parse stream prelude length", exc)
    if consumed != prefix_len:
        raise _protocol_prelude_error("non-canonical stream prelude length")
    if metadata_len == 0:
        return AcceptedStreamMetadata()
    if metadata_len + prefix_len > STREAM_PRELUDE_MAX_PAYLOAD:
        raise OpenMetadataTooLarge()
    metadata_raw = await _read_exactly(
        reader, int(metadata_len), timeout, "read stream metadata"
    )
    try:
        metadata_view, valid = parse_stream_metadata_bytes_view(metadata_raw)
    except Exception as exc:
        raise _protocol_prelude_error("parse stream metadata", exc)
    if not valid:
        return AcceptedStreamMetadata(StreamMetadata(), False)
    return AcceptedStreamMetadata(metadata_view.to_owned(), True)
