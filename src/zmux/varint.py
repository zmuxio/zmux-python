"""Public varint62 codec facade."""

from __future__ import annotations

from ._wire.varint import (
    append_varint,
    append_packed_varint,
    decode_varint_value,
    encode_varint,
    encode_varint_into,
    encoded_len_from_first,
    pack_varint,
    parse_varint,
    read_varint,
    validate_decoded_varint,
    varint_len,
)
from .protocol import MAX_VARINT62, MAX_VARINT_LEN

__all__ = (
    "MAX_VARINT62",
    "MAX_VARINT_LEN",
    "append_packed_varint",
    "append_varint",
    "decode_varint_value",
    "encode_varint",
    "encode_varint_into",
    "encoded_len_from_first",
    "pack_varint",
    "parse_varint",
    "read_varint",
    "validate_decoded_varint",
    "varint_len",
)
