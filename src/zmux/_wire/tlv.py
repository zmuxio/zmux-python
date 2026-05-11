"""TLV codec implementation."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, MutableSequence
from dataclasses import dataclass
from typing import List, Tuple

from .errors import (
    ERR_TLV_VALUE_OVERRUN,
    ERR_TRUNCATED_TLV,
    ERR_TRUNCATED_VARINT,
    ERR_VALUE_TOO_LARGE,
    frame_size_error,
    protocol_error,
)
from .varint import encode_varint_into, parse_varint, varint_len
from ..errors import ErrorOperation, ProtocolError
from ..protocol import MAX_VARINT62

MAX_TLV_PARSE_CAPACITY_HINT = 64

__all__ = (
    "MAX_TLV_PARSE_CAPACITY_HINT",
    "Tlv",
    "TlvView",
    "append_tlv",
    "encode_tlvs",
    "iter_tlvs_view",
    "parse_tlvs",
    "parse_tlvs_view",
    "tlv_encoded_len",
    "tlv_parse_capacity_hint",
    "validate_tlv_header",
    "validate_tlvs",
    "visit_tlvs",
)


@dataclass(frozen=True)
class Tlv:
    """Owned TLV item."""

    typ: int
    value: bytes = b""

    def __post_init__(self) -> None:
        value_view = _tlv_value_view(self.value)
        validate_tlv_header(self.typ, len(value_view))
        value = b"" if len(value_view) == 0 else value_view.tobytes()
        object.__setattr__(self, "value", value)

    def __repr__(self) -> str:
        return "%s(typ=%r, value_length=%r)" % (
            self.__class__.__name__,
            self.typ,
            len(self.value),
        )

    def validate(self) -> None:
        """Validate that this TLV can be encoded."""

        validate_tlv_header(self.typ, len(self.value))

    def is_empty(self) -> bool:
        """Return whether this TLV carries an empty value."""

        return len(self.value) == 0

    def encoded_len(self) -> int:
        """Return encoded byte length."""

        return tlv_encoded_len(self.typ, len(self.value))

    def append_to(self, dst: MutableSequence[int]) -> None:
        """Append this TLV to ``dst``."""

        append_tlv(dst, self.typ, self.value)

    def as_view(self) -> "TlvView":
        """Return a view over this TLV's value bytes."""

        return TlvView(self.typ, memoryview(self.value))


@dataclass(frozen=True)
class TlvView:
    """Borrowed TLV item view."""

    typ: int
    value: memoryview

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _tlv_value_view(self.value))

    def __repr__(self) -> str:
        return "%s(typ=%r, value_length=%r)" % (
            self.__class__.__name__,
            self.typ,
            len(self.value),
        )

    def validate(self) -> None:
        """Validate that this TLV can be encoded."""

        validate_tlv_header(self.typ, len(self.value))

    def is_empty(self) -> bool:
        """Return whether this TLV view carries an empty value."""

        return len(self.value) == 0

    def encoded_len(self) -> int:
        """Return encoded byte length."""

        return tlv_encoded_len(self.typ, len(self.value))

    def append_to(self, dst: MutableSequence[int]) -> None:
        """Append this TLV to ``dst``."""

        append_tlv(dst, self.typ, self.value)

    def to_owned(self) -> Tlv:
        """Copy this view into an owned TLV."""

        self.validate()
        return Tlv(self.typ, self.value.tobytes())


def append_tlv(dst: MutableSequence[int], typ: int, value: object = b"") -> None:
    """Append one TLV after validating the full header first."""

    value_view = _tlv_value_view(value)
    encoded_len = tlv_encoded_len(typ, len(value_view))
    if isinstance(dst, bytearray):
        offset = len(dst)
        dst.extend(b"\x00" * encoded_len)
        pos = offset + encode_varint_into(dst, offset, typ)
        pos += encode_varint_into(dst, pos, len(value_view))
        dst[pos: pos + len(value_view)] = value_view
        return

    encoded = bytearray(encoded_len)
    offset = encode_varint_into(encoded, 0, typ)
    offset += encode_varint_into(encoded, offset, len(value_view))
    encoded[offset:] = value_view
    dst_offset = len(dst)
    try:
        dst.extend(encoded)
    except Exception:
        try:
            del dst[dst_offset:]
        except Exception:
            pass
        raise


def encode_tlvs(items: Iterable[Tlv]) -> bytes:
    """Encode TLV items into bytes."""

    out = bytearray()
    for item in items:
        item.append_to(out)
    return bytes(out)


def visit_tlvs(data: bytes, visit: Callable[[int, memoryview], None]) -> None:
    """Visit TLV views in encoded order."""

    for item in iter_tlvs_view(data):
        visit(item.typ, item.value)


def iter_tlvs_view(data: bytes) -> Iterator[TlvView]:
    """Yield TLV views lazily in encoded order."""

    view = _tlv_data_view(data)
    pos = 0
    total = len(view)
    while pos < total:
        typ, n_typ = _parse_tlv_varint(view, pos, total)
        pos += n_typ
        length, n_len = _parse_tlv_varint(view, pos, total)
        pos += n_len
        end = pos + length
        if end > total:
            raise _wire_error(ERR_TLV_VALUE_OVERRUN)
        yield TlvView(typ, view[pos:end])
        pos = end


def parse_tlvs(data: bytes) -> List[Tlv]:
    """Parse a TLV byte sequence and copy values into owned bytes."""

    return [item.to_owned() for item in iter_tlvs_view(data)]


def parse_tlvs_view(data: bytes) -> List[TlvView]:
    """Parse a TLV byte sequence and return memory views into ``data``."""

    return list(iter_tlvs_view(data))


def validate_tlvs(data: bytes) -> None:
    """Validate a TLV byte sequence without retaining parsed items."""

    for _item in iter_tlvs_view(data):
        pass


def tlv_encoded_len(typ: int, value_len: int) -> int:
    """Return encoded byte length for a TLV header and value."""

    typ_len = varint_len(_require_tlv_type(typ))
    value_len = _require_tlv_value_len(value_len)
    return _tlv_encoded_len_with_type_len(typ_len, value_len)


def validate_tlv_header(typ: int, value_len: int) -> None:
    """Validate TLV type and value length."""

    tlv_encoded_len(typ, value_len)


def tlv_parse_capacity_hint(data_len: int) -> int:
    """Return the same bounded capacity hint used by other implementations."""

    data_len = _require_data_len(data_len)
    if data_len <= 0:
        return 0
    return min(MAX_TLV_PARSE_CAPACITY_HINT, data_len // 2)


def _tlv_value_view(value: object) -> memoryview:
    if value is None:
        return memoryview(b"")
    if isinstance(value, (bool, int)):
        raise TypeError("TLV value must be bytes-like")
    try:
        view = memoryview(value)
    except TypeError as exc:
        raise TypeError("TLV value must be bytes-like") from exc
    if (
            view.ndim == 1
            and view.itemsize == 1
            and view.format in ("B", "b", "c")
            and view.contiguous
    ):
        return view
    try:
        return view.cast("B")
    except (TypeError, ValueError):
        return memoryview(view.tobytes())


def _tlv_data_view(data: object) -> memoryview:
    if data is None:
        raise TypeError("TLV data must be bytes-like")
    return _tlv_value_view(data)


def _tlv_encoded_len_with_type_len(typ_len: int, value_len: int) -> int:
    return typ_len + varint_len(value_len) + value_len


def _require_tlv_type(typ: int) -> int:
    if isinstance(typ, bool) or not isinstance(typ, int):
        raise TypeError("TLV type must be an integer")
    if typ < 0 or typ > MAX_VARINT62:
        raise protocol_error(ERR_VALUE_TOO_LARGE, ErrorOperation.WRITE)
    return typ


def _require_tlv_value_len(value_len: int) -> int:
    if isinstance(value_len, bool) or not isinstance(value_len, int):
        raise TypeError("TLV value length must be an integer")
    if value_len < 0:
        raise ValueError("TLV value length cannot be negative")
    if value_len > MAX_VARINT62:
        raise _frame_size_error("tlv value too large")
    return value_len


def _require_data_len(data_len: int) -> int:
    if isinstance(data_len, bool) or not isinstance(data_len, int):
        raise TypeError("TLV data length must be an integer")
    if data_len < 0:
        raise ValueError("TLV data length cannot be negative")
    return data_len


def _parse_tlv_varint(data: memoryview, offset: int, limit: int) -> Tuple[int, int]:
    try:
        return parse_varint(data, offset, limit)
    except ProtocolError as exc:
        if str(exc) == ERR_TRUNCATED_VARINT:
            raise _wire_error(ERR_TRUNCATED_TLV) from exc
        raise


def _wire_error(message: str) -> ProtocolError:
    return protocol_error(message, ErrorOperation.READ)


def _frame_size_error(message: str) -> ProtocolError:
    return frame_size_error(message, ErrorOperation.WRITE)
