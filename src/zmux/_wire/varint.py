"""varint62 codec implementation."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import BinaryIO, Optional, Tuple

from .errors import (
    ERR_NON_CANONICAL_VARINT,
    ERR_TRUNCATED_VARINT,
    ERR_VALUE_TOO_LARGE,
    frame_size_error,
    protocol_error,
)
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ProtocolError,
    TransportError,
)
from ..protocol import MAX_VARINT62, MAX_VARINT_LEN

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


def varint_len(value: int) -> int:
    """Return the canonical encoded length for ``value``."""

    value = _require_int(value, "varint value")
    if value < 0 or value > MAX_VARINT62:
        raise _local_value_error(ERR_VALUE_TOO_LARGE)
    if value <= 63:
        return 1
    if value <= 16383:
        return 2
    if value <= 1073741823:
        return 4
    return 8


def append_varint(dst: MutableSequence[int], value: int) -> None:
    """Append the canonical varint62 encoding of ``value`` to ``dst``."""

    length = varint_len(value)
    if isinstance(dst, bytearray):
        _append_varint_to_bytearray(dst, value, length)
        return

    encoded = bytearray(length)
    _write_varint_into(encoded, 0, value, length)
    _extend_with_rollback(dst, encoded)


def _append_varint_to_bytearray(dst: bytearray, value: int, length: int) -> None:
    if length == 1:
        dst.append(value & 0xFF)
    elif length == 2:
        dst.extend((((value >> 8) & 0x3F) | 0x40, value & 0xFF))
    elif length == 4:
        dst.extend(
            (
                ((value >> 24) & 0x3F) | 0x80,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            )
        )
    elif length == 8:
        dst.extend(
            (
                ((value >> 56) & 0x3F) | 0xC0,
                (value >> 48) & 0xFF,
                (value >> 40) & 0xFF,
                (value >> 32) & 0xFF,
                (value >> 24) & 0xFF,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            )
        )
    else:
        raise ValueError("unsupported varint length")


def encode_varint(value: int) -> bytes:
    """Encode ``value`` as canonical varint62 bytes."""

    length = varint_len(value)
    encoded = bytearray(length)
    _write_varint_into(encoded, 0, value, length)
    return bytes(encoded)


def encode_varint_into(dst: bytearray, offset: int, value: int) -> int:
    """Encode ``value`` into ``dst`` at ``offset`` and return bytes written."""

    offset = _require_int(offset, "offset")
    length = varint_len(value)
    end = offset + length
    if offset < 0 or end > len(dst):
        raise _frame_size_error("varint destination too small")
    _write_varint_into(dst, offset, value, length)
    return length


def _write_varint_into(
        dst: MutableSequence[int], offset: int, value: int, length: int
) -> None:
    if length == 1:
        dst[offset] = value & 0xFF
    elif length == 2:
        dst[offset] = ((value >> 8) & 0x3F) | 0x40
        dst[offset + 1] = value & 0xFF
    elif length == 4:
        dst[offset] = ((value >> 24) & 0x3F) | 0x80
        dst[offset + 1] = (value >> 16) & 0xFF
        dst[offset + 2] = (value >> 8) & 0xFF
        dst[offset + 3] = value & 0xFF
    elif length == 8:
        dst[offset] = ((value >> 56) & 0x3F) | 0xC0
        dst[offset + 1] = (value >> 48) & 0xFF
        dst[offset + 2] = (value >> 40) & 0xFF
        dst[offset + 3] = (value >> 32) & 0xFF
        dst[offset + 4] = (value >> 24) & 0xFF
        dst[offset + 5] = (value >> 16) & 0xFF
        dst[offset + 6] = (value >> 8) & 0xFF
        dst[offset + 7] = value & 0xFF
    else:
        raise ValueError("unsupported varint length")


def pack_varint(value: int) -> Tuple[int, int]:
    """Return ``(packed, length)`` with encoded bytes packed little-endian."""

    length = varint_len(value)
    if length == 1:
        return value & 0xFF, 1
    if length == 2:
        return (((value >> 8) & 0x3F) | 0x40) | ((value & 0xFF) << 8), 2
    if length == 4:
        packed = (
                (((value >> 24) & 0x3F) | 0x80)
                | (((value >> 16) & 0xFF) << 8)
                | (((value >> 8) & 0xFF) << 16)
                | ((value & 0xFF) << 24)
        )
        return packed, 4
    packed = (
            (((value >> 56) & 0x3F) | 0xC0)
            | (((value >> 48) & 0xFF) << 8)
            | (((value >> 40) & 0xFF) << 16)
            | (((value >> 32) & 0xFF) << 24)
            | (((value >> 24) & 0xFF) << 32)
            | (((value >> 16) & 0xFF) << 40)
            | (((value >> 8) & 0xFF) << 48)
            | ((value & 0xFF) << 56)
    )
    return packed, 8


def append_packed_varint(dst: MutableSequence[int], packed: int, length: int) -> None:
    """Append a packed varint produced by :func:`pack_varint`."""

    packed = _require_int(packed, "packed varint")
    length = _require_int(length, "packed varint length")
    if length not in (1, 2, 4, 8):
        raise ValueError("unsupported packed varint length")
    if packed < 0 or packed >= (1 << (8 * length)):
        raise ValueError("packed varint out of range for length")
    encoded = packed.to_bytes(length, "little")
    if isinstance(dst, bytearray):
        dst.extend(encoded)
        return
    _extend_with_rollback(dst, encoded)


def parse_varint(data: bytes, offset: int = 0, limit: Optional[int] = None) -> Tuple[int, int]:
    """Parse one canonical varint62 from ``data``.

    Returns ``(value, length)``. ``offset`` and ``limit`` allow callers to parse
    inside a larger frame without slicing.
    """

    offset = _require_int(offset, "offset")
    if limit is None:
        limit = len(data)
    else:
        limit = _require_int(limit, "limit")
    if offset < 0:
        raise IndexError("offset < 0")
    if limit < offset or limit > len(data):
        raise IndexError("limit out of bounds")
    if offset >= limit:
        raise _wire_error(ERR_TRUNCATED_VARINT)

    first = data[offset] & 0xFF
    length = encoded_len_from_first(first)
    if length > limit - offset:
        raise _wire_error(ERR_TRUNCATED_VARINT)
    value = decode_varint_value(data, offset, length)
    return validate_decoded_varint(value, length)


def read_varint(reader: BinaryIO) -> Tuple[int, int]:
    """Read one canonical varint62 from a binary file-like object."""

    first = _read_exact(reader, 1)[0]
    length = encoded_len_from_first(first)
    if length == 1:
        return validate_decoded_varint(first & 0x3F, 1)
    tail = _read_exact(reader, length - 1)
    value = _decode_varint_value_from_parts(first, tail, length)
    return validate_decoded_varint(value, length)


def encoded_len_from_first(first: int) -> int:
    """Return encoded varint length from the first byte."""

    first = _require_int(first, "first byte")
    if first < 0 or first > 0xFF:
        raise ValueError("first byte out of range")
    return 1 << (first >> 6)


def decode_varint_value(data: bytes, offset: int, length: int) -> int:
    """Decode a varint value without canonical-length validation."""

    offset = _require_int(offset, "offset")
    length = _require_int(length, "varint length")
    if length not in (1, 2, 4, 8):
        raise _wire_error(ERR_TRUNCATED_VARINT)
    end = offset + length
    if offset < 0 or end > len(data):
        raise _wire_error(ERR_TRUNCATED_VARINT)
    first = data[offset] & 0x3F
    if length == 1:
        return first
    if length == 2:
        return (first << 8) | (data[offset + 1] & 0xFF)
    if length == 4:
        return (
                (first << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF)
        )
    return (
            (first << 56)
            | ((data[offset + 1] & 0xFF) << 48)
            | ((data[offset + 2] & 0xFF) << 40)
            | ((data[offset + 3] & 0xFF) << 32)
            | ((data[offset + 4] & 0xFF) << 24)
            | ((data[offset + 5] & 0xFF) << 16)
            | ((data[offset + 6] & 0xFF) << 8)
            | (data[offset + 7] & 0xFF)
    )


def _decode_varint_value_from_parts(first: int, tail: bytes, length: int) -> int:
    prefix = first & 0x3F
    if length == 2:
        return (prefix << 8) | (tail[0] & 0xFF)
    if length == 4:
        return (
                (prefix << 24)
                | ((tail[0] & 0xFF) << 16)
                | ((tail[1] & 0xFF) << 8)
                | (tail[2] & 0xFF)
        )
    return (
            (prefix << 56)
            | ((tail[0] & 0xFF) << 48)
            | ((tail[1] & 0xFF) << 40)
            | ((tail[2] & 0xFF) << 32)
            | ((tail[3] & 0xFF) << 24)
            | ((tail[4] & 0xFF) << 16)
            | ((tail[5] & 0xFF) << 8)
            | (tail[6] & 0xFF)
    )


def _extend_with_rollback(dst: MutableSequence[int], data: bytes) -> None:
    offset = len(dst)
    try:
        dst.extend(data)
    except Exception:
        try:
            del dst[offset:]
        except Exception:
            pass
        raise


def validate_decoded_varint(value: int, length: int) -> Tuple[int, int]:
    """Validate varint range and canonical length."""

    value = _require_int(value, "varint value")
    length = _require_int(length, "varint length")
    if value < 0 or value > MAX_VARINT62:
        raise _wire_error(ERR_VALUE_TOO_LARGE)
    if varint_len(value) != length:
        raise _wire_error(ERR_NON_CANONICAL_VARINT)
    return value, length


def _read_exact(reader: BinaryIO, size: int) -> bytes:
    if size <= 0:
        return b""

    chunks = None
    remaining = size
    while remaining:
        try:
            chunk = reader.read(remaining)
        except InterruptedError:
            continue
        except OSError as exc:
            raise _transport_read_error(exc) from exc
        if chunk is None:
            exc = BlockingIOError("non-blocking reader returned no data")
            raise _transport_read_error(exc) from exc
        view = _read_chunk_view(chunk)
        chunk_len = len(view)
        if chunk_len == 0:
            raise _wire_error(ERR_TRUNCATED_VARINT)
        if chunk_len > remaining:
            exc = OSError("reader returned more bytes than requested")
            raise _transport_read_error(exc) from exc
        if chunk_len == remaining and chunks is None and isinstance(chunk, bytes):
            return chunk
        chunk_bytes = view.tobytes()
        if chunk_len == remaining and chunks is None:
            return chunk_bytes
        if chunks is None:
            chunks = [chunk_bytes]
        else:
            chunks.append(chunk_bytes)
        remaining -= chunk_len
    return b"".join(chunks or ())


def _read_chunk_view(chunk: object) -> memoryview:
    if isinstance(chunk, (bool, int, str)):
        exc = OSError("reader returned non-bytes data")
        raise _transport_read_error(exc) from exc
    try:
        view = memoryview(chunk)
    except TypeError as exc:
        error = OSError("reader returned non-bytes data")
        raise _transport_read_error(error) from exc
    if (
            view.ndim == 1
            and view.itemsize == 1
            and view.format in ("B", "b", "c")
            and view.contiguous
    ):
        return view
    try:
        return view.cast("B")
    except (TypeError, ValueError) as exc:
        error = OSError("reader returned non-byte data")
        raise _transport_read_error(error) from exc


def _require_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value


def _wire_error(message: str) -> ProtocolError:
    return protocol_error(message, ErrorOperation.READ)


def _local_value_error(message: str) -> ProtocolError:
    return protocol_error(message, ErrorOperation.WRITE)


def _frame_size_error(message: str) -> ProtocolError:
    return frame_size_error(message, ErrorOperation.WRITE)


def _transport_read_error(error: OSError) -> TransportError:
    return TransportError(
        error,
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        direction=ErrorDirection.READ,
    )
