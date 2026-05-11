"""Frame envelope codec and validation."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import BinaryIO, Optional

from .errors import (
    ERR_INVALID_FLAGS,
    ERR_INVALID_FRAME_TYPE,
    ERR_PAYLOAD_TOO_LARGE,
    ERR_SHORT_FRAME,
    ERR_TRUNCATED_VARINT,
    frame_size_error,
    protocol_error,
)
from .tlv import validate_tlvs
from .varint import (
    append_packed_varint,
    append_varint,
    encoded_len_from_first,
    parse_varint,
    varint_len,
)
from ..config import Limits
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    FrameSizeError,
    ProtocolError,
    TransportError,
)
from ..frame import Frame, FrameView
from ..protocol import (
    EXT_PRIORITY_UPDATE,
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    MAX_VARINT62,
    FrameType,
)

MAX_INBOUND_FRAME_HEADER_OVERHEAD = 9
MAX_FRAME_HEADER_LEN = 17
FRAME_FLAG_OPEN_METADATA_FIN = FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN
_DATA_ALLOWED_FLAGS_MASK = FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN
_STREAM_ID_REQUIRED_TYPES = frozenset(
    (
        FrameType.DATA,
        FrameType.STOP_SENDING,
        FrameType.RESET,
        FrameType.ABORT,
    )
)
_STREAM_ID_ZERO_TYPES = frozenset(
    (
        FrameType.PING,
        FrameType.PONG,
        FrameType.GOAWAY,
        FrameType.CLOSE,
    )
)

__all__ = (
    "FRAME_FLAG_OPEN_METADATA_FIN",
    "MAX_FRAME_HEADER_LEN",
    "MAX_INBOUND_FRAME_HEADER_OVERHEAD",
    "append_frame",
    "append_frame_header_trusted",
    "append_frame_header_trusted_cached_stream_id",
    "frame_length_for_payload",
    "frame_total_len",
    "inbound_payload_limit",
    "marshal_frame",
    "max_inbound_frame_len",
    "normalize_limits",
    "parse_frame",
    "parse_frame_view",
    "read_frame",
    "validate_data_payload",
    "validate_error_and_diag_payload",
    "validate_exact_one_varint_payload",
    "validate_ext_payload",
    "validate_frame",
    "validate_frame_envelope",
    "validate_frame_flags",
    "validate_frame_parts",
    "validate_frame_scope",
    "validate_frame_view",
    "validate_go_away_payload",
)


def marshal_frame(frame: Frame) -> bytes:
    """Encode one frame into bytes."""

    out = bytearray()
    append_frame(out, frame)
    return bytes(out)


def append_frame(dst: MutableSequence[int], frame: Frame) -> None:
    """Append encoded ``frame`` to ``dst`` without partial writes on failure."""

    start = len(dst)
    try:
        validate_frame(frame, normalize_limits(None), False)
        append_frame_header_trusted(dst, frame.code(), frame.stream_id, len(frame.payload))
        dst.extend(frame.payload)
    except Exception:
        del dst[start:]
        raise


def append_frame_header_trusted(
        dst: MutableSequence[int],
        code: int,
        stream_id: int,
        payload_len: int,
) -> None:
    """Append a validated frame header."""

    stream_len = varint_len(stream_id)
    frame_len = frame_length_for_payload(stream_len, payload_len)
    append_varint(dst, frame_len)
    dst.append(code & 0xFF)
    append_varint(dst, stream_id)


def append_frame_header_trusted_cached_stream_id(
        dst: MutableSequence[int],
        code: int,
        stream_id: int,
        packed_stream_id: int,
        stream_id_len: int,
        payload_len: int,
) -> None:
    """Append a frame header using a cached packed stream-id when available."""

    if stream_id_len == 0:
        append_frame_header_trusted(dst, code, stream_id, payload_len)
        return
    frame_len = frame_length_for_payload(stream_id_len, payload_len)
    append_varint(dst, frame_len)
    dst.append(code & 0xFF)
    append_packed_varint(dst, packed_stream_id, stream_id_len)


def frame_length_for_payload(stream_id_len: int, payload_len: int) -> int:
    """Return frame body length for an encoded stream-id length and payload."""

    stream_id_len = _require_int(stream_id_len, "stream_id_len")
    payload_len = _require_int(payload_len, "payload_len")
    if stream_id_len <= 0 or stream_id_len > MAX_INBOUND_FRAME_HEADER_OVERHEAD - 1:
        raise _frame_size_write(ERR_PAYLOAD_TOO_LARGE)
    if payload_len < 0:
        raise _frame_size_write(ERR_PAYLOAD_TOO_LARGE)
    header_len = 1 + stream_id_len
    if payload_len > MAX_VARINT62 - header_len:
        raise _frame_size_write(ERR_PAYLOAD_TOO_LARGE)
    return header_len + payload_len


def parse_frame(src: bytes, limits: Optional[Limits] = None) -> tuple[Frame, int]:
    """Parse and copy one complete frame from ``src``."""

    view, consumed = parse_frame_view(src, limits)
    return view.to_owned(), consumed


def parse_frame_view(
        src: bytes,
        limits: Optional[Limits] = None,
) -> tuple[FrameView, int]:
    """Parse one frame and return a payload view into ``src``."""

    limits = normalize_limits(limits)
    frame_len, n_len = parse_varint(src)
    if frame_len < 2:
        raise _frame_size_read(ERR_SHORT_FRAME)
    if len(src) < n_len + 1:
        raise _frame_size_read("truncated frame")

    code = src[n_len]
    frame_type = _parse_frame_type(code & 0x1F)
    flags = code & 0xE0
    stream_start = n_len + 1
    if len(src) < stream_start + 1:
        raise _frame_size_read("truncated frame")
    stream_len = encoded_len_from_first(src[stream_start])
    if frame_len < 1 + stream_len:
        raise _frame_size_read(ERR_SHORT_FRAME)
    stream_end = stream_start + stream_len
    if len(src) < stream_end:
        raise _frame_size_read("truncated frame")

    stream_id, consumed = parse_varint(src, stream_start, stream_end)
    if consumed != stream_len:
        raise _protocol_read("invalid stream_id")

    payload_len = frame_len - 1 - stream_len
    if payload_len > inbound_payload_limit(frame_type, limits):
        raise _frame_size_read(ERR_PAYLOAD_TOO_LARGE)
    total = frame_total_len(frame_len, n_len)
    if total > len(src):
        raise _frame_size_read("truncated frame")

    payload = memoryview(src)[stream_end:total]
    frame = FrameView(frame_type, stream_id, flags, payload)
    validate_frame_view(frame, limits, True)
    return frame, total


def read_frame(reader: BinaryIO, limits: Optional[Limits] = None) -> Frame:
    """Read and parse one complete frame from a binary stream."""

    limits = normalize_limits(limits)
    frame_len = _read_frame_length(reader)
    if frame_len < 2:
        raise _frame_size_read(ERR_SHORT_FRAME)
    if frame_len > max_inbound_frame_len(limits):
        raise _frame_size_read(ERR_PAYLOAD_TOO_LARGE)
    code = _read_exact(reader, 1, "truncated frame")[0]
    frame_type = _parse_frame_type(code & 0x1F)
    flags = code & 0xE0
    first_stream = _read_exact(reader, 1, "truncated frame")[0]
    stream_len = encoded_len_from_first(first_stream)
    if frame_len < 1 + stream_len:
        raise _frame_size_read(ERR_SHORT_FRAME)

    stream_raw = bytearray(stream_len)
    stream_raw[0] = first_stream
    if stream_len > 1:
        stream_raw[1:] = _read_exact(reader, stream_len - 1, "truncated frame")
    stream_id, consumed = parse_varint(stream_raw)
    if consumed != stream_len:
        raise _protocol_read("invalid stream_id")

    payload_len = frame_len - 1 - stream_len
    if payload_len > inbound_payload_limit(frame_type, limits):
        raise _frame_size_read(ERR_PAYLOAD_TOO_LARGE)
    frame = Frame(
        frame_type,
        stream_id,
        flags,
        _read_exact(reader, payload_len, "truncated frame"),
    )
    validate_frame(frame, limits, True)
    return frame


def validate_frame(
        frame: Frame, limits: Optional[Limits] = None, inbound: bool = False
) -> None:
    """Validate a frame envelope and frame-type-specific payload."""

    validate_frame_parts(
        frame.frame_type,
        frame.flags,
        frame.stream_id,
        frame.payload,
        normalize_limits(limits),
        inbound,
    )


def validate_frame_view(
        frame: FrameView, limits: Optional[Limits] = None, inbound: bool = False
) -> None:
    """Validate a borrowed frame view."""

    validate_frame_parts(
        frame.frame_type,
        frame.flags,
        frame.stream_id,
        frame.payload,
        normalize_limits(limits),
        inbound,
    )


def validate_frame_parts(
        frame_type: FrameType,
        flags: int,
        stream_id: int,
        payload: bytes,
        limits: Limits,
        inbound: bool,
) -> None:
    validate_frame_envelope(frame_type, flags, stream_id, payload, limits, inbound)

    if frame_type == FrameType.DATA:
        validate_data_payload(payload, flags)
    elif frame_type in (FrameType.MAX_DATA, FrameType.BLOCKED):
        validate_exact_one_varint_payload(frame_type, payload)
    elif frame_type in (FrameType.PING, FrameType.PONG):
        if len(payload) < 8:
            raise _frame_size_read("ping/pong payload too short")
    elif frame_type in (
            FrameType.STOP_SENDING,
            FrameType.RESET,
            FrameType.ABORT,
            FrameType.CLOSE,
    ):
        validate_error_and_diag_payload(frame_type, payload)
    elif frame_type == FrameType.GOAWAY:
        validate_go_away_payload(payload)
    elif frame_type == FrameType.EXT:
        validate_ext_payload(stream_id, payload)
    else:
        raise _protocol_read(ERR_INVALID_FRAME_TYPE)


def validate_frame_envelope(
        frame_type: FrameType,
        flags: int,
        stream_id: int,
        payload: bytes,
        limits: Limits,
        inbound: bool,
) -> None:
    validate_frame_flags(frame_type, flags)
    validate_frame_scope(frame_type, stream_id)
    if inbound and len(payload) > inbound_payload_limit(frame_type, limits):
        raise _frame_size_read(ERR_PAYLOAD_TOO_LARGE)


def validate_frame_flags(frame_type: FrameType, flags: int) -> None:
    if frame_type != FrameType.DATA:
        if flags == 0:
            return
        raise _protocol_read(ERR_INVALID_FLAGS)
    if flags & ~_DATA_ALLOWED_FLAGS_MASK == 0:
        return
    raise _protocol_read(ERR_INVALID_FLAGS)


def validate_frame_scope(frame_type: FrameType, stream_id: int) -> None:
    if frame_type in _STREAM_ID_REQUIRED_TYPES and stream_id == 0:
        raise _protocol_read("%s requires non-zero stream_id" % frame_type)
    if frame_type in _STREAM_ID_ZERO_TYPES and stream_id != 0:
        raise _protocol_read("%s requires stream_id = 0" % frame_type)


def validate_data_payload(payload: bytes, flags: int) -> None:
    if flags & FRAME_FLAG_OPEN_METADATA == 0:
        return
    payload_view = memoryview(payload)
    try:
        metadata_len, consumed = parse_varint(payload_view)
    except ProtocolError as exc:
        raise _frame_size_read("invalid OPEN_METADATA length: %s" % exc)
    if metadata_len > len(payload_view) - consumed:
        raise _frame_size_read("OPEN_METADATA payload overrun")
    try:
        validate_tlvs(payload_view[consumed: consumed + metadata_len])
    except ProtocolError as exc:
        raise _frame_size_read("invalid OPEN_METADATA payload: %s" % exc)


def validate_exact_one_varint_payload(frame_type: FrameType, payload: bytes) -> None:
    try:
        _, consumed = parse_varint(payload)
    except ProtocolError as exc:
        raise _frame_size_read("invalid %s payload: %s" % (frame_type, exc))
    if consumed != len(payload):
        raise _protocol_read("%s payload has trailing bytes" % frame_type)


def validate_error_and_diag_payload(frame_type: FrameType, payload: bytes) -> None:
    payload_view = memoryview(payload)
    try:
        _, consumed = parse_varint(payload_view)
    except ProtocolError as exc:
        raise _frame_size_read("invalid %s payload: %s" % (frame_type, exc))
    try:
        validate_tlvs(payload_view[consumed:])
    except ProtocolError as exc:
        raise _frame_size_read("invalid %s diagnostic payload: %s" % (frame_type, exc))


def validate_go_away_payload(payload: bytes) -> None:
    payload_view = memoryview(payload)
    offset = 0
    for _ in range(3):
        try:
            _, consumed = parse_varint(payload_view, offset, len(payload_view))
        except ProtocolError as exc:
            raise _frame_size_read("malformed GOAWAY payload: %s" % exc)
        offset += consumed
    try:
        validate_tlvs(payload_view[offset:])
    except ProtocolError as exc:
        raise _frame_size_read("malformed GOAWAY diagnostics: %s" % exc)


def validate_ext_payload(stream_id: int, payload: bytes) -> None:
    payload_view = memoryview(payload)
    try:
        ext_type, consumed = parse_varint(payload_view)
    except ProtocolError as exc:
        raise _frame_size_read("malformed EXT payload: %s" % exc)
    if ext_type == EXT_PRIORITY_UPDATE:
        if stream_id == 0:
            raise _protocol_read("PRIORITY_UPDATE requires non-zero stream_id")
        try:
            from .payload import parse_priority_update_metadata

            parse_priority_update_metadata(payload_view[consumed:])
        except ProtocolError as exc:
            raise _frame_size_read("malformed PRIORITY_UPDATE payload: %s" % exc)


def normalize_limits(limits: Optional[Limits]) -> Limits:
    """Replace zero limit fields with repository defaults."""

    defaults = Limits()
    if limits is None:
        return defaults
    return Limits(
        max_frame_payload=limits.max_frame_payload or defaults.max_frame_payload,
        max_control_payload_bytes=limits.max_control_payload_bytes
                                  or defaults.max_control_payload_bytes,
        max_extension_payload_bytes=limits.max_extension_payload_bytes
                                    or defaults.max_extension_payload_bytes,
    )


def inbound_payload_limit(frame_type: FrameType, limits: Limits) -> int:
    if frame_type == FrameType.DATA:
        return limits.max_frame_payload
    if frame_type == FrameType.EXT:
        return limits.max_extension_payload_bytes
    return limits.max_control_payload_bytes


def max_inbound_frame_len(limits: Limits) -> int:
    max_payload = max(
        limits.max_frame_payload,
        limits.max_control_payload_bytes,
        limits.max_extension_payload_bytes,
    )
    if max_payload > MAX_VARINT62 - MAX_INBOUND_FRAME_HEADER_OVERHEAD:
        return MAX_VARINT62
    return max_payload + MAX_INBOUND_FRAME_HEADER_OVERHEAD


def frame_total_len(frame_len: int, frame_len_prefix_len: int) -> int:
    frame_len = _require_int(frame_len, "frame_len")
    frame_len_prefix_len = _require_int(frame_len_prefix_len, "frame_len_prefix_len")
    if frame_len < 0 or frame_len_prefix_len < 0:
        raise _frame_size_read(ERR_PAYLOAD_TOO_LARGE)
    return frame_len_prefix_len + frame_len


def _parse_frame_type(code: int) -> FrameType:
    try:
        return FrameType.from_code(code)
    except ValueError:
        raise _protocol_read(ERR_INVALID_FRAME_TYPE)


def _read_frame_length(reader: BinaryIO) -> int:
    first = _read_first_frame_length_byte(reader)
    if first is None:
        exc = EOFError("unexpected EOF while reading frame length")
        raise _transport_read_error(exc) from exc
    length = encoded_len_from_first(first)
    if length == 1:
        frame_len, _ = parse_varint(bytes((first,)))
        return frame_len
    raw = bytearray(length)
    raw[0] = first
    raw[1:] = _read_exact(reader, length - 1, ERR_TRUNCATED_VARINT)
    frame_len, _ = parse_varint(raw)
    return frame_len


def _read_first_frame_length_byte(reader: BinaryIO) -> Optional[int]:
    readinto = getattr(reader, "readinto", None)
    if readinto is not None:
        buf = bytearray(1)
        view = memoryview(buf)
        while True:
            try:
                n = readinto(view)
            except InterruptedError:
                continue
            except OSError as exc:
                raise _transport_read_error(exc) from exc
            if n is None:
                exc = BlockingIOError("non-blocking reader returned no data")
                raise _transport_read_error(exc) from exc
            n = _validate_readinto_progress(n, 1)
            if n == 0:
                return None
            if n == 1:
                return buf[0]
            exc = OSError("reader returned invalid byte count")
            raise _transport_read_error(exc) from exc

    while True:
        try:
            chunk = reader.read(1)
        except InterruptedError:
            continue
        except OSError as exc:
            raise _transport_read_error(exc) from exc
        if chunk is None:
            exc = BlockingIOError("non-blocking reader returned no data")
            raise _transport_read_error(exc) from exc
        if chunk == b"":
            return None
        if len(chunk) != 1:
            exc = OSError("reader returned more bytes than requested")
            raise _transport_read_error(exc) from exc
        return memoryview(chunk)[0]


def _read_exact(reader: BinaryIO, size: int, truncated_message: str) -> bytes:
    if size == 0:
        return b""
    readinto = getattr(reader, "readinto", None)
    if readinto is not None:
        out = bytearray(size)
        view = memoryview(out)
        offset = 0
        while offset < size:
            try:
                n = readinto(view[offset:])
            except InterruptedError:
                continue
            except OSError as exc:
                raise _transport_read_error(exc) from exc
            if n is None:
                exc = BlockingIOError("non-blocking reader returned no data")
                raise _transport_read_error(exc) from exc
            n = _validate_readinto_progress(n, size - offset)
            if n == 0:
                raise _protocol_read(truncated_message)
            offset += n
        return bytes(out)

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
        if chunk == b"":
            raise _protocol_read(truncated_message)
        if len(chunk) > remaining:
            exc = OSError("reader returned more bytes than requested")
            raise _transport_read_error(exc) from exc
        if len(chunk) == remaining:
            return bytes(chunk)
        chunks = [chunk]
        remaining -= len(chunk)
        break

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
        if chunk == b"":
            raise _protocol_read(truncated_message)
        if len(chunk) > remaining:
            exc = OSError("reader returned more bytes than requested")
            raise _transport_read_error(exc) from exc
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _protocol_read(message: str) -> ProtocolError:
    return protocol_error(message, ErrorOperation.READ)


def _frame_size_read(message: str) -> FrameSizeError:
    return frame_size_error(message, ErrorOperation.READ)


def _frame_size_write(message: str) -> FrameSizeError:
    return frame_size_error(message, ErrorOperation.WRITE)


def _transport_read_error(error: BaseException) -> TransportError:
    return TransportError(
        error,
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        direction=ErrorDirection.READ,
    )


def _validate_readinto_progress(value, requested: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        exc = OSError("reader returned invalid byte count")
        raise _transport_read_error(exc) from exc
    if value < 0 or value > requested:
        exc = OSError("reader returned invalid byte count")
        raise _transport_read_error(exc) from exc
    return value


def _require_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    return value
