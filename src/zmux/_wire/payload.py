"""Frame payload builders and parsers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from .tlv import Tlv, append_tlv, iter_tlvs_view, parse_tlvs
from .varint import append_varint, encode_varint_into, parse_varint, parse_varints, varint_len
from .._buffers import byte_view
from .._validation import require_varint62
from ..errors import (
    EMPTY_METADATA_UPDATE_MESSAGE,
    OPEN_INFO_UNAVAILABLE_MESSAGE,
    OPEN_METADATA_TOO_LARGE_MESSAGE,
    PRIORITY_UPDATE_TOO_LARGE_MESSAGE,
    PRIORITY_UPDATE_UNAVAILABLE_MESSAGE,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    ProtocolError,
)
from ..payload import (
    DataPayload,
    DataPayloadView,
    GoAwayPayload,
    MetadataUpdate,
    StreamMetadata,
    StreamMetadataView,
)
from ..protocol import (
    CAPABILITY_OPEN_METADATA,
    DIAG_DEBUG_TEXT,
    DIAG_OFFENDING_FRAME_TYPE,
    DIAG_OFFENDING_STREAM_ID,
    DIAG_RETRY_AFTER_MILLIS,
    EXT_PRIORITY_UPDATE,
    FRAME_FLAG_OPEN_METADATA,
    MAX_VARINT62,
    METADATA_OPEN_INFO,
    METADATA_STREAM_GROUP,
    METADATA_STREAM_PRIORITY,
    ErrorCode,
    capabilities_can_carry_group_in_update,
    capabilities_can_carry_group_on_open,
    capabilities_can_carry_open_info,
    capabilities_can_carry_priority_in_update,
    capabilities_can_carry_priority_on_open,
    has_capability,
)

_SEEN_METADATA_PRIORITY = 1 << 0
_SEEN_METADATA_GROUP = 1 << 1
_SEEN_METADATA_OPEN_INFO = 1 << 2
_SEEN_DIAG_DEBUG_TEXT = 1 << 0
_SEEN_DIAG_RETRY_AFTER_MILLIS = 1 << 1
_SEEN_DIAG_OFFENDING_STREAM_ID = 1 << 2
_SEEN_DIAG_OFFENDING_FRAME_TYPE = 1 << 3

__all__ = (
    "append_debug_text_tlv",
    "append_debug_text_tlv_capped",
    "append_metadata_varint_tlv",
    "build_error_payload",
    "build_go_away_payload",
    "build_go_away_payload_capped",
    "build_open_metadata_prefix",
    "build_priority_update_payload",
    "capped_debug_text_value_len",
    "metadata_bytes_tlv_len",
    "metadata_varint_tlv_len",
    "parse_data_payload",
    "parse_data_payload_metadata_offset",
    "parse_data_payload_view",
    "parse_diag_reason",
    "parse_error_payload",
    "parse_go_away_payload",
    "parse_metadata_varint",
    "parse_priority_update_metadata",
    "parse_priority_update_payload",
    "parse_stream_metadata_bytes_view",
    "parse_stream_metadata_tlvs",
    "parse_stream_metadata_tlvs_view",
)


def build_open_metadata_prefix(
        capabilities: int,
        priority: Optional[int] = None,
        group: Optional[int] = None,
        open_info: bytes = b"",
        max_frame_payload: int = 16384,
) -> bytes:
    """Build the DATA payload prefix carrying open metadata."""

    max_frame_payload = _require_payload_limit(max_frame_payload, "max_frame_payload")
    open_info_view = _as_byte_view(open_info)
    if open_info_view and not capabilities_can_carry_open_info(capabilities):
        raise _stream_open_error(OPEN_INFO_UNAVAILABLE_MESSAGE)
    if not has_capability(capabilities, CAPABILITY_OPEN_METADATA):
        return b""

    include_priority = priority is not None and capabilities_can_carry_priority_on_open(
        capabilities
    )
    include_group = group is not None and capabilities_can_carry_group_on_open(
        capabilities
    )
    include_open_info = bool(open_info_view)

    metadata_len = 0
    if include_priority:
        metadata_len += metadata_varint_tlv_len(METADATA_STREAM_PRIORITY, priority)
    if include_group:
        metadata_len += metadata_varint_tlv_len(METADATA_STREAM_GROUP, group)
    if include_open_info:
        metadata_len += metadata_bytes_tlv_len(METADATA_OPEN_INFO, len(open_info_view))
    if metadata_len == 0:
        return b""

    total_len = varint_len(metadata_len) + metadata_len
    if total_len > max_frame_payload:
        raise _stream_open_error(OPEN_METADATA_TOO_LARGE_MESSAGE)

    out = bytearray(total_len)
    offset = _write_varint(out, 0, metadata_len)
    if include_priority:
        offset = _write_metadata_varint_tlv(out, offset, METADATA_STREAM_PRIORITY, priority)
    if include_group:
        offset = _write_metadata_varint_tlv(out, offset, METADATA_STREAM_GROUP, group)
    if include_open_info:
        offset = _write_bytes_tlv(out, offset, METADATA_OPEN_INFO, open_info_view)
    if offset != total_len:
        raise AssertionError("open metadata payload length mismatch")
    return bytes(out)


def build_priority_update_payload(
        capabilities: int,
        update: MetadataUpdate,
        max_payload: int,
) -> bytes:
    """Build an EXT PRIORITY_UPDATE payload."""

    max_payload = _require_payload_limit(max_payload, "max_payload")
    if update.is_empty():
        raise _session_write_error(EMPTY_METADATA_UPDATE_MESSAGE, local=True)

    total_len = varint_len(EXT_PRIORITY_UPDATE)
    if update.priority is not None:
        if not capabilities_can_carry_priority_in_update(capabilities):
            raise _metadata_update_capability_error()
        total_len += metadata_varint_tlv_len(METADATA_STREAM_PRIORITY, update.priority)
    if update.group is not None:
        if not capabilities_can_carry_group_in_update(capabilities):
            raise _metadata_update_capability_error()
        total_len += metadata_varint_tlv_len(METADATA_STREAM_GROUP, update.group)
    if total_len > max_payload:
        raise _session_write_error(PRIORITY_UPDATE_TOO_LARGE_MESSAGE, local=True)

    out = bytearray(total_len)
    offset = _write_varint(out, 0, EXT_PRIORITY_UPDATE)
    if update.priority is not None:
        offset = _write_metadata_varint_tlv(
            out, offset, METADATA_STREAM_PRIORITY, update.priority
        )
    if update.group is not None:
        offset = _write_metadata_varint_tlv(out, offset, METADATA_STREAM_GROUP, update.group)
    if offset != total_len:
        raise AssertionError("priority update payload length mismatch")
    return bytes(out)


def parse_priority_update_payload(payload: bytes) -> tuple[StreamMetadata, bool]:
    """Parse a full EXT PRIORITY_UPDATE payload including subtype."""

    payload_view = memoryview(payload)
    subtype, consumed = parse_varint(payload_view)
    if subtype != EXT_PRIORITY_UPDATE:
        return StreamMetadata(), False
    return parse_priority_update_metadata(payload_view[consumed:])


def parse_priority_update_metadata(payload: bytes) -> tuple[StreamMetadata, bool]:
    """Parse PRIORITY_UPDATE metadata TLVs after the subtype."""

    priority = None
    group = None
    seen = 0
    for tlv in iter_tlvs_view(payload):
        if tlv.typ == METADATA_STREAM_PRIORITY:
            if seen & _SEEN_METADATA_PRIORITY:
                return StreamMetadata(), False
            seen |= _SEEN_METADATA_PRIORITY
            priority = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_STREAM_GROUP:
            if seen & _SEEN_METADATA_GROUP:
                return StreamMetadata(), False
            seen |= _SEEN_METADATA_GROUP
            group = parse_metadata_varint(tlv.value)
    return StreamMetadata(priority, group), True


def parse_data_payload(payload: bytes, flags: int) -> DataPayload:
    """Parse DATA payload metadata and application bytes."""

    payload_view = memoryview(payload)
    if flags & FRAME_FLAG_OPEN_METADATA == 0:
        return DataPayload(app_data=payload_view.tobytes())

    metadata_len, consumed = parse_varint(payload_view)
    if metadata_len > len(payload_view) - consumed:
        raise _frame_size_payload_error("OPEN_METADATA payload overrun")
    metadata_raw = payload_view[consumed: consumed + metadata_len]
    app_data = payload_view[consumed + metadata_len:].tobytes()
    tlvs = parse_tlvs(metadata_raw)
    metadata, valid = parse_stream_metadata_tlvs(tlvs)
    if not valid:
        return DataPayload(app_data=app_data, has_metadata=True, metadata_valid=False)
    return DataPayload(
        metadata_tlvs=tlvs,
        has_metadata=True,
        metadata=metadata,
        open_info=metadata.open_info,
        app_data=app_data,
        metadata_valid=True,
    )


def parse_data_payload_view(payload: bytes, flags: int) -> DataPayloadView:
    """Parse DATA payload without copying application data or open info."""

    payload_view = memoryview(payload)
    if flags & FRAME_FLAG_OPEN_METADATA == 0:
        return DataPayloadView(app_data=payload_view)

    metadata_len, consumed = parse_varint(payload_view)
    if metadata_len > len(payload_view) - consumed:
        raise _frame_size_payload_error("OPEN_METADATA payload overrun")
    metadata_raw = payload_view[consumed: consumed + metadata_len]
    app_data = payload_view[consumed + metadata_len:]
    metadata, valid = parse_stream_metadata_bytes_view(metadata_raw)
    if not valid:
        return DataPayloadView(app_data=app_data, has_metadata=True, metadata_valid=False)
    return DataPayloadView(
        metadata=metadata,
        app_data=app_data,
        has_metadata=True,
        metadata_valid=True,
    )


def parse_data_payload_metadata_offset(
        payload: bytes, flags: int
) -> tuple[StreamMetadata, bool, int]:
    """Parse DATA metadata and return the application-data byte offset."""

    payload_view = memoryview(payload)
    if flags & FRAME_FLAG_OPEN_METADATA == 0:
        return StreamMetadata(), True, 0

    metadata_len, consumed = parse_varint(payload_view)
    if metadata_len > len(payload_view) - consumed:
        raise _frame_size_payload_error("OPEN_METADATA payload overrun")
    metadata_raw = payload_view[consumed: consumed + metadata_len]
    metadata, valid = parse_stream_metadata_bytes_view(metadata_raw)
    return metadata.to_owned(), valid, consumed + metadata_len


def parse_stream_metadata_tlvs(tlvs: Iterable[Tlv]) -> tuple[StreamMetadata, bool]:
    """Parse stream metadata TLVs; duplicate singleton fields mark invalid."""

    priority = None
    group = None
    open_info = b""
    seen = 0
    for tlv in tlvs:
        seen_bit = _metadata_singleton_seen_bit(tlv.typ)
        if seen_bit:
            if seen & seen_bit:
                return StreamMetadata(), False
            seen |= seen_bit

        if tlv.typ == METADATA_STREAM_PRIORITY:
            priority = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_STREAM_GROUP:
            group = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_OPEN_INFO:
            open_info = bytes(tlv.value)
    return StreamMetadata(priority, group, open_info), True


def parse_stream_metadata_tlvs_view(
        tlvs: Iterable[Tlv],
) -> tuple[StreamMetadataView, bool]:
    """Parse pre-decoded stream metadata TLVs and retain value views."""

    priority = None
    group = None
    open_info = memoryview(b"")
    seen = 0
    for tlv in tlvs:
        seen_bit = _metadata_singleton_seen_bit(tlv.typ)
        if seen_bit:
            if seen & seen_bit:
                return StreamMetadataView(), False
            seen |= seen_bit

        if tlv.typ == METADATA_STREAM_PRIORITY:
            priority = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_STREAM_GROUP:
            group = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_OPEN_INFO:
            open_info = memoryview(tlv.value)
    return StreamMetadataView(priority, group, open_info), True


def parse_stream_metadata_bytes_view(payload: bytes) -> tuple[StreamMetadataView, bool]:
    """Parse encoded stream metadata TLVs lazily and retain value views."""

    priority = None
    group = None
    open_info = memoryview(b"")
    seen = 0
    for tlv in iter_tlvs_view(payload):
        seen_bit = _metadata_singleton_seen_bit(tlv.typ)
        if seen_bit:
            if seen & seen_bit:
                return StreamMetadataView(), False
            seen |= seen_bit

        if tlv.typ == METADATA_STREAM_PRIORITY:
            priority = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_STREAM_GROUP:
            group = parse_metadata_varint(tlv.value)
        elif tlv.typ == METADATA_OPEN_INFO:
            open_info = tlv.value
    return StreamMetadataView(priority, group, open_info), True


def parse_metadata_varint(value: bytes) -> int:
    """Parse a metadata value that must be exactly one varint."""

    parsed, consumed = parse_varint(value)
    if consumed != len(value):
        raise _session_read_error("tlv value overruns containing payload")
    return parsed


def append_metadata_varint_tlv(dst: bytearray, typ: int, value: int) -> None:
    value_len = varint_len(value)
    append_varint(dst, typ)
    append_varint(dst, value_len)
    append_varint(dst, value)


def metadata_varint_tlv_len(typ: int, value: int) -> int:
    value_len = varint_len(value)
    return varint_len(typ) + varint_len(value_len) + value_len


def metadata_bytes_tlv_len(typ: int, value_len: int) -> int:
    return varint_len(typ) + varint_len(value_len) + value_len


def _write_metadata_varint_tlv(
        dst: bytearray, offset: int, typ: int, value: int
) -> int:
    value_len = varint_len(value)
    offset = _write_varint(dst, offset, typ)
    offset = _write_varint(dst, offset, value_len)
    return _write_varint(dst, offset, value)


def _write_bytes_tlv(dst: bytearray, offset: int, typ: int, value: memoryview) -> int:
    offset = _write_varint(dst, offset, typ)
    offset = _write_varint(dst, offset, len(value))
    end = offset + len(value)
    dst[offset:end] = value
    return end


def _write_varint(dst: bytearray, offset: int, value: int) -> int:
    return offset + encode_varint_into(dst, offset, value)


def build_go_away_payload(
        last_accepted_bidi: int,
        last_accepted_uni: int,
        code: int,
        reason: str = "",
) -> bytes:
    out = bytearray()
    append_varint(out, last_accepted_bidi)
    append_varint(out, last_accepted_uni)
    append_varint(out, code)
    append_debug_text_tlv(out, reason)
    return bytes(out)


def build_go_away_payload_capped(
        last_accepted_bidi: int,
        last_accepted_uni: int,
        code: int,
        reason: str,
        max_payload: int,
) -> bytes:
    max_payload = _require_payload_limit(max_payload, "max_payload")
    out = bytearray()
    append_varint(out, last_accepted_bidi)
    append_varint(out, last_accepted_uni)
    append_varint(out, code)
    append_debug_text_tlv_capped(out, reason, max_payload)
    return bytes(out)


def parse_go_away_payload(payload: bytes) -> GoAwayPayload:
    payload_view = memoryview(payload)
    (last_accepted_bidi, last_accepted_uni, code), offset = parse_varints(
        payload_view, 0, len(payload_view), 3
    )
    return GoAwayPayload(
        last_accepted_bidi=last_accepted_bidi,
        last_accepted_uni=last_accepted_uni,
        code=code,
        reason=parse_diag_reason(payload_view[offset:]),
    )


def build_error_payload(code: int, reason: str = "", max_payload: int = 4096) -> bytes:
    max_payload = _require_payload_limit(max_payload, "max_payload")
    out = bytearray()
    append_varint(out, code)
    append_debug_text_tlv_capped(out, reason, max_payload)
    return bytes(out)


def parse_error_payload(payload: bytes) -> tuple[int, str]:
    payload_view = memoryview(payload)
    code, consumed = parse_varint(payload_view)
    return code, parse_diag_reason(payload_view[consumed:])


def parse_diag_reason(payload: bytes) -> str:
    seen = 0
    debug_text = None
    for tlv in iter_tlvs_view(payload):
        seen_bit = _diag_singleton_seen_bit(tlv.typ)
        if not seen_bit:
            continue
        if seen & seen_bit:
            return ""
        seen |= seen_bit
        if tlv.typ == DIAG_DEBUG_TEXT:
            debug_text = tlv.value.tobytes()
    if not debug_text:
        return ""
    try:
        return debug_text.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def append_debug_text_tlv(dst: bytearray, reason: str) -> None:
    value = _debug_text_bytes(reason)
    if value:
        append_tlv(dst, DIAG_DEBUG_TEXT, value)


def append_debug_text_tlv_capped(dst: bytearray, reason: str, max_payload: int) -> None:
    max_payload = _require_payload_limit(max_payload, "max_payload")
    if reason is None:
        return
    if not isinstance(reason, str):
        raise TypeError("diagnostic reason must be a string")
    if not reason or len(dst) >= max_payload:
        return
    remaining = max_payload - len(dst)
    encoded = _debug_text_bytes(reason)
    value_len = capped_debug_text_value_len(encoded, remaining)
    if value_len <= 0:
        return
    value = _utf8_prefix(encoded, value_len)
    if value:
        append_tlv(dst, DIAG_DEBUG_TEXT, value)


def _debug_text_bytes(reason: str) -> bytes:
    if reason is None:
        return b""
    if not isinstance(reason, str):
        raise TypeError("diagnostic reason must be a string")
    if not reason:
        return b""
    try:
        return reason.encode("utf-8")
    except UnicodeEncodeError:
        return b""


def capped_debug_text_value_len(encoded_reason: bytes, remaining: int) -> int:
    if not encoded_reason:
        return 0
    type_len = varint_len(DIAG_DEBUG_TEXT)
    if remaining <= type_len:
        return 0
    available = remaining - type_len
    high = min(len(encoded_reason), available, MAX_VARINT62)
    low = 0
    while low < high:
        mid = low + ((high - low + 1) // 2)
        if mid + varint_len(mid) <= available:
            low = mid
        else:
            high = mid - 1
    return low


def _utf8_prefix(data: bytes, length: int) -> bytes:
    length = min(length, len(data))
    if length <= 0:
        return b""
    if length >= len(data):
        return data
    while length > 0 and _is_utf8_continuation(data[length]):
        length -= 1
    if length <= 0:
        return b""
    return data[:length]


def _is_utf8_continuation(value: int) -> bool:
    return value & 0xC0 == 0x80


def _as_byte_view(value: bytes) -> memoryview:
    if value is None:
        return memoryview(b"")
    return byte_view(value)


def _require_payload_limit(value: int, field_name: str) -> int:
    return require_varint62(value, field_name)


def _metadata_singleton_seen_bit(typ: int) -> int:
    if typ == METADATA_STREAM_PRIORITY:
        return _SEEN_METADATA_PRIORITY
    if typ == METADATA_STREAM_GROUP:
        return _SEEN_METADATA_GROUP
    if typ == METADATA_OPEN_INFO:
        return _SEEN_METADATA_OPEN_INFO
    return 0


def _diag_singleton_seen_bit(typ: int) -> int:
    if typ == DIAG_DEBUG_TEXT:
        return _SEEN_DIAG_DEBUG_TEXT
    if typ == DIAG_RETRY_AFTER_MILLIS:
        return _SEEN_DIAG_RETRY_AFTER_MILLIS
    if typ == DIAG_OFFENDING_STREAM_ID:
        return _SEEN_DIAG_OFFENDING_STREAM_ID
    if typ == DIAG_OFFENDING_FRAME_TYPE:
        return _SEEN_DIAG_OFFENDING_FRAME_TYPE
    return 0


def _metadata_update_capability_error() -> ProtocolError:
    return _session_write_error(PRIORITY_UPDATE_UNAVAILABLE_MESSAGE, local=True)


def _stream_open_error(message: str) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.STREAM,
        operation=ErrorOperation.OPEN,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.WRITE,
    )


def _session_write_error(message: str, local: bool = False) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        source=ErrorSource.LOCAL if local else ErrorSource.REMOTE,
        direction=ErrorDirection.WRITE,
    )


def _session_read_error(message: str) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )


def _frame_size_payload_error(message: str) -> FrameSizeError:
    return FrameSizeError(
        message,
        code=int(ErrorCode.FRAME_SIZE),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )
