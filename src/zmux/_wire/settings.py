"""Settings TLV codec."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .varint import append_varint, encode_varint_into, parse_varint, varint_len
from ..config import Settings, default_settings
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    ProtocolError,
)
from ..protocol import (
    ErrorCode,
    SchedulerHint,
    SETTING_INITIAL_MAX_DATA,
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED,
    SETTING_INITIAL_MAX_STREAM_DATA_UNI,
    SETTING_MAX_CONTROL_PAYLOAD_BYTES,
    SETTING_MAX_EXTENSION_PAYLOAD_BYTES,
    SETTING_MAX_FRAME_PAYLOAD,
    SETTING_MAX_INCOMING_STREAMS_BIDI,
    SETTING_MAX_INCOMING_STREAMS_UNI,
    SETTING_PING_PADDING_KEY,
    SETTING_PREFACE_PADDING,
    SETTING_SCHEDULER_HINTS,
)

INLINE_UNKNOWN_SETTING_IDS = 8

__all__ = (
    "INLINE_UNKNOWN_SETTING_IDS",
    "append_setting_varint_tlv",
    "append_settings_tlv",
    "known_setting_seen_bit",
    "marshal_settings_tlv",
    "parse_settings_tlv",
    "setting_varint_tlv_len",
    "settings_entries",
    "settings_tlv_len",
)

_SETTING_FIELDS = (
    (
        SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
        "initial_max_stream_data_bidi_locally_opened",
    ),
    (
        SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED,
        "initial_max_stream_data_bidi_peer_opened",
    ),
    (SETTING_INITIAL_MAX_STREAM_DATA_UNI, "initial_max_stream_data_uni"),
    (SETTING_INITIAL_MAX_DATA, "initial_max_data"),
    (SETTING_MAX_INCOMING_STREAMS_BIDI, "max_incoming_streams_bidi"),
    (SETTING_MAX_INCOMING_STREAMS_UNI, "max_incoming_streams_uni"),
    (SETTING_MAX_FRAME_PAYLOAD, "max_frame_payload"),
    (SETTING_MAX_CONTROL_PAYLOAD_BYTES, "max_control_payload_bytes"),
    (SETTING_MAX_EXTENSION_PAYLOAD_BYTES, "max_extension_payload_bytes"),
    (SETTING_SCHEDULER_HINTS, "scheduler_hints"),
    (SETTING_PING_PADDING_KEY, "ping_padding_key"),
)

_SETTING_BY_ID = dict(_SETTING_FIELDS)

_KNOWN_SETTING_BITS = {
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED: 1 << 0,
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED: 1 << 1,
    SETTING_INITIAL_MAX_STREAM_DATA_UNI: 1 << 2,
    SETTING_INITIAL_MAX_DATA: 1 << 3,
    SETTING_MAX_INCOMING_STREAMS_BIDI: 1 << 4,
    SETTING_MAX_INCOMING_STREAMS_UNI: 1 << 5,
    SETTING_MAX_FRAME_PAYLOAD: 1 << 6,
    SETTING_MAX_CONTROL_PAYLOAD_BYTES: 1 << 7,
    SETTING_MAX_EXTENSION_PAYLOAD_BYTES: 1 << 8,
    SETTING_SCHEDULER_HINTS: 1 << 9,
    SETTING_PING_PADDING_KEY: 1 << 10,
    SETTING_PREFACE_PADDING: 1 << 11,
}


def marshal_settings_tlv(settings: Optional[Settings] = None) -> bytes:
    """Encode non-default settings as a TLV byte string."""

    defaults = default_settings()
    settings = _coerce_settings(settings, "settings", default=defaults)
    encoded_len = _settings_tlv_len(settings, defaults)
    if encoded_len == 0:
        return b""
    out = bytearray(encoded_len)
    offset = _write_settings_tlv_to_prevalidated(out, 0, settings, defaults)
    if offset != encoded_len:
        raise AssertionError("settings TLV length accounting mismatch")
    return bytes(out)


def append_settings_tlv(dst: MutableSequence[int], settings: Settings) -> None:
    """Append encoded settings TLVs to ``dst`` without partial writes on error."""

    encoded = marshal_settings_tlv(settings)
    offset = len(dst)
    try:
        dst.extend(encoded)
    except Exception:
        try:
            del dst[offset:]
        except Exception:
            pass
        raise


def settings_tlv_len(settings: Optional[Settings] = None) -> int:
    """Return the encoded TLV length for settings differing from defaults."""

    defaults = default_settings()
    settings = _coerce_settings(settings, "settings", default=defaults)
    return _settings_tlv_len(settings, defaults)


def _settings_tlv_len(settings: Settings, defaults: Settings) -> int:
    total = 0
    for setting_id, value, default in _iter_settings_entries(settings, defaults):
        if value != default:
            total += setting_varint_tlv_len(setting_id, value)
    return total


def settings_entries(
        settings: Settings, defaults: Optional[Settings] = None
) -> Tuple[Tuple[int, int, int], ...]:
    """Return ``(setting_id, value, default)`` entries in wire order."""

    settings = _coerce_settings(settings, "settings")
    defaults = _coerce_settings(defaults, "defaults", default=default_settings())
    return tuple(_iter_settings_entries(settings, defaults))


def _iter_settings_entries(
        settings: Settings, defaults: Settings
) -> Iterator[Tuple[int, int, int]]:
    for setting_id, field_name in _SETTING_FIELDS:
        value = getattr(settings, field_name)
        default = getattr(defaults, field_name)
        if field_name == "scheduler_hints":
            value = int(value)
            default = int(default)
        yield setting_id, value, default


def setting_varint_tlv_len(setting_id: int, value: int) -> int:
    """Return the encoded length of one varint-valued setting TLV."""

    value_len = varint_len(value)
    return varint_len(setting_id) + varint_len(value_len) + value_len


def parse_settings_tlv(src: bytes) -> Settings:
    """Parse settings TLVs, applying defaults and ignoring unknown IDs."""

    offset = 0
    limit = len(src)
    seen_known = 0
    seen_unknown = _UnknownSettingTracker()
    values = _settings_to_kwargs(default_settings())

    while offset < limit:
        typ, consumed = parse_varint(src, offset, limit)
        offset += consumed
        length, consumed = parse_varint(src, offset, limit)
        offset += consumed
        if length > limit - offset:
            raise _settings_parse_error("tlv value overruns containing payload")

        value_start = offset
        value_end = offset + length
        offset = value_end

        bit = known_setting_seen_bit(typ)
        if bit is not None:
            if seen_known & bit:
                raise _settings_parse_error("duplicate setting id %d" % typ)
            seen_known |= bit
            if typ == SETTING_PREFACE_PADDING:
                continue
        else:
            if not seen_unknown.insert(typ):
                raise _settings_parse_error("duplicate setting id %d" % typ)
            continue

        value, consumed = parse_varint(src, value_start, value_end)
        if consumed != length:
            raise _settings_parse_error("setting %d has trailing bytes" % typ)

        field_name = _SETTING_BY_ID[typ]
        if typ == SETTING_SCHEDULER_HINTS:
            values[field_name] = SchedulerHint.from_code(value)
        else:
            values[field_name] = value

    return Settings(**values)


def known_setting_seen_bit(typ: int) -> Optional[int]:
    """Return the duplicate-detection bit for a known setting ID."""

    return _KNOWN_SETTING_BITS.get(typ)


def _write_settings_tlv_to_prevalidated(
        dst: bytearray, offset: int, settings: Settings, defaults: Settings
) -> int:
    for setting_id, value, default in _iter_settings_entries(settings, defaults):
        if value != default:
            offset = _write_setting_varint_tlv(dst, offset, setting_id, value)
    return offset


def append_setting_varint_tlv(
        dst: MutableSequence[int], setting_id: int, value: int
) -> None:
    """Append one varint-valued setting TLV."""

    value_len = varint_len(value)
    append_varint(dst, setting_id)
    append_varint(dst, value_len)
    append_varint(dst, value)


def _write_setting_varint_tlv(
        dst: bytearray, offset: int, setting_id: int, value: int
) -> int:
    value_len = varint_len(value)
    offset += encode_varint_into(dst, offset, setting_id)
    offset += encode_varint_into(dst, offset, value_len)
    offset += encode_varint_into(dst, offset, value)
    return offset


class _UnknownSettingTracker:
    __slots__ = ("_inline", "_overflow")

    def __init__(self) -> None:
        self._inline = []  # type: List[int]
        self._overflow = None  # type: Optional[Set[int]]

    def insert(self, typ: int) -> bool:
        overflow = self._overflow
        if overflow is not None:
            before = len(overflow)
            overflow.add(typ)
            return len(overflow) != before

        if typ in self._inline:
            return False
        if len(self._inline) < INLINE_UNKNOWN_SETTING_IDS:
            self._inline.append(typ)
            return True

        overflow = set(self._inline)
        overflow.add(typ)
        self._overflow = overflow
        return True


def _settings_to_kwargs(settings: Settings) -> Dict[str, int]:
    values = {}
    for _, field_name in _SETTING_FIELDS:
        values[field_name] = getattr(settings, field_name)
    return values


def _coerce_settings(
        settings: Optional[Settings],
        field_name: str,
        *,
        default: Optional[Settings] = None,
) -> Settings:
    if settings is None:
        if default is None:
            raise TypeError("%s must be Settings" % field_name)
        return default
    if not isinstance(settings, Settings):
        raise TypeError("%s must be Settings" % field_name)
    return settings


def _settings_parse_error(message: str) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )
