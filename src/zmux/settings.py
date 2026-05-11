"""Public settings TLV facade."""

from __future__ import annotations

from ._wire.settings import (
    append_setting_varint_tlv,
    append_settings_tlv,
    known_setting_seen_bit,
    marshal_settings_tlv,
    parse_settings_tlv,
    setting_varint_tlv_len,
    settings_entries,
    settings_tlv_len,
)
from .config import Limits, Settings, default_settings
from .protocol import (
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
    SettingID,
)

__all__ = (
    "Limits",
    "Settings",
    "SETTING_INITIAL_MAX_DATA",
    "SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED",
    "SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED",
    "SETTING_INITIAL_MAX_STREAM_DATA_UNI",
    "SETTING_MAX_CONTROL_PAYLOAD_BYTES",
    "SETTING_MAX_EXTENSION_PAYLOAD_BYTES",
    "SETTING_MAX_FRAME_PAYLOAD",
    "SETTING_MAX_INCOMING_STREAMS_BIDI",
    "SETTING_MAX_INCOMING_STREAMS_UNI",
    "SETTING_PING_PADDING_KEY",
    "SETTING_PREFACE_PADDING",
    "SETTING_SCHEDULER_HINTS",
    "SettingID",
    "append_setting_varint_tlv",
    "append_settings_tlv",
    "default_settings",
    "known_setting_seen_bit",
    "marshal_settings_tlv",
    "parse_settings_tlv",
    "setting_varint_tlv_len",
    "settings_entries",
    "settings_tlv_len",
)
