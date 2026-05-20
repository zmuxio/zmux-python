"""Protocol registry values for zmux v1."""

from __future__ import annotations

from enum import IntEnum, IntFlag
from typing import Tuple, Type, TypeVar

from ._validation import require_varint62

MAGIC = b"ZMUX"
PREFACE_VERSION = 1
PROTO_VERSION = 1
MAX_PREFACE_SETTINGS_BYTES = 4096
MAX_VARINT62 = (1 << 62) - 1
MAX_VARINT_LEN = 8

_E = TypeVar("_E", bound=IntEnum)


def _enum_codes(*members: int) -> Tuple[int, ...]:
    return tuple(int(member) for member in members)


# noinspection PyTypeHints
def _enum_from_code(enum_type: Type[_E], code: int, label: str) -> _E:
    code = _coerce_int_code(code, label)
    try:
        return enum_type(code)
    except ValueError:
        raise ValueError("invalid %s: %r" % (label, code))


def _coerce_int_code(code: int, label: str) -> int:
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError("%s code must be an integer" % label)
    return code


class Role(IntEnum):
    """Stream-ID ownership role advertised in the session preface."""

    INITIATOR = 0
    RESPONDER = 1
    AUTO = 2

    @classmethod
    def from_code(cls, code: int) -> "Role":
        """Return the role for ``code`` or raise ``ValueError``."""

        return _enum_from_code(cls, code, "role")

    def valid(self) -> bool:
        """Return whether this role is a currently assigned registry value."""

        return self in (Role.INITIATOR, Role.RESPONDER, Role.AUTO)

    def as_str(self) -> str:
        """Return the wire-registry role name."""

        if self is Role.INITIATOR:
            return "initiator"
        if self is Role.RESPONDER:
            return "responder"
        return "auto"

    def __str__(self) -> str:
        return self.as_str()


class SchedulerHint(IntEnum):
    """Standard advisory scheduler hints."""

    UNSPECIFIED_OR_BALANCED = 0
    LATENCY = 1
    BALANCED_FAIR = 2
    BULK_THROUGHPUT = 3
    GROUP_FAIR = 4

    @classmethod
    def from_code(cls, code: int) -> "SchedulerHint":
        """Return the assigned hint for ``code`` or the balanced fallback."""

        code = _coerce_int_code(code, "scheduler hint")
        try:
            return cls(code)
        except ValueError:
            return cls.UNSPECIFIED_OR_BALANCED

    def as_str(self) -> str:
        """Return the wire-registry scheduler hint name."""

        if self is SchedulerHint.UNSPECIFIED_OR_BALANCED:
            return "unspecified_or_balanced"
        if self is SchedulerHint.LATENCY:
            return "latency"
        if self is SchedulerHint.BALANCED_FAIR:
            return "balanced_fair"
        if self is SchedulerHint.BULK_THROUGHPUT:
            return "bulk_throughput"
        return "group_fair"

    def __str__(self) -> str:
        return self.as_str()


class Capability(IntFlag):
    """Negotiated optional protocol behavior bits."""

    OPEN_METADATA = 1
    PRIORITY_HINTS = 2
    STREAM_GROUPS = 4
    PRIORITY_UPDATE = 8


class SettingID(IntEnum):
    """Standard session preface setting identifiers."""

    INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED = 1
    INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED = 2
    INITIAL_MAX_STREAM_DATA_UNI = 3
    INITIAL_MAX_DATA = 4
    MAX_INCOMING_STREAMS_BIDI = 5
    MAX_INCOMING_STREAMS_UNI = 6
    MAX_FRAME_PAYLOAD = 7
    MAX_CONTROL_PAYLOAD_BYTES = 8
    MAX_EXTENSION_PAYLOAD_BYTES = 9
    SCHEDULER_HINTS = 10
    PING_PADDING_KEY = 11
    PREFACE_PADDING = 12

    @classmethod
    def from_code(cls, code: int) -> "SettingID":
        """Return the standard setting for ``code`` or raise ``ValueError``."""

        return _enum_from_code(cls, code, "setting")


class FrameType(IntEnum):
    """Standard frame type codes."""

    DATA = 1
    MAX_DATA = 2
    STOP_SENDING = 3
    PING = 4
    PONG = 5
    BLOCKED = 6
    RESET = 7
    ABORT = 8
    GOAWAY = 9
    CLOSE = 10
    EXT = 11

    @classmethod
    def from_code(cls, code: int) -> "FrameType":
        """Return the frame type for ``code`` or raise ``ValueError``."""

        return _enum_from_code(cls, code, "frame type")

    def valid(self) -> bool:
        """Return whether this frame type is currently assigned."""

        return FrameType.DATA <= self <= FrameType.EXT

    def as_str(self) -> str:
        """Return the wire-registry frame type name."""

        return self.name

    def __str__(self) -> str:
        return self.as_str()


FRAME_TYPE_MASK = 0x1F
FRAME_FLAG_MASK = 0xE0
FRAME_FLAG_OPEN_METADATA = 0x20
FRAME_FLAG_FIN = 0x40
FRAME_FLAG_RESERVED_TYPE_SPECIFIC = 0x80


class MetadataType(IntEnum):
    """Standard stream metadata TLV identifiers."""

    STREAM_PRIORITY = 1
    STREAM_GROUP = 2
    OPEN_INFO = 3

    @classmethod
    def from_code(cls, code: int) -> "MetadataType":
        """Return the standard stream metadata TLV type."""

        return _enum_from_code(cls, code, "stream metadata type")


class DiagnosticType(IntEnum):
    """Standard diagnostic TLV identifiers."""

    DEBUG_TEXT = 1
    RETRY_AFTER_MILLIS = 2
    OFFENDING_STREAM_ID = 3
    OFFENDING_FRAME_TYPE = 4

    @classmethod
    def from_code(cls, code: int) -> "DiagnosticType":
        """Return the standard diagnostic TLV type."""

        return _enum_from_code(cls, code, "diagnostic type")


class ExtensionSubtype(IntEnum):
    """Standard EXT frame subtypes."""

    PRIORITY_UPDATE = 1

    @classmethod
    def from_code(cls, code: int) -> "ExtensionSubtype":
        """Return the standard EXT subtype for ``code``."""

        return _enum_from_code(cls, code, "extension subtype")

    def as_str(self) -> str:
        """Return the wire-registry EXT subtype name."""

        return self.name

    def __str__(self) -> str:
        return self.as_str()


class ErrorCode(IntEnum):
    """Core zmux error codes."""

    NO_ERROR = 0
    PROTOCOL = 1
    FLOW_CONTROL = 2
    STREAM_LIMIT = 3
    REFUSED_STREAM = 4
    STREAM_STATE = 5
    STREAM_CLOSED = 6
    SESSION_CLOSING = 7
    CANCELLED = 8
    IDLE_TIMEOUT = 9
    FRAME_SIZE = 10
    UNSUPPORTED_VERSION = 11
    ROLE_CONFLICT = 12
    INTERNAL = 13

    @classmethod
    def from_code(cls, code: int) -> "ErrorCode":
        """Return the standard error code for ``code``."""

        code = _coerce_int_code(code, "error code")
        try:
            return cls(code)
        except ValueError:
            raise ValueError("unknown zmux error code: %r" % code)

    def as_str(self) -> str:
        """Return the wire-registry error code name."""

        return self.name

    def __str__(self) -> str:
        return self.as_str()


(
    CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_STREAM_GROUPS,
    CAPABILITY_PRIORITY_UPDATE,
    CAPABILITY_OPEN_METADATA,
) = _enum_codes(
    Capability.PRIORITY_HINTS,
    Capability.STREAM_GROUPS,
    Capability.PRIORITY_UPDATE,
    Capability.OPEN_METADATA,
)
CAPABILITY_METADATA_CARRIAGE_MASK = CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_UPDATE
DEFAULT_CAPABILITIES = (
        CAPABILITY_OPEN_METADATA
        | CAPABILITY_PRIORITY_HINTS
        | CAPABILITY_STREAM_GROUPS
        | CAPABILITY_PRIORITY_UPDATE
)

(
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
    SETTING_INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED,
    SETTING_INITIAL_MAX_STREAM_DATA_UNI,
    SETTING_INITIAL_MAX_DATA,
    SETTING_MAX_INCOMING_STREAMS_BIDI,
    SETTING_MAX_INCOMING_STREAMS_UNI,
    SETTING_MAX_FRAME_PAYLOAD,
    SETTING_MAX_CONTROL_PAYLOAD_BYTES,
    SETTING_MAX_EXTENSION_PAYLOAD_BYTES,
    SETTING_SCHEDULER_HINTS,
    SETTING_PING_PADDING_KEY,
    SETTING_PREFACE_PADDING,
) = _enum_codes(
    SettingID.INITIAL_MAX_STREAM_DATA_BIDI_LOCALLY_OPENED,
    SettingID.INITIAL_MAX_STREAM_DATA_BIDI_PEER_OPENED,
    SettingID.INITIAL_MAX_STREAM_DATA_UNI,
    SettingID.INITIAL_MAX_DATA,
    SettingID.MAX_INCOMING_STREAMS_BIDI,
    SettingID.MAX_INCOMING_STREAMS_UNI,
    SettingID.MAX_FRAME_PAYLOAD,
    SettingID.MAX_CONTROL_PAYLOAD_BYTES,
    SettingID.MAX_EXTENSION_PAYLOAD_BYTES,
    SettingID.SCHEDULER_HINTS,
    SettingID.PING_PADDING_KEY,
    SettingID.PREFACE_PADDING,
)

(
    METADATA_STREAM_PRIORITY,
    METADATA_STREAM_GROUP,
    METADATA_OPEN_INFO,
) = _enum_codes(
    MetadataType.STREAM_PRIORITY,
    MetadataType.STREAM_GROUP,
    MetadataType.OPEN_INFO,
)

(
    DIAG_DEBUG_TEXT,
    DIAG_RETRY_AFTER_MILLIS,
    DIAG_OFFENDING_STREAM_ID,
    DIAG_OFFENDING_FRAME_TYPE,
) = _enum_codes(
    DiagnosticType.DEBUG_TEXT,
    DiagnosticType.RETRY_AFTER_MILLIS,
    DiagnosticType.OFFENDING_STREAM_ID,
    DiagnosticType.OFFENDING_FRAME_TYPE,
)

(EXT_PRIORITY_UPDATE,) = _enum_codes(ExtensionSubtype.PRIORITY_UPDATE)

CLAIM_WIRE_V1 = "zmux-wire-v1"
CLAIM_API_SEMANTICS_PROFILE_V1 = "zmux-api-semantics-profile-v1"
CLAIM_STREAM_ADAPTER_PROFILE_V1 = "zmux-stream-adapter-profile-v1"
CLAIM_OPEN_METADATA = "zmux-open_metadata"
CLAIM_PRIORITY_UPDATE = "zmux-priority_update"
PROFILE_V1 = "zmux-v1"
PROFILE_REFERENCE_V1 = "zmux-reference-profile-v1"


def has_any_capability(capabilities: int, capabilities_mask: int) -> bool:
    """Return whether any bit in ``capabilities_mask`` is present."""

    capabilities = _coerce_capability_bits(capabilities, "capabilities")
    capabilities_mask = _coerce_capability_bits(capabilities_mask, "capabilities_mask")
    return bool(capabilities & capabilities_mask)


def has_all_capabilities(capabilities: int, capabilities_mask: int) -> bool:
    """Return whether all bits in ``capabilities_mask`` are present."""

    capabilities = _coerce_capability_bits(capabilities, "capabilities")
    capabilities_mask = _coerce_capability_bits(capabilities_mask, "capabilities_mask")
    return capabilities & capabilities_mask == capabilities_mask


def has_capability(capabilities: int, capability: int) -> bool:
    """Return whether ``capabilities`` contains ``capability``."""

    return has_any_capability(capabilities, capability)


def _coerce_capability_bits(value: int, field_name: str) -> int:
    return require_varint62(value, field_name)


def capabilities_support_open_metadata(capabilities: int) -> bool:
    """Return whether OPEN_METADATA carriage is negotiated."""

    return has_capability(capabilities, Capability.OPEN_METADATA)


def capabilities_support_priority_update(capabilities: int) -> bool:
    """Return whether PRIORITY_UPDATE carriage is negotiated."""

    return has_capability(capabilities, Capability.PRIORITY_UPDATE)


def capabilities_can_carry_open_info(capabilities: int) -> bool:
    """Return whether opaque open-info metadata can be peer-visible."""

    return capabilities_support_open_metadata(capabilities)


def capabilities_can_carry_priority_on_open(capabilities: int) -> bool:
    """Return whether priority can be carried on the opening DATA frame."""

    return has_all_capabilities(
        capabilities, CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS
    )


def capabilities_can_carry_group_on_open(capabilities: int) -> bool:
    """Return whether group can be carried on the opening DATA frame."""

    return has_all_capabilities(
        capabilities, CAPABILITY_OPEN_METADATA | CAPABILITY_STREAM_GROUPS
    )


def capabilities_can_carry_priority_in_update(capabilities: int) -> bool:
    """Return whether priority can be carried in PRIORITY_UPDATE."""

    return has_all_capabilities(
        capabilities, CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS
    )


def capabilities_can_carry_group_in_update(capabilities: int) -> bool:
    """Return whether group can be carried in PRIORITY_UPDATE."""

    return has_all_capabilities(
        capabilities, CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS
    )


def capabilities_have_peer_visible_priority_semantics(capabilities: int) -> bool:
    """Return whether priority hints can affect peer-visible behavior."""

    return has_capability(capabilities, CAPABILITY_PRIORITY_HINTS) and has_any_capability(
        capabilities, CAPABILITY_METADATA_CARRIAGE_MASK
    )


def capabilities_have_peer_visible_group_semantics(capabilities: int) -> bool:
    """Return whether stream groups can affect peer-visible behavior."""

    return has_capability(capabilities, CAPABILITY_STREAM_GROUPS) and has_any_capability(
        capabilities, CAPABILITY_METADATA_CARRIAGE_MASK
    )


__all__ = [
    "CAPABILITY_METADATA_CARRIAGE_MASK",
    "CAPABILITY_OPEN_METADATA",
    "CAPABILITY_PRIORITY_HINTS",
    "CAPABILITY_PRIORITY_UPDATE",
    "CAPABILITY_STREAM_GROUPS",
    "CLAIM_API_SEMANTICS_PROFILE_V1",
    "CLAIM_OPEN_METADATA",
    "CLAIM_PRIORITY_UPDATE",
    "CLAIM_STREAM_ADAPTER_PROFILE_V1",
    "CLAIM_WIRE_V1",
    "Capability",
    "DIAG_DEBUG_TEXT",
    "DIAG_OFFENDING_FRAME_TYPE",
    "DIAG_OFFENDING_STREAM_ID",
    "DIAG_RETRY_AFTER_MILLIS",
    "DiagnosticType",
    "DEFAULT_CAPABILITIES",
    "EXT_PRIORITY_UPDATE",
    "ErrorCode",
    "ExtensionSubtype",
    "FRAME_FLAG_FIN",
    "FRAME_FLAG_MASK",
    "FRAME_FLAG_OPEN_METADATA",
    "FRAME_FLAG_RESERVED_TYPE_SPECIFIC",
    "FRAME_TYPE_MASK",
    "FrameType",
    "MAGIC",
    "MAX_PREFACE_SETTINGS_BYTES",
    "MAX_VARINT62",
    "MAX_VARINT_LEN",
    "METADATA_OPEN_INFO",
    "METADATA_STREAM_GROUP",
    "METADATA_STREAM_PRIORITY",
    "MetadataType",
    "PREFACE_VERSION",
    "PROFILE_REFERENCE_V1",
    "PROFILE_V1",
    "PROTO_VERSION",
    "Role",
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
    "SchedulerHint",
    "SettingID",
    "capabilities_can_carry_group_in_update",
    "capabilities_can_carry_group_on_open",
    "capabilities_can_carry_open_info",
    "capabilities_can_carry_priority_in_update",
    "capabilities_can_carry_priority_on_open",
    "capabilities_have_peer_visible_group_semantics",
    "capabilities_have_peer_visible_priority_semantics",
    "capabilities_support_open_metadata",
    "capabilities_support_priority_update",
    "has_all_capabilities",
    "has_any_capability",
    "has_capability",
]
