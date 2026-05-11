"""Public preface codec value types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Tuple

from .config import Settings
from .errors import ErrorDirection, ErrorOperation, ErrorScope, TransportError
from .protocol import (
    MAX_VARINT62,
    capabilities_can_carry_group_in_update,
    capabilities_can_carry_group_on_open,
    capabilities_can_carry_open_info,
    capabilities_can_carry_priority_in_update,
    capabilities_can_carry_priority_on_open,
    capabilities_have_peer_visible_group_semantics,
    capabilities_have_peer_visible_priority_semantics,
    capabilities_support_open_metadata,
    capabilities_support_priority_update,
    has_capability,
    Role,
)


class _CapabilityHelpers:
    capabilities: int

    def has_capability(self, bit: int) -> bool:
        return has_capability(self.capabilities, bit)

    def supports_open_metadata(self) -> bool:
        return capabilities_support_open_metadata(self.capabilities)

    def supports_priority_update(self) -> bool:
        return capabilities_support_priority_update(self.capabilities)

    def can_carry_open_info(self) -> bool:
        return capabilities_can_carry_open_info(self.capabilities)

    def can_carry_priority_on_open(self) -> bool:
        return capabilities_can_carry_priority_on_open(self.capabilities)

    def can_carry_group_on_open(self) -> bool:
        return capabilities_can_carry_group_on_open(self.capabilities)

    def can_carry_priority_in_update(self) -> bool:
        return capabilities_can_carry_priority_in_update(self.capabilities)

    def can_carry_group_in_update(self) -> bool:
        return capabilities_can_carry_group_in_update(self.capabilities)

    def has_peer_visible_priority_semantics(self) -> bool:
        return capabilities_have_peer_visible_priority_semantics(self.capabilities)

    def has_peer_visible_group_semantics(self) -> bool:
        return capabilities_have_peer_visible_group_semantics(self.capabilities)


@dataclass(frozen=True)
class Preface(_CapabilityHelpers):
    """Decoded session preface."""

    preface_version: int
    role: Role
    tie_breaker_nonce: int
    min_proto: int
    max_proto: int
    capabilities: int
    settings: Settings

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "preface_version", _require_byte(self.preface_version, "preface_version")
        )
        object.__setattr__(self, "role", _coerce_role(self.role, "role"))
        for field_name in (
                "tie_breaker_nonce",
                "min_proto",
                "max_proto",
                "capabilities",
        ):
            object.__setattr__(
                self,
                field_name,
                _require_varint62(getattr(self, field_name), field_name),
            )
        if not isinstance(self.settings, Settings):
            raise TypeError("settings must be Settings")

    def marshal(self) -> bytes:
        """Encode this preface without settings padding."""

        from ._wire.preface import marshal_preface

        return marshal_preface(self)

    def marshal_with_settings_padding(self, padding: bytes) -> bytes:
        """Encode this preface with one opaque settings padding TLV."""

        from ._wire.preface import marshal_preface_with_settings_padding

        return marshal_preface_with_settings_padding(self, padding)

    @classmethod
    def parse(cls, data: bytes) -> "Preface":
        """Parse a complete preface and reject trailing bytes."""

        from ._wire.preface import parse_preface

        return parse_preface(data)


@dataclass(frozen=True)
class Negotiated(_CapabilityHelpers):
    """Negotiated session parameters."""

    proto: int
    capabilities: int
    local_role: Role
    peer_role: Role
    peer_settings: Settings

    def __post_init__(self) -> None:
        object.__setattr__(self, "proto", _require_varint62(self.proto, "proto"))
        object.__setattr__(
            self,
            "capabilities",
            _require_varint62(self.capabilities, "capabilities"),
        )
        object.__setattr__(
            self, "local_role", _coerce_role(self.local_role, "local_role")
        )
        object.__setattr__(
            self, "peer_role", _coerce_role(self.peer_role, "peer_role")
        )
        if not isinstance(self.peer_settings, Settings):
            raise TypeError("peer_settings must be Settings")


def default_preface(role: Role = Role.AUTO) -> Preface:
    """Return a default v1 preface."""

    from ._wire.preface import default_preface as _default_preface

    return _default_preface(role)


def marshal_preface(preface: Preface) -> bytes:
    """Encode a session preface without settings padding."""

    from ._wire.preface import marshal_preface as _marshal_preface

    return _marshal_preface(preface)


def marshal_preface_with_settings_padding(preface: Preface, padding: bytes) -> bytes:
    """Encode a session preface with one opaque settings padding TLV."""

    from ._wire.preface import (
        marshal_preface_with_settings_padding as _marshal_preface_with_settings_padding,
    )

    return _marshal_preface_with_settings_padding(preface, padding)


def parse_preface(data: bytes) -> Preface:
    """Parse a complete preface and reject trailing bytes."""

    from ._wire.preface import parse_preface as _parse_preface

    return _parse_preface(data)


def parse_preface_prefix(data: bytes) -> Tuple[Preface, int]:
    """Parse a preface prefix and return ``(preface, consumed_bytes)``."""

    from ._wire.preface import parse_preface_prefix as _parse_preface_prefix

    return _parse_preface_prefix(data)


def read_preface(reader: BinaryIO) -> Preface:
    """Read and parse one complete preface from a binary stream."""

    from ._wire.preface import read_preface as _read_preface

    return _read_preface(reader)


def write_preface(
        writer: BinaryIO,
        preface: Preface,
        settings_padding: bytes = b"",
) -> None:
    """Validate and write one complete preface to a binary stream."""

    if writer is None or not callable(getattr(writer, "write", None)):
        raise TypeError("writer must provide write(bytes)")
    _write_all(writer, marshal_preface_with_settings_padding(preface, settings_padding))


def negotiate_prefaces(local: Preface, peer: Preface) -> Negotiated:
    """Negotiate protocol state from local and peer prefaces."""

    from ._wire.preface import negotiate_prefaces as _negotiate_prefaces

    return _negotiate_prefaces(local, peer)


def resolve_roles(
        local_role: Role, local_nonce: int, peer_role: Role, peer_nonce: int
) -> Tuple[Role, Role]:
    """Resolve local and peer roles after preface exchange."""

    from ._wire.preface import resolve_roles as _resolve_roles

    return _resolve_roles(local_role, local_nonce, peer_role, peer_nonce)


def _coerce_role(value: Role, field_name: str) -> Role:
    if isinstance(value, Role):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be a Role or integer" % field_name)
    return Role.from_code(value)


def _require_byte(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0 or value > 0xFF:
        raise ValueError("%s must fit in one byte" % field_name)
    return int(value)


def _require_varint62(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % field_name)
    return int(value)


def _write_all(writer: BinaryIO, data) -> None:
    view = memoryview(data)
    while view:
        try:
            written = writer.write(view)
        except OSError as exc:
            raise _transport_write_error(exc) from exc
        if written is None:
            raise _transport_write_error(
                BlockingIOError("preface writer returned no progress")
            )
        if isinstance(written, bool) or not isinstance(written, int):
            raise _transport_write_error(
                OSError("zmux: preface writer reported invalid progress")
            )
        if written <= 0 or written > len(view):
            raise _transport_write_error(
                OSError("zmux: preface writer reported invalid progress")
            )
        view = view[written:]


def _transport_write_error(error: OSError) -> TransportError:
    return TransportError(
        error,
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        direction=ErrorDirection.WRITE,
    )


__all__ = [
    "Negotiated",
    "Preface",
    "default_preface",
    "marshal_preface",
    "marshal_preface_with_settings_padding",
    "negotiate_prefaces",
    "parse_preface",
    "parse_preface_prefix",
    "read_preface",
    "resolve_roles",
    "write_preface",
]
