"""Session preface codec and negotiation helpers."""

from __future__ import annotations

from typing import BinaryIO

from .settings import marshal_settings_tlv, parse_settings_tlv
from .varint import encode_varint_into, parse_varint, read_varint, varint_len
from ..config import DEFAULT_CAPABILITIES, Settings, default_settings
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    ProtocolError,
    TransportError,
)
from ..preface import Negotiated, Preface
from ..protocol import (
    MAGIC,
    MAX_PREFACE_SETTINGS_BYTES,
    PREFACE_VERSION,
    PROTO_VERSION,
    SETTING_PREFACE_PADDING,
    ErrorCode,
    Role,
)

PREFACE_FIXED_LEN = 6
MIN_COMPAT_FRAME_PAYLOAD = 16384
MIN_COMPAT_CONTROL_PAYLOAD = 4096
MIN_COMPAT_EXTENSION_PAYLOAD = 4096
PREFACE_SETTINGS_TOO_LARGE = "settings_tlv exceeds 4096 bytes"

__all__ = (
    "MIN_COMPAT_CONTROL_PAYLOAD",
    "MIN_COMPAT_EXTENSION_PAYLOAD",
    "MIN_COMPAT_FRAME_PAYLOAD",
    "PREFACE_FIXED_LEN",
    "PREFACE_SETTINGS_TOO_LARGE",
    "default_preface",
    "marshal_preface",
    "marshal_preface_with_settings_padding",
    "negotiate_prefaces",
    "parse_preface",
    "parse_preface_prefix",
    "read_preface",
    "resolve_roles",
)


def marshal_preface(preface: Preface) -> bytes:
    """Encode a session preface without settings padding."""

    return marshal_preface_with_settings_padding(preface, b"")


def marshal_preface_with_settings_padding(preface: Preface, padding: bytes) -> bytes:
    """Encode a session preface and append optional opaque settings padding."""

    _validate_preface_for_marshal(preface)
    padding_view = _byte_view(padding)
    base_settings = marshal_settings_tlv(preface.settings)
    padding_len = (
        _settings_padding_tlv_len(len(padding_view)) if padding_view else 0
    )
    settings_len = len(base_settings) + padding_len
    if settings_len > MAX_PREFACE_SETTINGS_BYTES:
        raise _preface_frame_size_error(PREFACE_SETTINGS_TOO_LARGE, ErrorOperation.WRITE)

    encoded_len = _preface_encoded_len(preface, settings_len)
    out = bytearray(encoded_len)
    out[:4] = MAGIC
    out[4] = preface.preface_version
    out[5] = int(preface.role)
    offset = PREFACE_FIXED_LEN
    offset += encode_varint_into(out, offset, preface.tie_breaker_nonce)
    offset += encode_varint_into(out, offset, preface.min_proto)
    offset += encode_varint_into(out, offset, preface.max_proto)
    offset += encode_varint_into(out, offset, preface.capabilities)
    offset += encode_varint_into(out, offset, settings_len)
    out[offset: offset + len(base_settings)] = base_settings
    offset += len(base_settings)
    if padding_view:
        offset = _write_tlv(out, offset, SETTING_PREFACE_PADDING, padding_view)
    if offset != encoded_len:
        raise AssertionError("preface length accounting mismatch")
    return bytes(out)


def parse_preface(data: bytes) -> Preface:
    """Parse a complete preface and reject trailing bytes."""

    preface, consumed = parse_preface_prefix(data)
    if consumed != len(data):
        raise _preface_parse_error("unexpected trailing bytes after preface")
    return preface


def parse_preface_prefix(data: bytes) -> tuple[Preface, int]:
    """Parse a preface prefix and return ``(preface, consumed_bytes)``."""

    data_view = memoryview(data)
    if len(data_view) < PREFACE_FIXED_LEN:
        raise _preface_parse_error("truncated preface")
    if data_view[:4] != MAGIC:
        raise _preface_parse_error("invalid magic")
    if data_view[4] != PREFACE_VERSION:
        raise _preface_parse_error(
            "unsupported preface version", ErrorCode.UNSUPPORTED_VERSION
        )
    role = _parse_role(data_view[5], ErrorOperation.READ)
    offset = PREFACE_FIXED_LEN

    tie_breaker_nonce, consumed = parse_varint(data_view, offset, len(data_view))
    offset += consumed
    min_proto, consumed = parse_varint(data_view, offset, len(data_view))
    offset += consumed
    max_proto, consumed = parse_varint(data_view, offset, len(data_view))
    offset += consumed
    capabilities, consumed = parse_varint(data_view, offset, len(data_view))
    offset += consumed
    settings_len, consumed = parse_varint(data_view, offset, len(data_view))
    offset += consumed
    if settings_len > MAX_PREFACE_SETTINGS_BYTES:
        raise _preface_frame_size_error(PREFACE_SETTINGS_TOO_LARGE, ErrorOperation.READ)
    if len(data_view) - offset < settings_len:
        raise _preface_parse_error("truncated preface settings")

    settings_end = offset + settings_len
    settings = parse_settings_tlv(data_view[offset:settings_end])
    return (
        Preface(
            preface_version=data_view[4],
            role=role,
            tie_breaker_nonce=tie_breaker_nonce,
            min_proto=min_proto,
            max_proto=max_proto,
            capabilities=capabilities,
            settings=settings,
        ),
        settings_end,
    )


def read_preface(reader: BinaryIO) -> Preface:
    """Read and parse one complete preface from a binary stream."""

    fixed = _read_exact(reader, PREFACE_FIXED_LEN, "truncated preface")
    if fixed[:4] != MAGIC:
        raise _preface_parse_error("invalid magic")
    if fixed[4] != PREFACE_VERSION:
        raise _preface_parse_error(
            "unsupported preface version", ErrorCode.UNSUPPORTED_VERSION
        )
    role = _parse_role(fixed[5], ErrorOperation.READ)
    tie_breaker_nonce, _ = _read_preface_varint(reader)
    min_proto, _ = _read_preface_varint(reader)
    max_proto, _ = _read_preface_varint(reader)
    capabilities, _ = _read_preface_varint(reader)
    settings_len, _ = _read_preface_varint(reader)
    if settings_len > MAX_PREFACE_SETTINGS_BYTES:
        raise _preface_frame_size_error(PREFACE_SETTINGS_TOO_LARGE, ErrorOperation.READ)
    settings_bytes = _read_exact(reader, settings_len, "truncated settings_tlv")
    return Preface(
        preface_version=fixed[4],
        role=role,
        tie_breaker_nonce=tie_breaker_nonce,
        min_proto=min_proto,
        max_proto=max_proto,
        capabilities=capabilities,
        settings=parse_settings_tlv(settings_bytes),
    )


def negotiate_prefaces(local: Preface, peer: Preface) -> Negotiated:
    """Negotiate protocol state from local and peer prefaces."""

    _validate_preface_for_negotiate(local, "local")
    _validate_preface_for_negotiate(peer, "peer")
    if local.role == Role.AUTO and local.tie_breaker_nonce == 0:
        raise _preface_negotiate_error("local auto role requires non-zero nonce")
    if peer.role == Role.AUTO and peer.tie_breaker_nonce == 0:
        raise _preface_negotiate_error("peer auto role requires non-zero nonce")

    proto = min(local.max_proto, peer.max_proto)
    if proto < max(local.min_proto, peer.min_proto):
        raise _preface_negotiate_error(
            "no compatible protocol version", ErrorCode.UNSUPPORTED_VERSION
        )
    for settings in (local.settings, peer.settings):
        if (
                settings.max_frame_payload < MIN_COMPAT_FRAME_PAYLOAD
                or settings.max_control_payload_bytes < MIN_COMPAT_CONTROL_PAYLOAD
                or settings.max_extension_payload_bytes < MIN_COMPAT_EXTENSION_PAYLOAD
        ):
            raise _preface_negotiate_error("receive limits below compatibility floor")

    local_role, peer_role = resolve_roles(
        local.role, local.tie_breaker_nonce, peer.role, peer.tie_breaker_nonce
    )
    return Negotiated(
        proto=proto,
        capabilities=local.capabilities & peer.capabilities,
        local_role=local_role,
        peer_role=peer_role,
        peer_settings=peer.settings,
    )


def resolve_roles(
        local_role: Role, local_nonce: int, peer_role: Role, peer_nonce: int
) -> tuple[Role, Role]:
    """Resolve local and peer roles after exchanging prefaces."""

    local_role = _coerce_role(local_role, "local_role")
    peer_role = _coerce_role(peer_role, "peer_role")
    local_nonce = _require_varint62(local_nonce, "local_nonce")
    peer_nonce = _require_varint62(peer_nonce, "peer_nonce")

    if local_role == Role.INITIATOR and peer_role == Role.RESPONDER:
        return Role.INITIATOR, Role.RESPONDER
    if local_role == Role.RESPONDER and peer_role == Role.INITIATOR:
        return Role.RESPONDER, Role.INITIATOR
    if local_role == Role.INITIATOR and peer_role == Role.AUTO:
        return Role.INITIATOR, Role.RESPONDER
    if local_role == Role.RESPONDER and peer_role == Role.AUTO:
        return Role.RESPONDER, Role.INITIATOR
    if local_role == Role.AUTO and peer_role == Role.INITIATOR:
        return Role.RESPONDER, Role.INITIATOR
    if local_role == Role.AUTO and peer_role == Role.RESPONDER:
        return Role.INITIATOR, Role.RESPONDER
    if local_role == Role.INITIATOR and peer_role == Role.INITIATOR:
        raise _preface_negotiate_error(
            "both peers explicitly requested initiator", ErrorCode.ROLE_CONFLICT
        )
    if local_role == Role.RESPONDER and peer_role == Role.RESPONDER:
        raise _preface_negotiate_error(
            "both peers explicitly requested responder", ErrorCode.ROLE_CONFLICT
        )
    if local_role == Role.AUTO and peer_role == Role.AUTO:
        if local_nonce == peer_nonce:
            raise _preface_negotiate_error(
                "equal auto-role nonces", ErrorCode.ROLE_CONFLICT
            )
        if local_nonce > peer_nonce:
            return Role.INITIATOR, Role.RESPONDER
        return Role.RESPONDER, Role.INITIATOR
    raise _preface_negotiate_error("invalid role")


def default_preface(role: Role = Role.AUTO) -> Preface:
    """Return a default v1 preface for callers that fill role/nonce later."""

    return Preface(
        preface_version=PREFACE_VERSION,
        role=role,
        tie_breaker_nonce=0,
        min_proto=PROTO_VERSION,
        max_proto=PROTO_VERSION,
        capabilities=DEFAULT_CAPABILITIES,
        settings=default_settings(),
    )


def _validate_preface_for_marshal(preface: Preface) -> None:
    if not isinstance(preface, Preface):
        raise _preface_parse_error(
            "preface is required", operation=ErrorOperation.WRITE
        )
    if preface.preface_version != PREFACE_VERSION:
        raise _preface_parse_error(
            "unsupported preface version",
            ErrorCode.UNSUPPORTED_VERSION,
            ErrorOperation.WRITE,
        )
    if not isinstance(preface.role, Role):
        raise _preface_parse_error("invalid role", operation=ErrorOperation.WRITE)
    if preface.min_proto == 0 or preface.max_proto == 0:
        raise _preface_parse_error(
            "protocol version bounds must be non-zero", operation=ErrorOperation.WRITE
        )
    if preface.role == Role.AUTO and preface.tie_breaker_nonce == 0:
        raise _preface_parse_error(
            "role=auto requires non-zero tie-breaker nonce",
            operation=ErrorOperation.WRITE,
        )
    if not isinstance(preface.settings, Settings):
        raise _preface_parse_error("settings are required", operation=ErrorOperation.WRITE)
    for name in ("tie_breaker_nonce", "min_proto", "max_proto", "capabilities"):
        varint_len(getattr(preface, name))


def _preface_encoded_len(preface: Preface, settings_len: int) -> int:
    return (
            PREFACE_FIXED_LEN
            + varint_len(preface.tie_breaker_nonce)
            + varint_len(preface.min_proto)
            + varint_len(preface.max_proto)
            + varint_len(preface.capabilities)
            + varint_len(settings_len)
            + settings_len
    )


def _settings_padding_tlv_len(padding_len: int) -> int:
    return (
            varint_len(SETTING_PREFACE_PADDING)
            + varint_len(padding_len)
            + padding_len
    )


def _write_tlv(dst: bytearray, offset: int, typ: int, value: memoryview) -> int:
    offset += encode_varint_into(dst, offset, typ)
    offset += encode_varint_into(dst, offset, len(value))
    end = offset + len(value)
    dst[offset:end] = value
    return end


def _validate_preface_for_negotiate(preface: Preface, name: str) -> None:
    if not isinstance(preface, Preface):
        raise _preface_negotiate_error("%s preface is required" % name)
    if not isinstance(preface.role, Role):
        raise _preface_negotiate_error("invalid role")
    if not isinstance(preface.settings, Settings):
        raise _preface_negotiate_error("settings are required")


def _parse_role(code: int, operation: ErrorOperation) -> Role:
    try:
        return Role.from_code(code)
    except ValueError:
        raise _preface_parse_error("invalid role", operation=operation)


def _coerce_role(value: Role, field_name: str) -> Role:
    if isinstance(value, Role):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be a Role or integer" % field_name)
    return Role.from_code(value)


def _require_varint62(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > ((1 << 62) - 1):
        raise ValueError("%s must be within varint62 range" % field_name)
    return int(value)


def _read_preface_varint(reader: BinaryIO) -> tuple[int, int]:
    try:
        return read_varint(reader)
    except OSError as exc:
        raise _transport_read_error(exc) from exc


def _read_exact(reader: BinaryIO, size: int, truncated_message: str) -> bytes:
    if size == 0:
        return b""
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
            raise _preface_parse_error(truncated_message)
        if chunk_len > remaining:
            exc = OSError("reader returned more bytes than requested")
            raise _transport_read_error(exc) from exc
        if chunk_len == remaining:
            return chunk if isinstance(chunk, bytes) else view.tobytes()
        chunks = [view.tobytes()]
        remaining -= chunk_len
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
        view = _read_chunk_view(chunk)
        chunk_len = len(view)
        if chunk_len == 0:
            raise _preface_parse_error(truncated_message)
        if chunk_len > remaining:
            exc = OSError("reader returned more bytes than requested")
            raise _transport_read_error(exc) from exc
        chunks.append(view.tobytes())
        remaining -= chunk_len
    return b"".join(chunks)


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


def _byte_view(value: bytes) -> memoryview:
    if value is None:
        return memoryview(b"")
    view = memoryview(value)
    if view.ndim == 1 and view.itemsize == 1 and view.format in ("B", "b", "c"):
        return view
    try:
        return view.cast("B")
    except (TypeError, ValueError):
        return memoryview(view.tobytes())


def _preface_parse_error(
        message: str,
        code: ErrorCode = ErrorCode.PROTOCOL,
        operation: ErrorOperation = ErrorOperation.READ,
) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(code),
        scope=ErrorScope.SESSION,
        operation=operation,
        source=ErrorSource.REMOTE if operation == ErrorOperation.READ else ErrorSource.LOCAL,
        direction=ErrorDirection.READ
        if operation == ErrorOperation.READ
        else ErrorDirection.WRITE,
    )


def _preface_frame_size_error(
        message: str, operation: ErrorOperation
) -> FrameSizeError:
    return FrameSizeError(
        message,
        code=int(ErrorCode.FRAME_SIZE),
        scope=ErrorScope.SESSION,
        operation=operation,
        source=ErrorSource.REMOTE if operation == ErrorOperation.READ else ErrorSource.LOCAL,
        direction=ErrorDirection.READ
        if operation == ErrorOperation.READ
        else ErrorDirection.WRITE,
    )


def _preface_negotiate_error(
        message: str, code: ErrorCode = ErrorCode.PROTOCOL
) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(code),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.OPEN,
        source=ErrorSource.LOCAL,
        direction=ErrorDirection.BOTH,
    )


def _transport_read_error(error: OSError) -> TransportError:
    return TransportError(
        error,
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        direction=ErrorDirection.READ,
    )
