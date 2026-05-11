"""Wire-level error helpers and sentinel messages."""

from __future__ import annotations

from typing import Optional, Union

from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    ProtocolError,
    ZmuxError,
    code as error_code,
    is_error_code,
)
from ..protocol import ErrorCode, MAX_VARINT62

ERR_INVALID_MAGIC = "invalid magic"
ERR_UNSUPPORTED_PREFACE_VERSION = "unsupported preface version"
ERR_INVALID_ROLE = "invalid role"
ERR_NON_CANONICAL_VARINT = "non-canonical varint62"
ERR_VALUE_TOO_LARGE = "varint62 value out of range"
ERR_TRUNCATED_VARINT = "truncated varint62"
ERR_TRUNCATED_TLV = "truncated tlv"
ERR_TLV_VALUE_OVERRUN = "tlv value overruns containing payload"
ERR_INVALID_FRAME_TYPE = "invalid frame type"
ERR_INVALID_FLAGS = "invalid flags for frame type"
ERR_SHORT_FRAME = "frame too short"
ERR_PAYLOAD_TOO_LARGE = "payload exceeds configured limit"
ERR_OPEN_INFO_UNAVAILABLE = "zmux: open_info requires negotiated open_metadata"
ERR_OPEN_METADATA_TOO_LARGE = "zmux: opening metadata exceeds peer max_frame_payload"
ERR_PRIORITY_UPDATE_UNAVAILABLE = (
    "zmux: metadata update requires negotiated priority_update and matching semantic capability"
)
ERR_PRIORITY_UPDATE_TOO_LARGE = (
    "zmux: priority update exceeds peer max_extension_payload_bytes"
)
ERR_EMPTY_METADATA_UPDATE = "zmux: metadata update has no fields"

_READ_OPERATION_PREFIXES = ("read ", "parse ")
_WRITE_OPERATION_PREFIXES = ("write ", "marshal ", "build ")
_READ_OPERATION_TOKENS = ("read", "parse")
_WRITE_OPERATION_TOKENS = ("write", "marshal", "build")
_OPEN_OPERATION_TOKENS = ("open", "negotiate", "resolve")

__all__ = (
    "ERR_EMPTY_METADATA_UPDATE",
    "ERR_INVALID_FLAGS",
    "ERR_INVALID_FRAME_TYPE",
    "ERR_INVALID_MAGIC",
    "ERR_INVALID_ROLE",
    "ERR_NON_CANONICAL_VARINT",
    "ERR_OPEN_INFO_UNAVAILABLE",
    "ERR_OPEN_METADATA_TOO_LARGE",
    "ERR_PAYLOAD_TOO_LARGE",
    "ERR_PRIORITY_UPDATE_TOO_LARGE",
    "ERR_PRIORITY_UPDATE_UNAVAILABLE",
    "ERR_SHORT_FRAME",
    "ERR_TLV_VALUE_OVERRUN",
    "ERR_TRUNCATED_TLV",
    "ERR_TRUNCATED_VARINT",
    "ERR_UNSUPPORTED_PREFACE_VERSION",
    "ERR_VALUE_TOO_LARGE",
    "WireError",
    "error_code_of",
    "frame_size_error",
    "is_code",
    "protocol_error",
    "wrap_error",
)


class WireError(ProtocolError):
    """Wire codec error carrying a standard zmux error code and operation."""


def wrap_error(
        code: Union[ErrorCode, int],
        operation: str,
        error: Optional[BaseException],
) -> ZmuxError:
    """Wrap ``error`` with wire codec context while preserving its cause."""

    operation_label = _operation_label(operation)
    message = str(error) if error is not None else str(operation)
    wrapped = _make_error(
        code,
        message,
        _operation_from_label(operation_label),
        source=_codec_error_source_label(operation_label),
        direction=_codec_error_direction_label(operation_label),
    )
    if error is not None:
        wrapped.__cause__ = error
    return wrapped


def error_code_of(error: BaseException) -> Optional[int]:
    """Return the numeric zmux error code carried by ``error``."""

    return error_code(error)


def is_code(error: BaseException, code: Union[ErrorCode, int]) -> bool:
    """Return whether ``error`` carries ``code``."""

    return is_error_code(error, _coerce_error_code(code))


def protocol_error(message: str, operation: Union[ErrorOperation, str]) -> ProtocolError:
    """Construct a remote session protocol error."""

    return _make_error(ErrorCode.PROTOCOL, message, _coerce_operation(operation))


def frame_size_error(message: str, operation: Union[ErrorOperation, str]) -> FrameSizeError:
    """Construct a frame-size error for wire codecs."""

    return _make_error(ErrorCode.FRAME_SIZE, message, _coerce_operation(operation))


def _make_error(
        code: Union[ErrorCode, int],
        message: str,
        operation: ErrorOperation,
        *,
        source: Optional[ErrorSource] = None,
        direction: Optional[ErrorDirection] = None,
) -> ProtocolError:
    code_value = _coerce_error_code(code)
    error_cls = FrameSizeError if code_value == int(ErrorCode.FRAME_SIZE) else WireError
    if source is None:
        if operation == ErrorOperation.READ:
            source = ErrorSource.REMOTE
        elif operation == ErrorOperation.WRITE:
            source = ErrorSource.LOCAL
        else:
            source = ErrorSource.UNKNOWN
    if direction is None:
        if operation == ErrorOperation.READ:
            direction = ErrorDirection.READ
        elif operation == ErrorOperation.WRITE:
            direction = ErrorDirection.WRITE
        else:
            direction = ErrorDirection.BOTH
    return error_cls(
        message,
        code=code_value,
        scope=ErrorScope.SESSION,
        operation=operation,
        source=source,
        direction=direction,
    )


def _operation_from_string(operation: str) -> ErrorOperation:
    return _operation_from_label(_operation_label(operation))


def _operation_from_label(label: str) -> ErrorOperation:
    if _contains_any(label, _READ_OPERATION_TOKENS):
        return ErrorOperation.READ
    if _contains_any(label, _WRITE_OPERATION_TOKENS):
        return ErrorOperation.WRITE
    if _contains_any(label, _OPEN_OPERATION_TOKENS):
        return ErrorOperation.OPEN
    if "close" in label:
        return ErrorOperation.CLOSE
    if "ping" in label:
        return ErrorOperation.PING
    if "accept" in label:
        return ErrorOperation.ACCEPT
    return ErrorOperation.UNKNOWN


def _coerce_error_code(code: Union[ErrorCode, int]) -> int:
    if isinstance(code, ErrorCode):
        return int(code)
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError("error code must be an ErrorCode or integer")
    if code < 0:
        raise ValueError("error code must be >= 0")
    if code > MAX_VARINT62:
        raise ValueError("error code must be within varint62 range")
    return int(code)


def _coerce_operation(operation: Union[ErrorOperation, str]) -> ErrorOperation:
    if isinstance(operation, ErrorOperation):
        return operation
    if isinstance(operation, bool) or not isinstance(operation, str):
        raise TypeError("operation must be an ErrorOperation or string")
    return _operation_from_string(operation)


def _codec_error_source(operation: str) -> ErrorSource:
    return _codec_error_source_label(_operation_label(operation))


def _codec_error_source_label(label: str) -> ErrorSource:
    if label.startswith(_READ_OPERATION_PREFIXES):
        return ErrorSource.REMOTE
    if label.startswith(_WRITE_OPERATION_PREFIXES):
        return ErrorSource.LOCAL
    return ErrorSource.UNKNOWN


def _codec_error_direction(operation: str) -> ErrorDirection:
    return _codec_error_direction_label(_operation_label(operation))


def _codec_error_direction_label(label: str) -> ErrorDirection:
    if label.startswith(_READ_OPERATION_PREFIXES):
        return ErrorDirection.READ
    if label.startswith(_WRITE_OPERATION_PREFIXES):
        return ErrorDirection.WRITE
    return ErrorDirection.BOTH


def _operation_label(operation: str) -> str:
    if isinstance(operation, bool) or not isinstance(operation, str):
        raise TypeError("operation must be a string")
    return str(operation or "").lower()


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)
