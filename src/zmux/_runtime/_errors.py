"""Shared constructors for runtime protocol errors."""

from __future__ import annotations

from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    ProtocolError,
)
from ..protocol import ErrorCode


def frame_size_error(
        message: str,
        *,
        operation: ErrorOperation,
        source: ErrorSource,
        direction: ErrorDirection,
) -> FrameSizeError:
    return FrameSizeError(
        message,
        code=int(ErrorCode.FRAME_SIZE),
        scope=ErrorScope.SESSION,
        operation=operation,
        source=source,
        direction=direction,
    )


def local_internal_error(
        message: str,
        *,
        operation: ErrorOperation,
        direction: ErrorDirection,
) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.INTERNAL),
        scope=ErrorScope.SESSION,
        operation=operation,
        source=ErrorSource.LOCAL,
        direction=direction,
    )
