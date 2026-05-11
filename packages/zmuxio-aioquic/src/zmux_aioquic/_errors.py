"""Error translation for aioquic-like backends."""

from __future__ import annotations

import asyncio
from typing import Optional

from zmux.errors import (
    ApplicationError,
    ErrorCode,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    OpenLimited,
    OpenMetadataTooLarge,
    ProtocolError,
    ReadClosed,
    ReadTimeout,
    SessionClosed,
    ZmuxError,
)
from ._validation import _require_application_code


def _protocol_prelude_error(
        operation: str, cause: Optional[BaseException] = None
) -> ProtocolError:
    error = ProtocolError(
        "zmux: malformed QUIC adapter stream prelude: %s" % operation,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.STREAM,
        operation=ErrorOperation.OPEN,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )
    if cause is not None:
        error.__cause__ = cause
    return error


def translate_open_error(error: BaseException) -> BaseException:
    if _is_stream_limit_error(error):
        return OpenLimited()
    return translate_error(error)


def translate_read_error(error: BaseException) -> BaseException:
    if isinstance(error, ZmuxError):
        return error
    if isinstance(error, EOFError):
        return ReadClosed(source=ErrorSource.REMOTE)
    return translate_error(error)


def translate_write_error(error: BaseException) -> BaseException:
    if isinstance(error, ZmuxError):
        return error
    return translate_error(error)


def _translate_wait_error(error: BaseException) -> Optional[BaseException]:
    translated = translate_error(error)
    if (
            isinstance(translated, ApplicationError)
            and translated.code == 0
            and translated.reason == ""
    ):
        return None
    return translated


def _accepted_prelude_rejectable(error: BaseException) -> bool:
    return isinstance(
        error, (OpenMetadataTooLarge, ProtocolError, ReadClosed, ReadTimeout)
    )


def translate_error(error: BaseException) -> BaseException:
    if isinstance(error, ZmuxError):
        return error
    if isinstance(error, asyncio.CancelledError):
        return error
    if isinstance(error, asyncio.TimeoutError):
        return ReadTimeout()
    app = _application_error_from_backend(error)
    if app is not None:
        return app
    if _is_stream_limit_error(error):
        return OpenLimited()
    name = error.__class__.__name__.lower()
    if "closed" in name or "connection" in name or "eof" in name:
        return SessionClosed(str(error) or "zmux: session closed", source=ErrorSource.TRANSPORT)
    return SessionClosed(
        "zmux: aioquic transport failure: %s" % (str(error) or error.__class__.__name__),
        source=ErrorSource.TRANSPORT,
    )


def _application_error_from_backend(error: BaseException) -> Optional[ApplicationError]:
    for attr in ("error_code", "code"):
        value = getattr(error, attr, None)
        if value is None:
            continue
        try:
            code = _require_application_code(int(value))
        except Exception:
            continue
        reason = getattr(error, "reason_phrase", None)
        if reason is None:
            reason = getattr(error, "reason", "")
        return ApplicationError(code, "" if reason is None else str(reason))
    return None


def _is_stream_limit_error(error: BaseException) -> bool:
    name = error.__class__.__name__.lower()
    text = str(error).lower()
    return "streamlimit" in name or "stream limit" in text or "too many streams" in text
