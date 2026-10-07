"""Error translation for aioquic-like backends."""

from __future__ import annotations

import asyncio
from typing import Optional
from zmux.errors import (
    ApplicationError,
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
    TerminationKind,
    WriteClosed,
    WriteTimeout,
    ZmuxError,
)
from zmux.protocol import ErrorCode

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
    if isinstance(error, asyncio.TimeoutError):
        return WriteTimeout()
    if isinstance(error, AssertionError) and "after reset" in str(error):
        # aioquic resets the send half itself when the peer sends STOP_SENDING
        # and then asserts on later writes; the session is still alive.
        return WriteClosed(
            source=ErrorSource.REMOTE,
            termination_kind=TerminationKind.STOPPED,
        )
    return translate_error(error)


def _with_characters_written(error: BaseException, written: int) -> BaseException:
    """Return ``error`` carrying ``characters_written`` like ``BlockingIOError``.

    Native zmux sessions report bytes a failed write already handed to the
    send path the same way.  Stored stream errors are raised to later callers
    too, so the count is set on a shallow copy; the original is not modified.
    """

    if written <= 0:
        return error
    try:
        annotated = error.__class__.__new__(error.__class__)
        annotated.__dict__.update(error.__dict__)
        annotated.args = error.args
        annotated.characters_written = written
    except (AttributeError, TypeError):
        return error
    return annotated.with_traceback(error.__traceback__)


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
