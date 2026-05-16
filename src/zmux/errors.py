"""Exception types raised by zmux."""

from __future__ import annotations

from enum import Enum
from typing import Optional, Type, TypeVar

from .protocol import ErrorCode, MAX_VARINT62

OPEN_INFO_UNAVAILABLE_MESSAGE = "zmux: open_info requires negotiated open_metadata"
OPEN_METADATA_TOO_LARGE_MESSAGE = (
    "zmux: opening metadata exceeds peer max_frame_payload"
)
EMPTY_METADATA_UPDATE_MESSAGE = "zmux: metadata update has no fields"
PRIORITY_UPDATE_UNAVAILABLE_MESSAGE = (
    "zmux: metadata update requires negotiated priority_update and matching semantic capability"
)
PRIORITY_UPDATE_TOO_LARGE_MESSAGE = (
    "zmux: priority update exceeds peer max_extension_payload_bytes"
)
KEEPALIVE_TIMEOUT_MESSAGE = "zmux: keepalive timeout"
ACCEPT_TIMEOUT_MESSAGE = "zmux: accept timed out"
OPEN_TIMEOUT_MESSAGE = "zmux: open timed out"
READ_TIMEOUT_MESSAGE = "zmux: read timed out"
WRITE_TIMEOUT_MESSAGE = "zmux: write timed out"
PING_TIMEOUT_MESSAGE = "zmux: ping timed out"
SESSION_WAIT_TIMEOUT_MESSAGE = "zmux: session wait timed out"
JOINED_HALF_PAUSE_TIMEOUT_MESSAGE = "zmux: joined half pause timed out"
GRACEFUL_CLOSE_TIMEOUT_MESSAGE = "zmux: graceful close drain timed out"
NIL_CONN_MESSAGE = "zmux: nil conn"
STREAM_CLOSED_MESSAGE = "zmux: stream closed"
SESSION_CLOSED_MESSAGE = "zmux: session closed"
READ_SIDE_CLOSED_MESSAGE = "zmux: read side closed"
WRITE_SIDE_CLOSED_MESSAGE = "zmux: write side closed"
STREAM_NOT_READABLE_MESSAGE = "zmux: stream is not readable"
STREAM_NOT_WRITABLE_MESSAGE = "zmux: stream is not writable"
OPEN_LIMITED_MESSAGE = "zmux: too many provisional local opens"
OPEN_EXPIRED_MESSAGE = "zmux: provisional local open expired before first-frame commit"
ADAPTER_UNSUPPORTED_MESSAGE = "zmux: feature not supported by adapter"

ADAPTER_UNSUPPORTED_FRAGMENT = "feature not supported by adapter"
LOCAL_OPEN_LIMITED_BY_SESSION_MEMORY_CAP_FRAGMENT = (
    "local open limited by session memory cap"
)
PROVISIONAL_OPEN_LIMIT_REACHED_FRAGMENT = "provisional open limit reached"
PROVISIONAL_LOCAL_OPEN_EXPIRED_FRAGMENT = "provisional local open expired"
PRIORITY_UPDATE_UNAVAILABLE_FRAGMENT = (
    "metadata update requires negotiated priority_update"
)

MAX_ERROR_UNWRAP_DEPTH = 64

_E = TypeVar("_E", bound=BaseException)


class ErrorScope(str, Enum):
    """Where an error applies."""

    UNKNOWN = "unknown"
    SESSION = "session"
    STREAM = "stream"


class ErrorOperation(str, Enum):
    """Operation family active when an error was observed."""

    UNKNOWN = "unknown"
    OPEN = "open"
    ACCEPT = "accept"
    PING = "ping"
    READ = "read"
    WRITE = "write"
    CLOSE = "close"


class ErrorSource(str, Enum):
    """Locality of an error."""

    UNKNOWN = "unknown"
    LOCAL = "local"
    REMOTE = "remote"
    TRANSPORT = "transport"


class ErrorDirection(str, Enum):
    """I/O direction affected by an error."""

    UNKNOWN = "unknown"
    READ = "read"
    WRITE = "write"
    BOTH = "both"


class TerminationKind(str, Enum):
    """Terminal state category carried by an error."""

    UNKNOWN = "unknown"
    GRACEFUL = "graceful"
    STOPPED = "stopped"
    RESET = "reset"
    ABORT = "abort"
    SESSION_TERMINATION = "session_termination"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"


class ZmuxError(Exception):
    """Base class for all zmux exceptions."""

    def __init__(
            self,
            message: str = "",
            *,
            code: Optional[int] = None,
            scope: ErrorScope = ErrorScope.UNKNOWN,
            operation: ErrorOperation = ErrorOperation.UNKNOWN,
            source: ErrorSource = ErrorSource.UNKNOWN,
            direction: ErrorDirection = ErrorDirection.UNKNOWN,
            termination_kind: TerminationKind = TerminationKind.UNKNOWN,
    ) -> None:
        super().__init__(message)
        self.code = None if code is None else _require_error_code(code, "code")
        self.scope = _coerce_enum(scope, ErrorScope, "scope")
        self.operation = _coerce_enum(operation, ErrorOperation, "operation")
        self.source = _coerce_enum(source, ErrorSource, "source")
        self.direction = _coerce_enum(direction, ErrorDirection, "direction")
        self.termination_kind = _coerce_enum(
            termination_kind, TerminationKind, "termination_kind"
        )

    @property
    def message(self) -> str:
        """Return the human-readable error message."""

        return str(self)

    def is_error_code(self, code: ErrorCode) -> bool:
        """Return whether this error carries ``code``."""

        return self.code == _require_error_code(code, "code")

    @property
    def numeric_code(self) -> Optional[int]:
        """Return the numeric zmux code carried by this error, if any."""

        return self.code

    @property
    def application_code(self) -> Optional[int]:
        """Return the application code when this is an application error."""

        return None

    def with_scope(self, scope: ErrorScope) -> "ZmuxError":
        scope = _coerce_enum(scope, ErrorScope, "scope")
        if scope != ErrorScope.UNKNOWN:
            self.scope = scope
        return self

    def with_operation(self, operation: ErrorOperation) -> "ZmuxError":
        operation = _coerce_enum(operation, ErrorOperation, "operation")
        if operation != ErrorOperation.UNKNOWN:
            self.operation = operation
        return self

    def with_source(self, source: ErrorSource) -> "ZmuxError":
        source = _coerce_enum(source, ErrorSource, "source")
        if source != ErrorSource.UNKNOWN:
            self.source = source
        return self

    def with_direction(self, direction: ErrorDirection) -> "ZmuxError":
        direction = _coerce_enum(direction, ErrorDirection, "direction")
        if direction != ErrorDirection.UNKNOWN:
            self.direction = direction
        return self

    def with_termination_kind(self, termination_kind: TerminationKind) -> "ZmuxError":
        termination_kind = _coerce_enum(
            termination_kind, TerminationKind, "termination_kind"
        )
        if termination_kind != TerminationKind.UNKNOWN:
            self.termination_kind = termination_kind
        return self

    def with_session_context(
            self, operation: ErrorOperation = ErrorOperation.UNKNOWN
    ) -> "ZmuxError":
        """Apply standard session-scope context to this error."""

        self.scope = ErrorScope.SESSION
        if operation != ErrorOperation.UNKNOWN:
            self.operation = _coerce_enum(operation, ErrorOperation, "operation")
        if self.direction == ErrorDirection.UNKNOWN:
            self.direction = ErrorDirection.BOTH
        if (
                self.termination_kind == TerminationKind.UNKNOWN
                and isinstance(self, (SessionClosed, ApplicationError))
        ):
            self.termination_kind = TerminationKind.SESSION_TERMINATION
        return self

    def with_stream_context(
            self,
            operation: ErrorOperation = ErrorOperation.UNKNOWN,
            direction: ErrorDirection = ErrorDirection.UNKNOWN,
    ) -> "ZmuxError":
        """Apply standard stream-scope context to this error."""

        self.scope = ErrorScope.STREAM
        if operation != ErrorOperation.UNKNOWN:
            self.operation = _coerce_enum(operation, ErrorOperation, "operation")
        if direction != ErrorDirection.UNKNOWN:
            self.direction = _coerce_enum(direction, ErrorDirection, "direction")
        if (
                self.termination_kind == TerminationKind.UNKNOWN
                and isinstance(self, SessionClosed)
        ):
            self.termination_kind = TerminationKind.SESSION_TERMINATION
        return self


class ProtocolError(ZmuxError):
    """Raised when incoming bytes violate the zmux protocol."""


class StreamClosed(ZmuxError):
    """Raised when an operation is attempted on a closed stream."""

    def __init__(self, message: str = STREAM_CLOSED_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("code", int(ErrorCode.STREAM_CLOSED))
        super().__init__(message, **kwargs)


class SessionClosed(ZmuxError):
    """Raised when an operation is attempted on a closed session."""

    def __init__(self, message: str = SESSION_CLOSED_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("code", int(ErrorCode.SESSION_CLOSING))
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        kwargs.setdefault("termination_kind", TerminationKind.SESSION_TERMINATION)
        super().__init__(message, **kwargs)


class FlowControlError(ProtocolError):
    """Raised when peer traffic exceeds flow-control limits."""


class FrameSizeError(ProtocolError):
    """Raised when a frame violates negotiated size limits."""


class TransportError(ZmuxError):
    """Raised when the underlying byte transport fails."""

    def __init__(
            self,
            source_error: BaseException,
            message: Optional[str] = None,
            **kwargs: object,
    ) -> None:
        if not isinstance(source_error, BaseException):
            raise TypeError("source_error must be an exception")
        kwargs.setdefault("code", int(ErrorCode.INTERNAL))
        kwargs.setdefault("source", ErrorSource.TRANSPORT)
        kwargs.setdefault(
            "termination_kind", _termination_kind_from_exception(source_error)
        )
        super().__init__(
            str(source_error) if message is None else str(message),
            **kwargs,
        )
        self.source_error = source_error
        self.__cause__ = source_error


class NilConnection(ZmuxError):
    """Raised when a native constructor receives no transport connection."""

    def __init__(self, message: str = NIL_CONN_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.OPEN)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        super().__init__(message, **kwargs)


class ReadClosed(ZmuxError):
    """Raised when a read operation uses a closed receive side."""

    def __init__(self, message: str = READ_SIDE_CLOSED_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.READ)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.READ)
        kwargs.setdefault("termination_kind", TerminationKind.STOPPED)
        super().__init__(message, **kwargs)


class WriteClosed(ZmuxError):
    """Raised when a write operation uses a closed send side."""

    def __init__(
            self, message: str = WRITE_SIDE_CLOSED_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.WRITE)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        kwargs.setdefault("termination_kind", TerminationKind.GRACEFUL)
        super().__init__(message, **kwargs)


class StreamNotReadable(ZmuxError):
    """Raised when a stream does not expose a receive side."""

    def __init__(
            self, message: str = STREAM_NOT_READABLE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.READ)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.READ)
        super().__init__(message, **kwargs)


class StreamNotWritable(ZmuxError):
    """Raised when a stream does not expose a send side."""

    def __init__(
            self, message: str = STREAM_NOT_WRITABLE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.WRITE)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class OpenLimited(ZmuxError):
    """Raised when local stream opening is limited by runtime policy."""

    def __init__(self, message: str = OPEN_LIMITED_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.OPEN)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class OpenExpired(ZmuxError):
    """Raised when a provisional open expires before first-frame commit."""

    def __init__(self, message: str = OPEN_EXPIRED_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("code", int(ErrorCode.CANCELLED))
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.OPEN)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        kwargs.setdefault("termination_kind", TerminationKind.ABORT)
        super().__init__(message, **kwargs)


class AdapterUnsupported(ZmuxError):
    """Raised when an adapter does not support a requested feature."""

    def __init__(
            self, message: str = ADAPTER_UNSUPPORTED_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("source", ErrorSource.LOCAL)
        super().__init__(message, **kwargs)


class OpenInfoUnavailable(ProtocolError):
    """Raised when open_info is used without negotiated open_metadata."""

    def __init__(
            self, message: str = OPEN_INFO_UNAVAILABLE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("code", int(ErrorCode.PROTOCOL))
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.OPEN)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class OpenMetadataTooLarge(ProtocolError):
    """Raised when opening metadata exceeds the peer DATA payload limit."""

    def __init__(
            self, message: str = OPEN_METADATA_TOO_LARGE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("code", int(ErrorCode.PROTOCOL))
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.OPEN)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class PriorityUpdateUnavailable(AdapterUnsupported):
    """Raised when PRIORITY_UPDATE is unavailable for negotiated capabilities."""

    def __init__(
            self, message: str = PRIORITY_UPDATE_UNAVAILABLE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.WRITE)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class PriorityUpdateTooLarge(ProtocolError):
    """Raised when PRIORITY_UPDATE exceeds peer extension payload limits."""

    def __init__(
            self, message: str = PRIORITY_UPDATE_TOO_LARGE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("code", int(ErrorCode.PROTOCOL))
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.WRITE)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class EmptyMetadataUpdate(ZmuxError):
    """Raised when a metadata update contains no fields."""

    def __init__(
            self, message: str = EMPTY_METADATA_UPDATE_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.WRITE)
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class ZmuxTimeoutError(ZmuxError, TimeoutError):
    """Base class for zmux timeouts."""

    def __init__(self, message: str, **kwargs: object) -> None:
        kwargs.setdefault("source", ErrorSource.LOCAL)
        kwargs.setdefault("termination_kind", TerminationKind.TIMEOUT)
        super().__init__(message, **kwargs)


class AcceptTimeout(ZmuxTimeoutError):
    def __init__(self, message: str = ACCEPT_TIMEOUT_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.ACCEPT)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class OpenTimeout(ZmuxTimeoutError):
    def __init__(self, message: str = OPEN_TIMEOUT_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.OPEN)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class ReadTimeout(ZmuxTimeoutError):
    def __init__(self, message: str = READ_TIMEOUT_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.READ)
        kwargs.setdefault("direction", ErrorDirection.READ)
        super().__init__(message, **kwargs)


class WriteTimeout(ZmuxTimeoutError):
    def __init__(self, message: str = WRITE_TIMEOUT_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.WRITE)
        kwargs.setdefault("direction", ErrorDirection.WRITE)
        super().__init__(message, **kwargs)


class PingTimeout(ZmuxTimeoutError):
    def __init__(self, message: str = PING_TIMEOUT_MESSAGE, **kwargs: object) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.PING)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class SessionWaitTimeout(ZmuxTimeoutError):
    def __init__(
            self, message: str = SESSION_WAIT_TIMEOUT_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.CLOSE)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class JoinedHalfPauseTimeout(ZmuxTimeoutError):
    def __init__(
            self, message: str = JOINED_HALF_PAUSE_TIMEOUT_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.STREAM)
        kwargs.setdefault("operation", ErrorOperation.UNKNOWN)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class GracefulCloseTimeout(ZmuxTimeoutError):
    def __init__(
            self, message: str = GRACEFUL_CLOSE_TIMEOUT_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.CLOSE)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class KeepaliveTimeout(ZmuxTimeoutError):
    def __init__(
            self, message: str = KEEPALIVE_TIMEOUT_MESSAGE, **kwargs: object
    ) -> None:
        kwargs.setdefault("code", int(ErrorCode.IDLE_TIMEOUT))
        kwargs.setdefault("scope", ErrorScope.SESSION)
        kwargs.setdefault("operation", ErrorOperation.PING)
        kwargs.setdefault("direction", ErrorDirection.BOTH)
        super().__init__(message, **kwargs)


class ZmuxInterruptedError(ZmuxError, InterruptedError):
    """Raised when a zmux operation is interrupted."""

    def __init__(self, message: str = "zmux: interrupted", **kwargs: object) -> None:
        kwargs.setdefault("termination_kind", TerminationKind.INTERRUPTED)
        super().__init__(message, **kwargs)


class ApplicationError(ZmuxError):
    """Application-defined code carried by stream or session termination."""

    def __init__(
            self,
            code: int,
            reason: str = "",
            *,
            scope: ErrorScope = ErrorScope.UNKNOWN,
            operation: ErrorOperation = ErrorOperation.UNKNOWN,
            source: ErrorSource = ErrorSource.UNKNOWN,
            direction: ErrorDirection = ErrorDirection.BOTH,
            termination_kind: Optional[TerminationKind] = None,
    ) -> None:
        if isinstance(code, bool) or not isinstance(code, int):
            raise TypeError("zmux application error code must be an integer")
        if code < 0:
            raise ValueError("zmux application error code must be >= 0")
        if code > MAX_VARINT62:
            raise ValueError("zmux application error code must be within varint62 range")
        reason = "" if reason is None else str(reason)
        if termination_kind is None:
            termination_kind = _default_termination_kind(code)
        message = (
            "zmux application error %d" % code
            if not reason
            else "zmux application error %d: %s" % (code, reason)
        )
        super().__init__(
            message,
            code=code,
            scope=scope,
            operation=operation,
            source=source,
            direction=direction,
            termination_kind=termination_kind,
        )
        self.reason = reason

    @property
    def application_code(self) -> Optional[int]:
        return self.code

    def clone(self) -> "ApplicationError":
        return ApplicationError(
            self.code or 0,
            self.reason,
            scope=self.scope,
            operation=self.operation,
            source=self.source,
            direction=self.direction,
            termination_kind=self.termination_kind,
        )


def error_code_name(code: int) -> str:
    """Return a stable name for a core or application-defined error code."""

    try:
        return ErrorCode(_require_error_code(code, "code")).name
    except ValueError:
        return "APPLICATION_ERROR"


# noinspection PyTypeHints
def find_error(error: BaseException, error_type: Type[_E]) -> Optional[_E]:
    """Find the first nested exception of ``error_type`` within ``error``."""

    for candidate in _iter_error_tree(error):
        if isinstance(candidate, error_type):
            return candidate
    return None


def has_code(error: BaseException) -> bool:
    """Return whether a nested zmux error carries a numeric code."""

    return (
            _find_zmux_error(error, lambda candidate: candidate.numeric_code is not None)
            is not None
    )


def error_code(error: BaseException, fallback: Optional[int] = None) -> Optional[int]:
    """Return a nested zmux error code, or ``fallback``."""

    found = _find_zmux_error(error, lambda candidate: candidate.numeric_code is not None)
    return fallback if found is None else found.numeric_code


def typed_code(error: BaseException) -> Optional[ErrorCode]:
    """Return a standard typed error code if one is carried."""

    numeric = error_code(error)
    if numeric is None:
        return None
    try:
        return ErrorCode(numeric)
    except ValueError:
        return None


def is_error_code(error: BaseException, expected: int) -> bool:
    """Return whether a nested zmux error carries ``expected``."""

    return error_code(error) == _require_error_code(expected, "expected")


def error_reason(error: BaseException) -> str:
    """Return the application reason or best available exception message."""

    app = find_error(error, ApplicationError)
    if app is not None:
        return app.reason
    found = find_error(error, ZmuxError)
    if found is not None and found.message:
        return found.message
    return "" if error is None else str(error)


def error_scope(error: BaseException) -> ErrorScope:
    found = find_error(error, ZmuxError)
    return ErrorScope.UNKNOWN if found is None else found.scope


def error_operation(error: BaseException) -> ErrorOperation:
    found = find_error(error, ZmuxError)
    return ErrorOperation.UNKNOWN if found is None else found.operation


def error_source(error: BaseException) -> ErrorSource:
    found = find_error(error, ZmuxError)
    return ErrorSource.UNKNOWN if found is None else found.source


def error_direction(error: BaseException) -> ErrorDirection:
    found = find_error(error, ZmuxError)
    return ErrorDirection.UNKNOWN if found is None else found.direction


def error_termination_kind(error: BaseException) -> TerminationKind:
    found = find_error(error, ZmuxError)
    return TerminationKind.UNKNOWN if found is None else found.termination_kind


def as_structured_error(error: BaseException) -> Optional[ZmuxError]:
    """Return the first nested zmux structured error, if present."""

    return find_error(error, ZmuxError)


def session_closed(error: BaseException) -> bool:
    found = find_error(error, ZmuxError)
    return (
            isinstance(found, SessionClosed)
            or (found is not None and found.is_error_code(ErrorCode.SESSION_CLOSING))
            or _message_matches(error, SESSION_CLOSED_MESSAGE)
    )


def stream_closed(error: BaseException) -> bool:
    found = find_error(error, ZmuxError)
    return (
            isinstance(found, StreamClosed)
            or (found is not None and found.is_error_code(ErrorCode.STREAM_CLOSED))
            or _message_matches(error, STREAM_CLOSED_MESSAGE)
    )


def read_closed(error: BaseException) -> bool:
    return find_error(error, ReadClosed) is not None or _message_matches(
        error, READ_SIDE_CLOSED_MESSAGE
    )


def write_closed(error: BaseException) -> bool:
    return find_error(error, WriteClosed) is not None or _message_matches(
        error, WRITE_SIDE_CLOSED_MESSAGE
    )


def stream_not_readable(error: BaseException) -> bool:
    return find_error(error, StreamNotReadable) is not None or _message_matches(
        error, STREAM_NOT_READABLE_MESSAGE
    )


def stream_not_writable(error: BaseException) -> bool:
    return find_error(error, StreamNotWritable) is not None or _message_matches(
        error, STREAM_NOT_WRITABLE_MESSAGE
    )


def open_limited(error: BaseException) -> bool:
    message = error_reason(error)
    return (
            find_error(error, OpenLimited) is not None
            or OPEN_LIMITED_MESSAGE == message
            or LOCAL_OPEN_LIMITED_BY_SESSION_MEMORY_CAP_FRAGMENT in message
            or PROVISIONAL_OPEN_LIMIT_REACHED_FRAGMENT in message
    )


def open_expired(error: BaseException) -> bool:
    return _matches_named_error_fragment(
        error,
        OpenExpired,
        OPEN_EXPIRED_MESSAGE,
        PROVISIONAL_LOCAL_OPEN_EXPIRED_FRAGMENT,
    )


def open_info_unavailable(error: BaseException) -> bool:
    return _matches_named_error(error, OpenInfoUnavailable, OPEN_INFO_UNAVAILABLE_MESSAGE)


def open_metadata_too_large(error: BaseException) -> bool:
    return _matches_named_error(error, OpenMetadataTooLarge, OPEN_METADATA_TOO_LARGE_MESSAGE)


def adapter_unsupported(error: BaseException) -> bool:
    message = error_reason(error)
    return (
            find_error(error, AdapterUnsupported) is not None
            or ADAPTER_UNSUPPORTED_FRAGMENT in message
    )


def priority_update_unavailable(error: BaseException) -> bool:
    return _matches_named_error_fragment(
        error,
        PriorityUpdateUnavailable,
        PRIORITY_UPDATE_UNAVAILABLE_MESSAGE,
        PRIORITY_UPDATE_UNAVAILABLE_FRAGMENT,
    )


def priority_update_too_large(error: BaseException) -> bool:
    return _matches_named_error(error, PriorityUpdateTooLarge, PRIORITY_UPDATE_TOO_LARGE_MESSAGE)


def empty_metadata_update(error: BaseException) -> bool:
    return _matches_named_error(error, EmptyMetadataUpdate, EMPTY_METADATA_UPDATE_MESSAGE)


def keepalive_timeout(error: BaseException) -> bool:
    found = _find_zmux_error(
        error,
        lambda candidate: isinstance(candidate, KeepaliveTimeout)
                          or (
                                  candidate.is_error_code(ErrorCode.IDLE_TIMEOUT)
                                  and (
                                          candidate.message == KEEPALIVE_TIMEOUT_MESSAGE
                                          or error_reason(candidate) == KEEPALIVE_TIMEOUT_MESSAGE
                                  )
                          ),
    )
    return found is not None


def graceful_close_timeout(error: BaseException) -> bool:
    return find_error(error, GracefulCloseTimeout) is not None or _message_matches(
        error, GRACEFUL_CLOSE_TIMEOUT_MESSAGE
    )


def timeout(error: BaseException) -> bool:
    return (
            _find_zmux_error(
                error,
                lambda candidate: candidate.termination_kind == TerminationKind.TIMEOUT
                                  or candidate.is_error_code(ErrorCode.IDLE_TIMEOUT),
            )
            is not None
    ) or _contains_error_type(error, TimeoutError) or _message_looks_like_timeout(error)


def interrupted(error: BaseException) -> bool:
    return (
            _find_zmux_error(
                error,
                lambda candidate: candidate.termination_kind
                                  == TerminationKind.INTERRUPTED,
            )
            is not None
    ) or _contains_error_type(error, InterruptedError)


def source_exception(error: BaseException) -> Optional[BaseException]:
    """Return the underlying transport exception carried by ``error``, if any."""

    found = find_error(error, TransportError)
    return None if found is None else found.source_error


def _contains_error_type(error: BaseException, error_type: Type[BaseException]) -> bool:
    return find_error(error, error_type) is not None


def _message_matches(error: BaseException, expected: str) -> bool:
    for candidate in _iter_error_tree(error):
        if isinstance(candidate, ZmuxError) and candidate.message == expected:
            return True
        if str(candidate) == expected:
            return True
    return False


def _matches_named_error(
        error: BaseException,
        error_type: Type[BaseException],
        expected: str,
) -> bool:
    return _contains_error_type(error, error_type) or _message_matches(error, expected)


def _matches_named_error_fragment(
        error: BaseException,
        error_type: Type[BaseException],
        expected: str,
        fragment: str,
) -> bool:
    message = error_reason(error)
    return (
            find_error(error, error_type) is not None
            or message == expected
            or fragment in message
    )


def _message_looks_like_timeout(error: BaseException) -> bool:
    for candidate in _iter_error_tree(error):
        message = str(candidate)
        if message.startswith("zmux: ") and message.endswith(" timed out"):
            return True
    return False


def _find_zmux_error(error: BaseException, predicate) -> Optional[ZmuxError]:
    for candidate in _iter_error_tree(error):
        if isinstance(candidate, ZmuxError) and predicate(candidate):
            return candidate
    return None


def _iter_error_tree(error: BaseException):
    if error is None:
        return
    stack = [(error, 0)]
    seen = set()
    while stack:
        current, depth = stack.pop()
        if current is None or depth > MAX_ERROR_UNWRAP_DEPTH:
            continue
        ident = id(current)
        if ident in seen:
            continue
        seen.add(ident)
        yield current
        children = tuple(_iter_nested_errors(current))
        for child in reversed(children):
            stack.append((child, depth + 1))


def _iter_nested_errors(error: BaseException):
    cause = getattr(error, "__cause__", None)
    if cause is not None:
        yield cause
    context = getattr(error, "__context__", None)
    if context is not None and context is not cause:
        yield context
    try:
        children = iter(getattr(error, "exceptions", ()) or ())
    except TypeError:
        children = ()
    for child in children:
        if isinstance(child, BaseException):
            yield child


def _default_termination_kind(code_value: int) -> TerminationKind:
    return (
        TerminationKind.TIMEOUT
        if code_value == int(ErrorCode.IDLE_TIMEOUT)
        else TerminationKind.UNKNOWN
    )


def _termination_kind_from_exception(error: BaseException) -> TerminationKind:
    if isinstance(error, TimeoutError):
        return TerminationKind.TIMEOUT
    if isinstance(error, InterruptedError):
        return TerminationKind.INTERRUPTED
    return TerminationKind.UNKNOWN


def _require_error_code(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % field_name)
    return int(value)


def _coerce_enum(value, enum_type, field_name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        return enum_type(value)
    raise TypeError("%s must be a %s" % (field_name, enum_type.__name__))


__all__ = [
    "ACCEPT_TIMEOUT_MESSAGE",
    "ADAPTER_UNSUPPORTED_MESSAGE",
    "EMPTY_METADATA_UPDATE_MESSAGE",
    "GRACEFUL_CLOSE_TIMEOUT_MESSAGE",
    "JOINED_HALF_PAUSE_TIMEOUT_MESSAGE",
    "KEEPALIVE_TIMEOUT_MESSAGE",
    "NIL_CONN_MESSAGE",
    "OPEN_EXPIRED_MESSAGE",
    "OPEN_INFO_UNAVAILABLE_MESSAGE",
    "OPEN_LIMITED_MESSAGE",
    "OPEN_METADATA_TOO_LARGE_MESSAGE",
    "OPEN_TIMEOUT_MESSAGE",
    "PING_TIMEOUT_MESSAGE",
    "PRIORITY_UPDATE_TOO_LARGE_MESSAGE",
    "PRIORITY_UPDATE_UNAVAILABLE_MESSAGE",
    "READ_SIDE_CLOSED_MESSAGE",
    "READ_TIMEOUT_MESSAGE",
    "SESSION_CLOSED_MESSAGE",
    "SESSION_WAIT_TIMEOUT_MESSAGE",
    "STREAM_CLOSED_MESSAGE",
    "STREAM_NOT_READABLE_MESSAGE",
    "STREAM_NOT_WRITABLE_MESSAGE",
    "WRITE_SIDE_CLOSED_MESSAGE",
    "WRITE_TIMEOUT_MESSAGE",
    "AcceptTimeout",
    "AdapterUnsupported",
    "ApplicationError",
    "EmptyMetadataUpdate",
    "ErrorDirection",
    "ErrorOperation",
    "ErrorScope",
    "ErrorSource",
    "FlowControlError",
    "FrameSizeError",
    "GracefulCloseTimeout",
    "JoinedHalfPauseTimeout",
    "KeepaliveTimeout",
    "NilConnection",
    "OpenExpired",
    "OpenInfoUnavailable",
    "OpenLimited",
    "OpenMetadataTooLarge",
    "OpenTimeout",
    "PingTimeout",
    "PriorityUpdateTooLarge",
    "PriorityUpdateUnavailable",
    "ProtocolError",
    "ReadClosed",
    "ReadTimeout",
    "SessionClosed",
    "SessionWaitTimeout",
    "StreamClosed",
    "StreamNotReadable",
    "StreamNotWritable",
    "TerminationKind",
    "TransportError",
    "WriteClosed",
    "WriteTimeout",
    "ZmuxError",
    "ZmuxInterruptedError",
    "ZmuxTimeoutError",
    "adapter_unsupported",
    "as_structured_error",
    "empty_metadata_update",
    "error_code",
    "error_code_name",
    "error_direction",
    "error_operation",
    "error_reason",
    "error_scope",
    "error_source",
    "error_termination_kind",
    "find_error",
    "graceful_close_timeout",
    "has_code",
    "interrupted",
    "is_error_code",
    "keepalive_timeout",
    "open_expired",
    "open_info_unavailable",
    "open_limited",
    "open_metadata_too_large",
    "priority_update_too_large",
    "priority_update_unavailable",
    "read_closed",
    "session_closed",
    "source_exception",
    "stream_closed",
    "stream_not_readable",
    "stream_not_writable",
    "timeout",
    "typed_code",
    "write_closed",
]
