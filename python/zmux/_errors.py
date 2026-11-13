"""The exceptions of zmux. The native layer raises them by name; each sits
under `ZmuxError` and, where one fits, under the built-in exception that
asyncio and the standard library raise for the same condition."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._types import CandidateResult, ErrorKind

__all__ = [
    "ApplicationClosedError",
    "CarrierChoiceError",
    "ConnectError",
    "DatagramError",
    "EarlyDataRejectedError",
    "ExportError",
    "GoingAwayError",
    "HandshakeTimeoutError",
    "IdleTimeoutError",
    "IncompleteReadError",
    "JoinPendingError",
    "JoinRefusedError",
    "JoinSecretSetError",
    "LimitExceededError",
    "ListenerClosedError",
    "NoExporterError",
    "NoReplyError",
    "NotEstablishedError",
    "NotNegotiatedError",
    "OpenError",
    "PipeError",
    "PipeGoneError",
    "PipesLostError",
    "PreambleTooLargeError",
    "ResumeFailedError",
    "ResumeTimeoutError",
    "SessionClosedError",
    "StreamError",
    "StreamRejectedError",
    "StreamResetError",
    "StreamStoppedError",
    "TransportClosedError",
    "VerifyRejectedError",
    "VerifyUnavailableError",
    "ZmuxError",
]


class ZmuxError(Exception):
    """Base of every zmux error. `kind` names the native error, `retryable`
    tells whether the operation may succeed if repeated (a rejected or going
    away stream), and `code` is the application or transport error code
    where one applies."""

    kind: ErrorKind | str = ""
    retryable: bool = False
    code: int | None = None


class ConnectError(ZmuxError, ConnectionError):
    """Establishing a carrier or a session failed."""


class NoReplyError(ConnectError):
    """The secure carrier's server ended or timed out before message 2;
    `__cause__` is the end or the timeout."""


class SessionClosedError(ZmuxError, ConnectionError):
    """The session ended. `reason` and `remote` are set for application and
    transport closes; the subclasses name the kind of end."""

    reason: bytes | None = None
    remote: bool | None = None


class EarlyDataRejectedError(SessionClosedError):
    """The peer processed none of the early data; retry on a new session
    without it."""


class ApplicationClosedError(SessionClosedError):
    """Closed or aborted by either application."""


class TransportClosedError(SessionClosedError):
    """A protocol error ended the session."""


class IdleTimeoutError(SessionClosedError, TimeoutError):
    """The idle timer ended the session."""


class HandshakeTimeoutError(SessionClosedError, TimeoutError):
    """No peer parameters arrived in time."""


class ResumeTimeoutError(SessionClosedError, TimeoutError):
    """The resume grace period expired; `__cause__` is the last pipe's
    failure."""


class PipesLostError(SessionClosedError):
    """Every pipe in a direction was lost without resume; `__cause__` is the
    last pipe's failure."""


class ResumeFailedError(SessionClosedError):
    """Resume could not continue safely: the data in flight is in an
    unknown state."""


class StreamError(ZmuxError):
    """A stream operation failed."""


class StreamResetError(StreamError, ConnectionError):
    """The peer reset the stream; `code` is its error code."""


class StreamStoppedError(StreamError, ConnectionError):
    """The peer stopped reading the stream; `code` is its error code."""


class IncompleteReadError(StreamError, EOFError):
    """The stream finished before the requested bytes arrived: `partial`
    holds the bytes read, `expected` the count asked for (as
    `asyncio.IncompleteReadError`)."""

    partial: bytes = b""
    expected: int | None = None


class LimitExceededError(StreamError, ValueError):
    """The stream is longer than the read limit."""


class StreamRejectedError(StreamError):
    """The peer rejected the stream before processing it (retryable)."""


class GoingAwayError(StreamError):
    """The stream was opened after a GOAWAY or not taken before it
    (retryable)."""


class PreambleTooLargeError(ZmuxError, ValueError):
    """A stream's preamble is larger than the limit known: the peer's
    Maximum Preamble Size (before its parameters the remembered one or 1024
    bytes), at most 4096."""


class OpenError(ZmuxError):
    """Opening a stream failed."""


class DatagramError(ZmuxError):
    """Sending a datagram failed."""


class ListenerClosedError(ZmuxError):
    """The listener was closed."""


class PipeError(ZmuxError):
    """A pipe operation failed."""


class NotNegotiatedError(PipeError):
    """Multipath is not in use in this session."""


class NotEstablishedError(PipeError):
    """The session is not established yet."""


class JoinPendingError(PipeError):
    """The session has no join keys yet: the message names what is
    missing."""


class JoinRefusedError(PipeError):
    """The peer refused the join; the join backoff started."""


class JoinSecretSetError(PipeError):
    """The deferred pre-shared key was given already."""


class PipeGoneError(PipeError):
    """No such pipe: it was retired."""


class ExportError(ZmuxError):
    """Exporting keying material gave no value."""


class NoExporterError(ExportError):
    """The session has no exporter."""


class VerifyRejectedError(ZmuxError):
    """A verifier or gate does not accept the peer: it counts for the
    reject policy."""


class VerifyUnavailableError(ZmuxError):
    """A verifier or gate could not decide now, no fault of the peer."""


class CarrierChoiceError(ZmuxError):
    """No candidate of a carrier choice was usable: `results` lists every
    try in order."""

    def __init__(self, message: str, results: Any = ()) -> None:
        super().__init__(message)
        self.results: tuple[CandidateResult, ...] = tuple(results)


for _cls in list(globals().values()):
    if isinstance(_cls, type) and issubclass(_cls, ZmuxError):
        _cls.__module__ = "zmux"
del _cls
