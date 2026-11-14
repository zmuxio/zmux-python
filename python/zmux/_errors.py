"""The exceptions of zmux. The native layer raises them by name; each sits
under `ZmuxError` and, where one fits, under the built-in exception that
asyncio and the standard library raise for the same condition."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._types import CandidateResult, ErrorKind

__all__ = [
    "ApplicationClosedError",
    "CarrierChoiceError",
    "ConnectError",
    "DatagramError",
    "DeadlineExceededError",
    "EarlyDataRejectedError",
    "ExportError",
    "GoingAwayError",
    "HandshakeTimeoutError",
    "IdleTimeoutError",
    "IncompleteReadError",
    "InvalidArgumentError",
    "JoinPendingError",
    "JoinRefusedError",
    "JoinSecretSetError",
    "LimitExceededError",
    "ListenerClosedError",
    "NoExporterError",
    "NoReplyError",
    "NoRunningLoopError",
    "NotEstablishedError",
    "NotNegotiatedError",
    "PipeError",
    "PipeGoneError",
    "PipeUsedError",
    "PipesLostError",
    "PreambleTooLargeError",
    "ResumeFailedError",
    "ResumeTimeoutError",
    "SessionClosedError",
    "StreamBusyError",
    "StreamClosedError",
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
    away stream, a session lost to rejected early data), and `code` is the
    application or transport error code where one applies."""

    kind: ErrorKind | str = ""
    retryable: bool = False
    code: int | None = None


class InvalidArgumentError(ZmuxError, ValueError):
    """A value the caller passed cannot be used: an invalid configuration or
    option, an oversized or malformed preamble."""


class DeadlineExceededError(ZmuxError, TimeoutError):
    """A bound the library applies expired, such as `Config.join_timeout` for
    `Session.add_pipe`; the object stays usable. It is never the end of a
    session: a caller's own `asyncio.timeout` raises its own `TimeoutError`."""


class NoRunningLoopError(ZmuxError, RuntimeError):
    """The call needs a running asyncio event loop."""


class PipeUsedError(ZmuxError):
    """The pipe input was given to a session or a listener already."""


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


class IdleTimeoutError(SessionClosedError):
    """The idle timer ended the session."""


class HandshakeTimeoutError(SessionClosedError):
    """No peer parameters arrived in time."""


class ResumeTimeoutError(SessionClosedError):
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


class IncompleteReadError(StreamError, asyncio.IncompleteReadError):
    """The stream finished before the requested bytes arrived: `partial`
    holds the bytes read, `expected` the count asked for. It is the one
    `asyncio.IncompleteReadError` of this library, also raised by
    `StreamPairReader`."""


class LimitExceededError(StreamError):
    """The stream is longer than the read limit."""


class StreamRejectedError(StreamError):
    """The peer rejected the stream before processing it (retryable)."""


class GoingAwayError(StreamError):
    """The stream was opened after a GOAWAY or not taken before it
    (retryable)."""


class StreamClosedError(StreamError):
    """The stream direction was closed by this endpoint already: finished,
    reset, stopped or taken by another call."""


class StreamBusyError(StreamError):
    """Another operation on the stream part is in progress; a part takes one
    operation at a time."""


class PreambleTooLargeError(ZmuxError, ValueError):
    """A stream's preamble is larger than the limit known: the peer's
    Maximum Preamble Size (before its parameters the remembered one or 1024
    bytes), at most 4096."""


class NotNegotiatedError(ZmuxError):
    """The peer did not negotiate what the operation needs: multipath, or a
    preamble or priority extension it does not speak."""


class NotEstablishedError(ZmuxError):
    """The session is not established yet."""


class DatagramError(ZmuxError):
    """Sending a datagram failed."""


class ListenerClosedError(ZmuxError):
    """The listener was closed."""


class PipeError(ZmuxError):
    """A pipe operation failed."""


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
