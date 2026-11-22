"""The exceptions of zmux. The native layer raises them by name; each sits
under `ZmuxError` and, where one fits, under the built-in exception that
asyncio and the standard library raise for the same condition."""

from __future__ import annotations

import asyncio
import builtins
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._types import CandidateResult, ErrorKind

__all__ = [
    "ApplicationClosedError",
    "CarrierChoiceError",
    "ConnectError",
    "ConnectionRefusedError",
    "CredentialsFailedError",
    "DatagramBlockedError",
    "DatagramError",
    "DeadlineExceededError",
    "DuplicateUndecidedError",
    "EarlyDataRejectedError",
    "ExportError",
    "GoingAwayError",
    "HandshakeTimeoutError",
    "IdleTimeoutError",
    "IncompleteReadError",
    "InvalidArgumentError",
    "JoinEvictedError",
    "JoinPendingError",
    "JoinRefusedError",
    "JoinSecretSetError",
    "LimitExceededError",
    "ListenerClosedError",
    "MalformedPacketError",
    "NoExporterError",
    "NoReplyError",
    "NoRunningLoopError",
    "NotEstablishedError",
    "NotNegotiatedError",
    "PacketError",
    "PacketTooLargeError",
    "PipeAbortedError",
    "PipeError",
    "PipeGoneError",
    "PipeUsedError",
    "PipesLostError",
    "PreambleTooLargeError",
    "ResumeFailedError",
    "ResumeTimeoutError",
    "SecureCarrierError",
    "SessionClosedError",
    "StreamBusyError",
    "StreamClosedError",
    "StreamError",
    "StreamRejectedError",
    "StreamResetError",
    "StreamStoppedError",
    "TakeoverReturnedError",
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


class TakeoverReturnedError(ZmuxError):
    """`Takeover.detach` after the listener's fallback returned without
    detaching it: what the adapter held of the carrier is closed."""


class ConnectError(ZmuxError, ConnectionError):
    """Establishing a carrier or a session failed."""


class NoReplyError(ConnectError):
    """The secure carrier failed before receiving message 2. `__cause__`
    is the transport exception, an `EOFError`, or a `TimeoutError`."""


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
    """A protocol error ended the session. `frame_type` identifies the frame
    involved, and `details` contains the diagnostic key/value pairs."""

    frame_type: int = 0
    details: tuple[tuple[str, int], ...] = ()


class ConnectionRefusedError(TransportClosedError, builtins.ConnectionRefusedError):
    """The listener refused a new session with its drain reason."""


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
    """The peer reset the stream. `code` is its error code and
    `reliable_size` is the length of the reliable prefix."""

    reliable_size: int = 0


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
    """A stream's preamble is larger than the limit known, `max`: the
    peer's Maximum Preamble Size (before its parameters the remembered one
    or 1024 bytes), at most 4096 and the carrier record floor less 32
    (8160)."""

    max: int = 0


class DuplicateUndecidedError(ZmuxError, ValueError):
    """`resolve_duplicate` could not decide between the two sessions: the
    dialers are the same and no identity was given for the tie. An argument
    error, which the caller can mend by passing `local_identity` and
    `peer_identity`."""


class SecureCarrierError(ZmuxError):
    """The secure carrier failed. `kind` names the failure: the secure
    carrier's error class as a string, for example `"random_failed"` when the
    operating system's random source failed, which `StaticKey.generate`
    reports. A class is not on the wire, so `code` is `None`."""


class CredentialsFailedError(SecureCarrierError):
    """The peer failed credential verification. `kind` is
    `"credentials_failed"`. `reason` gives the specific local failure when
    available. `__cause__` carries the underlying error when available.
    Client establishment preserves the original Python verifier exception.
    Listener refusals carry the verifier error category and message from Rust."""

    kind = "credentials_failed"

    # "verifier", "proof", or "pq_auth_required" when supplied by the handshake.
    reason: str | None = None


class NotNegotiatedError(ZmuxError):
    """The peer did not negotiate what the operation needs: multipath, or a
    preamble or priority extension it does not speak."""


class NotEstablishedError(ZmuxError):
    """The session is not established yet."""


class DatagramError(ZmuxError):
    """Sending a datagram failed."""


class DatagramBlockedError(DatagramError):
    """The stream has no identifier yet and the peer's stream limit allows
    none now: its datagram was refused and the stream stays unopened. A
    datagram sent once the stream is opened may pass."""


class PacketError(ZmuxError):
    """A packet stream operation failed. A Context ID out of range is an
    `InvalidArgumentError`, `SendPolicy.DATAGRAM_ONLY` without datagrams a
    `NotNegotiatedError`, and a failure of the stream or its datagram the
    error of that stream or datagram."""


class PacketTooLargeError(PacketError, ValueError):
    """The payload is larger than `max`: the stream's packet bound or, for
    `SendPolicy.DATAGRAM_ONLY`, the stream's largest datagram now."""

    max: int = 0


class MalformedPacketError(PacketError):
    """The peer's bytes were malformed (a capsule above the bound, or the
    stream ended inside one): the stream was reset and stopped with
    `ZMUX_PACKET_ERROR`, its `code`, and later receives fail the same way."""


class ListenerClosedError(ZmuxError):
    """The listener was closed."""


class PipeError(ZmuxError):
    """A pipe operation failed."""


class JoinPendingError(PipeError):
    """The session has no join keys yet: the message names what is
    missing."""


class JoinEvictedError(PipeError):
    """A newer join displaced this pending join."""


class JoinRefusedError(PipeError):
    """The peer refused the join; the join backoff started."""


class JoinSecretSetError(PipeError):
    """The deferred pre-shared key was given already."""


class PipeGoneError(PipeError):
    """No such pipe: it was retired."""


class PipeAbortedError(PipeGoneError):
    """This endpoint removed the pipe abruptly (`Pipe.abort()`, a resource
    limit, or room made for a new join): how the pipe's `wait_closed()`
    reports its end."""


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
