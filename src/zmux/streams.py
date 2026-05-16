"""Public stream protocols for native zmux and adapters."""

from __future__ import annotations

import math
from collections.abc import Iterable
from types import TracebackType
from typing import Optional, Protocol, Union, runtime_checkable

from .payload import MetadataUpdate, StreamMetadata

ReadableBuffer = Union[bytes, bytearray, memoryview]
WritableBuffer = Union[bytearray, memoryview]
Deadline = Optional[float]


@runtime_checkable
class StreamHandle(Protocol):
    """Common stream metadata and close surface."""

    @property
    def stream_id(self) -> int:
        """Numeric stream identifier after opening-frame commit."""
        raise NotImplementedError

    @property
    def opened_locally(self) -> bool:
        """Whether this endpoint opened the stream."""
        raise NotImplementedError

    @property
    def bidirectional(self) -> bool:
        """Whether the stream has both read and write halves."""
        raise NotImplementedError

    @property
    def open_info(self) -> bytes:
        """Return opaque open-time metadata known locally."""
        raise NotImplementedError

    @property
    def metadata(self) -> StreamMetadata:
        """Return the current peer-visible metadata snapshot."""
        raise NotImplementedError

    @property
    def local_addr(self) -> Optional[object]:
        """Return the local address object when the transport exposes one."""
        raise NotImplementedError

    @property
    def remote_addr(self) -> Optional[object]:
        """Return the peer address object when the transport exposes one."""
        raise NotImplementedError

    def set_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute read/write deadline."""

    def set_timeout(self, timeout: Optional[float]) -> None:
        """Set a relative read/write timeout in seconds."""

    def close(self) -> None:
        """End ordinary local use of the stream."""

    def close_with_error(self, code: int, reason: str = "") -> None:
        """Abort the whole stream with an application-defined code."""

    def __enter__(self) -> "StreamHandle":
        """Return this stream for use as a context manager."""

    # noinspection PyTypeHints
    def __exit__(
            self,
            exc_type: Optional[type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        """Close the stream when leaving a context manager."""


@runtime_checkable
class RecvStream(StreamHandle, Protocol):
    """Synchronous receive stream surface."""

    @property
    def read_closed(self) -> bool:
        """Whether the local read half is closed."""
        raise NotImplementedError

    def read(self, max_bytes: int = -1, *, timeout: Optional[float] = None) -> bytes:
        """Read ordered inbound bytes."""

    def readinto(
            self, buffer: WritableBuffer, *, timeout: Optional[float] = None
    ) -> int:
        """Read ordered inbound bytes into a writable bytes-like buffer."""

    def read_exact(self, n: int, *, timeout: Optional[float] = None) -> bytes:
        """Read exactly ``n`` bytes or raise EOF/timeout from the implementation."""

    def set_read_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute read deadline."""

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        """Set a relative read timeout in seconds."""

    def close_read(self) -> None:
        """Stop local interest in further inbound bytes."""

    def cancel_read(self, code: int) -> None:
        """Send read-side cancellation using ``STOP_SENDING(code)``."""


@runtime_checkable
class SendStream(StreamHandle, Protocol):
    """Synchronous send stream surface."""

    @property
    def write_closed(self) -> bool:
        """Whether the local write half is closed."""
        raise NotImplementedError

    def write(self, data: ReadableBuffer, *, timeout: Optional[float] = None) -> int:
        """Write bytes into the local zmux send path."""

    def write_all(
            self, data: ReadableBuffer, *, timeout: Optional[float] = None
    ) -> None:
        """Write all bytes in ``data``."""

    def write_vectored(
            self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        """Write from multiple byte buffers without requiring callers to join them."""

    def write_final(
            self, data: ReadableBuffer = b"", *, timeout: Optional[float] = None
    ) -> int:
        """Write bytes and gracefully close the local send half."""

    def write_vectored_final(
            self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        """Write multiple byte buffers and gracefully close the local send half."""

    def set_write_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute write deadline."""

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        """Set a relative write timeout in seconds."""

    def close_write(self, *, timeout: Optional[float] = None) -> None:
        """Gracefully finish the local send half."""

    def cancel_write(self, code: int) -> None:
        """Abort the local send half using ``RESET(code)``."""

    def update_metadata(self, update: MetadataUpdate) -> None:
        """Request a post-open advisory metadata update."""


@runtime_checkable
class Stream(RecvStream, SendStream, Protocol):
    """Synchronous bidirectional stream surface."""


@runtime_checkable
class AsyncStreamHandle(Protocol):
    """Common asynchronous stream metadata and close surface."""

    @property
    def stream_id(self) -> int:
        """Numeric stream identifier after opening-frame commit."""
        raise NotImplementedError

    @property
    def opened_locally(self) -> bool:
        """Whether this endpoint opened the stream."""
        raise NotImplementedError

    @property
    def bidirectional(self) -> bool:
        """Whether the stream has both read and write halves."""
        raise NotImplementedError

    @property
    def open_info(self) -> bytes:
        """Return opaque open-time metadata known locally."""
        raise NotImplementedError

    @property
    def metadata(self) -> StreamMetadata:
        """Return the current peer-visible metadata snapshot."""
        raise NotImplementedError

    @property
    def local_addr(self) -> Optional[object]:
        """Return the local address object when the transport exposes one."""
        raise NotImplementedError

    @property
    def remote_addr(self) -> Optional[object]:
        """Return the peer address object when the transport exposes one."""
        raise NotImplementedError

    def set_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute read/write deadline."""

    def set_timeout(self, timeout: Optional[float]) -> None:
        """Set a relative read/write timeout in seconds."""

    async def close(self) -> None:
        """End ordinary local use of the stream."""

    async def close_with_error(self, code: int, reason: str = "") -> None:
        """Abort the whole stream with an application-defined code."""

    async def __aenter__(self) -> "AsyncStreamHandle":
        """Return this stream for use as an async context manager."""

    # noinspection PyTypeHints
    async def __aexit__(
            self,
            exc_type: Optional[type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        """Close the stream when leaving an async context manager."""


@runtime_checkable
class AsyncRecvStream(AsyncStreamHandle, Protocol):
    """Asynchronous receive stream surface."""

    @property
    def read_closed(self) -> bool:
        """Whether the local read half is closed."""
        raise NotImplementedError

    async def read(
            self, max_bytes: int = -1, *, timeout: Optional[float] = None
    ) -> bytes:
        """Read ordered inbound bytes."""

    async def readinto(
            self, buffer: WritableBuffer, *, timeout: Optional[float] = None
    ) -> int:
        """Read ordered inbound bytes into a writable bytes-like buffer."""

    async def read_exact(
            self, n: int, *, timeout: Optional[float] = None
    ) -> bytes:
        """Read exactly ``n`` bytes or raise EOF/timeout from the implementation."""

    def set_read_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute read deadline."""

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        """Set a relative read timeout in seconds."""

    async def close_read(self) -> None:
        """Stop local interest in further inbound bytes."""

    async def cancel_read(self, code: int) -> None:
        """Send read-side cancellation using ``STOP_SENDING(code)``."""


@runtime_checkable
class AsyncSendStream(AsyncStreamHandle, Protocol):
    """Asynchronous send stream surface."""

    @property
    def write_closed(self) -> bool:
        """Whether the local write half is closed."""
        raise NotImplementedError

    async def write(
            self, data: ReadableBuffer, *, timeout: Optional[float] = None
    ) -> int:
        """Write bytes into the local zmux send path."""

    async def write_all(
            self, data: ReadableBuffer, *, timeout: Optional[float] = None
    ) -> None:
        """Write all bytes in ``data``."""

    async def write_vectored(
            self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        """Write from multiple byte buffers without requiring callers to join them."""

    async def write_final(
            self, data: ReadableBuffer = b"", *, timeout: Optional[float] = None
    ) -> int:
        """Write bytes and gracefully close the local send half."""

    async def write_vectored_final(
            self, parts: Iterable[ReadableBuffer], *, timeout: Optional[float] = None
    ) -> int:
        """Write multiple byte buffers and gracefully close the local send half."""

    def set_write_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute write deadline."""

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        """Set a relative write timeout in seconds."""

    async def close_write(self, *, timeout: Optional[float] = None) -> None:
        """Gracefully finish the local send half."""

    async def cancel_write(self, code: int) -> None:
        """Abort the local send half using ``RESET(code)``."""

    async def update_metadata(self, update: MetadataUpdate) -> None:
        """Request a post-open advisory metadata update."""


@runtime_checkable
class AsyncStream(AsyncRecvStream, AsyncSendStream, Protocol):
    """Asynchronous bidirectional stream surface."""


def maybe_timeout(timeout: Optional[float]) -> Optional[float]:
    """Normalize an optional relative timeout in seconds.

    ``None`` and non-finite values mean unbounded. Negative values clamp to an
    immediate timeout, matching the runtime deadline helpers.
    """

    if timeout is None:
        return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number or None")
    value = float(timeout)
    if math.isnan(value) or math.isinf(value):
        return None
    return max(0.0, value)


__all__ = (
    "AsyncRecvStream",
    "AsyncSendStream",
    "AsyncStream",
    "AsyncStreamHandle",
    "Deadline",
    "ReadableBuffer",
    "RecvStream",
    "SendStream",
    "Stream",
    "StreamHandle",
    "WritableBuffer",
    "maybe_timeout",
)
