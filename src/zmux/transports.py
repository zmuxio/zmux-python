"""Reliable byte-stream transport protocols and adapters.

The core runtime consumes a small reliable ordered byte-stream surface instead
of binding itself to ``socket.socket``.  This mirrors the Go ``net.Conn`` and
Rust ``DuplexConnection`` boundary while keeping the Python package dependency
free and friendly to file-like objects, sockets, and already split stream
halves.
"""

from __future__ import annotations

import math
import socket
import threading
import time
from dataclasses import dataclass
from typing import (
    Iterable,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    runtime_checkable,
)

from .errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    NilConnection,
    ReadTimeout,
    SessionClosed,
    StreamNotReadable,
    StreamNotWritable,
    WriteTimeout,
    ZmuxTimeoutError,
)
from .streams import Deadline, ReadableBuffer, WritableBuffer, maybe_timeout

DEFAULT_READ_CHUNK = 16 * 1024
DEFAULT_WRITE_CHUNK = 16 * 1024
MAX_RETAINED_IO_BUFFER = 64 * 1024
_MIN_SOCKET_TIMEOUT = 1e-6
_UNSET = object()

Address = object


@dataclass(frozen=True)
class ZmuxSocketAddress:
    """Synthetic address used when a stream transport has no network address."""

    endpoint: str
    stream_id: int = 0
    stream_id_set: bool = False

    def __post_init__(self) -> None:
        if self.endpoint not in ("local", "remote"):
            raise ValueError("endpoint must be 'local' or 'remote'")
        if isinstance(self.stream_id, bool) or not isinstance(self.stream_id, int):
            raise TypeError("stream_id must be an integer")
        if self.stream_id < 0:
            raise ValueError("stream_id must be >= 0")

    @classmethod
    def local_pending(cls) -> "ZmuxSocketAddress":
        return cls("local")

    @classmethod
    def remote_pending(cls) -> "ZmuxSocketAddress":
        return cls("remote")

    @classmethod
    def local_stream(cls, stream_id: int) -> "ZmuxSocketAddress":
        return cls("local", stream_id, True)

    @classmethod
    def remote_stream(cls, stream_id: int) -> "ZmuxSocketAddress":
        return cls("remote", stream_id, True)

    def local(self) -> bool:
        return self.endpoint == "local"

    def has_stream_id(self) -> bool:
        return self.stream_id_set

    def __str__(self) -> str:
        if self.stream_id_set:
            return "%s/stream/%d" % (self.endpoint, self.stream_id)
        return "%s/stream/pending" % self.endpoint


@runtime_checkable
class SyncByteReceiveStream(Protocol):
    """Synchronous byte receive half."""

    def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        """Read up to ``max_bytes`` bytes."""

    def readinto(self, buffer: WritableBuffer) -> int:
        """Read bytes into a writable bytes-like buffer."""


@runtime_checkable
class SyncByteSendStream(Protocol):
    """Synchronous byte send half."""

    def write_all(self, data: ReadableBuffer) -> None:
        """Write all bytes in ``data``."""


@runtime_checkable
class SyncByteStream(SyncByteReceiveStream, SyncByteSendStream, Protocol):
    """Synchronous reliable ordered full-duplex byte stream."""

    def close(self) -> None:
        """Close the stream."""


@runtime_checkable
class ReadHalf(SyncByteReceiveStream, Protocol):
    """Directional read half accepted by :class:`JoinedTransport`."""

    def close_read(self) -> None:
        """Close or cancel the read side."""

    def set_read_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute read deadline."""

    def local_addr(self) -> Optional[object]:
        """Return the local endpoint address."""

    def remote_addr(self) -> Optional[object]:
        """Return the peer endpoint address."""


@runtime_checkable
class WriteHalf(SyncByteSendStream, Protocol):
    """Directional write half accepted by :class:`JoinedTransport`."""

    def close_write(self) -> None:
        """Close or finish the write side."""

    def set_write_deadline(self, deadline: Deadline) -> None:
        """Set an implementation-defined absolute write deadline."""

    def local_addr(self) -> Optional[object]:
        """Return the local endpoint address."""

    def remote_addr(self) -> Optional[object]:
        """Return the peer endpoint address."""


@runtime_checkable
class DuplexTransportControl(Protocol):
    """Optional hooks for timeout and whole-resource transport control."""

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        """Apply a relative read timeout, or clear it with ``None``."""

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        """Apply a relative write timeout, or clear it with ``None``."""

    def close(self) -> None:
        """Close the underlying transport resource."""


@runtime_checkable
class AsyncByteReceiveStream(Protocol):
    """Asynchronous byte receive half."""

    async def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        """Read up to ``max_bytes`` bytes."""

    async def readinto(self, buffer: WritableBuffer) -> int:
        """Read bytes into a writable bytes-like buffer."""


@runtime_checkable
class AsyncByteSendStream(Protocol):
    """Asynchronous byte send half."""

    async def write_all(self, data: ReadableBuffer) -> None:
        """Write all bytes in ``data``."""


@runtime_checkable
class AsyncByteStream(AsyncByteReceiveStream, AsyncByteSendStream, Protocol):
    """Asynchronous reliable ordered full-duplex byte stream."""

    async def close(self) -> None:
        """Close the stream."""


class BasicDuplexTransport:
    """Adapt a read half plus write half into a full-duplex byte stream."""

    def __init__(
            self,
            reader: object,
            writer: object,
            *,
            closer: Optional[object] = None,
            local_addr: Optional[object] = None,
            remote_addr: Optional[object] = None,
            gathering_writer: Optional[object] = None,
            control: Optional[DuplexTransportControl] = None,
    ) -> None:
        if reader is None or writer is None:
            raise NilConnection()
        self._reader = reader
        self._writer = writer
        self._closer = closer
        self._local_addr = local_addr
        self._remote_addr = remote_addr
        self._gathering_writer = gathering_writer
        self._control = control
        self._closed = False

    @property
    def reader(self) -> object:
        return self._reader

    @property
    def writer(self) -> object:
        return self._writer

    @property
    def gathering_writer(self) -> Optional[object]:
        return self._gathering_writer

    def into_parts(self) -> Tuple[object, object]:
        return self._reader, self._writer

    def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        _ensure_open(self._closed)
        return _read_from_half(self._reader, max_bytes)

    def readinto(self, buffer: WritableBuffer) -> int:
        _ensure_open(self._closed)
        return _readinto_from_half(self._reader, buffer)

    def write_all(self, data: ReadableBuffer) -> None:
        _ensure_open(self._closed)
        _write_to_half(self._writer, data)

    def write(self, data: ReadableBuffer) -> int:
        self.write_all(data)
        return len(_byte_view(data))

    def write_vectored(self, parts: Iterable[ReadableBuffer]) -> int:
        _ensure_open(self._closed)
        vectors = _nonempty_memoryviews(parts)
        if not vectors:
            return 0
        writer = self._gathering_writer or self._writer
        return _write_vectored_views_to_half(writer, vectors)

    def close_read(self) -> None:
        if self._closed:
            return
        _close_read_half(self._reader)

    def close_write(self) -> None:
        if self._closed:
            return
        _close_write_half(self._writer)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close_control = None if self._closer is not None else self._control
        _close_unique(
            (
                self._closer,
                close_control,
                self._reader,
                self._writer,
                self._gathering_writer,
            ),
            prefer_directional=False,
        )

    def set_deadline(self, deadline: Deadline) -> None:
        self.set_read_deadline(deadline)
        self.set_write_deadline(deadline)

    def set_timeout(self, timeout: Optional[float]) -> None:
        self.set_deadline(deadline_after(timeout))

    def set_read_deadline(self, deadline: Deadline) -> None:
        _ensure_open(self._closed)
        if self._control is not None:
            self._control.set_read_timeout(_remaining(deadline))
        else:
            _set_read_deadline(self._reader, deadline)

    def set_write_deadline(self, deadline: Deadline) -> None:
        _ensure_open(self._closed)
        if self._control is not None:
            self._control.set_write_timeout(_remaining(deadline))
        else:
            _set_write_deadline(self._writer, deadline)

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self.set_read_deadline(deadline_after(timeout))

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        self.set_write_deadline(deadline_after(timeout))

    def local_addr(self) -> Optional[object]:
        if self._local_addr is not None:
            return self._local_addr
        addr = _local_addr(self._reader)
        return addr if addr is not None else _local_addr(self._writer)

    def remote_addr(self) -> Optional[object]:
        if self._remote_addr is not None:
            return self._remote_addr
        addr = _remote_addr(self._reader)
        return addr if addr is not None else _remote_addr(self._writer)

    def __enter__(self) -> "BasicDuplexTransport":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class SocketTransport:
    """Wrap ``socket.socket`` with the synchronous byte-stream protocol."""

    def __init__(self, sock: socket.socket) -> None:
        if sock is None:
            raise NilConnection()
        self._sock = sock
        self._lock = threading.Lock()
        self._closed = False
        self._read_deadline: Deadline = None
        self._write_deadline: Deadline = None

    @property
    def socket(self) -> socket.socket:
        return self._sock

    def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        max_bytes = _check_max_bytes(max_bytes)
        if max_bytes == 0:
            return b""
        self._raise_if_closed()
        self._raise_if_deadline_expired(self._read_deadline, ReadTimeout)
        try:
            return self._sock.recv(max_bytes)
        except socket.timeout as exc:
            raise ReadTimeout() from exc

    def readinto(self, buffer: WritableBuffer) -> int:
        view = _writable_byte_view(buffer)
        if len(view) == 0:
            return 0
        self._raise_if_closed()
        self._raise_if_deadline_expired(self._read_deadline, ReadTimeout)
        try:
            return self._sock.recv_into(view)
        except socket.timeout as exc:
            raise ReadTimeout() from exc

    def write_all(self, data: ReadableBuffer) -> None:
        view = _byte_view(data)
        if not view:
            return
        self._raise_if_closed()
        self._raise_if_deadline_expired(self._write_deadline, WriteTimeout)
        try:
            self._sock.sendall(view)
        except socket.timeout as exc:
            raise WriteTimeout() from exc

    def write(self, data: ReadableBuffer) -> int:
        self.write_all(data)
        return len(_byte_view(data))

    def write_vectored(self, parts: Iterable[ReadableBuffer]) -> int:
        self._raise_if_closed()
        buffers = _nonempty_memoryviews(parts)
        if not buffers:
            return 0
        self._raise_if_deadline_expired(self._write_deadline, WriteTimeout)
        if hasattr(self._sock, "sendmsg"):
            try:
                return int(self._sock.sendmsg(buffers))
            except socket.timeout as exc:
                raise WriteTimeout() from exc
        total = 0
        for buffer in buffers:
            self.write_all(buffer)
            total += len(buffer)
        return total

    def close_read(self) -> None:
        self._shutdown(socket.SHUT_RD)

    def close_write(self) -> None:
        self._shutdown(socket.SHUT_WR)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._sock.close()

    def set_deadline(self, deadline: Deadline) -> None:
        self.set_read_deadline(deadline)
        self.set_write_deadline(deadline)

    def set_timeout(self, timeout: Optional[float]) -> None:
        self.set_deadline(deadline_after(timeout))

    def set_read_deadline(self, deadline: Deadline) -> None:
        self._set_deadline(read=deadline)

    def set_write_deadline(self, deadline: Deadline) -> None:
        self._set_deadline(write=deadline)

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self.set_read_deadline(deadline_after(timeout))

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        self.set_write_deadline(deadline_after(timeout))

    def local_addr(self) -> Optional[object]:
        try:
            return self._sock.getsockname()
        except OSError:
            return None

    def remote_addr(self) -> Optional[object]:
        try:
            return self._sock.getpeername()
        except OSError:
            return None

    def fileno(self) -> int:
        return self._sock.fileno()

    def __enter__(self) -> "SocketTransport":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _set_deadline(
            self,
            *,
            read: object = _UNSET,
            write: object = _UNSET,
    ) -> None:
        with self._lock:
            if self._closed:
                raise SessionClosed()
            if read is not _UNSET:
                self._read_deadline = _validate_deadline(read)
            if write is not _UNSET:
                self._write_deadline = _validate_deadline(write)
            self._apply_socket_timeout_locked()

    def _apply_socket_timeout_locked(self) -> None:
        timeout = _nearest_timeout(self._read_deadline, self._write_deadline)
        self._sock.settimeout(timeout)

    def _shutdown(self, how: int) -> None:
        with self._lock:
            if self._closed:
                return
        try:
            self._sock.shutdown(how)
        except OSError:
            pass

    def _raise_if_closed(self) -> None:
        with self._lock:
            if self._closed:
                raise SessionClosed()

    @staticmethod
    def _raise_if_deadline_expired(deadline: Deadline, error_type) -> None:
        if deadline is not None and _remaining(deadline) <= 0:
            raise error_type()


class JoinedTransport:
    """Join independent read and write halves into a full-duplex stream.

    ``pause_read`` and ``pause_write`` detach one direction once in-flight work
    becomes quiescent.  A detached half is owned by the returned pause handle
    until it is resumed; dropping the handle resumes on a best-effort basis.
    ``close`` only closes halves still attached at close time.
    """

    def __init__(
            self,
            read_half: Optional[object],
            write_half: Optional[object],
            *,
            local_addr: Optional[object] = None,
            remote_addr: Optional[object] = None,
    ) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._read_half = read_half
        self._write_half = write_half
        self._fallback_local_addr = local_addr
        self._fallback_remote_addr = remote_addr

        self._read_paused = False
        self._write_paused = False
        self._active_read_ops = 0
        self._active_write_ops = 0
        self._active_read_deadline_ops = 0
        self._active_write_deadline_ops = 0

        self._read_deadline: Deadline = None
        self._write_deadline: Deadline = None
        self._read_deadline_gen = 0
        self._write_deadline_gen = 0
        self._closed = False

    def read_half(self) -> Optional[object]:
        with self._condition:
            if self._closed or self._read_paused:
                read_half = None
            else:
                read_half = self._read_half
        return read_half

    def write_half(self) -> Optional[object]:
        with self._condition:
            if self._closed or self._write_paused:
                write_half = None
            else:
                write_half = self._write_half
        return write_half

    def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        max_bytes = _check_max_bytes(max_bytes)
        if max_bytes == 0:
            return b""
        read_half = self._enter_read()
        try:
            if read_half is None:
                raise StreamNotReadable()
            return _read_from_half(read_half, max_bytes)
        finally:
            self._leave_read()

    def readinto(self, buffer: WritableBuffer) -> int:
        view = _writable_byte_view(buffer)
        if len(view) == 0:
            return 0
        read_half = self._enter_read()
        try:
            if read_half is None:
                raise StreamNotReadable()
            return _readinto_from_half(read_half, view)
        finally:
            self._leave_read()

    def write_all(self, data: ReadableBuffer) -> None:
        view = _byte_view(data)
        if not view:
            return
        write_half = self._enter_write()
        try:
            if write_half is None:
                raise StreamNotWritable()
            _write_to_half(write_half, view)
        finally:
            self._leave_write()

    def write(self, data: ReadableBuffer) -> int:
        self.write_all(data)
        return len(_byte_view(data))

    def write_vectored(self, parts: Iterable[ReadableBuffer]) -> int:
        vectors = _nonempty_memoryviews(parts)
        if not vectors:
            return 0
        write_half = self._enter_write()
        try:
            if write_half is None:
                raise StreamNotWritable()
            return _write_vectored_views_to_half(write_half, vectors)
        finally:
            self._leave_write()

    def close_read(self) -> None:
        try:
            read_half = self._enter_read()
        except SessionClosed:
            return
        try:
            if read_half is not None:
                _close_read_half(read_half)
        finally:
            self._leave_read()

    def close_write(self) -> None:
        try:
            write_half = self._enter_write()
        except SessionClosed:
            return
        try:
            if write_half is not None:
                _close_write_half(write_half)
        finally:
            self._leave_write()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            read_half = self._read_half
            write_half = self._write_half
            self._read_half = None
            self._write_half = None
            self._read_paused = False
            self._write_paused = False
            self._condition.notify_all()

        errors = []
        read_closed_fully = False
        if read_half is not None:
            try:
                read_closed_fully = _close_full_read_half(read_half)
            except BaseException as exc:
                errors.append(exc)
        write_half_needs_close = not read_closed_fully or not _same_joined_half(
            read_half, write_half
        )
        if write_half is not None and write_half_needs_close:
            try:
                _close_full_write_half(write_half)
            except BaseException as exc:
                errors.append(exc)
        _raise_close_errors(errors)

    def set_deadline(self, deadline: Deadline) -> None:
        self.set_read_deadline(deadline)
        self.set_write_deadline(deadline)

    def set_timeout(self, timeout: Optional[float]) -> None:
        self.set_deadline(deadline_after(timeout))

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self.set_read_deadline(deadline_after(timeout))

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        self.set_write_deadline(deadline_after(timeout))

    def set_read_deadline(self, deadline: Deadline) -> None:
        self._set_half_deadline(deadline, read_side=True)

    def set_write_deadline(self, deadline: Deadline) -> None:
        self._set_half_deadline(deadline, read_side=False)

    @staticmethod
    def supports_read_deadline() -> bool:
        return True

    @staticmethod
    def supports_write_deadline() -> bool:
        return True

    def pause_read(self, timeout: Optional[float] = None) -> "PausedReadHalf":
        deadline = deadline_after(timeout)
        owned_pause = False
        with self._condition:
            while True:
                if self._closed:
                    raise SessionClosed()
                if not owned_pause and self._read_paused:
                    self._wait_for_change(deadline, "zmux: joined connection pause timed out")
                elif not owned_pause:
                    self._read_paused = True
                    owned_pause = True
                    self._condition.notify_all()
                elif self._active_read_ops == 0 and self._active_read_deadline_ops == 0:
                    current = self._read_half
                    self._read_half = None
                    self._condition.notify_all()
                    return PausedReadHalf(self, current)
                else:
                    try:
                        self._wait_for_change(deadline, "zmux: joined connection pause timed out")
                    except BaseException:
                        if owned_pause and not self._closed:
                            self._read_paused = False
                            self._condition.notify_all()
                        raise
        raise RuntimeError("unreachable")

    def pause_write(self, timeout: Optional[float] = None) -> "PausedWriteHalf":
        deadline = deadline_after(timeout)
        owned_pause = False
        with self._condition:
            while True:
                if self._closed:
                    raise SessionClosed()
                if not owned_pause and self._write_paused:
                    self._wait_for_change(deadline, "zmux: joined connection pause timed out")
                elif not owned_pause:
                    self._write_paused = True
                    owned_pause = True
                    self._condition.notify_all()
                elif self._active_write_ops == 0 and self._active_write_deadline_ops == 0:
                    current = self._write_half
                    self._write_half = None
                    self._condition.notify_all()
                    return PausedWriteHalf(self, current)
                else:
                    try:
                        self._wait_for_change(deadline, "zmux: joined connection pause timed out")
                    except BaseException:
                        if owned_pause and not self._closed:
                            self._write_paused = False
                            self._condition.notify_all()
                        raise
        raise RuntimeError("unreachable")

    def local_addr(self) -> object:
        with self._condition:
            read_half = self._read_half
            write_half = self._write_half
            fallback = self._fallback_local_addr
        addr = _local_addr(read_half)
        if addr is not None:
            return addr
        addr = _local_addr(write_half)
        if addr is not None:
            return addr
        return fallback if fallback is not None else ZmuxSocketAddress.local_pending()

    def remote_addr(self) -> object:
        with self._condition:
            read_half = self._read_half
            write_half = self._write_half
            fallback = self._fallback_remote_addr
        addr = _remote_addr(read_half)
        if addr is not None:
            return addr
        addr = _remote_addr(write_half)
        if addr is not None:
            return addr
        return fallback if fallback is not None else ZmuxSocketAddress.remote_pending()

    def __enter__(self) -> "JoinedTransport":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _enter_read(self) -> Optional[object]:
        with self._condition:
            while True:
                if self._closed:
                    raise SessionClosed()
                if not self._read_paused:
                    read_half = self._read_half
                    self._active_read_ops += 1
                    return read_half
                self._wait_for_read_resume()
        raise RuntimeError("unreachable")

    def _leave_read(self) -> None:
        with self._condition:
            if self._active_read_ops > 0:
                self._active_read_ops -= 1
            self._condition.notify_all()

    def _enter_write(self) -> Optional[object]:
        with self._condition:
            while True:
                if self._closed:
                    raise SessionClosed()
                if not self._write_paused:
                    write_half = self._write_half
                    self._active_write_ops += 1
                    return write_half
                self._wait_for_write_resume()
        raise RuntimeError("unreachable")

    def _set_half_deadline(self, deadline: Deadline, *, read_side: bool) -> None:
        deadline = _validate_deadline(deadline)
        with self._condition:
            if self._closed:
                raise SessionClosed()
            if read_side:
                previous_deadline = self._read_deadline
                self._read_deadline = deadline
                self._read_deadline_gen = _next_generation(self._read_deadline_gen)
                generation = self._read_deadline_gen
                half = self._read_half
                if half is not None:
                    self._active_read_deadline_ops += 1
            else:
                previous_deadline = self._write_deadline
                self._write_deadline = deadline
                self._write_deadline_gen = _next_generation(self._write_deadline_gen)
                generation = self._write_deadline_gen
                half = self._write_half
                if half is not None:
                    self._active_write_deadline_ops += 1
            self._condition.notify_all()

        if half is None:
            return

        failed = False
        try:
            if read_side:
                _set_read_deadline(half, deadline)
            else:
                _set_write_deadline(half, deadline)
        except BaseException:
            failed = True
            raise
        finally:
            with self._condition:
                if read_side:
                    if self._active_read_deadline_ops > 0:
                        self._active_read_deadline_ops -= 1
                    if failed and self._read_deadline_gen == generation:
                        self._read_deadline = previous_deadline
                        self._read_deadline_gen = _next_generation(self._read_deadline_gen)
                else:
                    if self._active_write_deadline_ops > 0:
                        self._active_write_deadline_ops -= 1
                    if failed and self._write_deadline_gen == generation:
                        self._write_deadline = previous_deadline
                        self._write_deadline_gen = _next_generation(
                            self._write_deadline_gen
                        )
                self._condition.notify_all()

    def _leave_write(self) -> None:
        with self._condition:
            if self._active_write_ops > 0:
                self._active_write_ops -= 1
            self._condition.notify_all()

    def _wait_for_read_resume(self) -> None:
        remaining = _remaining(self._read_deadline)
        if remaining is not None and remaining <= 0:
            raise ReadTimeout("zmux: joined connection read deadline exceeded")
        self._condition.wait(remaining)

    def _wait_for_write_resume(self) -> None:
        remaining = _remaining(self._write_deadline)
        if remaining is not None and remaining <= 0:
            raise WriteTimeout("zmux: joined connection write deadline exceeded")
        self._condition.wait(remaining)

    def _wait_for_change(self, deadline: Deadline, message: str) -> None:
        remaining = _remaining(deadline)
        if remaining is not None and remaining <= 0:
            raise ZmuxTimeoutError(
                message,
                scope=ErrorScope.SESSION,
                operation=ErrorOperation.CLOSE,
                source=ErrorSource.LOCAL,
                direction=ErrorDirection.BOTH,
            )
        self._condition.wait(remaining)

    def resume_read_half(self, paused: "PausedReadHalf") -> None:
        self._resume_paused_half(paused, read_side=True)

    def resume_write_half(self, paused: "PausedWriteHalf") -> None:
        self._resume_paused_half(paused, read_side=False)

    def _resume_paused_half(
            self,
            paused: "PausedReadHalf | PausedWriteHalf",
            *,
            read_side: bool,
    ) -> None:
        while True:
            current = paused.current()
            with self._condition:
                if paused.resumed:
                    return
                if self._closed:
                    paused.mark_resumed()
                    raise SessionClosed()
                deadline = self._read_deadline if read_side else self._write_deadline
                generation = (
                    self._read_deadline_gen if read_side else self._write_deadline_gen
                )
            if current is not None:
                if read_side:
                    _set_read_deadline(current, deadline)
                else:
                    _set_write_deadline(current, deadline)
            with self._condition:
                if self._closed:
                    paused.mark_resumed()
                    raise SessionClosed()
                current_generation = (
                    self._read_deadline_gen if read_side else self._write_deadline_gen
                )
                if current is not None and current_generation != generation:
                    continue
                if read_side:
                    self._read_half = current
                    self._read_paused = False
                else:
                    self._write_half = current
                    self._write_paused = False
                paused.mark_resumed()
                self._condition.notify_all()
                return


def join(
        read_half: object,
        write_half: object,
        *,
        local_addr: Optional[object] = None,
        remote_addr: Optional[object] = None,
) -> JoinedTransport:
    """Join independent read and write halves into a full-duplex transport."""

    return JoinedTransport(
        read_half,
        write_half,
        local_addr=local_addr,
        remote_addr=remote_addr,
    )


class PausedReadHalf:
    """Caller-owned read half detached from a :class:`JoinedTransport`."""

    def __init__(self, owner: JoinedTransport, current: Optional[object]) -> None:
        self._owner = owner
        self._current = current
        self._resumed = False
        self._lock = threading.RLock()

    def current(self) -> Optional[object]:
        with self._lock:
            current = self._current
        return current

    def set(self, next_half: Optional[object]) -> Optional[object]:
        with self._lock:
            if self._resumed:
                raise RuntimeError("paused read half already resumed")
            previous = self._current
            self._current = next_half
        return previous

    def resume(self) -> None:
        with self._lock:
            if self._resumed:
                return
            self._owner.resume_read_half(self)
            self._current = None

    def __enter__(self) -> "PausedReadHalf":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.resume()

    def __del__(self) -> None:
        try:
            self.resume()
        except BaseException:
            pass

    @property
    def resumed(self) -> bool:
        with self._lock:
            resumed = self._resumed
        return resumed

    def mark_resumed(self) -> None:
        with self._lock:
            self._resumed = True


class PausedWriteHalf:
    """Caller-owned write half detached from a :class:`JoinedTransport`."""

    def __init__(self, owner: JoinedTransport, current: Optional[object]) -> None:
        self._owner = owner
        self._current = current
        self._resumed = False
        self._lock = threading.RLock()

    def current(self) -> Optional[object]:
        with self._lock:
            current = self._current
        return current

    def set(self, next_half: Optional[object]) -> Optional[object]:
        with self._lock:
            if self._resumed:
                raise RuntimeError("paused write half already resumed")
            previous = self._current
            self._current = next_half
        return previous

    def resume(self) -> None:
        with self._lock:
            if self._resumed:
                return
            self._owner.resume_write_half(self)
            self._current = None

    def __enter__(self) -> "PausedWriteHalf":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.resume()

    def __del__(self) -> None:
        try:
            self.resume()
        except BaseException:
            pass

    @property
    def resumed(self) -> bool:
        with self._lock:
            resumed = self._resumed
        return resumed

    def mark_resumed(self) -> None:
        with self._lock:
            self._resumed = True


class FileReadHalf:
    """Read-half adapter for binary file-like objects."""

    def __init__(
            self,
            fileobj: object,
            *,
            local_addr: Optional[object] = None,
            remote_addr: Optional[object] = None,
    ) -> None:
        if fileobj is None:
            raise NilConnection()
        self._file = fileobj
        self._local_addr = local_addr
        self._remote_addr = remote_addr

    def read(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        return _read_from_half(self._file, max_bytes)

    def readinto(self, buffer: WritableBuffer) -> int:
        return _readinto_from_half(self._file, buffer)

    def close_read(self) -> None:
        _close_read_half(self._file)

    def set_read_deadline(self, deadline: Deadline) -> None:
        _set_read_deadline(self._file, deadline)

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self.set_read_deadline(deadline_after(timeout))

    def local_addr(self) -> Optional[object]:
        return self._local_addr

    def remote_addr(self) -> Optional[object]:
        return self._remote_addr

    def close_identity(self) -> object:
        return self._file


class FileWriteHalf:
    """Write-half adapter for binary file-like objects."""

    def __init__(
            self,
            fileobj: object,
            *,
            local_addr: Optional[object] = None,
            remote_addr: Optional[object] = None,
    ) -> None:
        if fileobj is None:
            raise NilConnection()
        self._file = fileobj
        self._local_addr = local_addr
        self._remote_addr = remote_addr

    def write_all(self, data: ReadableBuffer) -> None:
        _write_to_half(self._file, data)

    def write_vectored(self, parts: Iterable[ReadableBuffer]) -> int:
        return _write_vectored_to_half(self._file, parts)

    def flush(self) -> None:
        flush = getattr(self._file, "flush", None)
        if flush is not None:
            flush()

    def close_write(self) -> None:
        _close_write_half(self._file)

    def set_write_deadline(self, deadline: Deadline) -> None:
        _set_write_deadline(self._file, deadline)

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        self.set_write_deadline(deadline_after(timeout))

    def local_addr(self) -> Optional[object]:
        return self._local_addr

    def remote_addr(self) -> Optional[object]:
        return self._remote_addr

    def close_identity(self) -> object:
        return self._file


def deadline_after(timeout: Optional[float]) -> Deadline:
    """Return an absolute monotonic deadline ``timeout`` seconds from now."""

    timeout_value = maybe_timeout(timeout)
    if timeout_value is None:
        return None
    if timeout_value == 0:
        return time.monotonic()
    return time.monotonic() + timeout_value


def _validate_deadline(deadline: object) -> Deadline:
    if deadline is None:
        return None
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise TypeError("deadline must be a timestamp or None")
    value = float(deadline)
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def _remaining(deadline: Deadline) -> Optional[float]:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    return remaining if remaining > 0 else 0.0


def _nearest_timeout(read_deadline: Deadline, write_deadline: Deadline) -> Optional[float]:
    timeouts = []
    for deadline in (read_deadline, write_deadline):
        remaining = _remaining(deadline)
        if remaining is not None:
            timeouts.append(max(_MIN_SOCKET_TIMEOUT, remaining))
    return min(timeouts) if timeouts else None


def _check_max_bytes(max_bytes: int) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be an integer")
    if max_bytes < 0:
        raise ValueError("max_bytes must be >= 0")
    return max_bytes


def _ensure_open(closed: bool) -> None:
    if closed:
        raise SessionClosed()


def _next_generation(current: int) -> int:
    return (current + 1) & ((1 << 64) - 1) or 1


def _read_from_half(half: object, max_bytes: int) -> bytes:
    max_bytes = _check_max_bytes(max_bytes)
    if max_bytes == 0:
        return b""
    if half is None:
        raise StreamNotReadable()
    method = getattr(half, "recv", None)
    if method is None:
        method = getattr(half, "read", None)
    if method is None and hasattr(half, "readinto"):
        buffer = bytearray(max_bytes)
        n = _read_progress(getattr(half, "readinto")(buffer), max_bytes)
        return bytes(buffer[:n])
    if method is None:
        raise StreamNotReadable()
    try:
        data = method(max_bytes)
    except socket.timeout as exc:
        raise ReadTimeout() from exc
    if data is None:
        raise OSError("zmux: read returned no bytes")
    view = _byte_view(data)
    if len(view) > max_bytes:
        raise OSError("zmux: read reported invalid progress")
    return view.tobytes()


def _readinto_from_half(half: object, buffer: WritableBuffer) -> int:
    if half is None:
        raise StreamNotReadable()
    view = _writable_byte_view(buffer)
    if not view:
        return 0

    method = getattr(half, "recv_into", None)
    if method is None:
        method = getattr(half, "readinto", None)
    if method is not None:
        try:
            return _read_progress(method(view), len(view))
        except socket.timeout as exc:
            raise ReadTimeout() from exc

    data = _read_from_half(half, len(view))
    size = len(data)
    if size:
        view[:size] = data
    return size


def _read_progress(value: object, limit: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OSError("zmux: read reported invalid progress")
    if value < 0 or value > limit:
        raise OSError("zmux: read reported invalid progress")
    return value


def _write_to_half(half: object, data: ReadableBuffer) -> None:
    if half is None:
        raise StreamNotWritable()
    view = _byte_view(data)
    if not view:
        return

    method = getattr(half, "write_all", None)
    if method is not None:
        method(view)
        return

    method = getattr(half, "sendall", None)
    if method is not None:
        try:
            method(view)
        except socket.timeout as exc:
            raise WriteTimeout() from exc
        return

    method = getattr(half, "write", None)
    if method is None:
        raise StreamNotWritable()

    offset = 0
    total = len(view)
    while offset < total:
        n = method(view[offset:])
        if n is None:
            return
        if isinstance(n, bool) or not isinstance(n, int):
            raise OSError("zmux: write reported invalid progress")
        if n <= 0 or n > total - offset:
            raise OSError("zmux: write reported invalid progress")
        offset += n


def _nonempty_memoryviews(parts: Iterable[ReadableBuffer]) -> Tuple[memoryview, ...]:
    vectors = []
    for part in parts:
        view = _byte_view(part)
        if view:
            vectors.append(view)
    return tuple(vectors)


def _write_vectored_to_half(half: object, parts: Iterable[ReadableBuffer]) -> int:
    return _write_vectored_views_to_half(half, _nonempty_memoryviews(parts))


def _write_vectored_views_to_half(half: object, vectors: Tuple[memoryview, ...]) -> int:
    if half is None:
        raise StreamNotWritable()
    if not vectors:
        return 0
    total = sum(len(vector) for vector in vectors)

    for name in ("write_vectored", "writev", "sendmsg"):
        method = getattr(half, name, None)
        if method is None:
            continue
        try:
            written = method(vectors)
        except socket.timeout as exc:
            raise WriteTimeout() from exc
        if written is None:
            return total
        if isinstance(written, bool) or not isinstance(written, int):
            raise OSError("zmux: vectored write reported invalid progress")
        if written < 0 or written > total:
            raise OSError("zmux: vectored write reported invalid progress")
        return written

    for vector in vectors:
        _write_to_half(half, vector)
    return total


def _byte_view(data: ReadableBuffer) -> memoryview:
    view = memoryview(data)
    if view.ndim == 1 and view.itemsize == 1 and view.format in ("B", "b", "c"):
        return view
    try:
        return view.cast("B")
    except TypeError:
        return memoryview(view.tobytes())


def _writable_byte_view(buffer: WritableBuffer) -> memoryview:
    try:
        view = memoryview(buffer)
    except TypeError as exc:
        raise TypeError("buffer must be writable bytes-like") from exc
    if view.readonly:
        raise TypeError("buffer must be writable")
    if view.ndim == 1 and view.itemsize == 1 and view.format in ("B", "b", "c"):
        return view
    try:
        return view.cast("B")
    except TypeError as exc:
        raise TypeError("buffer must be a contiguous writable bytes-like object") from exc


def _set_read_deadline(half: object, deadline: Deadline) -> None:
    if half is None:
        return
    method = getattr(half, "set_read_deadline", None)
    if method is not None:
        method(deadline)
        return
    method = getattr(half, "set_deadline", None)
    if method is not None:
        method(deadline)
        return
    method = getattr(half, "set_read_timeout", None)
    if method is not None:
        method(_remaining(deadline))
        return


def _set_write_deadline(half: object, deadline: Deadline) -> None:
    if half is None:
        return
    method = getattr(half, "set_write_deadline", None)
    if method is not None:
        method(deadline)
        return
    method = getattr(half, "set_deadline", None)
    if method is not None:
        method(deadline)
        return
    method = getattr(half, "set_write_timeout", None)
    if method is not None:
        method(_remaining(deadline))
        return


def _close_read_half(half: object) -> None:
    method = getattr(half, "close_read", None)
    if method is not None:
        method()
        return
    method = getattr(half, "close", None)
    if method is not None:
        method()


def _close_write_half(half: object) -> None:
    method = getattr(half, "close_write", None)
    if method is not None:
        method()
        return
    method = getattr(half, "close", None)
    if method is not None:
        method()


def _close_full_read_half(half: object) -> bool:
    target = _close_target(half)
    method = getattr(target, "close", None)
    if method is not None:
        method()
        return True
    _close_read_half(half)
    return False


def _close_full_write_half(half: object) -> None:
    target = _close_target(half)
    method = getattr(target, "close", None)
    if method is not None:
        method()
        return
    _close_write_half(half)


def _close_unique(objects: Sequence[Optional[object]], *, prefer_directional: bool) -> None:
    seen = set()
    errors = []
    for obj in objects:
        if obj is None:
            continue
        ident = id(_close_identity(obj))
        if ident in seen:
            continue
        seen.add(ident)
        try:
            if prefer_directional:
                _close_read_half(obj)
            else:
                close = getattr(_close_target(obj), "close", None)
                if close is not None:
                    close()
                elif callable(obj):
                    obj()
        except BaseException as exc:
            errors.append(exc)
    _raise_close_errors(errors)


def _close_identity(obj: object) -> object:
    method = getattr(obj, "close_identity", None)
    if method is None:
        return obj
    identity = method()
    return obj if identity is None else identity


def _close_target(obj: object) -> object:
    identity = _close_identity(obj)
    return identity if hasattr(identity, "close") else obj


def _same_joined_half(first: Optional[object], second: Optional[object]) -> bool:
    if first is None or second is None:
        return False
    return _close_identity(first) is _close_identity(second)


def _raise_close_errors(errors: Sequence[BaseException]) -> None:
    if not errors:
        return
    if len(errors) == 1:
        raise errors[0]
    combined = OSError("zmux: multiple close errors")
    combined.close_errors = tuple(errors)  # type: ignore[attr-defined]
    raise combined from errors[0]


def _local_addr(half: Optional[object]) -> Optional[object]:
    if half is None:
        return None
    for name in ("local_addr", "local_address", "getsockname"):
        method = getattr(half, name, None)
        if method is None:
            continue
        try:
            addr = method()
        except OSError:
            return None
        if addr is not None:
            return addr
    return None


def _remote_addr(half: Optional[object]) -> Optional[object]:
    if half is None:
        return None
    for name in ("remote_addr", "peer_addr", "remote_address", "getpeername"):
        method = getattr(half, name, None)
        if method is None:
            continue
        try:
            addr = method()
        except OSError:
            return None
        if addr is not None:
            return addr
    return None


__all__ = (
    "Address",
    "AsyncByteReceiveStream",
    "AsyncByteSendStream",
    "AsyncByteStream",
    "BasicDuplexTransport",
    "DEFAULT_READ_CHUNK",
    "DEFAULT_WRITE_CHUNK",
    "DuplexTransportControl",
    "FileReadHalf",
    "FileWriteHalf",
    "JoinedTransport",
    "MAX_RETAINED_IO_BUFFER",
    "PausedReadHalf",
    "PausedWriteHalf",
    "ReadHalf",
    "SocketTransport",
    "SyncByteReceiveStream",
    "SyncByteSendStream",
    "SyncByteStream",
    "WriteHalf",
    "ZmuxSocketAddress",
    "deadline_after",
    "join",
)
