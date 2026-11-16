"""asyncio stream conveniences: a stream as an asyncio-style reader and
writer pair (`Session.open_stream_pair`), and an asyncio stream pair as a
pipe input (`pipe_from_streams`)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from ._errors import (
    IncompleteReadError,
    LimitExceededError,
    StreamBusyError,
    StreamClosedError,
    ZmuxError,
)
from ._types import ErrorKind
from ._zmux import PipeIo, RecvStream, SendStream, UnsentCount, pipe_pair

_DEFAULT_LIMIT = 1 << 16


class StreamPairReader:
    """The receiving part of a stream with the reads of
    `asyncio.StreamReader`: `read`, `readexactly`, `readline`, `readuntil`,
    `at_eof` and line iteration. `readexactly` and `readuntil`
    raise `IncompleteReadError`, an `asyncio.IncompleteReadError`, and
    `readuntil` `asyncio.LimitOverrunError`, as `asyncio.StreamReader` does; a reset by the peer raises
    `StreamResetError`, a `ConnectionError`. Every read is
    cancellation-safe: a cancelled read loses no byte."""

    def __init__(self, stream: RecvStream, *, limit: int = _DEFAULT_LIMIT) -> None:
        if limit <= 0:
            raise ValueError("limit is positive")
        self.stream = stream
        """The underlying `RecvStream`."""
        self._limit = limit
        self._buf = bytearray()
        self._eof = False

    async def _fill(self) -> bool:
        """Reads one chunk into the buffer; `False` at the end."""
        if self._eof:
            return False
        data = await self.stream.read(_DEFAULT_LIMIT)
        if not data:
            self._eof = True
            return False
        self._buf += data
        return True

    def _take(self, n: int) -> bytes:
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def read(self, n: int = -1) -> bytes:
        """Up to `n` bytes, at least one unless at the end; with `n` -1
        (the default), everything up to the end."""
        if n == 0:
            return b""
        if n < 0:
            while await self._fill():
                pass
            return self._take(len(self._buf))
        if not self._buf:
            await self._fill()
        return self._take(n)

    async def readexactly(self, n: int) -> bytes:
        """Exactly `n` bytes; `IncompleteReadError` (with the bytes read as
        `partial`) when the stream ends first."""
        if n < 0:
            raise ValueError("readexactly size can not be less than zero")
        while len(self._buf) < n:
            if not await self._fill():
                partial = self._take(len(self._buf))
                raise IncompleteReadError(partial, n)
        return self._take(n)

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        """The bytes up to and including `separator`.
        `IncompleteReadError` when the stream ends first (the bytes read as
        `partial`); `asyncio.LimitOverrunError` when the separator is
        not within the reader's limit (the bytes stay)."""
        if not separator:
            raise ValueError("Separator should be at least one-byte string")
        start = 0
        while True:
            i = self._buf.find(separator, start)
            if i >= 0:
                if i > self._limit:
                    raise asyncio.LimitOverrunError(
                        "Separator is found, but chunk is longer than limit", i
                    )
                return self._take(i + len(separator))
            start = max(0, len(self._buf) + 1 - len(separator))
            if start > self._limit:
                raise asyncio.LimitOverrunError(
                    "Separator is not found, and chunk exceed the limit", start
                )
            if not await self._fill():
                partial = self._take(len(self._buf))
                raise IncompleteReadError(partial, None)

    async def readline(self) -> bytes:
        """One line ending with `b"\\n"`, or what remains at the end;
        `ValueError` for a line beyond the reader's limit."""
        try:
            return await self.readuntil(b"\n")
        except IncompleteReadError as e:
            return e.partial
        except asyncio.LimitOverrunError as e:
            if self._buf.startswith(b"\n", e.consumed):
                del self._buf[: e.consumed + 1]
            else:
                self._buf.clear()
            raise ValueError(e.args[0]) from e

    def at_eof(self) -> bool:
        """Whether the stream ended and every byte was read."""
        return self._eof and not self._buf

    def __aiter__(self) -> StreamPairReader:
        return self

    async def __anext__(self) -> bytes:
        line = await self.readline()
        if not line:
            raise StopAsyncIteration
        return line


class StreamPairWriter:
    """The sending part of a stream with the writes of
    `asyncio.StreamWriter`. `write` never blocks: data is queued and sent in
    the background; `drain` waits while more than `high_water` bytes are
    queued. The first failed send is kept: `drain`, `flush` and every later
    `write` raise it. `close` and `write_eof` finish the stream once the
    queue is sent; `abort` resets it at once. It has no asyncio transport."""

    def __init__(self, stream: SendStream, *, high_water: int = _DEFAULT_LIMIT) -> None:
        self.stream = stream
        """The underlying `SendStream`."""
        self._high_water = high_water
        self._buf = bytearray()
        self._queued = 0
        self._task: asyncio.Future[None] | None = None
        self._closing: asyncio.Future[None] | None = None
        self._error: BaseException | None = None
        self._aborted = False

    def _check(self) -> None:
        if self._error is not None:
            raise self._error

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Queues `data`; raises the error of an earlier failed send."""
        self._check()
        if self._closing is not None:
            raise StreamClosedError("write after close or write_eof")
        self._buf += data
        self._queued += len(data)
        if self._task is None or self._task.done():
            self._task = asyncio.ensure_future(self._flush())
            self._task.add_done_callback(_retrieve)

    def writelines(self, data: Iterable[bytes | bytearray | memoryview]) -> None:
        """Queues each item of `data`."""
        for d in data:
            self.write(d)

    async def _flush(self) -> None:
        while self._buf:
            # The write copies the queued bytes once: new writes queue in a
            # fresh buffer meanwhile.
            data, self._buf = self._buf, bytearray()
            try:
                await self.stream.write(data)
            except BaseException as e:
                if self._error is None and not isinstance(e, asyncio.CancelledError):
                    self._error = e
                raise
            finally:
                self._queued -= len(data)

    async def _settled(self) -> None:
        task = self._task
        if task is not None:
            await asyncio.wait({task})
        self._check()

    async def flush(self) -> None:
        """Sends the queue, then opens the stream now if it is not open
        (`SendStream.flush`); raises the error of a failed send."""
        await self._settled()
        await self.stream.flush()

    async def drain(self) -> None:
        """Waits while more than `high_water` bytes are queued; raises the
        error of a failed send."""
        task = self._task
        if task is not None and not task.done() and self._queued > self._high_water:
            await asyncio.wait({task})
        self._check()

    # Part of the `asyncio.StreamWriter` interface: callers use an instance.
    # noinspection PyMethodMayBeStatic
    def can_write_eof(self) -> bool:
        """Always true: a stream can be finished."""
        return True

    def write_eof(self) -> None:
        """Finishes the stream once the queue is sent."""
        self._finishing()

    def _finishing(self) -> asyncio.Future[None]:
        if self._closing is None:
            self._closing = asyncio.ensure_future(self._finish())
            self._closing.add_done_callback(_retrieve)
        return self._closing

    async def _finish(self) -> None:
        await self._settled()
        if self._aborted:
            return
        try:
            await self.stream.finish()
        except ZmuxError:
            # An abort during the finish ends the stream as asked.
            if not self._aborted:
                raise

    def close(self) -> None:
        """Finishes the stream once the queue is sent (`write_eof`)."""
        self.write_eof()

    def abort(self, code: int) -> None:
        """Resets the stream with the application error `code` at once; the
        queue is dropped."""
        self._aborted = True
        self._buf.clear()
        if self._task is not None:
            self._task.cancel()
        self.stream.reset(code)

    def is_closing(self) -> bool:
        """Whether `close`, `write_eof` or `abort` was called."""
        return self._closing is not None or self._aborted

    async def wait_closed(self) -> None:
        """Waits until the stream is finished, or returns once it was
        aborted; raises the error of a failed send."""
        if self._aborted:
            return
        await self._finishing()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """`stream_id` (the stream's ID, or `None` before it has one) and
        `send_stream` (the `SendStream`); `default` otherwise."""
        if name == "stream_id":
            return self.stream.id
        if name == "send_stream":
            return self.stream
        return default


async def _read(recv: RecvStream, n: int, view: bool) -> bytes | memoryview:
    """`RecvStream.read` and `read_chunk`: the only await waits for
    readiness and takes nothing, and the take is synchronous, so a
    cancellation never lands after bytes were taken."""
    while True:
        b = recv._take(n, view)
        if b is not None:
            return b
        await recv._readable()


async def _collect(recv: RecvStream, want: int) -> list[bytes]:
    """Chunks until they hold `want` bytes or the stream ends. On a
    cancellation or an error what they took goes back to the stream."""
    parts: list[bytes] = []
    have = 0
    try:
        while have < want:
            b = recv._take(want - have, False)
            if b is None:
                await recv._readable()
                continue
            if not b:
                break
            parts.append(bytes(b))
            have += len(b)
    except BaseException:
        recv._put_back(parts)
        raise
    return parts


async def _read_exact(recv: RecvStream, n: int) -> bytes:
    """`RecvStream.read_exact`."""
    data = b"".join(await _collect(recv, n))
    if len(data) < n:
        e = IncompleteReadError(data, n)
        e.kind = ErrorKind.FINISHED_EARLY
        raise e
    return data


async def _read_to_end(recv: RecvStream, limit: int) -> bytes:
    """`RecvStream.read_to_end`; what it read stays in the stream when the
    stream is longer than `limit`."""
    parts = await _collect(recv, limit + 1)
    if sum(map(len, parts)) > limit:
        recv._put_back(parts)
        e = LimitExceededError("stream longer than the limit")
        e.kind = ErrorKind.TOO_LONG
        raise e
    return b"".join(parts)


async def _anext(recv: RecvStream) -> bytes:
    """`RecvStream.__anext__`."""
    b = await _read(recv, 65536, False)
    if not b:
        raise StopAsyncIteration
    return bytes(b)


async def _write_some(send: SendStream, data: Any) -> int:
    """`SendStream.write_some`: the only await waits for write readiness and
    takes nothing, and the write itself is synchronous, so a cancellation never
    lands after bytes were taken."""
    if not memoryview(data).nbytes:
        return 0
    while True:
        try:
            n = send.try_write(data)
        except StreamBusyError:
            n = 0
        if n:
            return n
        await send.writable()


async def _writev(send: SendStream, buffers: list[Any]) -> int:
    """`SendStream.writev`, as `_write_some`."""
    if not any(memoryview(b).nbytes for b in buffers):
        return 0
    while True:
        try:
            n = send.try_writev(buffers)
        except StreamBusyError:
            n = 0
        if n:
            return n
        await send.writable()


def _retrieve(task: asyncio.Future[None]) -> None:
    # The writer keeps a failed send's error and raises it itself.
    if not task.cancelled():
        task.exception()


def _stream_pair(
    send: SendStream, recv: RecvStream, high_water: int, limit: int
) -> tuple[StreamPairReader, StreamPairWriter]:
    return StreamPairReader(recv, limit=limit), StreamPairWriter(
        send, high_water=high_water
    )


_bridges: set[asyncio.Future[None]] = set()


def pipe_from_streams(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    max_record: int | None = None,
    exporter: Callable[[str, bytes, int], Awaitable[bytes | None] | bytes | None]
    | None = None,
) -> PipeIo:
    """A pipe input over an asyncio stream pair. Bytes cross into Python and
    back, so this is slower than the built-in carriers; use it for
    transports the binding has no carrier for. The bridge lives as long as
    the pipe: it ends, and closes `writer`, once the session lets the pipe
    go; the end of `reader` ends only the inbound direction. The
    transport's `get_write_buffer_size()`, where it has one, is the
    carrier's unsent count, taken at each write and drain. `max_record` is
    the largest record plaintext the carrier takes (`PipeIo.set_max_record`:
    at least 8192, no upper bound); `exporter(label, context, length)`
    is the exporter of the carrier's innermost end-to-end handshake (see
    `pipe_pair`)."""
    size = getattr(writer.transport, "get_write_buffer_size", None)
    count = UnsentCount() if size is not None else None
    pipe, end = pipe_pair(unsent=count, max_record=max_record, exporter=exporter)

    def note() -> None:
        if count is not None and size is not None:
            # The inspection does not narrow `size` inside the closure.
            # noinspection PyCallingNonCallable
            count.set(size())

    async def inbound() -> None:
        try:
            while data := await reader.read(65536):
                await end.write(data)
        finally:
            await end.write(b"")

    async def outbound() -> None:
        while data := await end.read():
            writer.write(data)
            note()
            await writer.drain()
            note()

    async def bridge() -> None:
        reading = asyncio.ensure_future(inbound())
        try:
            await outbound()
        finally:
            reading.cancel()
            await asyncio.gather(reading, return_exceptions=True)
            writer.close()

    task = asyncio.ensure_future(bridge())
    _bridges.add(task)
    task.add_done_callback(_settle)
    return pipe


def _settle(task: asyncio.Future[None]) -> None:
    # A carrier's failure ends the bridge; the session reports it.
    _bridges.discard(task)
    if not task.cancelled():
        task.exception()
