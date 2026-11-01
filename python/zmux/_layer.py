"""Carriers as asyncio streams, for layers over a carrier (`PipeIo.wrap`,
`open_carrier`)."""

from __future__ import annotations

import asyncio
import collections
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, cast

from ._zmux import CarrierStream, LayerEnd, ZmuxError


class LayerWriter(Protocol):
    """The writing half a layer returns: an `asyncio.StreamWriter`, or any
    object with these methods."""

    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...
    def close(self) -> None: ...


Layer = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter],
    Awaitable[tuple[asyncio.StreamReader, LayerWriter]],
]

_tasks: set[asyncio.Future[None]] = set()


def _keep(coro: Any) -> None:
    task = asyncio.ensure_future(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def _receiving(
    protocol: asyncio.BaseProtocol,
) -> asyncio.Protocol | asyncio.BufferedProtocol:
    # A transport's protocol receives data, so it is one of the two
    # receiving kinds (asyncio's stream and TLS protocols are).
    return cast("asyncio.Protocol | asyncio.BufferedProtocol", protocol)


class _CarrierTransport(asyncio.Transport):
    """An asyncio transport over a `CarrierStream`: each `write` is one
    write on the carrier, in order."""

    _start_tls_compatible = True

    def __init__(self, stream: CarrierStream, protocol: asyncio.BaseProtocol) -> None:
        super().__init__({"carrier_stream": stream})
        self._stream = stream
        self._protocol = _receiving(protocol)
        self._queue: collections.deque[bytes] = collections.deque()
        self._queued = 0
        self._high, self._low = 65536, 16384
        self._paused = False
        self._wake = asyncio.Event()
        self._reading = asyncio.Event()
        self._reading.set()
        self._eof = False
        self._closing = False
        self._lost = False
        protocol.connection_made(self)
        self._reader = asyncio.ensure_future(self._read_loop())
        self._writer = asyncio.ensure_future(self._write_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                await self._reading.wait()
                data = await self._stream.read()
                if not data:
                    break
                self._deliver(data)
            if not self._protocol.eof_received():
                self.close()
        except asyncio.CancelledError:
            raise
        except (OSError, ZmuxError, RuntimeError) as e:
            self._lose(e)

    def _deliver(self, data: bytes) -> None:
        proto = self._protocol
        if isinstance(proto, asyncio.BufferedProtocol):
            # Such as asyncio's TLS protocol.
            view = memoryview(data)
            while view:
                buf = memoryview(proto.get_buffer(len(view)))
                n = min(len(buf), len(view))
                buf[:n] = view[:n]
                proto.buffer_updated(n)
                view = view[n:]
        else:
            proto.data_received(data)

    async def _write_loop(self) -> None:
        try:
            while True:
                while not self._queue:
                    if self._eof or self._closing:
                        await self._stream.shutdown()
                        if self._closing:
                            self._lose(None)
                        return
                    self._wake.clear()
                    await self._wake.wait()
                data = self._queue.popleft()
                await self._stream.write(data)
                self._queued -= len(data)
                if self._paused and self._queued <= self._low:
                    self._paused = False
                    self._protocol.resume_writing()
        except asyncio.CancelledError:
            raise
        except (OSError, ZmuxError, RuntimeError) as e:
            self._lose(e)

    def _lose(self, exc: Exception | None) -> None:
        if self._lost:
            return
        self._lost = True
        self._closing = True
        for t in (self._reader, self._writer):
            if t is not asyncio.current_task():
                t.cancel()
        asyncio.get_running_loop().call_soon(self._protocol.connection_lost, exc)

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self._closing or self._eof or not data:
            return
        b = bytes(data)
        self._queue.append(b)
        self._queued += len(b)
        self._wake.set()
        if not self._paused and self._queued > self._high:
            self._paused = True
            self._protocol.pause_writing()

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self._eof = True
        self._wake.set()

    def close(self) -> None:
        if not self._closing:
            self._closing = True
            self._wake.set()
            if self._writer.done():
                self._lose(None)

    def abort(self) -> None:
        self._lose(None)

    def is_closing(self) -> bool:
        return self._closing

    def pause_reading(self) -> None:
        self._reading.clear()

    def resume_reading(self) -> None:
        self._reading.set()

    def is_reading(self) -> bool:
        return self._reading.is_set()

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        self._protocol = _receiving(protocol)

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self._protocol

    def get_write_buffer_size(self) -> int:
        return self._queued

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return self._low, self._high

    def set_write_buffer_limits(
        self, high: int | None = None, low: int | None = None
    ) -> None:
        if high is None:
            high = 65536 if low is None else 4 * low
        if low is None:
            low = high // 4
        self._high, self._low = high, low


def _streams(
    stream: CarrierStream,
    *,
    server_side: bool = False,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader = asyncio.StreamReader()
    writers: list[asyncio.StreamWriter] = []
    # A protocol with a connection callback makes StreamWriter.start_tls
    # take the server side.
    protocol = asyncio.StreamReaderProtocol(
        reader,
        (lambda r, w: writers.append(w)) if server_side else None,
    )
    transport = _CarrierTransport(stream, protocol)
    if writers:
        return reader, writers[0]
    return reader, asyncio.StreamWriter(
        transport, protocol, reader, asyncio.get_running_loop()
    )


async def open_carrier(
    pipe: Any,
    *,
    server_side: bool = False,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """The carrier `pipe` (a `PipeIo`, used up) as an asyncio stream pair,
    for a protocol of the application's own over it. Each write on the
    writer is one write on the carrier (one message on a carrier with
    message framing), in order; bytes a listener already read come first.
    The carrier's other properties are dropped. With `server_side`,
    `writer.start_tls` takes the server side."""
    return _streams(pipe.into_stream(), server_side=server_side)


async def run(
    layer: Layer, stream: CarrierStream, end: LayerEnd, server_side: bool
) -> None:
    """Runs `layer` over `stream`; then pumps between the layer's streams
    and `end` until either ends."""
    reader, writer = _streams(stream, server_side=server_side)
    r2, w2 = await layer(reader, writer)

    # A failure either way ends that way: the carrier sees its end.
    async def up() -> None:
        try:
            while data := await r2.read(65536):
                await end.write(data)
        except (OSError, EOFError, asyncio.IncompleteReadError, RuntimeError):
            pass
        finally:
            end.close()

    async def down() -> None:
        try:
            while data := await end.read():
                w2.write(data)
                await w2.drain()
        except (OSError, RuntimeError):
            pass
        finally:
            w2.close()

    _keep(up())
    _keep(down())
