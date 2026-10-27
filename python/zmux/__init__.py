"""QMux-compatible stream and datagram multiplexing; a binding over the zmux Rust crates."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from typing import Any

from ._types import (
    CapacityBelow, CapacityRestored, CloseInfo, Config, Direction, EarlyDataState, ErrorKind, Event, EventKind,
    GoAway, JoinAuthFailed, JoinSecurityUnavailable, PipeHalf, PipePolicy, PipePriorityChanged,
    PipeQualityChanged, PipesRetired, PipeState, PipeStateChanged, PipeStats, Preamble, Priority,
    PrioritySource, Resumed, Role, SessionState, SessionStats, Suspended, TierSaturation, Tlv,
    UnknownEvent,
)
from ._zmux import (
    ConnectError, DatagramError, DatagramStream, EarlyDataRejected, EventStream, Http2Connection,
    IncompleteRead, LimitExceeded, Listener, ListenerClosed, OpenError, Pipe, PipeEnd, PipeError,
    PipeIo, PipeReservation, QuicClient, RecvStream, SendStream, Session, SessionClosed,
    StreamError, StreamReset, StreamStopped, TlsConfig, ZeroRtt, ZmuxError, dial_h3, dial_http,
    dial_quic, dial_tcp, dial_tls, dial_webtransport, dial_websocket, pipe_pair,
)

__version__ = "0.3.1"

__all__ = [
    "CapacityBelow", "CapacityRestored", "CloseInfo", "Config", "ConnectError", "DatagramError",
    "DatagramStream", "Direction", "EarlyDataRejected", "EarlyDataState", "ErrorKind", "Event", "EventKind",
    "EventStream", "GoAway", "Http2Connection", "IncompleteRead", "JoinAuthFailed",
    "JoinSecurityUnavailable", "LimitExceeded", "Listener", "ListenerClosed", "OpenError", "Pipe",
    "PipeEnd", "PipeError", "PipeHalf", "PipeIo", "PipePolicy", "PipePriorityChanged",
    "PipeQualityChanged", "PipeReservation", "PipeState", "PipeStateChanged", "PipeStats",
    "PipesRetired", "Preamble", "Priority", "PrioritySource", "QuicClient", "RecvStream", "Resumed",
    "Role", "SendStream", "Session", "SessionClosed", "SessionState", "SessionStats", "StreamError",
    "StreamReset", "StreamStopped", "StreamWriter", "Suspended", "TierSaturation", "TlsConfig",
    "Tlv", "UnknownEvent", "ZeroRtt", "ZmuxError", "connect_h3", "connect_http", "connect_http2",
    "connect_quic", "connect_tcp", "connect_tls", "connect_webtransport", "connect_websocket",
    "dial_h3", "dial_http", "dial_http2", "dial_quic", "dial_tcp", "dial_tls", "dial_webtransport",
    "dial_websocket", "open_connection", "pipe_from_streams", "pipe_pair",
]

_Headers = Mapping[str, str] | Iterable[tuple[str, str]]


async def connect_tcp(addr: str, *, config: Config | None = None) -> Session:
    return await Session.connect(await dial_tcp(addr), config)


async def connect_tls(
    addr: str, *, tls: TlsConfig | None = None, server_name: str | None = None,
    config: Config | None = None,
) -> Session:
    return await Session.connect(await dial_tls(addr, tls=tls, server_name=server_name), config)


async def connect_quic(
    addr: str, *, tls: TlsConfig | None = None, server_name: str | None = None, lanes: int = 4,
    config: Config | None = None,
) -> Session:
    pipe = await dial_quic(addr, tls=tls, server_name=server_name, lanes=lanes)
    return await Session.connect(pipe, config)


async def connect_websocket(
    url: str, *, tls: TlsConfig | None = None, headers: _Headers | None = None,
    config: Config | None = None,
) -> Session:
    return await Session.connect(await dial_websocket(url, tls=tls, headers=headers), config)


async def dial_http2(
    addr: str, *, path: str = "/zmux", tls: TlsConfig | None = None, server_name: str | None = None
) -> PipeIo:
    conn = await Http2Connection.connect(addr, path=path, tls=tls, server_name=server_name)
    return await conn.open_pipe()


async def connect_http2(
    addr: str, *, path: str = "/zmux", tls: TlsConfig | None = None,
    server_name: str | None = None, config: Config | None = None,
) -> Session:
    pipe = await dial_http2(addr, path=path, tls=tls, server_name=server_name)
    return await Session.connect(pipe, config)


async def connect_h3(
    url: str, *, tls: TlsConfig | None = None, addr: str | None = None, lanes: int = 4,
    config: Config | None = None,
) -> Session:
    return await Session.connect(await dial_h3(url, tls=tls, addr=addr, lanes=lanes), config)


async def connect_webtransport(
    url: str, *, tls: TlsConfig | None = None, lanes: int = 4, config: Config | None = None
) -> Session:
    return await Session.connect(await dial_webtransport(url, tls=tls, lanes=lanes), config)


async def connect_http(addr: str, *, path: str = "/zmux", config: Config | None = None) -> Session:
    return await Session.connect(await dial_http(addr, path=path), config)


_bridges: set[asyncio.Future[None]] = set()


def pipe_from_streams(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> PipeIo:
    """A pipe over an asyncio stream pair. Bytes cross into Python and back,
    so this is slower than the built-in carriers; use it for transports the
    binding has no carrier for. The bridge ends when either side closes."""
    pipe, end = pipe_pair()

    async def inbound() -> None:
        try:
            while data := await reader.read(65536):
                await end.write(data)
        finally:
            await end.write(b"")

    async def outbound() -> None:
        try:
            while data := await end.read():
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    for coro in (inbound(), outbound()):
        task = asyncio.ensure_future(coro)
        _bridges.add(task)
        task.add_done_callback(_bridges.discard)
    return pipe




class StreamWriter:
    """An asyncio.StreamWriter-style view of a SendStream.

    write() never blocks: data is queued and sent in the background;
    drain() waits while more than `high_water` bytes are queued and raises
    the error of a failed send. close()/write_eof() finish the stream once
    the queue is sent."""

    def __init__(self, stream: SendStream, *, high_water: int = 65536) -> None:
        self.stream = stream
        self._high_water = high_water
        self._buf = bytearray()
        self._queued = 0
        self._task: asyncio.Future[None] | None = None
        self._closing: asyncio.Future[None] | None = None

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self._closing is not None:
            raise RuntimeError("write after close or write_eof")
        self._buf += data
        self._queued += len(data)
        if self._task is None or self._task.done():
            self._task = asyncio.ensure_future(self._flush())

    def writelines(self, data: Iterable[bytes | bytearray | memoryview]) -> None:
        for d in data:
            self.write(d)

    async def _flush(self) -> None:
        while self._buf:
            data = bytes(self._buf)
            self._buf.clear()
            try:
                await self.stream.write(data)
            finally:
                self._queued -= len(data)

    async def drain(self) -> None:
        task = self._task
        if task is None:
            return
        if not task.done() and self._queued > self._high_water:
            await asyncio.shield(task)
        if task.done() and not task.cancelled() and task.exception() is not None:
            raise task.exception()  # type: ignore[misc]

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        if self._closing is None:
            self._closing = asyncio.ensure_future(self._finish())

    async def _finish(self) -> None:
        if self._task is not None:
            await self._task
        await self.stream.finish()

    def close(self) -> None:
        self.write_eof()

    def is_closing(self) -> bool:
        return self._closing is not None

    async def wait_closed(self) -> None:
        self.close()
        assert self._closing is not None
        await self._closing

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "stream_id":
            return self.stream.id
        if name == "send_stream":
            return self.stream
        return default


async def open_connection(
    session: Session,
    *,
    info: bytes | None = None,
    tlvs: Iterable[Tlv | tuple[int, bytes]] | None = None,
    priority: Priority | tuple[int, bool] | None = None,
    peer_priority: Priority | tuple[int, bool] | None = None,
) -> tuple[RecvStream, StreamWriter]:
    """Opens a bidirectional stream as a (reader, writer) pair in the asyncio streams style.
    The reader is the RecvStream itself (read, read_exact, async for)."""
    send, recv = await session.open_bi(
        info=info, tlvs=list(tlvs) if tlvs is not None else None, priority=priority,
        peer_priority=peer_priority,
    )
    return recv, StreamWriter(send)
