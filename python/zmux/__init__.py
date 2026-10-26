"""QMux-compatible stream and datagram multiplexing; a binding over the zmux Rust crates."""

from __future__ import annotations

import asyncio

from ._zmux import (
    Config,
    ConnectError,
    Http2Connection,
    DatagramError,
    EarlyDataRejected,
    IncompleteRead,
    Listener,
    OpenError,
    Pipe,
    PipeEnd,
    PipeError,
    PipeIo,
    PipeReservation,
    QuicClient,
    RecvStream,
    SendStream,
    Session,
    SessionClosed,
    StreamError,
    StreamReset,
    StreamStopped,
    TlsConfig,
    ZeroRtt,
    ZmuxError,
    dial_h3,
    dial_http,
    dial_quic,
    dial_tcp,
    dial_tls,
    dial_webtransport,
    dial_websocket,
    pipe_pair,
)

__version__ = "0.3.0"

__all__ = [
    "Config", "ConnectError", "DatagramError", "EarlyDataRejected", "Http2Connection",
    "IncompleteRead", "Listener", "OpenError", "Pipe", "PipeEnd", "PipeError", "PipeIo",
    "PipeReservation", "QuicClient", "RecvStream", "SendStream", "Session", "SessionClosed",
    "StreamError", "StreamReset", "StreamStopped", "StreamWriter", "TlsConfig", "ZeroRtt",
    "ZmuxError", "connect_h3", "connect_http", "connect_http2", "connect_quic", "connect_tcp",
    "connect_tls", "connect_webtransport", "connect_websocket", "dial_h3", "dial_http",
    "dial_http2", "dial_quic", "dial_tcp", "dial_tls", "dial_webtransport", "dial_websocket",
    "open_connection", "pipe_from_streams", "pipe_pair",
]


async def connect_tcp(addr: str, config: Config | None = None) -> Session:
    return await Session.connect(await dial_tcp(addr), config)


async def connect_tls(addr: str, server_name: str, tls: TlsConfig, config: Config | None = None) -> Session:
    return await Session.connect(await dial_tls(addr, server_name, tls), config)


async def connect_quic(
    addr: str, server_name: str, tls: TlsConfig, config: Config | None = None, *, lanes: int = 4
) -> Session:
    return await Session.connect(await dial_quic(addr, server_name, tls, lanes), config)


async def connect_websocket(
    url: str, config: Config | None = None, *, tls: TlsConfig | None = None
) -> Session:
    return await Session.connect(await dial_websocket(url, tls), config)


async def dial_http2(
    addr: str, path: str = "/zmux", tls: TlsConfig | None = None, server_name: str | None = None
) -> PipeIo:
    """A pipe on a new HTTP/2 connection; keep an Http2Connection to open more on one connection."""
    return await (await Http2Connection.connect(addr, path, tls, server_name)).open_pipe()


async def connect_http2(
    addr: str,
    config: Config | None = None,
    *,
    path: str = "/zmux",
    tls: TlsConfig | None = None,
    server_name: str | None = None,
) -> Session:
    return await Session.connect(await dial_http2(addr, path, tls, server_name), config)


async def connect_h3(
    url: str, tls: TlsConfig, config: Config | None = None, *, addr: str | None = None, lanes: int = 4
) -> Session:
    return await Session.connect(await dial_h3(url, tls, addr, lanes), config)


async def connect_webtransport(
    url: str, tls: TlsConfig, config: Config | None = None, *, lanes: int = 4
) -> Session:
    return await Session.connect(await dial_webtransport(url, tls, lanes), config)


async def connect_http(addr: str, config: Config | None = None, *, path: str = "/zmux") -> Session:
    return await Session.connect(await dial_http(addr, path), config)


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
    """An asyncio.StreamWriter-style view of a SendStream: write() buffers, drain() sends."""

    def __init__(self, stream: SendStream) -> None:
        self.stream = stream
        self._buf = bytearray()
        self._closing: asyncio.Future[None] | None = None

    def write(self, data: bytes) -> None:
        self._buf += data

    async def drain(self) -> None:
        if self._buf:
            data, self._buf = bytes(self._buf), bytearray()
            await self.stream.write(data)

    def close(self) -> None:
        """Finishes the stream once buffered data is sent; await wait_closed() for the result."""
        if self._closing is None:
            self._closing = asyncio.ensure_future(self._close())

    async def _close(self) -> None:
        await self.drain()
        await self.stream.finish()

    async def wait_closed(self) -> None:
        self.close()
        assert self._closing is not None
        await self._closing


async def open_connection(session: Session, **open_args: object) -> tuple[RecvStream, StreamWriter]:
    """Opens a bidirectional stream as a (reader, writer) pair in the asyncio streams style.
    The reader is the RecvStream itself (read, read_exact)."""
    send, recv = await session.open_bi(**open_args)  # type: ignore[arg-type]
    return recv, StreamWriter(send)
