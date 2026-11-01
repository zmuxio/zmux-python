"""QMux-compatible stream and datagram multiplexing; a binding over the zmux Rust crates."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from typing import Any

from ._layer import Layer, LayerWriter, open_carrier
from ._types import (
    AdmissionStats,
    CandidateOutcome,
    CandidateResult,
    CapacityBelow,
    CapacityFloor,
    CapacityRestored,
    CarrierCandidate,
    CarrierChosen,
    CarrierKind,
    CloseInfo,
    Config,
    Credential,
    Direction,
    DuplicateRule,
    EarlyDataState,
    ErrorKind,
    Event,
    EventKind,
    Forwarded,
    GoAway,
    InboundState,
    JoinAuthFailed,
    JoinSecurityUnavailable,
    LaneStats,
    Limiter,
    ListenerStats,
    OutboundState,
    PipeAuth,
    PipeHalf,
    PipeOptions,
    PipePriorityChanged,
    PipeQualityChanged,
    PipeRequest,
    PipesRetired,
    PipeStateChanged,
    PipeStats,
    Preamble,
    Priority,
    PrioritySource,
    QualityBand,
    Resolved,
    Resumed,
    Role,
    RttSource,
    Scheduler,
    SessionState,
    SessionStats,
    ShapingLimits,
    ShapingSizeLimits,
    Spliced,
    SpliceEnd,
    StreamStats,
    Suspended,
    TierSaturation,
    Tlv,
    TransportErrorCode,
    UnknownEvent,
)
from ._zmux import (
    DEFAULT_BACKOFF_MAX,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_KEEP_ALIVE_PERIOD,
    DEFAULT_MAX_RECORD_SIZE,
    DEFAULT_PROBE_JITTER,
    DEFAULT_STANDBY_PROBE,
    MIN_MAX_LEN,
    STARTUP_ALLOWANCE,
    Admission,
    Candidate,
    CarrierCache,
    CarrierInfo,
    CarrierStream,
    ConnectError,
    DatagramError,
    DatagramStream,
    EarlyDataRejected,
    EventStream,
    ExchangeOptions,
    Http2Connection,
    IncompleteRead,
    LimitExceeded,
    Listener,
    ListenerClosed,
    MaintainHandle,
    Mode,
    ModeError,
    OpenError,
    Pipe,
    PipeEnd,
    PipeError,
    PipeHint,
    PipeIo,
    PipePool,
    PipeReservation,
    PoolPolicy,
    PoolPolicyDecision,
    PreambleTooLargeError,
    PrefixAuth,
    QuicClient,
    RecvStream,
    SendStream,
    Session,
    SessionClosed,
    StreamError,
    StreamReset,
    StreamStopped,
    TlsConfig,
    UnsentCount,
    Verdict,
    ZeroRtt,
    ZmuxError,
    dial_exchange,
    dial_h3,
    dial_http,
    dial_http_split,
    dial_mode,
    dial_quic,
    dial_tcp,
    dial_tls,
    dial_websocket,
    dial_webtransport,
    join_http_split,
    pipe_pair,
    resolve_duplicate,
    splice,
    stream_pipe,
)

__version__ = "0.3.2"

__all__ = [
    "DEFAULT_BACKOFF_MAX",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_KEEP_ALIVE_PERIOD",
    "DEFAULT_MAX_RECORD_SIZE",
    "DEFAULT_PROBE_JITTER",
    "DEFAULT_STANDBY_PROBE",
    "MIN_MAX_LEN",
    "STARTUP_ALLOWANCE",
    "Admission",
    "AdmissionStats",
    "Candidate",
    "CandidateOutcome",
    "CandidateResult",
    "CapacityBelow",
    "CapacityFloor",
    "CapacityRestored",
    "CarrierCache",
    "CarrierCandidate",
    "CarrierChosen",
    "CarrierInfo",
    "CarrierKind",
    "CarrierStream",
    "CloseInfo",
    "Config",
    "ConnectError",
    "Credential",
    "DatagramError",
    "DatagramStream",
    "Direction",
    "DuplicateRule",
    "EarlyDataRejected",
    "EarlyDataState",
    "ErrorKind",
    "Event",
    "EventKind",
    "EventStream",
    "ExchangeOptions",
    "Forwarded",
    "GoAway",
    "Http2Connection",
    "InboundState",
    "IncompleteRead",
    "JoinAuthFailed",
    "JoinSecurityUnavailable",
    "LaneStats",
    "Layer",
    "LayerWriter",
    "LimitExceeded",
    "Limiter",
    "Listener",
    "ListenerClosed",
    "ListenerStats",
    "MaintainHandle",
    "Mode",
    "ModeError",
    "OpenError",
    "OutboundState",
    "Pipe",
    "PipeAuth",
    "PipeEnd",
    "PipeError",
    "PipeHalf",
    "PipeHint",
    "PipeIo",
    "PipeOptions",
    "PipePool",
    "PipePriorityChanged",
    "PipeQualityChanged",
    "PipeRequest",
    "PipeReservation",
    "PipeStateChanged",
    "PipeStats",
    "PipesRetired",
    "PoolPolicy",
    "PoolPolicyDecision",
    "Preamble",
    "PreambleTooLargeError",
    "PrefixAuth",
    "Priority",
    "PrioritySource",
    "QualityBand",
    "QuicClient",
    "RecvStream",
    "Resolved",
    "Resumed",
    "Role",
    "RttSource",
    "Scheduler",
    "SendStream",
    "Session",
    "SessionClosed",
    "SessionState",
    "SessionStats",
    "ShapingLimits",
    "ShapingSizeLimits",
    "SpliceEnd",
    "Spliced",
    "StreamError",
    "StreamReset",
    "StreamStats",
    "StreamStopped",
    "StreamWriter",
    "Suspended",
    "TierSaturation",
    "TlsConfig",
    "Tlv",
    "TransportErrorCode",
    "UnknownEvent",
    "UnsentCount",
    "Verdict",
    "ZeroRtt",
    "ZmuxError",
    "connect_exchange",
    "connect_h3",
    "connect_http",
    "connect_http2",
    "connect_http_split",
    "connect_quic",
    "connect_tcp",
    "connect_tls",
    "connect_websocket",
    "connect_webtransport",
    "dial_exchange",
    "dial_h3",
    "dial_http",
    "dial_http2",
    "dial_http_split",
    "dial_mode",
    "dial_quic",
    "dial_tcp",
    "dial_tls",
    "dial_websocket",
    "dial_webtransport",
    "join_http_split",
    "open_carrier",
    "open_connection",
    "pipe_from_streams",
    "pipe_pair",
    "resolve_duplicate",
    "splice",
    "stream_pipe",
]

_Headers = Mapping[str, str] | Iterable[tuple[str, str]]
_Credential = PrefixAuth | Credential


async def connect_tcp(
    addr: str,
    *,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    return await Session.connect(await dial_tcp(addr, credential=credential), config)


async def connect_tls(
    addr: str,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    pipe = await dial_tls(addr, tls=tls, server_name=server_name, credential=credential)
    return await Session.connect(pipe, config)


async def connect_quic(
    addr: str,
    *,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    lanes: int = 4,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    pipe = await dial_quic(
        addr, tls=tls, server_name=server_name, lanes=lanes, credential=credential
    )
    return await Session.connect(pipe, config)


async def connect_websocket(
    url: str,
    *,
    tls: TlsConfig | None = None,
    headers: _Headers | None = None,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    pipe = await dial_websocket(url, tls=tls, headers=headers, credential=credential)
    return await Session.connect(pipe, config)


async def dial_http2(
    addr: str,
    *,
    path: str = "/zmux",
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    credential: _Credential | None = None,
) -> PipeIo:
    conn = await Http2Connection.connect(
        addr, path=path, tls=tls, server_name=server_name, credential=credential
    )
    return await conn.open_pipe()


async def connect_http2(
    addr: str,
    *,
    path: str = "/zmux",
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    pipe = await dial_http2(
        addr, path=path, tls=tls, server_name=server_name, credential=credential
    )
    return await Session.connect(pipe, config)


async def connect_h3(
    url: str,
    *,
    tls: TlsConfig | None = None,
    addr: str | None = None,
    lanes: int = 4,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    return await Session.connect(
        await dial_h3(url, tls=tls, addr=addr, lanes=lanes, credential=credential),
        config,
    )


async def connect_webtransport(
    url: str,
    *,
    tls: TlsConfig | None = None,
    lanes: int = 4,
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    pipe = await dial_webtransport(url, tls=tls, lanes=lanes, credential=credential)
    return await Session.connect(pipe, config)


async def connect_http(
    addr: str,
    *,
    path: str = "/zmux",
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    return await Session.connect(
        await dial_http(addr, path=path, credential=credential), config
    )


async def connect_http_split(
    addr: str,
    *,
    path: str = "/zmux",
    credential: _Credential | None = None,
    config: Config | None = None,
) -> Session:
    """A session on a split bootstrap: an uplink POST and a downlink GET
    paired by a fresh token (run it over TLS or a trusted TLS-terminating
    intermediary: the token is a bearer secret until the session is up)."""
    return await Session.connect(
        await dial_http_split(addr, path=path, credential=credential), config
    )


async def connect_exchange(
    addr: str,
    *,
    options: ExchangeOptions | None = None,
    down_addr: str | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    config: Config | None = None,
) -> Session:
    pipe = await dial_exchange(
        addr, options=options, down_addr=down_addr, tls=tls, server_name=server_name
    )
    return await Session.connect(pipe, config)


_bridges: set[asyncio.Future[None]] = set()


def pipe_from_streams(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> PipeIo:
    """A pipe over an asyncio stream pair. Bytes cross into Python and back,
    so this is slower than the built-in carriers; use it for transports the
    binding has no carrier for. The bridge ends when either side closes.
    The transport's `get_write_buffer_size()`, where it has one, is the
    carrier's unsent count, taken at each write and drain."""
    pipe, end = pipe_pair()
    size = getattr(writer.transport, "get_write_buffer_size", None)
    count = UnsentCount() if size is not None else None
    if count is not None:
        pipe = pipe.with_unsent(count)

    def note() -> None:
        if count is not None and size is not None:
            count.set(size())

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
                note()
                await writer.drain()
                note()
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
        if (
            task.done()
            and not task.cancelled()
            and (exc := task.exception()) is not None
        ):
            raise exc

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self._finishing()

    def _finishing(self) -> asyncio.Future[None]:
        if self._closing is None:
            self._closing = asyncio.ensure_future(self._finish())
        return self._closing

    async def _finish(self) -> None:
        if self._task is not None:
            await self._task
        await self.stream.finish()

    def close(self) -> None:
        self.write_eof()

    def is_closing(self) -> bool:
        return self._closing is not None

    async def wait_closed(self) -> None:
        await self._finishing()

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
        info=info,
        tlvs=list(tlvs) if tlvs is not None else None,
        priority=priority,
        peer_priority=peer_priority,
    )
    return recv, StreamWriter(send)
