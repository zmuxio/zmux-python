"""Client sessions in one call: the carrier's `dial_*` function, then
`Session.connect`."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ._types import CarrierCredential, Config, Direction
from ._zmux import (
    DEFAULT_LANES,
    ExchangeOptions,
    Http2Connection,
    PipeIo,
    PrefixAuth,
    Session,
    TlsConfig,
    dial_exchange,
    dial_http3,
    dial_quic,
    dial_split,
    dial_streaming,
    dial_tcp,
    dial_tls,
    dial_websocket,
    dial_webtransport,
)

type _Credential = PrefixAuth | CarrierCredential
type _Headers = Mapping[str, str] | Iterable[tuple[str, str]]
type _Address = tuple[str, int]


async def dial_http2(
    host: str,
    port: int,
    *,
    path: str = "/zmux",
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _Credential | None = None,
    pair_field: str | None = None,
) -> PipeIo:
    """A pipe input on a new HTTP/2 connection to `host` and `port` (prior
    knowledge without `tls`, ALPN `h2` with it): one bidirectional request to
    `path`. For more requests on one connection use `Http2Connection`."""
    conn = await Http2Connection.dial(
        host,
        port,
        path=path,
        tls=tls,
        server_name=server_name,
        carrier_credential=carrier_credential,
        pair_field=pair_field,
    )
    return await conn.open_pipe()


async def connect_tcp(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    carrier_credential: _Credential | None = None,
) -> Session:
    """A client session on a TCP carrier: `dial_tcp`, then
    `Session.connect`."""
    pipe = await dial_tcp(host, port, carrier_credential=carrier_credential)
    return await Session.connect(pipe, config=config)


async def connect_tls(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _Credential | None = None,
) -> Session:
    """A client session on a TLS carrier: `dial_tls`, then
    `Session.connect`."""
    pipe = await dial_tls(
        host,
        port,
        tls=tls,
        server_name=server_name,
        carrier_credential=carrier_credential,
    )
    return await Session.connect(pipe, config=config)


async def connect_quic(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _Credential | None = None,
) -> Session:
    """A client session on a QUIC carrier: `dial_quic`, then
    `Session.connect`."""
    pipe = await dial_quic(
        host,
        port,
        tls=tls,
        server_name=server_name,
        lanes=lanes,
        carrier_credential=carrier_credential,
    )
    return await Session.connect(pipe, config=config)


async def connect_websocket(
    url: str,
    *,
    config: Config | None = None,
    tls: TlsConfig | None = None,
    headers: _Headers | None = None,
    carrier_credential: _Credential | None = None,
    no_subprotocol: bool = False,
) -> Session:
    """A client session on a WebSocket carrier: `dial_websocket`, then
    `Session.connect`."""
    pipe = await dial_websocket(
        url,
        tls=tls,
        headers=headers,
        carrier_credential=carrier_credential,
        no_subprotocol=no_subprotocol,
    )
    return await Session.connect(pipe, config=config)


async def connect_http2(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    path: str = "/zmux",
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _Credential | None = None,
    pair_field: str | None = None,
) -> Session:
    """A client session on an HTTP/2 carrier: `dial_http2`, then
    `Session.connect`."""
    pipe = await dial_http2(
        host,
        port,
        path=path,
        tls=tls,
        server_name=server_name,
        carrier_credential=carrier_credential,
        pair_field=pair_field,
    )
    return await Session.connect(pipe, config=config)


async def connect_http3(
    url: str,
    *,
    config: Config | None = None,
    tls: TlsConfig | None = None,
    addr: _Address | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _Credential | None = None,
) -> Session:
    """A client session on an HTTP/3 carrier: `dial_http3`, then
    `Session.connect`."""
    pipe = await dial_http3(
        url,
        tls=tls,
        addr=addr,
        lanes=lanes,
        carrier_credential=carrier_credential,
    )
    return await Session.connect(pipe, config=config)


async def connect_webtransport(
    url: str,
    *,
    config: Config | None = None,
    tls: TlsConfig | None = None,
    lanes: int = DEFAULT_LANES,
    carrier_credential: _Credential | None = None,
) -> Session:
    """A client session on a WebTransport carrier: `dial_webtransport`,
    then `Session.connect`."""
    pipe = await dial_webtransport(
        url, tls=tls, lanes=lanes, carrier_credential=carrier_credential
    )
    return await Session.connect(pipe, config=config)


async def connect_streaming(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    path: str = "/zmux",
    carrier_credential: _Credential | None = None,
    direction: Direction | str = Direction.BIDI,
    pair_field: str | None = None,
) -> Session:
    """A client session on an HTTP/1.1 streaming carrier:
    `dial_streaming`, then `Session.connect`."""
    pipe = await dial_streaming(
        host,
        port,
        path=path,
        carrier_credential=carrier_credential,
        direction=direction,
        pair_field=pair_field,
    )
    return await Session.connect(pipe, config=config)


async def connect_split(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    path: str = "/zmux",
    carrier_credential: _Credential | None = None,
    pair_field: str | None = None,
) -> Session:
    """A client session on a split bootstrap, an uplink `POST` and a
    downlink `GET` paired by a fresh token (`dial_split`); run it over TLS or
    a trusted TLS-terminating intermediary: the token is a bearer secret
    until the session is up."""
    pipe = await dial_split(
        host,
        port,
        path=path,
        carrier_credential=carrier_credential,
        pair_field=pair_field,
    )
    return await Session.connect(pipe, config=config)


async def connect_exchange(
    host: str,
    port: int,
    *,
    config: Config | None = None,
    options: ExchangeOptions | None = None,
    down_addr: _Address | None = None,
    tls: TlsConfig | None = None,
    server_name: str | None = None,
    carrier_credential: _Credential | None = None,
) -> Session:
    """A client session on the exchange carrier: `dial_exchange`, then
    `Session.connect`."""
    pipe = await dial_exchange(
        host,
        port,
        options=options,
        down_addr=down_addr,
        tls=tls,
        server_name=server_name,
        carrier_credential=carrier_credential,
    )
    return await Session.connect(pipe, config=config)
