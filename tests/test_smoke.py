import asyncio
import contextlib
import datetime
import ipaddress
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from types import CoroutineType
from typing import Any, Never, cast

import pytest
import zmux

Tls = tuple[zmux.TlsConfig, zmux.TlsConfig]
StreamPair = tuple[asyncio.StreamReader, asyncio.StreamWriter]
JoinReport = tuple[zmux.PipeId, BaseException | None]
SessionJoinReport = tuple[zmux.SessionId, zmux.PipeId, BaseException | None]


@pytest.fixture(scope="module")
def tls() -> Tls:
    pytest.importorskip("cryptography")  # no 32-bit Windows wheels
    from certs import self_signed

    cert_pem, key_pem = self_signed()
    return zmux.TlsConfig(cert=cert_pem, key=key_pem), zmux.TlsConfig(ca=cert_pem)


async def echo(listener: zmux.Listener) -> None:
    async for session in listener:
        async for send, recv in session:
            await send.write(await recv.read_to_end())
            await send.finish()


async def round_trip(
    session: zmux.Session, data: bytes = b"hello", **open_args: Any
) -> None:
    send, recv = await session.open_bi(
        **(open_args or {"info": b"meta", "priority": zmux.Priority(2)})
    )
    await send.write(data)
    await send.finish()
    assert await recv.read_to_end() == data


@pytest.mark.parametrize(
    "carrier",
    [
        "tcp",
        "tls",
        "quic",
        "websocket",
        "wss",
        "http",
        "http2",
        "http2-tls",
        "h3",
        "webtransport",
    ],
)
# HS-08
async def test_carrier(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        if carrier == "tcp":
            addr = await listener.serve_tcp("127.0.0.1", 0)
            dial = zmux.dial_tcp(*addr)
        elif carrier == "tls":
            addr = await listener.serve_tls("127.0.0.1", 0, tls=server_tls)
            # HS-08. Finish one malformed handshake before opening the good one.
            reader, writer = await asyncio.open_connection(*addr)
            writer.write(b"not a TLS record")
            await writer.drain()
            with contextlib.suppress(ConnectionResetError):
                await reader.read()
            writer.close()
            dial = zmux.dial_tls(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
            dial = zmux.dial_quic(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "websocket":
            addr = await listener.serve_websocket("127.0.0.1", 0)
            dial = zmux.dial_websocket(f"ws://{addr[0]}:{addr[1]}/")
        elif carrier == "wss":
            addr = await listener.serve_websocket("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_websocket(f"wss://localhost:{port}/", tls=client_tls)
        elif carrier == "http2":
            addr = await listener.serve_http("127.0.0.1", 0)
            dial = zmux.dial_http2(*addr)
        elif carrier == "http2-tls":
            addr = await listener.serve_http("127.0.0.1", 0, tls=server_tls)
            dial = zmux.dial_http2(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "h3":
            addr = await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
        elif carrier == "webtransport":
            # The client resolves the URL's host: serve on its first address.
            addr = await listener.serve_webtransport("localhost", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_webtransport(
                f"https://localhost:{port}/zmux", tls=client_tls
            )
        else:
            addr = await listener.serve_http("127.0.0.1", 0)
            dial = zmux.dial_streaming(*addr)
        server = asyncio.create_task(echo(listener))
        async with await zmux.Session.connect(await dial) as session:
            await round_trip(session)
        server.cancel()


async def test_http2_over_tls_has_the_connection_exporter(tls: Tls) -> None:
    """Every bidirectional request of an HTTP/2 connection on TLS both ends
    terminate has that connection's exporter: the session's exporter is the
    same at both ends, and over h2c there is none."""
    server_tls, client_tls = tls
    cfg = zmux.Config(max_pipes=2, pipe_auth=zmux.PipeAuth.exporter().with_end_to_end())
    async with zmux.Listener(config=cfg) as listener:
        addr = await listener.serve_http("127.0.0.1", 0, tls=server_tls)
        conn = await zmux.Http2Connection.dial(
            *addr, tls=client_tls, server_name="localhost"
        )
        pipe = await conn.open_pipe()
        assert pipe.terminated_tls is not None
        async with (
            await zmux.Session.connect(pipe, config=cfg) as c,
            await listener.accept() as s,
        ):
            got = c.export_keying_material("app", length=16)
            assert got == s.export_keying_material("app", length=16)
            extra = await conn.open_pipe()
            assert extra.terminated_tls is not None
            await c.add_pipe(extra)
            first, second = c.pipe_stats()
            assert first.carrier_sample is not None
            assert second.carrier_sample is not None
            assert first.carrier_sample.carrier_id == second.carrier_sample.carrier_id
            assert first.carrier_sample.sampled_at == second.carrier_sample.sampled_at
            assert isinstance(first.carrier_sample.sampled_at, int)
        plain = await listener.serve_http("127.0.0.1", 0)
        pipe = await zmux.dial_http2(*plain)
        assert pipe.terminated_tls is None


def prefix_auth(
    psk: bytes = b"prefix secret", bind_tls: bool = False
) -> zmux.PrefixAuth:
    return zmux.PrefixAuth(psk, slot=30, bind_tls=bind_tls)


def admit(auth: zmux.PrefixAuth) -> zmux.Admission:
    return zmux.Admission.prefix_auth(
        auth, skew=1, max_nonces=1024, peek_timeout=0.3, stall=(0.05, 0.1)
    )


async def serve_admitted(
    listener: zmux.Listener, carrier: str, server_tls: zmux.TlsConfig
) -> tuple[str, int]:
    if carrier == "tcp":
        return await listener.serve_tcp("127.0.0.1", 0)
    if carrier == "quic":
        return await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
    if carrier == "http":
        return await listener.serve_http("127.0.0.1", 0)
    if carrier == "h3":
        return await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
    if carrier == "websocket":
        return await listener.serve_websocket("127.0.0.1", 0)
    if carrier == "wss":
        return await listener.serve_websocket("127.0.0.1", 0, tls=server_tls)
    if carrier == "webtransport":
        return await listener.serve_webtransport("localhost", 0, tls=server_tls)
    return await listener.serve_tls("127.0.0.1", 0, tls=server_tls)


def dial_with(
    carrier: str,
    addr: tuple[str, int],
    client_tls: zmux.TlsConfig,
    credential: zmux.PrefixAuth | zmux.CarrierCredential | None,
) -> Awaitable[zmux.PipeIo]:
    port = addr[1]
    if carrier == "tcp":
        return zmux.dial_tcp(*addr, carrier_credential=credential)
    if carrier == "quic":
        return zmux.dial_quic(
            *addr,
            tls=client_tls,
            server_name="localhost",
            carrier_credential=credential,
        )
    if carrier == "http":
        return zmux.dial_streaming(*addr, carrier_credential=credential)
    if carrier == "h3":
        return zmux.dial_http3(
            f"https://localhost:{port}/zmux",
            tls=client_tls,
            addr=addr,
            carrier_credential=credential,
        )
    if carrier == "websocket":
        return zmux.dial_websocket(
            f"ws://{addr[0]}:{addr[1]}/", carrier_credential=credential
        )
    if carrier == "wss":
        return zmux.dial_websocket(
            f"wss://localhost:{port}/", tls=client_tls, carrier_credential=credential
        )
    if carrier == "webtransport":
        return zmux.dial_webtransport(
            f"https://localhost:{port}/zmux",
            tls=client_tls,
            carrier_credential=credential,
        )
    return zmux.dial_tls(
        *addr, tls=client_tls, server_name="localhost", carrier_credential=credential
    )


@pytest.mark.parametrize(
    ("carrier", "bind_tls"),
    [
        ("tcp", False),
        ("tls", False),
        ("tls", True),
        ("quic", False),
        ("quic", True),
        ("http", False),
        ("h3", False),
        ("h3", True),
        ("websocket", False),
        ("wss", False),
        ("wss", True),
        ("webtransport", False),
        ("webtransport", True),
    ],
)
async def test_prefix_auth(carrier: str, bind_tls: bool, tls: Tls) -> None:
    server_tls, client_tls = tls
    auth = prefix_auth(bind_tls=bind_tls)
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admit(auth))
    ) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        server = asyncio.create_task(echo(listener))
        pipe = await asyncio.wait_for(dial_with(carrier, addr, client_tls, auth), 10)
        async with await zmux.Session.connect(pipe) as session:
            await round_trip(session)
        server.cancel()


async def test_held_carriers_count_per_source() -> None:
    admission = zmux.Admission.prefix_auth(
        zmux.PrefixAuth(b"k", slot=30), skew=1, peek_timeout=5, stall=(60, 60)
    )
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            limits=zmux.ListenerLimits(max_pending_per_source=2), admission=admission
        )
    ) as listener:
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        conns = [await asyncio.open_connection(host, port) for _ in range(3)]
        for _, w in conns:
            w.write(bytes(32))
            await w.drain()
        reads = [asyncio.create_task(r.read()) for r, _ in conns]
        # A source stalls at most max_pending_per_source - 1 carriers: one
        # stalls and holds its slot, the others are refused or closed.
        done: set[asyncio.Task[bytes]] = set()
        pending = set(reads)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 10
        while len(done) < 2 and loop.time() < deadline:
            d, pending = await asyncio.wait(
                pending,
                timeout=deadline - loop.time(),
                return_when=asyncio.FIRST_COMPLETED,
            )
            done |= d
        assert len(done) == 2 and len(pending) == 1
        for t in done:
            # Closed, or reset over the bytes sent.
            assert isinstance(t.exception(), ConnectionResetError) or t.result() == b""
        await asyncio.sleep(0.1)
        assert not pending.pop().done()
        assert (
            listener.stats().admission.stall_overflow >= 1
            or listener.stats().refused >= 1
        )
        for t in reads:
            t.cancel()
        for _, w in conns:
            w.close()


@pytest.mark.parametrize(
    "carrier", ["tcp", "tls", "quic", "http", "h3", "websocket", "webtransport"]
)
@pytest.mark.parametrize("token", ["none", "wrong"])
async def test_prefix_auth_refused(carrier: str, token: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admit(prefix_auth()))
    ) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        other = prefix_auth(psk=b"other secret") if token == "wrong" else None
        with pytest.raises((asyncio.TimeoutError, zmux.ZmuxError, OSError)):
            pipe = await asyncio.wait_for(
                dial_with(carrier, addr, client_tls, other), 5
            )
            session = await asyncio.wait_for(zmux.Session.connect(pipe), 2)
            await asyncio.wait_for(round_trip(session), 2)


def test_prefix_auth_config() -> None:
    with pytest.raises(ValueError):
        zmux.PrefixAuth(b"", slot=30)
    with pytest.raises(ValueError):
        zmux.PrefixAuth(b"k", slot=0)
    auth = zmux.PrefixAuth(b"k", slot=30, bind_tls=True)
    assert auth.bind_tls and auth.header == "Zmux-Prefix-Auth"
    assert zmux.PrefixAuth(b"k", slot=30, header="X-Token").header == "X-Token"
    assert isinstance(auth, zmux.PrefixAuth)
    with pytest.raises(ValueError):
        _ = zmux.dial_streaming("127.0.0.1", 1, carrier_credential=auth)
    with pytest.raises(ValueError):
        _ = zmux.dial_tcp("127.0.0.1", 1, carrier_credential=object())  # type: ignore[arg-type]  # not a credential, on purpose
    a = zmux.Admission(
        lambda info, prefix: zmux.AdmissionVerdict.CLOSE,
        peek=4,
        peek_timeout=1,
        stall=(2, 3),
    )
    assert (a.peek, a.peek_timeout, a.stall) == (4, 1, (2, 3))
    assert (
        zmux.AdmissionVerdict.accept()
        == zmux.AdmissionVerdict.accept(0)
        != zmux.AdmissionVerdict.fallback()
    )
    assert zmux.ExchangeOptions(psk=b"k", time_window=30, max_recorded=16).path


# A label of zmux's own, whose value the carrier metadata holds.
LABEL = "EXPORTER-zmux-prefix-auth"


class ExportedToken:
    """A credential of the application's own: the TLS exporter as the
    prefix, or in a header field."""

    def __init__(self) -> None:
        self.calls: list[zmux.CarrierInfo] = []

    def _value(self, info: zmux.CarrierInfo) -> bytes:
        self.calls.append(info)
        value = info.export(LABEL, b"", 32)
        assert value is not None and len(value) == 32
        return value

    def prefix(self, info: zmux.CarrierInfo) -> bytes:
        return self._value(info)

    def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
        return "x-token", self._value(info).hex()


@pytest.mark.parametrize("carrier", ["tls", "quic", "wss", "webtransport"])
async def test_custom_credential_and_decider(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    seen: list[zmux.CarrierInfo] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append(info)
        expected = info.export(LABEL, b"", 32)
        assert expected is not None
        if info.stage is zmux.AdmissionStage.HEAD:
            assert info.upgrade
            assert prefix == b"" and info.headers is not None
            fields = dict(info.headers)
            return (
                zmux.AdmissionVerdict.accept()
                if fields.get("x-token") == expected.hex().encode()
                else zmux.AdmissionVerdict.fallback()
            )
        assert info.headers is None
        return (
            zmux.AdmissionVerdict.accept(32)
            if prefix == expected
            else zmux.AdmissionVerdict.fallback()
        )

    credential = ExportedToken()
    admission = zmux.Admission(decide, peek=32, peek_timeout=5, stall=(0.05, 0.1))
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admission)
    ) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        server = asyncio.create_task(echo(listener))
        pipe = await asyncio.wait_for(
            dial_with(carrier, addr, client_tls, credential), 10
        )
        async with await zmux.Session.connect(pipe) as session:
            await round_trip(session)
        server.cancel()
    assert len(seen) == 1 and seen[0].source is not None and seen[0].peer is not None
    head = carrier in ("wss", "webtransport")
    assert (seen[0].stage is zmux.AdmissionStage.HEAD) == head
    assert seen[0].upgrade == head
    # A TLS listener's metadata holds zmux's own labels only.
    if carrier == "tls":
        assert seen[0].export(LABEL) is not None
        assert seen[0].export("EXPORTER-test") is None


@pytest.mark.parametrize("carrier", ["websocket", "webtransport"])
async def test_a_deferred_decision_on_the_carrier(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    seen: list[tuple[zmux.AdmissionStage, zmux.adapter.Framing, bool, bytes]] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append((info.stage, info.framing, info.upgrade, prefix))
        if info.stage is zmux.AdmissionStage.HEAD:
            return zmux.AdmissionVerdict.DEFER
        kind, need = zmux.adapter.classify_first_bytes(prefix, framing=info.framing)
        if kind is zmux.adapter.FirstBytes.RECORD:
            return zmux.AdmissionVerdict.accept()
        if kind is zmux.adapter.FirstBytes.NEED_MORE:
            return zmux.AdmissionVerdict.more(need)
        return zmux.AdmissionVerdict.CLOSE

    admission = zmux.Admission(
        decide, peek=1, max_peek=zmux.adapter.MAX_FIRST_BYTES, peek_timeout=5
    )
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admission)
    ) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        server = asyncio.create_task(echo(listener))
        pipe = await asyncio.wait_for(dial_with(carrier, addr, client_tls, None), 10)
        async with await zmux.Session.connect(pipe) as session:
            await round_trip(session)
        server.cancel()
        stats = listener.stats().admission
    framing = (
        zmux.adapter.Framing.RECORDS
        if carrier == "websocket"
        else zmux.adapter.Framing.BYTE_STREAM
    )
    assert seen[0][:3] == (
        zmux.AdmissionStage.HEAD,
        zmux.adapter.Framing.BYTE_STREAM,
        True,
    )
    assert seen[-1][:3] == (zmux.AdmissionStage.CARRIER, framing, True)
    assert seen[-1][3]
    assert (stats.accepted, stats.closed, stats.too_large) == (1, 0, 0)


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
# HS-07
async def test_a_failing_decider_closes() -> None:
    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        raise RuntimeError("no")

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=zmux.Admission(decide, peek=1))
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        host, port = addr
        r, w = await asyncio.open_connection(host, int(port))
        w.write(b"x")
        await w.drain()
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()


@pytest.mark.parametrize("secure", [False, True])
async def test_exchange(secure: bool, tls: Tls) -> None:
    server_tls, client_tls = tls
    opts = zmux.ExchangeOptions(
        psk=b"exchange secret",
        encoding="base64",
        path="/up/{instance}",
        down_path="/down/{instance}/{nonce}",
    )
    assert zmux.ExchangeOptions().down_path is zmux.AUTO
    assert (opts.encoding, opts.path, opts.down_path) == (
        "base64",
        "/up/{instance}",
        "/down/{instance}/{nonce}",
    )
    with pytest.raises(ValueError):
        zmux.ExchangeOptions(encoding="hex")  # type: ignore[arg-type]  # an invalid value on purpose
    async with zmux.Listener() as listener:
        if secure:
            addr = await listener.serve_http(
                "127.0.0.1", 0, tls=server_tls, exchange=opts
            )
            port = addr[1]
            target = ("localhost", port)
            dial: dict[str, Any] = {"tls": client_tls}
        else:
            addr = await listener.serve_http("127.0.0.1", 0, exchange=opts)
            target = addr
            dial = {}
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            async with await zmux.connect_exchange(
                *target, **dial, options=opts
            ) as session:
                await round_trip(session)
                await round_trip(session, bytes(range(256)) * 1024)
            # A client with another key gets no session.
            with pytest.raises(zmux.ZmuxError):
                async with asyncio.timeout(3):
                    other = zmux.ExchangeOptions(
                        psk=b"wrong",
                        encoding="base64",
                        path="/up/{instance}",
                        down_path="/down/{instance}/{nonce}",
                        deadline=1,
                    )
                    await zmux.connect_exchange(*target, **dial, options=other)
        server.cancel()


async def test_preamble_and_errors() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            send, _ = await client.open_bi(info=b"route", tlvs=[(0x1000, b"x")])
            await send.write(b"a")
            _, recv = await server.accept_bi()
            assert recv.preamble == zmux.Preamble(b"route", (zmux.Tlv(0x1000, b"x"),))
            send.reset(7)
            with pytest.raises(zmux.StreamResetError) as e:
                await recv.read_to_end()
            assert (
                e.value.code == 7
                and e.value.kind == zmux.ErrorKind.RESET
                and isinstance(e.value, zmux.ZmuxError)
            )
            server.abort(3)
            with pytest.raises(zmux.SessionClosedError) as closed:
                await client.accept_bi()
            assert closed.value.code == 3 and not e.value.retryable
            info = await client.wait_closed()
            assert (
                info.code == 3
                and info.remote
                and isinstance(info, zmux.ApplicationClosedError)
            )


async def test_cancellation() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            _, recv = await client.open_bi()
            task = asyncio.ensure_future(recv.read())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            recv.stop(1)  # the cancelled read released the stream
            accept = asyncio.ensure_future(server.accept_uni())
            await asyncio.sleep(0.05)
            accept.cancel()
            with pytest.raises(asyncio.CancelledError):
                await accept
            assert await client.ping() >= 0  # the session is still healthy


async def test_a_pipes_quality_band_follows_is_own_or_off() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    own = zmux.QualityBand(rtt=0.1)
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            session.quality_band = zmux.QualityBand(rate_ratio=2.0)

            async def added(**options: Any) -> zmux.Pipe:
                p = await session.add_pipe(
                    await zmux.dial_tcp(*addr), options=zmux.PipeOptions(**options)
                )
                await p.joined()
                return p

            def band(p: zmux.Pipe) -> object:
                o = p.options
                assert o is not None
                return o.quality_band

            follows, off, mine = (
                await added(),
                await added(quality_band=None),
                await added(quality_band=own),
            )
            assert band(follows) is zmux.INHERIT
            assert band(off) is None
            assert band(mine) == own
            # An update sets an own band, off for the pipe, or clears to the
            # session's; a band that is not one is refused.
            for value in (own, None, zmux.CLEAR):
                follows.update(quality_band=value)
            for bad in (zmux.INHERIT, 0.5, "off"):
                with pytest.raises(TypeError):
                    follows.update(quality_band=bad)  # type: ignore[arg-type]
            assert band(mine) == own
        server.cancel()


async def test_multipath() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            options = zmux.PipeOptions(
                send_priority=1, receive_priority=1, send_standby=True, label="b"
            )
            pipe = await session.add_pipe(await zmux.dial_tcp(*addr), options=options)
            await pipe.joined()
            stats = session.pipe_stats()
            assert len(stats) == 2 and all(isinstance(s, zmux.PipeStats) for s in stats)
            o = pipe.options
            assert (o.send_priority, o.receive_priority, o.send_standby, o.label) == (
                1,
                1,
                True,
                "b",
            )
            # update: left out keeps, CLEAR clears, a value sets.
            pipe.update(weight=3, receive_standby=True, send_priority=zmux.CLEAR)
            o = pipe.options
            assert (
                o.send_priority,
                o.receive_priority,
                o.weight,
                o.receive_standby,
            ) == (zmux.INHERIT, 1, 3, True)
            bad: dict[str, Any]
            for bad in (
                {"label": "x"},
                {"direction": "in"},
                {"probe_interval": 2},
                {"nope": 1},
            ):
                with pytest.raises(TypeError):
                    pipe.update(**bad)
            with pytest.raises(ValueError):
                pipe.update(weight=None)  # type: ignore[arg-type]  # no off setting
            with pytest.raises(ValueError):
                pipe.update(weight=2, receive_priority=-1)
            o = pipe.options
            assert o.weight == 3
            with pytest.raises(ValueError):
                await session.add_pipe(
                    await zmux.dial_tcp(*addr),
                    options=zmux.PipeOptions(
                        liveness=zmux.PipeLiveness(suspect_floor=0.01)
                    ),
                )
            await round_trip(session, b"x" * 100_000)
            assert session.stats().streams_opened_local == 1
            assert pipe.session.pipe_stats()[1].pipe == pipe.id
            pipe.close()
            await asyncio.wait_for(pipe.wait_closed(), 10)
            ev = await asyncio.wait_for(anext(session.events()), 5)
            assert isinstance(ev, zmux.Event) and isinstance(ev.kind, zmux.EventKind)
        server.cancel()


async def test_early_data() -> None:
    config = zmux.Config(early_data=True)
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            # Before the peer's parameters arrive: the preamble and the
            # requested priority travel within the floor.
            await round_trip(session, b"early", info=b"meta", peer_priority=(1, True))
            # On loopback the parameters may arrive before the stream opens.
            assert session.early_data in (
                zmux.EarlyDataState.ACCEPTED,
                zmux.EarlyDataState.NOT_SENT,
            )
        server.cancel()


async def test_quic_zero_rtt(tls: Tls) -> None:
    server_tls, client_tls = tls
    # Carrier early data only: connect waits for the server's parameters,
    # which the client remembers for the next connection.
    config = zmux.Config(carrier_early_data=True)
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls, zero_rtt=True)
        server = asyncio.create_task(echo(listener))
        client = zmux.QuicClient(client_tls, zero_rtt=True)
        session = await client.connect(*addr, server_name="localhost", config=config)
        zero = session.zero_rtt
        assert zero is not None
        async with session:
            await round_trip(session)
            assert session.early_data is zmux.EarlyDataState.NOT_SENT
        assert not zero.sent and client.remembers("localhost")
        session = await client.connect(*addr, server_name="localhost", config=config)
        zero = session.zero_rtt
        assert zero is not None
        async with session:
            await round_trip(session)
        assert zero.sent
        server.cancel()


async def test_resume_controls() -> None:
    config = zmux.Config(
        max_pipes=8,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        resume_timeout=5,
        liveness=zmux.Liveness(dead_timeout=2, suspect_floor=0.1),
        probation=None,
    )
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            assert zmux.adapter.join_ready(session)
            session.revalidate_pipes()
            await round_trip(session)
        server.cancel()


@pytest.mark.parametrize("field", ["peer", "source"])
@pytest.mark.parametrize(
    ("address", "error"),
    [(("!", 0), ValueError), ((str(ipaddress.IPv4Address(0)), 65536), OverflowError)],
)
async def test_handle_pipe_consumes_the_carrier_on_invalid_address(
    field: str, address: tuple[str, int], error: type[Exception]
) -> None:
    async with zmux.Listener() as listener:
        pipe, peer = zmux.adapter.pipe_pair()
        with pytest.raises(error):
            await listener.handle_pipe(pipe, **{field: address})
        with pytest.raises(zmux.PipeUsedError):
            await listener.handle_pipe(pipe)
        assert await asyncio.wait_for(peer.read(), timeout=2) == b""


async def test_stream_pair() -> None:
    # Multipath, where the carrier's unsent count feeds the scheduler.
    config = zmux.Config(
        max_pipes=2, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(config=config) as listener:
        server = asyncio.create_task(echo(listener))

        handed_off = asyncio.Event()

        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await listener.handle_pipe(zmux.pipe_from_streams(reader, writer))
            handed_off.set()

        tcp = await asyncio.start_server(handle, "127.0.0.1", 0)
        host, port = tcp.sockets[0].getsockname()[:2]
        reader, writer = await asyncio.open_connection(host, port)
        async with await zmux.Session.connect(
            zmux.pipe_from_streams(reader, writer), config=config
        ) as session:
            await asyncio.wait_for(handed_off.wait(), timeout=5)
            await round_trip(session)
            listener.close()
            await round_trip(session)
            # The transport's write buffer is the carrier's unsent count.
            async with asyncio.timeout(5):
                while session.pipe_stats()[0].queued_bytes is None:
                    await round_trip(session)
            (st,) = session.pipe_stats()
            assert st.queued_bytes is not None and st.queued_bytes >= 0
        server.cancel()
        tcp.close()


# HS-02
async def test_stream_bridge_keeps_reading_after_inbound_join_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    async def pair() -> tuple[StreamPair, StreamPair]:
        near, far = socket.socketpair()
        return await asyncio.open_connection(sock=near), await asyncio.open_connection(
            sock=far
        )

    config = zmux.Config(
        max_pipes=3, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with asyncio.timeout(8), zmux.Listener(config=config) as listener:
        near, far = await pair()
        boot = asyncio.ensure_future(listener.handle_pipe(zmux.pipe_from_streams(*far)))
        async with await zmux.Session.connect(
            zmux.pipe_from_streams(*near), config=config
        ) as client:
            server = await listener.accept()
            await boot
            (bootstrap,) = client.pipes()
            near, far = await pair()
            half_closed = asyncio.Event()
            end_write = far[1].write_eof

            def finish_write() -> None:
                end_write()
                half_closed.set()

            monkeypatch.setattr(far[1], "write_eof", finish_write)
            handled = asyncio.ensure_future(
                listener.handle_pipe(zmux.pipe_from_streams(*far))
            )
            added = await client.add_pipe(
                zmux.pipe_from_streams(*near),
                options=zmux.PipeOptions(direction=zmux.Direction.OUT),
            )
            await handled
            await half_closed.wait()
            # Keep a return path for acknowledgements, then remove the only
            # other sending pipe. Scheduling policy cannot mask a broken half.
            rnear, rfar = await pair()
            handling = asyncio.ensure_future(
                listener.handle_pipe(zmux.pipe_from_streams(*rfar))
            )
            reverse = await client.add_pipe(
                zmux.pipe_from_streams(*rnear),
                options=zmux.PipeOptions(direction=zmux.Direction.IN),
            )
            await handling
            await reverse.wait_attached()
            await added.wait_attached()
            bootstrap.abort()
            stats = added.stats()
            assert stats is not None
            sent = stats.bytes_sent
            payload = b"after outbound EOF" * 2048
            send = await client.open_uni()
            await send.write(payload)
            await send.finish()
            recv = await server.accept_uni()
            assert await recv.read_to_end() == payload
            stats = added.stats()
            assert stats is not None
            assert stats.bytes_sent - sent >= len(payload)


# HS-50
async def test_stream_bridge_bounds_a_blocked_final_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from zmux import _streams

    entered, closed = asyncio.Event(), asyncio.Event()

    class Transport:
        def abort(self) -> None:
            aborted.set()

    aborted = asyncio.Event()

    class Writer:
        transport = Transport()

        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            entered.set()
            await asyncio.Future()

        async def wait_closed(self) -> None:
            await closed.wait()

        def close(self) -> None:
            closed.set()

    monkeypatch.setattr(_streams, "_BRIDGE_FLUSH_TIMEOUT", 0.05)
    before = set(_streams._bridges)
    pipe = zmux.pipe_from_streams(
        asyncio.StreamReader(), cast(asyncio.StreamWriter, Writer())
    )
    (bridge,) = _streams._bridges - before
    task = asyncio.ensure_future(zmux.Session.connect(pipe))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(closed.wait(), 2)
    await asyncio.wait({bridge}, timeout=1)
    assert bridge.done() and bridge not in _streams._bridges
    assert aborted.is_set()


@pytest.mark.parametrize(
    "ending", ["normal", "hang", "ignore_cancel", "both_timeouts", "cancel"]
)
async def test_bridge_settles_host_close(
    ending: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zmux import _streams

    release, waiting, cancelled, resume, done = (asyncio.Event() for _ in range(5))
    aborts: list[None] = []
    host_close: asyncio.Task[None] | None = None

    async def inbound() -> None:
        await asyncio.Future()

    async def outbound() -> None:
        if ending == "both_timeouts":
            await asyncio.Future()

    async def released() -> None:
        await release.wait()

    async def wait_closed() -> None:
        nonlocal host_close
        host_close = asyncio.current_task()
        waiting.set()
        if ending == "normal":
            return
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.set()
            if ending != "ignore_cancel":
                raise
            await resume.wait()
            raise OSError("late host close failure") from None

    # An expired deadline schedules cancellation once cleanup next yields.
    if ending in {"hang", "ignore_cancel", "both_timeouts"}:
        monkeypatch.setattr(_streams, "_BRIDGE_FLUSH_TIMEOUT", 0.0)

    before = set(_streams._bridges)
    _streams._start_bridge(
        inbound,
        outbound,
        released,
        lambda: None,
        wait_closed,
        lambda: aborts.append(None),
        done.set,
    )
    (bridge,) = _streams._bridges - before
    try:
        async with asyncio.timeout(2):
            release.set()
            await waiting.wait()
            if ending == "cancel":
                bridge.cancel()
            await done.wait()
            assert len(aborts) == (0 if ending == "normal" else 1)
            if ending != "normal":
                await cancelled.wait()
            assert host_close is not None
            if ending == "ignore_cancel":
                assert not host_close.done()
    finally:
        resume.set()
        if host_close is not None:
            await asyncio.gather(host_close, return_exceptions=True)
        if not bridge.done():
            bridge.cancel()
            await asyncio.gather(bridge, return_exceptions=True)


# HS-50
async def test_pipe_closed_waits_for_stream_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    from zmux import _streams

    local, remote = socket.socketpair()
    reader, writer = await asyncio.open_connection(sock=local)
    peer, peer_writer = await asyncio.open_connection(sock=remote)
    arrived = asyncio.Event()
    release = asyncio.Event()
    original_close = writer.close
    original_wait_closed = writer.wait_closed

    async def wait_for_transport() -> None:
        # Hold the transport open at the bridge's close barrier.
        arrived.set()
        await release.wait()
        original_close()
        await original_wait_closed()

    monkeypatch.setattr(writer, "can_write_eof", lambda: False)
    monkeypatch.setattr(writer, "close", lambda: None)
    monkeypatch.setattr(writer, "wait_closed", wait_for_transport)
    monkeypatch.setattr(_streams, "_BRIDGE_FLUSH_TIMEOUT", 8.0)
    config = zmux.Config(
        max_pipes=3, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    try:
        async with (
            asyncio.timeout(8),
            zmux.Listener(config=config) as listener,
            asyncio.TaskGroup() as tasks,
        ):
            handler = tasks.create_task(
                listener.handle_pipe(zmux.pipe_from_streams(peer, peer_writer))
            )
            before = set(_streams._bridges)
            io = zmux.pipe_from_streams(reader, writer)
            (bridge,) = _streams._bridges - before
            async with (
                await zmux.Session.connect(io, config=config) as client,
                await listener.accept(),
            ):
                await handler
                pipe = client.pipes()[0]

                async def wait_for_pipe() -> None:
                    with pytest.raises(zmux.PipeAbortedError):
                        await pipe.wait_closed()

                waiting = tasks.create_task(wait_for_pipe())
                pipe.abort()
                await arrived.wait()
                assert not waiting.done()
                assert not bridge.done()
                assert local.fileno() >= 0
                release.set()
                await waiting
                assert bridge.done() and bridge not in _streams._bridges
                assert local.fileno() == -1
    finally:
        release.set()
        original_close()
        peer_writer.close()
        await asyncio.gather(
            original_wait_closed(), peer_writer.wait_closed(), return_exceptions=True
        )


async def test_unsent_count_needs_no_interpreter_lock() -> None:
    # The driver reads the count the application sets, with the
    # interpreter lock held elsewhere all the while.
    import time

    count = zmux.adapter.UnsentCount()
    assert count.value is None
    count.set(1234)
    assert count.value == 1234
    config = zmux.Config(
        max_pipes=2, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(config=config) as listener:
        server = asyncio.create_task(echo(listener))
        addr = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(*addr)
        pipe, end = zmux.adapter.pipe_pair(unsent=count)

        async def inbound() -> None:
            while data := await reader.read(65536):
                await end.write(data)
            await end.write(b"")

        async def outbound() -> None:
            while data := await end.read():
                writer.write(data)
                await writer.drain()

        bridges = [asyncio.ensure_future(inbound()), asyncio.ensure_future(outbound())]
        async with await zmux.Session.connect(pipe, config=config) as session:
            await round_trip(session)
            # Busy in Python without awaiting: a driver that needed the
            # lock to read the count would stall until it is released.
            start = time.monotonic()
            while time.monotonic() - start < 0.3:
                pass
            async with asyncio.timeout(5):
                while session.pipe_stats()[0].queued_bytes != 1234:
                    await round_trip(session)
            count.set(None)
        for b in bridges:
            b.cancel()
        writer.close()
        server.cancel()


def test_threads() -> None:
    """Sessions on several threads' event loops at once (free-threaded builds run them in parallel)."""
    import threading

    async def one() -> None:
        async with zmux.Listener() as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            server = asyncio.ensure_future(echo(listener))
            async with await zmux.connect_tcp(*addr) as session:
                for _ in range(20):
                    await round_trip(session, b"t" * 10_000)
            server.cancel()

    errors: list[BaseException] = []

    def run() -> None:
        try:
            asyncio.run(one())
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors


async def test_typed_surface() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            assert (
                client.role == zmux.Role.CLIENT
                and client.state == zmux.SessionState.ACTIVE
            )
            send, recv = await client.open_bi()
            async with send:
                send.priority = zmux.Priority(1, True)
                assert send.priority == zmux.Priority(1, True)
                await send.write(b"ab")
            s2, r2 = await server.accept_bi()
            assert b"".join([c async for c in r2]) == b"ab"
            with pytest.raises(ValueError):
                async with s2:
                    await s2.write(b"x")
                    raise ValueError
            with pytest.raises(zmux.StreamResetError):
                await recv.read_to_end()
            _, _r3 = await client.open_bi()
            _s3, w = await server.open_stream_pair()
            w.writelines([b"1", b"2"])
            await w.drain()
            assert w.can_write_eof() and not w.is_closing()
            await w.wait_closed()
            _, r4 = await client.accept_bi()
            assert await r4.read_to_end() == b"12"
            s5 = await client.open_uni()
            await s5.write(b"y" * 10)
            await s5.finish()
            with pytest.raises(zmux.LimitExceededError):
                await (await server.accept_uni()).read_to_end(limit=4)
        listener.close()
        with pytest.raises(zmux.ListenerClosedError):
            await listener.accept()


def test_config() -> None:
    c = zmux.Config(max_idle_timeout=5, protocols=["a"])  # type: ignore[arg-type]  # a list, to check its conversion
    # Durations are float seconds only.
    with pytest.raises((TypeError, ValueError)):
        zmux.Config(max_idle_timeout=datetime.timedelta(seconds=5))  # type: ignore[arg-type]  # removed on purpose
    assert c.replace(early_data=True).early_data and c.protocols == ("a",)
    assert "max_idle_timeout" in repr(c)


async def test_no_leaks_on_cancel() -> None:
    """Cancelled reads, writes and accepts release their streams; fds stay flat."""
    import gc
    import os

    def fds() -> int:
        return len(os.listdir("/dev/fd")) if os.path.isdir("/dev/fd") else 0

    async def cancel_soon(coro: Coroutine[Any, Any, object]) -> None:
        task = asyncio.ensure_future(coro)
        await asyncio.sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, zmux.ZmuxError):
            await task

    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            base = fds()
            for _ in range(200):
                send, recv = await client.open_bi()
                await cancel_soon(recv.read())
                await cancel_soon(send.write(b"z" * 1_000_000))
                await cancel_soon(server.accept_uni())
                send.reset(0)
                recv.stop(0)
                del send, recv
            gc.collect()
            for _ in range(100):
                if client.stats().streams_active == 0:
                    break
                await asyncio.sleep(0.02)
            assert client.stats().streams_active == 0
            assert fds() <= base + 2
            assert await client.ping() >= 0


async def test_shaper() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(definition="not json")
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(definition=PAD_1000, by_kind={})
            client.shaper = zmux.shaping.Shaper(definition=PAD_1000)
            send, _recv = await client.open_bi()
            await send.write(b"x" * 10)
            await send.finish()
            _s_send, s_recv = await server.accept_bi()
            assert await s_recv.read_to_end() == b"x" * 10
            st = client.shaping_stats()
            assert st["wire_spent"] >= 900 and st["faults"] == 0, st
            client.shaper = None
            assert set(st) == {
                "wire_spent",
                "stall_spent",
                "injected",
                "inject_dropped",
                "clamped",
                "handshake_unplanned",
                "faults",
            }


PAD_1000 = '{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'
PAD_RANGE = (
    '{"machines":[{"start":0,"states":[{"record":{"pad_to":{"t":[[1,500,3000]]}}}]}]}'
)


async def shaped_padding(
    config: zmux.Config | None = None, **shaper: Any
) -> dict[str, int | float]:
    """The padding a client shaped by `shaper` adds to one short stream."""
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr, config=config) as client:
            server = await listener.accept()
            client.shaper = zmux.shaping.Shaper(**shaper)
            send, _recv = await client.open_bi()
            await send.write(b"x" * 10)
            await send.finish()
            _, s_recv = await server.accept_bi()
            assert await s_recv.read_to_end() == b"x" * 10
            return client.shaping_stats()


async def test_shaping_limits_and_seed() -> None:
    limits = zmux.shaping.ShapingLimits(
        wire=zmux.shaping.ShapingAccount(initial=1), max_delay=1
    )
    assert limits.max_delay == 1.0
    # An account never refuses padding.
    st = await shaped_padding(zmux.Config(shaping_limits=limits), definition=PAD_1000)
    assert st["wire_spent"] >= 900, st
    bad: dict[str, Any]
    for bad in (
        {"max_delay": -0.1},
        {"max_delay": 0},
        {"max_delay": float("nan")},
    ):
        with pytest.raises(ValueError):
            zmux.shaping.ShapingLimits(**bad)
    for bad in ({"initial": -1}, {"per_mb": 1.5}, {"per_sec": (1 << 43) + 1}):
        with pytest.raises(ValueError):
            zmux.shaping.ShapingAccount(**bad)
    assert zmux.shaping.ShapingLimits(max_delay=None).max_delay is None  # no bound
    assert zmux.shaping.ShapingLimits().max_delay == zmux.shaping.DEFAULT_MAX_DELAY
    assert zmux.shaping.ShapingSizeLimits(max_slots=0).max_slots == 0  # no slot
    assert zmux.shaping.ShapingSizeLimits().max_slots == zmux.shaping.DEFAULT_MAX_SLOTS
    assert zmux.shaping.ShapingSizeLimits(max_slots=None).max_slots is None
    st = await shaped_padding(
        zmux.Config(shaping_limits=zmux.shaping.ShapingLimits(no_padding=True)),
        definition=PAD_1000,
    )
    assert st["wire_spent"] == 0, st
    for bad in ({"max_bytes": -1}, {"max_states": 1.5}):
        with pytest.raises(ValueError):
            zmux.shaping.ShapingSizeLimits(**bad)
    assert zmux.DEFAULT_STANDBY_PROBE == 1
    assert (
        zmux.DEFAULT_KEEP_ALIVE_PERIOD,
        zmux.DEFAULT_MAX_IDLE_TIMEOUT,
        zmux.DEFAULT_PROBE_JITTER,
    ) == (15, 30, 0.25)
    assert (
        zmux.DEFAULT_MAX_RECORD_SIZE,
        zmux.shaping.MIN_MAX_LEN,
        zmux.shaping.DEFAULT_MAX_DELAY,
    ) == (
        16382,
        64,
        1.0,
    )
    assert (zmux.DEFAULT_MIN_BACKOFF, zmux.DEFAULT_MAX_BACKOFF) == (1, 60)
    assert zmux.DEFAULT_JOIN_TIMEOUT == 10
    assert zmux.DEFAULT_FIRST_RECORD_TIMEOUT == 2
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(
                    definition=PAD_1000,
                    limits=zmux.shaping.ShapingSizeLimits(max_bytes=4),
                )
            client.shaper = zmux.shaping.Shaper(
                definition=PAD_1000,
                limits=zmux.shaping.ShapingSizeLimits(max_bytes=len(PAD_1000)),
            )
    runs = [
        (await shaped_padding(definition=PAD_RANGE, seed=b"seed"))["wire_spent"]
        for _ in range(2)
    ]
    # The same draw both times; the records it pads differ by a few control bytes.
    assert runs[0] > 0 and abs(runs[0] - runs[1]) < 64, runs


# HS-40
async def test_split_bootstrap_and_one_endpoint() -> None:
    auth = zmux.PrefixAuth(b"split secret", slot=30)
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            admission=zmux.Admission.prefix_auth(auth, skew=1)
        )
    ) as listener:
        addr = await listener.serve_http("127.0.0.1", 0, websocket=True)
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            async with await zmux.connect_split(
                *addr, carrier_credential=auth
            ) as session:
                await round_trip(session)
            async with await zmux.connect_streaming(
                *addr, carrier_credential=auth
            ) as session:
                await round_trip(session)
            async with await zmux.connect_websocket(
                f"ws://{addr[0]}:{addr[1]}/zmux", carrier_credential=auth
            ) as session:
                await round_trip(session)
            conn = await zmux.Http2Connection.dial(*addr, carrier_credential=auth)
            async with await zmux.Session.connect(await conn.open_split()) as session:
                await round_trip(session)
            # Without the credential, neither half is admitted.
            with pytest.raises(zmux.ZmuxError):
                async with asyncio.timeout(15):
                    await zmux.connect_split(*addr)
        server.cancel()


async def test_carrier_choices() -> None:
    auth = zmux.PrefixAuth(b"mode secret", slot=30)
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            admission=zmux.Admission.prefix_auth(auth, skew=1)
        )
    ) as listener:
        addr = await listener.serve_http("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            refused = zmux.Candidate.websocket(
                f"ws://{addr[0]}:{addr[1]}/zmux", carrier_credential=auth
            )
            streaming = zmux.Candidate.streaming(*addr, carrier_credential=auth)
            assert streaming.kind is zmux.CarrierKind.STREAMING
            # No WebSocket on this endpoint: an explicit choice reports it.
            with pytest.raises(zmux.CarrierChoiceError) as e:
                await zmux.connect_choice(zmux.CarrierChoice.explicit(refused))
            (result,) = e.value.results
            assert result.carrier == zmux.CarrierKind.WEBSOCKET
            assert result.outcome == zmux.CandidateOutcome.REFUSED
            cache = zmux.CarrierCache()
            choice = zmux.CarrierChoice.auto([refused, streaming])
            policy = zmux.CarrierChoicePolicy(cache=cache, key="local")
            async with await zmux.connect_choice(
                choice, choice_policy=policy
            ) as session:
                await round_trip(session)
                stats = session.stats()
                assert stats.carrier == zmux.CarrierKind.STREAMING
                assert [(r.carrier, r.outcome) for r in stats.carrier_candidates] == [
                    (zmux.CarrierKind.WEBSOCKET, zmux.CandidateOutcome.REFUSED),
                    (zmux.CarrierKind.STREAMING, zmux.CandidateOutcome.USABLE),
                ]
                events = session.events()
                seen = [await anext(events) for _ in range(3)]
                assert zmux.CarrierChosen(zmux.CarrierKind.STREAMING) in seen
            assert cache.is_failed("local", "websocket") and cache.is_usable(
                "local", "streaming"
            )
        server.cancel()


@pytest.mark.parametrize("carrier", ["quic", "http3", "webtransport"])
async def test_direct_candidates(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        if carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
            candidate = zmux.Candidate.quic(
                *addr, tls=client_tls, server_name="localhost"
            )
        elif carrier == "http3":
            addr = await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            candidate = zmux.Candidate.http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
        else:
            addr = await listener.serve_webtransport("localhost", 0, tls=server_tls)
            port = addr[1]
            candidate = zmux.Candidate.webtransport(
                f"https://localhost:{port}/zmux", tls=client_tls
            )
        assert candidate.kind is zmux.CarrierKind(carrier)
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            async with await zmux.connect_choice(
                zmux.CarrierChoice.explicit(candidate)
            ) as session:
                await round_trip(session)
                assert session.stats().carrier == zmux.CarrierKind(carrier)
        server.cancel()


async def test_auto_choice_falls_back_to_quic(tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
        port = addr[1]
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            # The QUIC listener offers no HTTP/3: that candidate fails.
            h3 = zmux.Candidate.http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
            quic = zmux.Candidate.quic(*addr, tls=client_tls, server_name="localhost")
            async with await zmux.connect_choice(
                zmux.CarrierChoice.auto([h3, quic])
            ) as session:
                await round_trip(session)
                stats = session.stats()
                assert stats.carrier == zmux.CarrierKind.QUIC
                assert [r.carrier for r in stats.carrier_candidates] == [
                    zmux.CarrierKind.HTTP3,
                    zmux.CarrierKind.QUIC,
                ]
                assert (
                    stats.carrier_candidates[1].outcome == zmux.CandidateOutcome.USABLE
                )
        server.cancel()


async def test_trusted_source_and_early_data() -> None:
    seen: list[tuple[str, int] | None] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append(info.source)
        return zmux.AdmissionVerdict.accept(0)

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            trusted_proxies=["127.0.0.0/8"],
            forwarded_header="X-Forwarded-For",
            admission=zmux.Admission(decide, peek=0),
        )
    ) as listener:
        addr = await listener.serve_http("127.0.0.1", 0)
        host, port = addr
        head = (
            "GET /zmux HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.7\r\n"
            "Zmux-Pipe-Pair: AAECAwQFBgcICQoLDA0ODw\r\n{}\r\n"
        )
        for extra, status in [("", b"200"), ("Early-Data: 1\r\n", b"425")]:
            r, w = await asyncio.open_connection(host, int(port))
            w.write(head.format(extra).encode())
            await w.drain()
            line = await asyncio.wait_for(r.readline(), 5)
            assert line.split()[1] == status, line
            w.close()
        assert seen and seen[0] is not None and seen[0][0] == "198.51.100.7"


async def test_proxy_protocol_sources(tls: Tls) -> None:
    import ssl

    server_tls, _ = tls
    seen: asyncio.Queue[str] = asyncio.Queue()

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        assert info.source is not None
        seen.put_nowait(info.source[0])
        return zmux.AdmissionVerdict.CLOSE

    admission = zmux.Admission(decide, peek=0)

    def insecure(alpn: list[str]) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(alpn)
        return ctx

    upgrade = (
        b"GET /zmux HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Protocol: qmux-02\r\n\r\n"
    )
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            trusted_proxies=["127.0.0.0/8"], proxy_protocol=True, admission=admission
        )
    ) as listener:
        servers = [
            (await listener.serve_tcp("127.0.0.1", 0), None, b""),
            (
                await listener.serve_tls("127.0.0.1", 0, tls=server_tls),
                insecure(["qmux-02"]),
                b"",
            ),
            (await listener.serve_websocket("127.0.0.1", 0), None, upgrade),
            (
                await listener.serve_websocket("127.0.0.1", 0, tls=server_tls),
                insecure(["http/1.1"]),
                upgrade,
            ),
        ]
        async with asyncio.timeout(20):
            for addr, ctx, request in servers:
                host, port = addr
                _r, w = await asyncio.open_connection(host, int(port))
                w.write(b"PROXY TCP4 198.51.100.7 10.0.0.1 4000 443\r\n")
                await w.drain()
                if ctx is not None:
                    await w.start_tls(ctx, server_hostname="localhost")
                w.write(request)
                await w.drain()
                assert await seen.get() == "198.51.100.7", addr
                w.close()


@pytest.mark.parametrize("carrier", ["quic", "h3", "webtransport", "tcp"])
async def test_datagram_channels(carrier: str, tls: Tls) -> None:
    """QUIC, HTTP/3 and WebTransport carriers send datagrams on their own
    datagram channel when the session enables datagrams; others in records."""
    server_tls, client_tls = tls
    config = zmux.Config(enable_datagrams=True)
    async with zmux.Listener(config=config) as listener:
        if carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
            dial = zmux.dial_quic(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "h3":
            addr = await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
        elif carrier == "webtransport":
            addr = await listener.serve_webtransport("localhost", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_webtransport(
                f"https://localhost:{port}/zmux", tls=client_tls
            )
        else:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            dial = zmux.dial_tcp(*addr)
        async with await zmux.Session.connect(await dial, config=config) as client:
            server = await asyncio.wait_for(listener.accept(), 10)
            for i in range(10):
                client.send_datagram(bytes([i]) * 100)
                assert (
                    await asyncio.wait_for(server.read_datagram(), 10)
                    == bytes([i]) * 100
                )
                server.send_datagram(bytes([i]) * 50)
                assert (
                    await asyncio.wait_for(client.read_datagram(), 10)
                    == bytes([i]) * 50
                )
            c, s = client.stats(), server.stats()
            assert c.datagrams_received_channel <= c.datagrams_received == 10
            if carrier == "tcp":
                assert (c.datagrams_sent_channel, s.datagrams_sent_channel) == (0, 0)
            else:
                # HTTP/3: the client's first ones may precede the server's SETTINGS.
                assert c.datagrams_sent_channel >= 8 and s.datagrams_sent_channel == 10
                assert s.datagrams_received_channel == c.datagrams_sent_channel
            server.close()


async def test_split_join_as_further_pipes() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
        ),
    ) as listener:
        addr = await listener.serve_http("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            async with await zmux.connect_streaming(*addr, config=config) as session:
                # A split bootstrap's carrier makes pipe pair 0 only.
                with pytest.raises(zmux.InvalidArgumentError) as refused:
                    await session.add_pipe(await zmux.dial_split(*addr))
                assert refused.value.kind == zmux.ErrorKind.INVALID_ARGUMENT
                options = zmux.PipeOptions(label="split")
                pipes = await zmux.join_split(session, *addr, options=options)
                assert len(pipes) == 1, "one Join across the pair, one attachment"
                assert pipes[0].options is not None
                assert pipes[0].options.label == "split"
                await round_trip(session)
                assert len(session.pipe_stats()) == 2
        server.cancel()


async def test_admission_stats_and_async_decide() -> None:
    seen: list[tuple[tuple[str, int] | None, tuple[str, int] | None]] = []

    async def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append((info.source, info.peer))
        await asyncio.sleep(0.01)
        return (
            zmux.AdmissionVerdict.accept(1)
            if prefix == b"z"
            else zmux.AdmissionVerdict.CLOSE
        )

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            admission=zmux.Admission(decide, peek=1, peek_timeout=5)
        )
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        host, port = addr
        r, w = await asyncio.open_connection(host, int(port))
        w.write(b"x")
        await w.drain()
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        server = asyncio.create_task(echo(listener))
        pipe = await zmux.dial_tcp(*addr, carrier_credential=_Fixed(b"z"))
        async with await zmux.Session.connect(pipe) as session:
            await round_trip(session)
        server.cancel()
        st = listener.stats()
        assert isinstance(st.admission, zmux.AdmissionStats)
        assert (st.admission.accepted, st.admission.closed, st.rejected) == (1, 1, 0)
        assert (
            seen[0][0] == seen[0][1]
            and seen[0][0] is not None
            and seen[0][0][0] == "127.0.0.1"
        )


class _Fixed:
    """A credential of fixed bytes."""

    def __init__(self, prefix: bytes) -> None:
        self._prefix = prefix

    def prefix(self, info: zmux.CarrierInfo) -> bytes:
        return self._prefix

    def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
        return "x-token", self._prefix.decode()


# HS-55
async def test_a_late_async_decide_is_a_peek_timeout() -> None:
    cancelling: asyncio.Queue[None] = asyncio.Queue()
    exited: asyncio.Queue[asyncio.Task[Any]] = asyncio.Queue()
    release = asyncio.Event()
    calls = 0

    async def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        nonlocal calls
        calls += 1
        if calls > 2:
            return zmux.AdmissionVerdict.CLOSE
        # The native done callback was registered before this task started.
        task = asyncio.current_task()
        assert task is not None
        task.add_done_callback(exited.put_nowait)
        never: asyncio.Future[Never] = asyncio.Future()
        try:
            return await never
        except asyncio.CancelledError:
            cancelling.put_nowait(None)
            await release.wait()
            raise

    async with (
        asyncio.timeout(8),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(
                limits=zmux.ListenerLimits(max_pending_per_source=2),
                admission=zmux.Admission(decide, peek_timeout=0.2),
            )
        ) as listener,
    ):
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        connections = await asyncio.gather(
            asyncio.open_connection(host, port), asyncio.open_connection(host, port)
        )
        try:
            await cancelling.get()
            await cancelling.get()
            r, w = await asyncio.open_connection(host, port)
            assert await r.read() == b""
            w.close()
            await w.wait_closed()
            assert calls == 2
            assert listener.stats().admission.peek_timed_out == 2
            assert listener.stats().refused == 1
        finally:
            release.set()
            for _, writer in connections:
                writer.close()
        await exited.get()
        await exited.get()
        r, w = await asyncio.open_connection(host, port)
        assert await r.read() == b""
        w.close()
        await w.wait_closed()
        assert calls == 3


async def test_handle_pipe_is_admitted_with_its_source() -> None:
    seen: list[tuple[tuple[str, int] | None, tuple[str, int] | None]] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append((info.source, info.peer))
        return zmux.AdmissionVerdict.CLOSE

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=zmux.Admission(decide))
    ) as listener:
        io, _end = zmux.adapter.pipe_pair()
        with pytest.raises(zmux.ZmuxError):
            await listener.handle_pipe(
                io, peer=("127.0.0.1", 9), source=("198.51.100.7", 4000)
            )
        assert seen == [(("198.51.100.7", 4000), ("127.0.0.1", 9))]
        assert listener.stats().admission.closed == 1


# HS-34, HS-35
async def test_shutdown_refuses_new_sessions() -> None:
    async with asyncio.timeout(8), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        handling = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near) as client:
            server = await listener.accept()
            await handling
            send, _recv = await client.open_bi()
            await send.write(b"hold shutdown")
            held = await server.accept_bi()
            shutdown = asyncio.ensure_future(listener.shutdown(17, b"bye"))
            with pytest.raises(zmux.ListenerClosedError):
                await listener.accept()
            listener.undrain()
            near, far = await _connected_carriers()
            handling = asyncio.ensure_future(listener.handle_pipe(far))
            refused: zmux.SessionClosedError
            try:
                second = await zmux.Session.connect(near)
            except zmux.ConnectionRefusedError as e:
                refused = e
            else:
                refused = await second.wait_closed()
            assert isinstance(refused, zmux.ConnectionRefusedError)
            assert refused.remote and refused.reason == b"bye"
            with pytest.raises(zmux.ConnectError):
                await handling
            assert listener.stats().refused == 1
            del send, held, _recv
            client.close()
            await shutdown


async def test_preamble_too_large() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr) as session:
            with pytest.raises(zmux.PreambleTooLargeError) as e:
                await session.open_bi(info=b"x" * 5000)
            assert isinstance(e.value, ValueError)
            assert 0 < e.value.max <= 4096
            await round_trip(session)
        server.cancel()


async def dial_then_connect(
    addr: tuple[str, int], client_tls: zmux.TlsConfig
) -> zmux.Session:
    pipe = await zmux.dial_quic(*addr, tls=client_tls, server_name="localhost")
    return await zmux.Session.connect(pipe)


async def test_a_coded_close_over_quic_closes_the_connection_after_the_zmux_close(
    tls: Tls,
) -> None:
    server_tls, client_tls = tls
    data = b"before the close" * 4096
    async with zmux.Listener() as listener:
        addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
        client = zmux.QuicClient(client_tls)
        for via_client in (True, False):
            if via_client:
                session = await client.connect(*addr, server_name="localhost")
            else:
                session = await dial_then_connect(addr, client_tls)
            server = await asyncio.wait_for(listener.accept(), 5)
            send, _ = await session.open_bi()
            await send.write(b"x")
            _, recv = await asyncio.wait_for(server.accept_bi(), 5)
            await asyncio.wait_for(recv.read_exact(1), 5)
            await send.write(data)
            session.close(0x2A, b"bye")
            got = bytearray()
            with pytest.raises(zmux.ApplicationClosedError) as err:
                while True:
                    chunk = await asyncio.wait_for(recv.read(65536), 5)
                    assert chunk
                    got += chunk
            assert bytes(got) == data and err.value.code == 0x2A
            # Both ends end; the QUIC close came after the zmux close.
            info = await asyncio.wait_for(server.wait_closed(), 5)
            assert (info.code, info.reason, info.remote) == (0x2A, b"bye", True)
            local = await asyncio.wait_for(session.wait_closed(), 5)
            assert (local.code, local.remote) == (0x2A, False)


@pytest.mark.parametrize("invalid", ["duplicate", "keyword", "positional", "reenter"])
async def test_handle_pipe_claim_precedes_argument_dispatch(invalid: str) -> None:
    async with zmux.Listener() as listener:
        pipe, peer = zmux.adapter.pipe_pair()

        # Exercise runtime argument rejection beyond the typed signature.
        handle_pipe: Callable[..., Coroutine[Any, Any, None]] = listener.handle_pipe

        class Port:
            def __index__(self) -> Never:
                with pytest.raises(zmux.PipeUsedError):
                    handle_pipe(pipe).close()
                raise ValueError("after reentry")

        with pytest.raises(ValueError if invalid == "reenter" else TypeError):
            if invalid == "duplicate":
                handle_pipe(pipe, pipe=pipe).close()
            elif invalid == "keyword":
                handle_pipe(pipe=pipe, extra=True).close()
            elif invalid == "positional":
                handle_pipe(pipe, 0).close()
            else:
                handle_pipe(pipe, peer=("!", Port())).close()
        with pytest.raises(zmux.PipeUsedError):
            listener.handle_pipe(pipe).close()
        assert await asyncio.wait_for(peer.read(), 2) == b""


# HS-01
async def test_handle_pipe_withdraw_before_start_and_during_transform() -> None:
    import socket

    entered, resume = asyncio.Event(), asyncio.Event()

    async def transform(pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint) -> zmux.PipeIo:
        entered.set()
        await resume.wait()
        return pipe

    async with (
        asyncio.timeout(5),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(inbound_transform=transform)
        ) as listener,
    ):
        pipe, peer = zmux.adapter.pipe_pair()
        unstarted = asyncio.ensure_future(listener.handle_pipe(pipe))
        unstarted.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unstarted
        with pytest.raises(zmux.PipeUsedError):
            listener.handle_pipe(pipe).close()
        assert await peer.read() == b""

        left, right = socket.socketpair()
        server = zmux.pipe_from_streams(*await asyncio.open_connection(sock=left))
        client = zmux.pipe_from_streams(*await asyncio.open_connection(sock=right))
        handling = asyncio.ensure_future(listener.handle_pipe(server))
        connecting = asyncio.ensure_future(zmux.Session.connect(client))
        await entered.wait()
        resume.set()
        handling.cancel()
        with pytest.raises(asyncio.CancelledError):
            await handling
        with pytest.raises(zmux.ZmuxError):
            await connecting
        assert listener.stats().sessions == 0


@pytest.mark.parametrize("ending", ["graceful", "timeout", "error"])
# HS-05, HS-51
async def test_layer_wait_closed_includes_retained_writer(
    ending: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zmux import _streams

    closing, resume = asyncio.Event(), asyncio.Event()
    retained = []
    if ending == "timeout":
        monkeypatch.setattr(_streams, "_BRIDGE_FLUSH_TIMEOUT", 0.1)

    class Writer:
        def __init__(self, writer: asyncio.StreamWriter) -> None:
            self.inner = writer

        def write(self, data: bytes) -> None:
            self.inner.write(data)

        async def drain(self) -> None:
            await self.inner.drain()

        def close(self) -> None:
            self.inner.close()

        async def wait_closed(self) -> None:
            closing.set()
            await resume.wait()
            if ending == "error":
                raise OSError("layer shutdown")
            await self.inner.wait_closed()

    async def layer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, Writer]:
        wrapped = Writer(writer)
        retained.append(wrapped)
        return reader, wrapped

    import socket

    config = zmux.Config(
        max_pipes=3, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with asyncio.timeout(8), zmux.Listener(config=config) as listener:
        near, far = socket.socketpair()
        remote = zmux.pipe_from_streams(*await asyncio.open_connection(sock=far))
        handling = asyncio.ensure_future(listener.handle_pipe(remote))
        native = zmux.pipe_from_streams(*await asyncio.open_connection(sock=near))
        before = set(_streams._bridges)
        wrapped = await native.wrap(layer)
        (bridge,) = _streams._bridges - before
        async with await zmux.Session.connect(wrapped, config=config) as session:
            server = await listener.accept()
            await handling
            (pipe,) = session.pipes()
            waiting = asyncio.ensure_future(pipe.wait_closed())
            pipe.abort()
            await closing.wait()
            assert not waiting.done() and not bridge.done()
            if ending != "timeout":
                resume.set()
            with pytest.raises(zmux.PipeAbortedError):
                await waiting
            assert bridge.done() and retained[0].inner.is_closing()
            assert near.fileno() == -1
            server.close()


async def serve_test_http(listener: zmux.Listener) -> tuple[str, int]:
    from ipaddress import IPv4Address
    from socket import INADDR_LOOPBACK

    return await listener.serve_http(str(IPv4Address(INADDR_LOOPBACK)), 0)


async def _connected_carriers() -> tuple[zmux.PipeIo, zmux.PipeIo]:
    import socket

    left, right = socket.socketpair()
    return (
        zmux.pipe_from_streams(*await asyncio.open_connection(sock=left)),
        zmux.pipe_from_streams(*await asyncio.open_connection(sock=right)),
    )


# HS-30, HS-32
async def test_listener_drain_can_be_reversed_and_replaced() -> None:
    async with asyncio.timeout(8), zmux.Listener() as listener:
        for reason in (b"first", None, b"second"):
            if reason is None:
                listener.undrain()
            else:
                listener.drain(b"obsolete")
                listener.drain(reason)
            near, far = await _connected_carriers()
            handling = asyncio.ensure_future(listener.handle_pipe(far))
            if reason is None:
                async with await zmux.Session.connect(near) as client:
                    server = await listener.accept()
                    await handling
                    assert client.id != server.id
                    server.close()
            else:
                error: zmux.SessionClosedError
                try:
                    session = await zmux.Session.connect(near)
                except zmux.ConnectionRefusedError as refused:
                    error = refused
                else:
                    error = await session.wait_closed()
                assert isinstance(error, zmux.ConnectionRefusedError)
                assert error.kind == zmux.ErrorKind.CONNECTION_REFUSED
                assert error.reason == reason and error.remote
                with pytest.raises(zmux.ZmuxError):
                    await handling
        assert listener.stats().refused == 2
        assert listener.stats().sessions == 1


# HS-20, HS-27
async def test_both_join_outcomes_precede_pipe_events() -> None:
    observed: asyncio.Queue[SessionJoinReport] = asyncio.Queue()
    release = asyncio.Event()

    held = set()

    async def joined(
        session: zmux.Session, pipe_id: zmux.PipeId, error: BaseException | None
    ) -> None:
        await observed.put((session.id, pipe_id, error))
        if session.id not in held:
            held.add(session.id)
            await release.wait()

    cfg = zmux.Config(
        max_pipes=3,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        join_outcome=joined,
        tracer=zmux.Tracer(),
    )
    async with asyncio.timeout(8), zmux.Listener(config=cfg) as listener:
        near, far = await _connected_carriers()
        boot = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await boot
            near, far = await _connected_carriers()
            handle = asyncio.ensure_future(listener.handle_pipe(far))
            pipe = await client.add_pipe(
                near, options=zmux.PipeOptions(return_on_reply=True)
            )
            await handle
            outcomes = [await observed.get(), await observed.get()]
            assert set(outcomes) == {
                (client.id, pipe.id, None),
                (server.id, pipe.id, None),
            }
            near, far = await _connected_carriers()
            other, _ = await asyncio.gather(
                client.add_pipe(near), listener.handle_pipe(far)
            )
            assert {await observed.get(), await observed.get()} == {
                (client.id, other.id, None),
                (server.id, other.id, None),
            }
            for side in (client, server):
                while (event := await side.next_event()) is not None:
                    key = getattr(event, "pipe", None)
                    assert key != pipe.id
                    if key == other.id:
                        break
                else:
                    pytest.fail("unrelated pipe was held behind the blocked hook")
            release.set()
            for side in (client, server):
                while (event := await side.next_event()) is not None:
                    if getattr(event, "pipe", None) == pipe.id:
                        break
                else:
                    pytest.fail("missing joined pipe event")
            assert observed.empty()
            server.close()


# HS-24
async def test_silent_policy_refusal_reports_each_endpoints_evidence() -> None:
    from dataclasses import replace

    calls: asyncio.Queue[SessionJoinReport] = asyncio.Queue()
    cfg = zmux.Config(
        max_pipes=3,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        join_outcome=lambda session, pipe, error: calls.put_nowait(
            (session.id, pipe, error)
        ),
    )
    acceptor = replace(cfg, allow_record_mode=lambda *_: False)
    async with asyncio.timeout(8), zmux.Listener(config=acceptor) as listener:
        near, far = await _connected_carriers()
        boot = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await boot
            near, far = await _connected_carriers()
            handled = asyncio.ensure_future(listener.handle_pipe(far))
            with pytest.raises(zmux.PipeError):
                await client.add_pipe(near)
            with pytest.raises(zmux.ZmuxError):
                await handled
            reports = [await calls.get(), await calls.get()]
            assert {sid for sid, _, _ in reports} == {client.id, server.id}
            failures = {sid: error for sid, _, error in reports}
            # MULTIPATH 5.4 step 7 silently closes a policy refusal.
            server_failure = failures[server.id]
            assert isinstance(server_failure, zmux.JoinRefusedError)
            assert server_failure.kind is zmux.ErrorKind.JOIN_REFUSED
            assert isinstance(failures[client.id], zmux.PipeGoneError)
            assert calls.empty()
            server.close()


# HS-25
async def test_unawaited_join_reports_reserved_id_and_releases_carrier() -> None:
    reports: asyncio.Queue[JoinReport] = asyncio.Queue()
    cfg = zmux.Config(
        join_outcome=lambda _, pipe, error: reports.put_nowait((pipe, error))
    )
    async with asyncio.timeout(8), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        boot = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await boot
            carrier, peer = zmux.adapter.pipe_pair()
            pending = client.add_pipe(carrier)
            pending.close()
            del pending
            pipe, error = await reports.get()
            assert pipe == zmux.PIPE_UNASSIGNED == 1 << 62
            assert isinstance(error, asyncio.CancelledError)
            assert await peer.read() == b""
            assert reports.empty()
            server.close()


# HS-24
async def test_join_withdrawal_preserves_the_callers_error() -> None:
    reports: asyncio.Queue[JoinReport] = asyncio.Queue()
    config = zmux.Config(
        max_pipes=3,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        join_outcome=lambda _, pipe, error: reports.put_nowait((pipe, error)),
    )
    async with asyncio.timeout(8), zmux.Listener(config=config) as listener:
        near, far = await _connected_carriers()
        setup = asyncio.create_task(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=config) as client:
            server = await listener.accept()
            await setup
            carrier, peer = zmux.adapter.pipe_pair()
            join = asyncio.create_task(client.add_pipe(carrier))
            assert await peer.read()
            reason = object()
            join.cancel(reason)
            with pytest.raises(asyncio.CancelledError) as caught:
                await join
            pipe, error = await reports.get()
            assert pipe != zmux.PIPE_UNASSIGNED
            assert isinstance(error, asyncio.CancelledError)
            assert error.args == caught.value.args == (reason,)
            assert await peer.read() == b""
            assert reports.empty()
            server.close()


async def test_invalid_join_options_consume_the_carrier_and_report_the_same_error() -> (
    None
):
    reports: asyncio.Queue[JoinReport] = asyncio.Queue()
    cfg = zmux.Config(
        join_outcome=lambda _, pipe, error: reports.put_nowait((pipe, error))
    )
    async with asyncio.timeout(8), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        setup = asyncio.create_task(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await setup
            carrier, peer = zmux.adapter.pipe_pair()
            with pytest.raises(AttributeError) as invalid:
                client.add_pipe(
                    carrier, options=cast(zmux.PipeOptions, object())
                ).close()
            pipe, error = await reports.get()
            assert pipe == zmux.PIPE_UNASSIGNED and error is invalid.value
            with pytest.raises(zmux.PipeUsedError):
                client.add_pipe(carrier).close()
            assert await peer.read() == b""
            assert reports.empty()
            server.close()


def test_quality_band_checks_subnanoseconds_before_rounding() -> None:
    with pytest.raises(ValueError):
        zmux.QualityBand(rtt=0.75e-9)
    with pytest.raises(ValueError):
        zmux.QualityBand(min_interval=0.75e-9)


@pytest.mark.parametrize("outcome", ["queued", "fallback", "fallback_error"])
async def test_committed_setup_survives_cancellation_during_delivery(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    failure = ValueError("host result")
    unraisable: list[BaseException | None] = []
    monkeypatch.setattr(
        "sys.unraisablehook", lambda event: unraisable.append(event.exc_value)
    )

    def fallback(_takeover: zmux.Takeover) -> None:
        if outcome == "fallback_error":
            raise failure

    cfg = (
        zmux.ListenerConfig()
        if outcome == "queued"
        else zmux.ListenerConfig(
            admission=zmux.Admission(
                lambda *_: zmux.AdmissionVerdict.fallback(), peek=0
            ),
            fallback=fallback,
        )
    )
    async with asyncio.timeout(8), zmux.Listener(listener_config=cfg) as listener:
        near, far = await _connected_carriers()
        arrival = listener.handle_pipe(far)
        frame = cast("CoroutineType[Any, Any, None]", arrival).cr_frame
        assert frame is not None
        future_type = frame.f_globals["SetupFuture"]
        method = "set_exception" if outcome == "fallback_error" else "set_result"
        original = getattr(future_type, method)
        attempts: list[bool] = []

        def deliver(future: asyncio.Future[None], result: object) -> None:
            attempts.append(setup.cancel("after commit"))
            original(future, result)

        monkeypatch.setattr(future_type, method, deliver)
        setup = asyncio.create_task(arrival)
        if outcome == "queued":
            async with await zmux.Session.connect(near) as client:
                await setup
                async with await listener.accept():
                    assert await client.ping() >= 0
        else:
            try:
                if outcome == "fallback_error":
                    with pytest.raises(zmux.ConnectError) as raised:
                        await setup
                    assert raised.value.__cause__ is failure
                    assert unraisable == [failure]
                else:
                    await setup
                    assert not unraisable
            finally:
                await near.into_stream().shutdown()
        assert attempts == [True]


# HS-04, HS-22
async def test_join_attachment_beats_cancellation_during_python_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports: asyncio.Queue[SessionJoinReport] = asyncio.Queue()
    config = zmux.Config(
        max_pipes=3,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        join_outcome=lambda session, pipe, error: reports.put_nowait(
            (session.id, pipe, error)
        ),
    )
    async with asyncio.timeout(8), zmux.Listener(config=config) as listener:
        near, far = await _connected_carriers()
        setup = asyncio.create_task(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=config) as client:
            server = await listener.accept()
            await setup
            a, b = await _connected_carriers()
            incoming = asyncio.create_task(listener.handle_pipe(b))
            outbound = client.add_pipe(a)
            frame = cast("CoroutineType[Any, Any, zmux.Pipe]", outbound).cr_frame
            assert frame is not None
            future_type = frame.f_globals["SetupFuture"]
            original = future_type.set_result
            attempts = []

            def deliver(future: Any, value: Any) -> None:
                if isinstance(value, zmux.Pipe):
                    attempts.append(join.cancel("late withdrawal"))
                original(future, value)

            monkeypatch.setattr(future_type, "set_result", deliver)
            join = asyncio.create_task(outbound)
            pipe = await join
            await incoming
            assert attempts == [True]
            assert {await reports.get(), await reports.get()} == {
                (client.id, pipe.id, None),
                (server.id, pipe.id, None),
            }
            await pipe.wait_attached()
            server.close()


# HS-28
async def test_local_join_abort_is_a_kind_of_pipe_gone() -> None:
    reports: asyncio.Queue[JoinReport] = asyncio.Queue()
    config = zmux.Config(
        max_pipes=3,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        join_outcome=lambda _, pipe, error: reports.put_nowait((pipe, error)),
    )
    async with asyncio.timeout(8), zmux.Listener(config=config) as listener:
        near, far = await _connected_carriers()
        setup = asyncio.create_task(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=config) as client:
            server = await listener.accept()
            await setup
            carrier, peer = zmux.adapter.pipe_pair()
            join = asyncio.create_task(client.add_pipe(carrier))
            assert await peer.read()
            pending = next(p for p in client.pipes() if p.id != 0)
            pending.abort()
            for operation in (join, pending.wait_attached()):
                with pytest.raises(zmux.PipeGoneError) as caught:
                    await operation
                assert isinstance(caught.value, zmux.PipeAbortedError)
            pipe, error = await reports.get()
            assert pipe == pending.id
            assert isinstance(error, zmux.PipeAbortedError)
            assert await peer.read() == b""
            assert reports.empty()
            server.close()


# HS-26. A hook runs outside the work whose exit wait_closed observes.
# HS-26
async def test_join_hook_can_close_and_await_its_session() -> None:
    finished: asyncio.Queue[zmux.PipeId] = asyncio.Queue()

    async def joined(
        session: zmux.Session, pipe: zmux.PipeId, error: BaseException | None
    ) -> None:
        assert error is None
        session.close()
        await session.wait_closed()
        await finished.put(pipe)

    cfg = zmux.Config(
        max_pipes=3, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    from dataclasses import replace

    async with asyncio.timeout(8), zmux.Listener(config=cfg) as listener:
        a, b = await _connected_carriers()
        setup = asyncio.create_task(listener.handle_pipe(b))
        async with await zmux.Session.connect(
            a, config=replace(cfg, join_outcome=joined)
        ) as client:
            server = await listener.accept()
            await setup
            a, b = await _connected_carriers()
            pipe, _ = await asyncio.gather(client.add_pipe(a), listener.handle_pipe(b))
            assert await finished.get() == pipe.id
            assert finished.empty()
            server.close()


# HS-03. The decider stops its own listener before delivering its final verdict.
@pytest.mark.parametrize(
    "verdict", [zmux.AdmissionVerdict.accept(), zmux.AdmissionVerdict.fallback()]
)
# HS-03
async def test_admission_stop_precedes_the_handoff(
    verdict: zmux.AdmissionVerdict,
) -> None:
    called = []

    def decide(*_: object) -> zmux.AdmissionVerdict:
        listener.close()
        return verdict

    conf = zmux.ListenerConfig(
        admission=zmux.Admission(decide), fallback=lambda _: called.append(True)
    )
    async with asyncio.timeout(6), zmux.Listener(listener_config=conf) as listener:
        carrier, peer = zmux.adapter.pipe_pair()
        with pytest.raises(zmux.ConnectError):
            await listener.handle_pipe(carrier)
        assert not called
        assert listener.stats().sessions == 0
        assert await peer.read() == b""


@pytest.mark.parametrize("stage", ["exporter", "handshake"])
# HS-01
async def test_cancel_during_exporter_or_handshake(stage: str) -> None:
    entered, stopped = asyncio.Event(), asyncio.Event()

    async def pending(*_: object) -> Never:
        entered.set()
        try:
            never: asyncio.Future[Never] = asyncio.Future()
            await never
        finally:
            stopped.set()

    conf = zmux.ListenerConfig(session_config=pending if stage == "handshake" else None)
    async with asyncio.timeout(6), zmux.Listener(listener_config=conf) as listener:
        if stage == "exporter":
            carrier, peer = zmux.adapter.pipe_pair(exporter=pending)
        else:
            near, carrier = await _connected_carriers()
            dial = asyncio.ensure_future(zmux.Session.connect(near))
        setup = asyncio.ensure_future(listener.handle_pipe(carrier))
        await entered.wait()
        setup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await setup
        if stage == "exporter":
            assert await peer.read() == b""
        else:
            with pytest.raises(zmux.ZmuxError):
                await dial
            await stopped.wait()
        assert listener.stats().sessions == 0


# HS-06
async def test_finished_bridge_receipt_is_idempotent() -> None:
    pipe, end = zmux.adapter.pipe_pair()
    end._track_bridge(pipe)
    end._bridge_done()
    end._bridge_done()
    del pipe
    async with asyncio.timeout(5):
        await end._released()
        fresh, peer = zmux.adapter.pipe_pair()
        end._track_bridge(fresh)
        del fresh
        await peer._released()
        await end._released()


# HS-54
async def test_cancelled_pipe_waiters_can_be_registered_again() -> None:
    async with asyncio.timeout(6), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near) as client:
            server = await listener.accept()
            await setup
            pipe = client.pipes()[0]
            for _ in range(32):
                task = asyncio.Task(
                    pipe.wait_closed(),
                    eager_start=True,
                    loop=asyncio.get_running_loop(),
                )
                assert not task.done()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert await client.ping() >= 0
            server.close()
            with contextlib.suppress(zmux.SessionClosedError, zmux.PipeError):
                await pipe.wait_closed()


# HS-30
async def test_drained_split_reports_protocol_reason() -> None:
    async with asyncio.timeout(10), zmux.Listener() as listener:
        addr = await serve_test_http(listener)
        listener.drain(b"split drain")
        refused: zmux.SessionClosedError
        try:
            session = await zmux.connect_split(*addr)
        except zmux.ConnectionRefusedError as e:
            refused = e
        else:
            refused = await session.wait_closed()
        assert isinstance(refused, zmux.ConnectionRefusedError)
        assert refused.remote and refused.reason == b"split drain"


@pytest.mark.parametrize("refuse", [True, False])
# HS-33
async def test_bootstrap_keeps_its_decision_across_drain(refuse: bool) -> None:
    entered, proceed = asyncio.Event(), asyncio.Event()

    async def configure(_: zmux.SessionCarrier) -> None:
        entered.set()
        await proceed.wait()

    async with (
        asyncio.timeout(8),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(session_config=configure)
        ) as listener,
    ):
        if refuse:
            listener.drain(b"captured")
        a, b = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(b))
        dial = asyncio.ensure_future(zmux.Session.connect(a))
        await entered.wait()
        if refuse:
            listener.undrain()
        else:
            listener.drain(b"subsequent")
        proceed.set()
        if refuse:
            with pytest.raises(zmux.ConnectError):
                await setup
            try:
                client = await dial
            except zmux.ConnectionRefusedError as e:
                reason = e.reason
            else:
                reason = (await client.wait_closed()).reason
            assert reason == b"captured"
            assert listener.stats().sessions == 0
        else:
            async with await dial as client:
                await setup
                accepted = await listener.accept()
                assert await client.ping() >= 0
                accepted.close()


# HS-21
async def test_internal_dial_outcomes_count_only_carriers() -> None:
    from dataclasses import replace

    reports: asyncio.Queue[JoinReport] = asyncio.Queue()
    handlers = []
    gave = 0

    async def carrier(*_: object) -> zmux.PipeIo:
        nonlocal gave
        a, b = await _connected_carriers()
        handlers.append(asyncio.ensure_future(listener.handle_pipe(b)))
        gave += 1
        return a

    cfg = zmux.Config(
        max_pipes=8,
        epoch_policy=zmux.EpochPolicy.MANUAL,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    failed = False

    async def redial(direction: zmux.Direction) -> zmux.PipeIo:
        if failed:
            raise OSError("no carrier")
        return await carrier(direction)

    async with asyncio.timeout(8), zmux.Listener(config=cfg) as listener:
        near, far = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(far))

        def observed(
            session: zmux.Session, pipe: zmux.PipeId, error: BaseException | None
        ) -> None:
            reports.put_nowait((pipe, error))

        async with await zmux.Session.connect(
            near, config=replace(cfg, redial=redial, join_outcome=observed)
        ) as client:
            server = await listener.accept()
            await setup
            extra = await client.add_pipe(await carrier())
            assert await reports.get() == (extra.id, None)
            failed = True
            with pytest.raises((OSError, zmux.ZmuxError)):
                await client.replace_pipes()
            failed = False
            pool = client.maintain_pipes(zmux.helpers.PipePool(1, carrier))
            second, error = await reports.get()
            assert error is None and second not in (extra.id, zmux.PIPE_UNASSIGNED)
            pool.stop()
            await asyncio.gather(*handlers)
            assert gave == 2 and reports.empty()
            server.close()


# HS-31
async def test_draining_listener_accepts_a_resumption() -> None:
    cfg = zmux.Config(
        max_pipes=4,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        resume_timeout=30,
    )
    async with (
        asyncio.timeout(8),
        zmux.Listener(
            config=cfg, listener_config=zmux.ListenerConfig(instance_id=b"drain")
        ) as listener,
    ):
        near, far = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await setup
            listener.drain(b"emptying")
            client.pipes()[0].abort()
            for side in (client, server):
                async for event in side.events():
                    if event.kind == zmux.EventKind.SESSION_SUSPENDED:
                        break
            near, far = await _connected_carriers()
            await asyncio.gather(client.add_pipe(near), listener.handle_pipe(far))
            assert await client.ping() >= 0
            server.close()


@pytest.mark.parametrize(
    ("on_reply", "caller_deadline"), [(False, False), (True, False), (False, True)]
)
# HS-22, HS-23
async def test_timeout_precedes_a_late_confirm(
    on_reply: bool, caller_deadline: bool
) -> None:
    from dataclasses import replace

    reports: asyncio.Queue[JoinReport] = asyncio.Queue()
    cfg = zmux.Config(
        max_pipes=3, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def bootstrap() -> AsyncIterator[
        tuple[zmux.PipeIo, zmux.PipeIo, asyncio.Event]
    ]:
        near, left = zmux.adapter.pipe_pair()
        far, right = zmux.adapter.pipe_pair()
        forwarding = asyncio.Event()
        forwarding.set()

        async def forward(src: zmux.adapter.PipeEnd, dst: zmux.adapter.PipeEnd) -> None:
            while data := await src.read():
                await forwarding.wait()
                await dst.write(data)

        pumps = [
            asyncio.create_task(forward(a, b))
            for a, b in [(left, right), (right, left)]
        ]
        try:
            yield near, far, forwarding
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)

    async with (
        asyncio.timeout(8),
        zmux.Listener(config=cfg) as listener,
        bootstrap() as (near, far, forwarding),
    ):
        setup = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(
            near,
            config=replace(
                cfg,
                join_timeout=10 if caller_deadline else 0.6,
                join_outcome=lambda _, i, e: reports.put_nowait((i, e)),
            ),
        ) as client:
            server = await listener.accept()
            await setup
            # Prevent the bootstrap path from forwarding the local retirement to the
            # peer before the delayed Confirm. Only the deliberate relay controls it.
            forwarding.clear()
            near, tx = zmux.adapter.pipe_pair()
            far, rx = zmux.adapter.pipe_pair()
            inbound = asyncio.ensure_future(listener.handle_pipe(far))
            request = asyncio.ensure_future(
                client.add_pipe(
                    near, options=zmux.PipeOptions(return_on_reply=on_reply)
                )
            )
            await rx.write(await tx.read())  # Hello
            await tx.write(await rx.read())  # Reply
            confirm = await tx.read()
            assert confirm
            reason = TimeoutError("join caller deadline")
            if caller_deadline:
                assert request.cancel(reason)
                with pytest.raises(asyncio.CancelledError) as stopped:
                    await request
                assert stopped.value.args == (reason,)
                assert len(client.pipes()) == 1
            elif on_reply:
                pipe = await request
                with pytest.raises(zmux.DeadlineExceededError):
                    await pipe.wait_attached()
            else:
                with pytest.raises(zmux.DeadlineExceededError):
                    await request
            number, error = await reports.get()
            if caller_deadline:
                assert isinstance(error, asyncio.CancelledError) and error.args == (
                    reason,
                )
            else:
                assert isinstance(error, zmux.DeadlineExceededError)
            assert all(p.id != number for p in client.pipes())
            await rx.write(confirm)
            await inbound
            forwarding.set()
            assert await client.ping() >= 0
            assert all(p.id != number for p in client.pipes())
            assert reports.empty()
            await rx.write(b"")
            server.close()


def _reset(w: asyncio.StreamWriter) -> None:
    """Reset a connection that _split_half set to zero linger.

    The Windows Proactor shuts the socket down before closing it, which turns
    the zero-linger close into an orderly FIN: close the socket first there.
    """
    import sys

    if sys.platform == "win32":
        w.get_extra_info("socket")._sock.close()
    w.transport.abort()


async def _split_half(
    addr: tuple[str, int], token: bytes, method: str, initial: int = 0
) -> StreamPair:
    import socket
    import struct
    import sys

    r, w = await asyncio.open_connection(*addr)
    # Winsock's linger fields are unsigned shorts.
    linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)
    w.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    hdr = b"Transfer-Encoding: chunked\r\n" if method == "POST" else b""
    w.write(
        method.encode()
        + b" /zmux HTTP/1.1\r\nHost: "
        + addr[0].encode()
        + b"\r\nZmux-Pipe-Pair: "
        + token
        + b"\r\n"
        + hdr
        + b"\r\n"
    )
    if initial and method == "POST":
        w.write(f"{initial:x}\r\n".encode() + b"a" * initial + b"\r\n")
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    assert b" 200 " in head
    return r, w


@pytest.mark.parametrize("first", ["GET", "POST"])
@pytest.mark.parametrize("initial_bytes", [3, 128 * 1024])
# HS-05, HS-42, HS-43, HS-44
async def test_split_request_withdrawal(first: str, initial_bytes: int) -> None:
    import base64
    from secrets import token_bytes

    entered: asyncio.Queue[None] = asyncio.Queue()
    stopped: asyncio.Queue[None] = asyncio.Queue()
    held = []

    async def transform(pipe: zmux.PipeIo, _: zmux.adapter.PipeHint) -> Never:
        unused, worker = zmux.adapter.pipe_pair()
        del unused
        worker._track_bridge(pipe)
        held.append(worker)
        entered.put_nowait(None)
        try:
            never: asyncio.Future[Never] = asyncio.Future()
            await never
        finally:
            stopped.put_nowait(None)

    conf = zmux.ListenerConfig(
        admission=zmux.Admission(lambda *_: zmux.AdmissionVerdict.accept()),
        inbound_transform=transform,
    )
    token = base64.urlsafe_b64encode(token_bytes(16)).rstrip(b"=")
    async with (
        asyncio.timeout(8),
        zmux.Listener(listener_config=conf) as listener,
        contextlib.AsyncExitStack() as cleanup,
    ):

        def release_workers() -> None:
            while held:
                held.pop()._bridge_done()

        cleanup.callback(release_workers)
        addr = await serve_test_http(listener)

        async def half(method: str) -> StreamPair:
            # The large POST exceeds the Rust setup probe's replay budget.
            # Withdrawal then depends on observing the TCP reset independently.
            reader, writer = await _split_half(
                addr, token, method, initial=initial_bytes
            )
            cleanup.callback(_reset, writer)
            return reader, writer

        other = "POST" if first == "GET" else "GET"
        _, a = await half(first)
        _, b = await half(other)
        await entered.get()
        _reset(a)
        await a.wait_closed()
        # The active token outlives even both requests if the joined carrier
        # has a separately owned worker. A duplicate POST's empty body ends.
        duplicate, writer = await half("POST")
        assert await duplicate.readline() in (b"0\r\n", b"")
        writer.close()
        assert stopped.empty()
        _reset(b)
        await b.wait_closed()
        await stopped.get()
        assert listener.stats().sessions == 0
        duplicate, writer = await half("POST")
        assert await duplicate.readline() in (b"0\r\n", b"")
        writer.close()
        held.pop()._bridge_done()
        _, a = await half(other)
        _, b = await half(first)
        await entered.get()
        _reset(a)
        _reset(b)
        await stopped.get()
        held.pop()._bridge_done()


@pytest.mark.parametrize("first", ["GET", "POST"])
# HS-40, HS-41
async def test_expired_split_half_cannot_join_its_replacement(first: str) -> None:
    from secrets import token_urlsafe

    token = token_urlsafe(16).encode()
    cfg = zmux.ListenerConfig(
        handshake_timeout=1.5,
        admission=zmux.Admission(lambda *_: zmux.AdmissionVerdict.accept()),
    )
    async with asyncio.timeout(9), zmux.Listener(listener_config=cfg) as listener:
        addr = await serve_test_http(listener)
        expired, old = await _split_half(addr, token, first)
        with contextlib.suppress(ConnectionResetError):
            await expired.read()
        old.close()
        assert listener.stats().sessions == 0
        # Establish a real session over this same token, in the opposite order.
        directions = ["POST", "GET"] if first == "GET" else ["GET", "POST"]
        halves = {
            method: await _split_half(addr, token, method) for method in directions
        }
        _, up = halves["POST"]
        down, response = halves["GET"]
        near, end = zmux.adapter.pipe_pair()

        async def upload() -> None:
            while data := await end.read():
                up.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                await up.drain()

        async def download() -> None:
            while size := await down.readline():
                n = int(size.strip(), 16)
                if n == 0:
                    break
                await end.write(await down.readexactly(n))
                assert await down.readexactly(2) == b"\r\n"

        pumps = [asyncio.create_task(upload()), asyncio.create_task(download())]
        try:
            async with await zmux.Session.connect(near) as client:
                server = await listener.accept()
                assert await client.ping() >= 0
                server.close()
            assert listener.stats().sessions == 1
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            up.close()
            response.close()


# HS-02
async def test_session_close_reaches_peer_after_handler_cancel() -> None:
    async with asyncio.timeout(6), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        handling = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near) as client:
            server = await listener.accept()
            await handling
            assert not handling.cancel()
            assert await client.ping() >= 0
            server.close(23, b"handed off")
            reason = await client.wait_closed()
            assert isinstance(reason, zmux.ApplicationClosedError)
            assert (
                reason.remote and reason.code == 23 and reason.reason == b"handed off"
            )


# HS-20, HS-24. Reading the Reply proves the acceptor authorized this join.
@pytest.mark.parametrize("ending", ["stop", "withdraw", "session", "evict", "timeout"])
async def test_authorized_inbound_join_reports_its_terminal_cause(ending: str) -> None:
    from dataclasses import replace

    outcomes: asyncio.Queue[JoinReport] = asyncio.Queue()
    cfg = zmux.Config(
        max_pipes=6, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    limits = zmux.ListenerConfig(limits=zmux.ListenerLimits(max_pending_per_session=1))
    accepting = replace(
        cfg,
        join_timeout=0.6 if ending == "timeout" else 10,
        join_outcome=lambda _, pipe, error: outcomes.put_nowait((pipe, error)),
    )
    async with (
        asyncio.timeout(8),
        zmux.Listener(config=accepting, listener_config=limits) as listener,
    ):
        near, far = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await setup

            async def waiting() -> tuple[
                zmux.Pipe,
                asyncio.Future[None],
                zmux.adapter.PipeEnd,
                zmux.adapter.PipeEnd,
            ]:
                near, tx = zmux.adapter.pipe_pair()
                far, rx = zmux.adapter.pipe_pair()
                handler = asyncio.ensure_future(listener.handle_pipe(far))
                added = asyncio.ensure_future(
                    client.add_pipe(
                        near, options=zmux.PipeOptions(return_on_reply=True)
                    )
                )
                await rx.write(await tx.read())
                await tx.write(await rx.read())
                pipe = await added
                assert await tx.read()  # Confirm stays in the relay.
                return pipe, handler, tx, rx

            first = await waiting()
            extra = None
            expected: type[BaseException]
            if ending == "stop":
                listener.close()
                expected = zmux.ListenerClosedError
            elif ending == "withdraw":
                first[1].cancel()
                expected = asyncio.CancelledError
            elif ending == "session":
                server.abort(17, b"ending")
                expected = zmux.ApplicationClosedError
            elif ending == "evict":
                extra = await waiting()
                expected = zmux.JoinEvictedError
            else:
                expected = zmux.DeadlineExceededError
            number, cause = await outcomes.get()
            assert number == first[0].id and isinstance(cause, expected)
            if ending == "session":
                assert isinstance(cause, zmux.ApplicationClosedError)
                assert cause.code == 17 and cause.reason == b"ending"
            await asyncio.gather(first[1], return_exceptions=True)
            if extra is not None:
                extra[1].cancel()
                await asyncio.gather(extra[1], return_exceptions=True)
                number, cause = await outcomes.get()
                assert number == extra[0].id and isinstance(
                    cause, asyncio.CancelledError
                )
            assert outcomes.empty()
            server.close()
