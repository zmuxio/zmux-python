import asyncio
import contextlib
import datetime
from collections.abc import Awaitable, Coroutine
from typing import Any

import pytest
import zmux

Tls = tuple[zmux.TlsConfig, zmux.TlsConfig]


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
async def test_carrier(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        if carrier == "tcp":
            addr = await listener.serve_tcp("127.0.0.1", 0)
            dial = zmux.dial_tcp(*addr)
        elif carrier == "tls":
            addr = await listener.serve_tls("127.0.0.1", 0, tls=server_tls)
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
            assert (await conn.open_pipe()).terminated_tls is not None
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
            max_pending_per_source=2, admission=admission
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
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
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
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
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


async def test_stream_pair() -> None:
    # Multipath, where the carrier's unsent count feeds the scheduler.
    config = zmux.Config(
        max_pipes=2, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(config=config) as listener:
        server = asyncio.create_task(echo(listener))

        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await listener.handle_pipe(zmux.pipe_from_streams(reader, writer))

        tcp = await asyncio.start_server(handle, "127.0.0.1", 0)
        host, port = tcp.sockets[0].getsockname()[:2]
        reader, writer = await asyncio.open_connection(host, port)
        async with await zmux.Session.connect(
            zmux.pipe_from_streams(reader, writer), config=config
        ) as session:
            await round_trip(session)
            # The transport's write buffer is the carrier's unsent count.
            async with asyncio.timeout(5):
                while session.pipe_stats()[0].queued_bytes is None:
                    await round_trip(session)
            (st,) = session.pipe_stats()
            assert st.queued_bytes is not None and st.queued_bytes >= 0
        server.cancel()
        tcp.close()


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
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
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


async def test_a_late_async_decide_is_a_peek_timeout() -> None:
    async def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        await asyncio.sleep(3600)
        raise AssertionError("not reached")

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            admission=zmux.Admission(decide, peek_timeout=0.05)
        )
    ) as listener:
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        r, w = await asyncio.open_connection(host, port)
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        for _ in range(100):
            if listener.stats().admission.peek_timed_out == 1:
                break
            await asyncio.sleep(0.01)
        assert listener.stats().admission.peek_timed_out == 1


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


async def test_shutdown_refuses_new_sessions() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr) as session:
            await round_trip(session)
            shutdown = asyncio.ensure_future(listener.shutdown(0, b"bye"))
            await asyncio.sleep(0.05)
            # Refused with CONNECTION_REFUSED after the listener's parameters:
            # the session may come up, then ends at once, closed by the peer.
            with contextlib.suppress(zmux.ZmuxError, OSError):
                async with asyncio.timeout(2):
                    refused = await zmux.connect_tcp(*addr)
                    info = await refused.wait_closed()
                    assert info.remote
            assert listener.stats().refused >= 1
        await asyncio.wait_for(shutdown, 10)
        server.cancel()


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
