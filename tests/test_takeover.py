"""The listener's fallback: every carrier the admission hands back reaches
`ListenerConfig.fallback` as a `Takeover`, with the verdict's value, its
replay, its framing and its detach."""

import asyncio
from collections.abc import Awaitable, Callable

import pytest
import zmux
import zmux._zmux
from test_smoke import Tls, dial_with, serve_admitted

HELLO = b"HELO"


@pytest.fixture(scope="module")
def tls() -> Tls:
    pytest.importorskip("cryptography")  # no 32-bit Windows wheels
    from certs import self_signed

    cert_pem, key_pem = self_signed()
    return zmux.TlsConfig(cert=cert_pem, key=key_pem), zmux.TlsConfig(ca=cert_pem)


def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
    """Defers an upgrade's head; hands a carrier that starts with HELLO to
    the fallback with a value naming the service."""
    if info.stage is zmux.AdmissionStage.HEAD:
        return zmux.AdmissionVerdict.DEFER
    if prefix == HELLO:
        return zmux.AdmissionVerdict.fallback(value=("echo", 7))
    return zmux.AdmissionVerdict.CLOSE


def config(
    fallback: Callable[[zmux.Takeover], Awaitable[None] | None],
) -> zmux.ListenerConfig:
    return zmux.ListenerConfig(
        admission=zmux.Admission(decide, peek=len(HELLO), peek_timeout=5),
        fallback=fallback,
    )


async def read_to_end(s: "zmux._zmux.CarrierStream") -> bytes:
    out = b""
    while chunk := await s.read():
        out += chunk
    return out


async def read_exactly(s: "zmux._zmux.CarrierStream", n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = await s.read(n - len(out))
        assert chunk, f"the stream ended after {out!r}"
        out += chunk
    return out


def test_fallback_verdict_values() -> None:
    v = zmux.AdmissionVerdict.fallback(value="svc")
    assert v.value == "svc" and v.skip is None
    assert v == zmux.AdmissionVerdict.fallback(value="svc")
    assert v != zmux.AdmissionVerdict.fallback() != zmux.AdmissionVerdict.accept()
    assert zmux.AdmissionVerdict.fallback().value is None
    assert repr(v) == "AdmissionVerdict.fallback(value='svc')"
    assert not hasattr(zmux.AdmissionVerdict, "FALLBACK")


@pytest.mark.parametrize(
    "carrier", ["tcp", "tls", "http", "h3", "quic", "websocket", "webtransport"]
)
async def test_every_carrier_reaches_the_fallback(carrier: str, tls: Tls) -> None:
    """The host detaches each carrier and serves it after its fallback
    returned: a message-framed one by whole messages, the others as streams,
    the response half ended first and the request half read on."""
    server_tls, client_tls = tls
    served: asyncio.Queue[tuple[object, bytes, bytes]] = asyncio.Queue()
    tasks: list[asyncio.Task[None]] = []

    async def serve(t: zmux.Takeover) -> None:
        if t.framing is zmux.adapter.Framing.RECORDS:
            # A WebSocket: whole messages, the first one replayed; it has
            # no half-close, so the peer's close ends it.
            m = t.into_messages()
            first, second = await m.read_message(), await m.read_message()
            assert first is not None and second is not None
            await m.write_message(b"pong")
            assert await m.read_message() is None
            await served.put((t.value, first + second, b""))
            return
        with pytest.raises(TypeError):
            t.into_messages()
        s = t.into_pipe().into_stream()
        head = await read_exactly(s, 8)
        await s.write(b"pong")
        await s.shutdown()
        await served.put((t.value, head, await read_to_end(s)))

    async def fallback(t: zmux.Takeover) -> None:
        assert t.info.stage is zmux.AdmissionStage.CARRIER
        assert t.replayed == HELLO
        assert not t.detached
        t.detach()
        t.detach()
        assert t.detached
        # Served on a task of its own, after this call returned.
        tasks.append(asyncio.create_task(serve(t)))

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        pipe = await asyncio.wait_for(dial_with(carrier, addr, client_tls, None), 10)
        c = pipe.into_stream()
        if carrier == "websocket":
            # Each write is one message.
            await c.write(HELLO)
            await c.write(b"ping")
        else:
            await c.write(HELLO + b"ping")
        assert await asyncio.wait_for(read_exactly(c, 4), 10) == b"pong"
        if carrier != "websocket":
            # The response half ended; the request half writes on.
            assert await asyncio.wait_for(c.read(), 10) == b""
            await c.write(b"tail")
        await c.shutdown()
        value, head, tail = await asyncio.wait_for(served.get(), 10)
        assert value == ("echo", 7)
        assert head == HELLO + b"ping"
        assert tail == (b"" if carrier == "websocket" else b"tail")
        await asyncio.gather(*tasks)
        a = listener.stats().admission
        assert (a.fallback, a.accepted) == (1, 0)


async def test_a_returned_takeover_is_closed() -> None:
    """A fallback that keeps the takeover without detaching it: once it
    returned the carrier is closed, and the takeover refuses to be taken
    or detached."""
    kept: asyncio.Future[zmux.Takeover] = asyncio.get_running_loop().create_future()

    def fallback(t: zmux.Takeover) -> None:
        kept.set_result(t)

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        _, port = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(HELLO)
        await writer.drain()
        t = await asyncio.wait_for(kept, 10)
        assert await asyncio.wait_for(reader.read(), 10) == b""
        writer.close()
        assert not t.detached
        with pytest.raises(zmux.TakeoverReturnedError):
            t.detach()
        with pytest.raises(zmux.TakeoverReturnedError):
            t.into_pipe()
        assert "returned" in repr(t)


async def test_a_taken_carrier_is_the_hosts() -> None:
    """Taken in the call, the carrier outlives it without a detach; the
    takeover then refuses a second take and a detach."""
    done: asyncio.Queue[bytes] = asyncio.Queue()
    tasks: list[asyncio.Task[None]] = []

    async def fallback(t: zmux.Takeover) -> None:
        s = t.into_pipe().into_stream()
        with pytest.raises(zmux.PipeUsedError):
            t.into_pipe()
        with pytest.raises(zmux.PipeUsedError):
            t.detach()
        assert not t.detached and "taken" in repr(t)

        async def later() -> None:
            await asyncio.sleep(0.05)
            await s.write(await read_exactly(s, 4))
            await s.shutdown()
            await done.put(b"")

        tasks.append(asyncio.create_task(later()))

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        _, port = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(HELLO)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 10) == HELLO
        writer.close()
        await asyncio.wait_for(done.get(), 10)
        await asyncio.gather(*tasks)


async def test_a_failing_fallback_closes_its_carrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raised: list[BaseException | None] = []
    monkeypatch.setattr("sys.unraisablehook", lambda u: raised.append(u.exc_value))

    async def fallback(t: zmux.Takeover) -> None:
        raise RuntimeError("no service")

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        _, port = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(HELLO)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 10) == b""
        writer.close()
    for _ in range(100):
        if raised:
            break
        await asyncio.sleep(0.01)
    assert isinstance(raised[0], RuntimeError)


async def test_handle_pipe_reaches_the_fallback() -> None:
    """A pipe the application hands over goes to the fallback too, with
    every capability it was given."""
    got: asyncio.Future[zmux.PipeIo] = asyncio.get_running_loop().create_future()

    def fallback(t: zmux.Takeover) -> None:
        got.set_result(t.into_pipe())

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        server, client = await socket_pair()
        given = zmux.pipe_from_streams(*server)
        given.reports_failure = True
        handled: Awaitable[None] = listener.handle_pipe(given)
        client[1].write(HELLO)
        await client[1].drain()
        # Not admitted to the listener: it went to the fallback.
        with pytest.raises(zmux.ConnectError):
            await handled
        pipe = await asyncio.wait_for(got, 10)
        assert pipe.reports_failure
        s = pipe.into_stream()
        assert await read_exactly(s, 4) == HELLO
        client[1].close()


async def socket_pair() -> tuple[
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
]:
    accepted: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
        asyncio.get_running_loop().create_future()
    )

    async def on(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        accepted.set_result((r, w))

    srv = await asyncio.start_server(on, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    client = await asyncio.open_connection("127.0.0.1", port)
    server = await accepted
    srv.close()
    return server, client


async def test_messages_are_full_duplex(tls: Tls) -> None:
    """A read waiting for a message does not hold back writes from another
    task."""
    server_tls, client_tls = tls
    result: asyncio.Future[bytes | None] = asyncio.get_running_loop().create_future()
    tasks: list[asyncio.Task[None]] = []

    async def serve(m: zmux.TakeoverMessages) -> None:
        assert await m.read_message() == HELLO
        pending = asyncio.create_task(m.read_message())
        await asyncio.sleep(0.05)
        assert not pending.done()
        # Written while the read waits.
        await asyncio.wait_for(m.write_message(b"one"), 5)
        await asyncio.wait_for(m.write_message(b"two"), 5)
        result.set_result(await pending)

    def fallback(t: zmux.Takeover) -> None:
        t.detach()
        tasks.append(asyncio.create_task(serve(t.into_messages())))

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        addr = await serve_admitted(listener, "websocket", server_tls)
        pipe = await asyncio.wait_for(
            dial_with("websocket", addr, client_tls, None), 10
        )
        c = pipe.into_stream()
        await c.write(HELLO)
        assert await asyncio.wait_for(read_exactly(c, 6), 10) == b"onetwo"
        assert not result.done()
        await c.write(b"last")
        assert await asyncio.wait_for(result, 10) == b"last"
        await c.shutdown()
        await asyncio.gather(*tasks)


@pytest.mark.parametrize("carrier", ["http", "h3"])
async def test_an_undetached_request_carrier_is_cut(carrier: str, tls: Tls) -> None:
    """A request carrier taken but not detached: once the fallback
    returned, its response is reset wherever the host keeps the pipe."""
    server_tls, client_tls = tls
    kept: list[zmux.PipeIo] = []

    def fallback(t: zmux.Takeover) -> None:
        kept.append(t.into_pipe())

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        pipe = await asyncio.wait_for(dial_with(carrier, addr, client_tls, None), 10)
        c = pipe.into_stream()
        await c.write(HELLO)
        # The unfinished response is reset, not ended.
        with pytest.raises(zmux.ConnectError):
            await asyncio.wait_for(read_to_end(c), 10)
        assert len(kept) == 1
