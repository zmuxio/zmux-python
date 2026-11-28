"""The listener's fallback: every carrier the admission hands back reaches
`ListenerConfig.fallback` as a `Takeover`, with the verdict's value, its
replay, its framing and its detach."""

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress

import pytest
import zmux
from support import TEST_HOOKS, WATCHDOG, Tls, manual_clock, start_pending, until
import zmux._zmux
from test_smoke import dial_with, serve_admitted, serve_test_http

HELLO = b"HELO"


def decide(
    info: zmux.CarrierInfo, prefix: bytes
) -> zmux.AdmissionVerdict | zmux.Decision:
    """Defers an upgrade's head; hands a carrier that starts with HELLO to
    the fallback with a value naming the service."""
    if info.stage is zmux.AdmissionStage.HEAD:
        return zmux.AdmissionVerdict.DEFER
    if prefix == HELLO:
        return zmux.AdmissionVerdict.takeover(value=("echo", 7)).labelled("relay")
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
# HS-15
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
        request_head = await read_exactly(s, 8)
        await s.write(b"pong")
        await s.shutdown()
        await served.put((t.value, request_head, await read_to_end(s)))

    async def fallback(t: zmux.Takeover) -> None:
        assert listener.stats().admission.takeover == 1
        assert listener.variant_stats().variants["relay"] == zmux.VariantStats(
            takeover=1
        )
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
        assert (a.takeover, a.fallback, a.accepted) == (1, 0, 0)


async def test_a_returned_takeover_is_closed() -> None:
    """A fallback that keeps the takeover without detaching it: once it
    returned the carrier is closed, and the takeover refuses to be taken
    or detached."""
    kept: asyncio.Future[zmux.Takeover] = asyncio.get_running_loop().create_future()

    def fallback(takeover: zmux.Takeover) -> None:
        kept.set_result(takeover)

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


# HS-10
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


# HS-07
async def test_a_failing_fallback_closes_its_carrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = asyncio.get_running_loop()
    raised = loop.create_future()
    monkeypatch.setattr(
        "sys.unraisablehook",
        lambda u: loop.call_soon_threadsafe(raised.set_result, u.exc_value),
    )

    async def fallback(t: zmux.Takeover) -> None:
        raise RuntimeError("no service")

    async with zmux.Listener(listener_config=config(fallback)) as listener:
        _, port = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(HELLO)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 10) == b""
        writer.close()
    assert isinstance(await asyncio.wait_for(raised, 5), RuntimeError)


# HS-17
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
        handled: Awaitable[object] = listener.handle_pipe(given)
        client[1].write(HELLO)
        await client[1].drain()
        assert await handled is None
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
    # Check before starting the fallback task so a production build skips cleanly.
    if not TEST_HOOKS:
        pytest.skip("requires the test-hooks build")
    server_tls, client_tls = tls
    result: asyncio.Future[bytes | None] = asyncio.get_running_loop().create_future()
    tasks: list[asyncio.Task[None]] = []

    async def serve(m: zmux.TakeoverMessages) -> None:
        assert await m.read_message() == HELLO
        pending = await start_pending(m.read_message)
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


@pytest.mark.parametrize("take", [True, False])
# HS-12
async def test_cancelling_handler_after_fallback_dispatch(take: bool) -> None:
    entered = asyncio.get_running_loop().create_future()
    resume = asyncio.Event()

    async def fallback(t: zmux.Takeover) -> None:
        entered.set_result(t)
        await resume.wait()
        if take:
            carrier = t.into_pipe().into_stream()
            await carrier.write(b"host")
            await carrier.shutdown()

    async with (
        asyncio.timeout(5),
        zmux.Listener(listener_config=config(fallback)) as listener,
    ):
        pipe, peer = zmux.adapter.pipe_pair()
        handler = asyncio.ensure_future(listener.handle_pipe(pipe))
        await peer.write(HELLO)
        retained = await entered
        assert handler.cancel()
        resume.set()
        await handler
        if take:
            assert await peer.read() == b"host"
        assert await peer.read() == b""
        with pytest.raises(zmux.PipeUsedError if take else zmux.TakeoverReturnedError):
            retained.into_pipe()


@pytest.mark.parametrize("raises", [False, True])
# HS-10, HS-11
async def test_fallback_result_with_an_undetached_carrier(
    raises: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    if raises:
        monkeypatch.setattr("sys.unraisablehook", lambda _: None)

    failure = RuntimeError("fallback failed")

    def fallback(_takeover: zmux.Takeover) -> None:
        if raises:
            raise failure

    cfg = zmux.ListenerConfig(
        admission=zmux.Admission(
            lambda *_: zmux.AdmissionVerdict.fallback(), peek=len(HELLO)
        ),
        fallback=fallback,
    )
    async with zmux.Listener(listener_config=cfg) as listener:
        server, client = await socket_pair()
        handled: Awaitable[object] = listener.handle_pipe(
            zmux.pipe_from_streams(*server)
        )
        client[1].write(HELLO)
        await client[1].drain()
        if raises:
            with pytest.raises(zmux.ConnectError) as caught:
                await handled
            assert caught.value.__cause__ is failure
        else:
            assert await handled is None
        assert await asyncio.wait_for(client[0].read(), 10) == b""
        client[1].close()
        await client[1].wait_closed()


# HS-35
async def test_listener_close_before_accept_reports_application_zero() -> None:
    async with zmux.Listener() as listener:
        server, peer = await socket_pair()
        _, client = await asyncio.gather(
            listener.handle_pipe(zmux.pipe_from_streams(*server)),
            zmux.Session.connect(zmux.pipe_from_streams(*peer)),
        )
        listener.close()
        end = await asyncio.wait_for(client.wait_closed(), 10)
        assert isinstance(end, zmux.ApplicationClosedError)
        assert end.remote and end.code == 0


# HS-18, HS-19
async def test_takeover_without_a_target_stalls_until_listener_closes() -> None:
    cfg = zmux.ListenerConfig(
        admission=zmux.Admission(
            lambda *_: zmux.Decision(zmux.AdmissionVerdict.takeover(), variant="relay"),
            peek=0,
        )
    )
    async with asyncio.timeout(5), zmux.Listener(listener_config=cfg) as listener:
        stream, peer = zmux.adapter.pipe_pair()
        with pytest.raises(zmux.ZmuxError):
            await listener.handle_pipe(stream)
        a = listener.stats().admission
        assert (a.takeover, a.fallback, a.stalled) == (0, 0, 1)
        assert listener.variant_stats().variants["relay"] == zmux.VariantStats(
            stalled=1
        )
        listener.close()
        assert await peer.read() == b""


@pytest.mark.parametrize(
    ("carrier", "verdict"),
    [
        ("http", zmux.AdmissionVerdict.takeover),
        ("h3", zmux.AdmissionVerdict.takeover),
        ("websocket", zmux.AdmissionVerdict.takeover),
        ("websocket", zmux.AdmissionVerdict.fallback),
        ("webtransport", zmux.AdmissionVerdict.takeover),
        ("webtransport", zmux.AdmissionVerdict.fallback),
    ],
)
async def test_takeover_or_deferred_fallback_stalls_without_target(
    carrier: str, verdict: Callable[[], zmux.AdmissionVerdict], tls: Tls
) -> None:
    server_tls, client_tls = tls
    upgrade = carrier in ("websocket", "webtransport")

    def classify_stage(
        info: zmux.CarrierInfo, _prefix: bytes
    ) -> zmux.AdmissionVerdict | zmux.Decision:
        if info.stage is zmux.AdmissionStage.HEAD:
            assert upgrade
            return zmux.AdmissionVerdict.DEFER
        assert info.upgrade is upgrade
        return verdict().labelled("relay")

    cfg = zmux.ListenerConfig(
        admission=zmux.Admission(
            classify_stage, peek=0, stall=(2 * WATCHDOG, 2 * WATCHDOG)
        )
    )
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(listener_config=cfg) as listener,
    ):
        addr = await serve_admitted(listener, carrier, server_tls)
        stream = (await dial_with(carrier, addr, client_tls, None)).into_stream()
        if upgrade:
            await stream.write(HELLO)
        await until(listener, lambda: listener.stats().admission.stalled > 0)
        if carrier == "webtransport":
            # The stall owns the whole session, including its other streams.
            listener.close()
        else:
            # The stalled peer drains until EOF. End the request explicitly.
            with suppress(zmux.ConnectError):
                await stream.shutdown()
        if upgrade:
            try:
                assert await stream.read() == b""
            except zmux.ConnectError:
                # WebTransport can end by closing the whole session.
                assert carrier == "webtransport"
        else:
            with pytest.raises(zmux.ConnectError):
                await stream.read()
        counts = listener.stats().admission
        assert (counts.accepted, counts.takeover, counts.fallback, counts.stalled) == (
            0,
            0,
            0,
            1,
        )
        assert listener.variant_stats().variants["relay"] == zmux.VariantStats(
            stalled=1
        )


@pytest.mark.parametrize("has_target", [False, True])
@pytest.mark.skipif(not TEST_HOOKS, reason="requires the test-hooks build")
async def test_longer_prefix_timeout_replays_or_stalls(has_target: bool) -> None:
    clock = manual_clock()
    peek_timeout = 7
    seen: asyncio.Queue[bytes] = asyncio.Queue()
    served: asyncio.Queue[bytes] = asyncio.Queue()
    decide_more = asyncio.Event()

    async def request_more(info: zmux.CarrierInfo, prefix: bytes) -> zmux.Decision:
        seen.put_nowait(prefix)
        await decide_more.wait()
        return zmux.AdmissionVerdict.more(4).labelled("longer")

    def fallback(taken: zmux.Takeover) -> None:
        served.put_nowait(taken.replayed)

    async def handle(owner: zmux.Listener, input_pipe: zmux.PipeIo) -> None:
        if has_target:
            await owner.handle_pipe(input_pipe)
        else:
            with pytest.raises(zmux.ZmuxError):
                await owner.handle_pipe(input_pipe)

    cfg = zmux.ListenerConfig(
        admission=zmux.Admission(
            request_more,
            peek=1,
            max_peek=4,
            peek_timeout=peek_timeout,
            stall=(60, 60),
            fallback_on_peek_timeout=True,
        ),
        fallback=fallback if has_target else None,
    )
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            config=zmux.Config(clock_domain=clock.domain), listener_config=cfg
        ) as listener,
        asyncio.TaskGroup() as tasks,
    ):
        carrier, peer = zmux.adapter.pipe_pair()
        # Buffer both bytes before the initial one-byte peek.
        await peer.write(b"ab")
        handling = tasks.create_task(handle(listener, carrier))
        assert await seen.get() == b"a"
        await clock.wait_for_timer(peek_timeout)
        decide_more.set()
        # The same deadline bounds both the decision and the longer read.
        await clock.wait_for_timer(peek_timeout, count=2)
        clock.advance(peek_timeout)
        await handling
        if has_target:
            assert await served.get() == b"ab"
        else:
            # The listener's stall still owns the carrier after setup ended.
            await peer.write(b"x")
            assert served.empty()
        counts = listener.stats().admission
        expected = (1, 0, 0) if has_target else (0, 1, 0)
        assert (counts.fallback, counts.stalled, counts.peek_timed_out) == expected
        variant = listener.variant_stats().variants["longer"]
        assert (variant.fallback, variant.stalled) == expected[:2]
        listener.close()
        assert await peer.read() == b""


# HS-13
async def test_http_fallback_without_http_handler_returns_not_found() -> None:
    called = asyncio.Event()
    cfg = zmux.ListenerConfig(
        admission=zmux.Admission(lambda *_: zmux.AdmissionVerdict.fallback(), peek=1),
        fallback=lambda _: called.set(),
    )
    async with asyncio.timeout(5), zmux.Listener(listener_config=cfg) as listener:
        addr = await serve_test_http(listener)
        reader, writer = await asyncio.open_connection(*addr)
        try:
            writer.write(
                b"POST /zmux HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"
            )
            await writer.drain()
            assert (await reader.readline()).split()[1] == b"404"
            assert not called.is_set()
            counts = listener.stats().admission
            assert (counts.fallback, counts.stalled, counts.takeover) == (0, 1, 0)
        finally:
            writer.close()
            await writer.wait_closed()
