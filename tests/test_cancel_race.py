"""A result that arrives as its awaiter is cancelled is taken back for the
next call, never lost. Each test fixes the interleaving: the result is
ready before the call, and the cancellation lands either just before or
just after the native side completes the call's future."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

import zmux

ORDERS = ("cancel-first", "complete-first")


async def cancelled_as_it_completes(
    start: Callable[[], Awaitable[Any]], order: str
) -> Any:
    """Runs `start()` as a task and cancels it at the moment its result is
    handed to the loop; the result it would have returned."""
    loop = asyncio.get_running_loop()
    original = loop.call_soon_threadsafe
    seen: list[Any] = []
    task: asyncio.Task[Any] | None = None

    def hook(cb: Any, *args: Any, **kw: Any) -> Any:
        if type(cb).__name__ != "Complete" or seen:
            return original(cb, *args, **kw)
        seen.append(args[2])

        def run(*a: Any) -> None:
            assert task is not None
            if order == "cancel-first":
                task.cancel()
                cb(*a)
            else:
                cb(*a)
                task.cancel()

        return original(run, *args, **kw)

    async def call() -> Any:
        return await start()

    setattr(loop, "call_soon_threadsafe", hook)  # noqa: B010
    try:
        task = asyncio.ensure_future(call())
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(task), 5)
    finally:
        delattr(loop, "call_soon_threadsafe")
    assert task.cancelled() and len(seen) == 1
    return seen[0]


@asynccontextmanager
async def sessions(**config: Any) -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    cfg = zmux.Config(**config)
    async with zmux.Listener(config=cfg) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr), config=cfg) as c,
            await asyncio.wait_for(listener.accept(), 5) as s,
        ):
            yield c, s


@pytest.mark.parametrize("order", ORDERS)
async def test_accept_bi(order: str) -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"first")
        lost = await cancelled_as_it_completes(s.accept_bi, order)
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        assert recv is lost[1]
        assert await recv.read_exact(5) == b"first"


@pytest.mark.parametrize("order", ORDERS)
async def test_accept_bi_by_iteration(order: str) -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"first")
        lost = await cancelled_as_it_completes(s.__anext__, order)
        _, recv = await asyncio.wait_for(s.__anext__(), 5)
        assert recv is lost[1]


@pytest.mark.parametrize("order", ORDERS)
async def test_accept_uni(order: str) -> None:
    async with sessions() as (c, s):
        send = await c.open_uni()
        await send.write(b"uni")
        lost = await cancelled_as_it_completes(s.accept_uni, order)
        recv = await asyncio.wait_for(s.accept_uni(), 5)
        assert recv is lost
        assert await recv.read_exact(3) == b"uni"


@pytest.mark.parametrize("order", ORDERS)
async def test_read_datagram(order: str) -> None:
    async with sessions(enable_datagrams=True) as (c, s):
        c.send_datagram(b"one")
        c.send_datagram(b"two")
        assert await cancelled_as_it_completes(s.read_datagram, order) == b"one"
        # Shared with the datagram iterator; the order is kept.
        assert await asyncio.wait_for(s.datagrams().__anext__(), 5) == b"one"
        assert await asyncio.wait_for(s.read_datagram(), 5) == b"two"


@pytest.mark.parametrize("order", ORDERS)
async def test_listener_accept(order: str) -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.Session.connect(await zmux.dial_tcp(*addr)):
            lost = await cancelled_as_it_completes(listener.accept, order)
            again = await asyncio.wait_for(listener.accept(), 5)
            assert again is lost
            again.close()


@pytest.mark.parametrize("order", ORDERS)
async def test_pipe_end_read(order: str) -> None:
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await stream.write(b"hello world")
    lost = await cancelled_as_it_completes(lambda: end.read(5), order)
    assert lost == b"hello"
    assert await asyncio.wait_for(end.read(3), 5) == b"hel"
    assert await asyncio.wait_for(end.read(), 5) == b"lo"
    assert await asyncio.wait_for(end.read(), 5) == b" world"


@pytest.mark.parametrize("order", ORDERS)
async def test_carrier_stream_read(order: str) -> None:
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await end.write(b"abcdef")
    lost = await cancelled_as_it_completes(lambda: stream.read(4), order)
    assert lost == b"abcd"
    assert await asyncio.wait_for(stream.read(), 5) == b"abcd"
    assert await asyncio.wait_for(stream.read(), 5) == b"ef"


@pytest.mark.parametrize("order", ORDERS)
async def test_layer_end_read(order: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import zmux._layer

    ends: asyncio.Queue[Any] = asyncio.Queue()

    async def capture(layer: Any, stream: Any, end: Any, server_side: bool) -> None:
        # No pump: the test reads the carrier's writes itself.
        ends.put_nowait(end)

    monkeypatch.setattr(zmux._layer, "run", capture)

    async def identity(r: Any, w: Any) -> Any:
        return r, w

    pipe, _far = zmux.adapter.pipe_pair()
    wrapped = await pipe.wrap(identity)
    connecting = asyncio.ensure_future(zmux.Session.connect(wrapped))
    try:
        end = await asyncio.wait_for(ends.get(), 5)
        lost = await cancelled_as_it_completes(end.read, order)
        assert lost
        assert await asyncio.wait_for(end.read(), 5) == lost
    finally:
        connecting.cancel()
        await asyncio.gather(connecting, return_exceptions=True)


async def test_pipe_session_is_the_session_object() -> None:
    async with sessions() as (c, s):
        assert all(p.session is s for p in s.pipes())
        assert all(p.session is c for p in c.pipes())
        # What one handle took back, the pipe's session gives.
        send, _ = await c.open_bi()
        await send.write(b"x")
        lost = await cancelled_as_it_completes(s.accept_bi, "complete-first")
        _, recv = await asyncio.wait_for(s.pipes()[0].session.accept_bi(), 5)
        assert recv is lost[1]


@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize("by_iteration", [False, True])
async def test_events(order: str, by_iteration: bool) -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.connect_tcp(*addr, config=config) as c,
            await asyncio.wait_for(listener.accept(), 5),
        ):
            first = c.events().__anext__ if by_iteration else c.next_event
            await c.add_pipe(await zmux.dial_tcp(*addr))
            await asyncio.sleep(0.1)  # the events are queued
            lost = await cancelled_as_it_completes(first, order)
            assert lost is not None
            # The taken-back event comes first, from either reader.
            again = await asyncio.wait_for(c.next_event(), 5)
            assert again is lost


async def test_send_exit_by_exception_does_not_wait_for_a_blocked_write() -> None:
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, _s):
        send, _ = await c.open_bi()
        # The peer reads nothing: writes pile up until flow control holds one.
        for _ in range(100):
            blocked = asyncio.ensure_future(send.write(b"x" * 65536))
            await asyncio.sleep(0.05)
            if not blocked.done():
                break
        else:
            pytest.fail("no write was held by flow control")
        with pytest.raises(RuntimeError):
            async with asyncio.timeout(2):  # not held by the blocked write
                async with send:
                    raise RuntimeError
        # The reset follows once that write is cancelled.
        assert not blocked.done()
        blocked.cancel()
        await asyncio.gather(blocked, return_exceptions=True)


async def test_recv_exit_stops_the_stream() -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"data")
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        async with recv:
            pass  # normal exit, not read to the end
        assert await asyncio.wait_for(send.stopped(), 5) == 0
