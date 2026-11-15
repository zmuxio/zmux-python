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
    start: Callable[[], Awaitable[Any]],
    order: str,
    waiter: Callable[[], Awaitable[Any]] | None = None,
) -> Any:
    """Runs `start()` as a task and cancels it at the moment its result is
    handed to the loop; the result it would have returned. With `waiter`, a
    call of the same kind is started once the result exists and given time
    to block before the cancellation: it is returned too, as a task."""
    loop = asyncio.get_running_loop()
    blocked: list[asyncio.Task[Any]] = []
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

        if waiter is None:
            return original(run, *args, **kw)

        def block_first(*a: Any) -> None:
            assert waiter is not None
            blocked.append(asyncio.ensure_future(waiter()))
            loop.call_later(0.05, run, *a)

        return original(block_first, *args, **kw)

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
    if waiter is not None:
        assert len(blocked) == 1
        return seen[0], blocked[0]
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
        # The peer reads nothing and the part may hold one byte: a write of
        # more than the peer's window can never finish by itself, however
        # slowly the loop runs (a deterministic block, not a timing guess).
        send.send_buffer = 1
        blocked = asyncio.ensure_future(send.write(b"x" * 65536))
        await asyncio.sleep(0.05)  # the write holds the part
        with pytest.raises(RuntimeError):
            async with asyncio.timeout(2):  # not held by the blocked write
                async with send:
                    raise RuntimeError
        # The reset follows once that write is cancelled; a write that had
        # not yet started meets the reset at once. It never succeeds.
        blocked.cancel()
        (outcome,) = await asyncio.gather(blocked, return_exceptions=True)
        assert isinstance(outcome, Exception | asyncio.CancelledError)


async def test_recv_exit_stops_the_stream() -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"data")
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        async with recv:
            pass  # normal exit, not read to the end
        assert await asyncio.wait_for(send.stopped(), 5) == 0


# A call already blocked when the cancelled call's result is taken back
# gets it: the result was the last one, nothing else would wake the call.


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_accept_bi_gets_the_result(order: str) -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        lost, blocked = await cancelled_as_it_completes(s.accept_bi, order, s.accept_bi)
        _, recv = await asyncio.wait_for(blocked, 5)
        assert recv is lost[1]


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_accept_uni_gets_the_result(order: str) -> None:
    async with sessions() as (c, s):
        send = await c.open_uni()
        await send.write(b"x")
        lost, blocked = await cancelled_as_it_completes(
            s.accept_uni, order, s.accept_uni
        )
        assert await asyncio.wait_for(blocked, 5) is lost


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_read_datagram_gets_the_result(order: str) -> None:
    async with sessions(enable_datagrams=True) as (c, s):
        c.send_datagram(b"only")
        lost, blocked = await cancelled_as_it_completes(
            s.read_datagram, order, s.datagrams().__anext__
        )
        assert lost == b"only"
        assert await asyncio.wait_for(blocked, 5) == b"only"


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_read_chunk_gets_the_result(order: str) -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"chunk")
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        await asyncio.sleep(0.05)  # the bytes have arrived
        lost, blocked = await cancelled_as_it_completes(
            recv.read_chunk, order, recv.read_chunk
        )
        assert bytes(lost) == b"chunk"
        assert bytes(await asyncio.wait_for(blocked, 5)) == b"chunk"


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_next_event_gets_the_result(order: str) -> None:
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
            await c.add_pipe(await zmux.dial_tcp(*addr))
            await asyncio.sleep(0.2)  # the events are queued
            # Added, joined, committed: the commit is the last one.
            for _ in range(2):
                await asyncio.wait_for(c.next_event(), 5)
            lost, blocked = await cancelled_as_it_completes(
                c.next_event, order, c.events().__anext__
            )
            assert type(lost).__name__ == "EpochCommitted"
            assert await asyncio.wait_for(blocked, 5) is lost


async def bytes_written(send: zmux.SendStream) -> int:
    """The part's `bytes_written`, once a cancelled write let go of it: the
    native side does so just after the cancellation."""
    async with asyncio.timeout(5):
        while True:
            try:
                return send.stats().bytes_written
            except zmux.StreamBusyError:
                await asyncio.sleep(0.001)


async def test_write_some_cancelled_while_waiting_takes_nothing() -> None:
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, _s):
        send, _ = await c.open_bi()
        send.send_buffer = 1
        # Fill the part until it takes nothing more.
        while True:
            try:
                async with asyncio.timeout(0.2):
                    await send.write_some(b"x" * 65536)
            except TimeoutError:
                break
        before = await bytes_written(send)
        blocked = asyncio.ensure_future(send.write_some(b"y" * 100))
        await asyncio.sleep(0.05)
        assert not blocked.done()
        blocked.cancel()
        (outcome,) = await asyncio.gather(blocked, return_exceptions=True)
        assert isinstance(outcome, asyncio.CancelledError)
        assert await bytes_written(send) == before
