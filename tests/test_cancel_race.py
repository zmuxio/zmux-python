"""A result that arrives as its awaiter is cancelled is taken back for the
next call, never lost. Each test fixes the interleaving: the result is
ready before the call, and the cancellation lands either just before or
just after the loop runs the completions, the call's among them."""

import asyncio
import random
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

import zmux

ORDERS = ("cancel-first", "complete-first")


# The completion queue's reader on the test's loop, by descriptor: none on
# a loop without `add_reader`, which the native side wakes with
# `call_soon_threadsafe`.
READERS: dict[int, Any] = {}


@pytest.fixture(autouse=True)
async def drains() -> AsyncIterator[None]:
    loop = asyncio.get_running_loop()
    original = loop.add_reader

    def add_reader(fd: Any, cb: Any, *args: Any) -> Any:
        result = original(fd, cb, *args)
        # Recorded only once the loop took it: the proactor loop raises
        # NotImplementedError and the native side falls back.
        if type(cb).__name__ == "Drain":
            READERS[fd] = cb
        return result

    setattr(loop, "add_reader", add_reader)  # noqa: B010
    yield
    delattr(loop, "add_reader")
    READERS.clear()


async def cancelled_as_it_completes(
    start: Callable[[], Awaitable[Any]],
    order: str,
    waiter: Callable[[], Awaitable[Any]] | None = None,
) -> asyncio.Task[Any] | None:
    """Runs `start()` as a task and cancels it at the moment the loop runs
    the completions, its own among them (its result is ready before the
    call). With `waiter`, a call of the same kind is started at that moment
    and given time to block before the cancellation: it is returned, as a
    task."""
    loop = asyncio.get_running_loop()
    blocked: list[asyncio.Task[Any]] = []
    task: asyncio.Task[Any] | None = None

    def intercept(drain: Callable[[], None], restore: Callable[[], None]) -> None:
        def run() -> None:
            assert task is not None
            restore()
            if order == "cancel-first":
                task.cancel()
                drain()
            else:
                drain()
                task.cancel()

        if waiter is None:
            run()
            return
        blocked.append(asyncio.ensure_future(waiter()))
        loop.call_later(0.05, run)

    if READERS:
        ((fd, drain),) = READERS.items()

        def on_read() -> None:
            loop.remove_reader(fd)
            intercept(drain, lambda: loop.add_reader(fd, drain))

        loop.remove_reader(fd)
        loop.add_reader(fd, on_read)
    else:
        original = loop.call_soon_threadsafe

        def hook(cb: Any, *args: Any, **kw: Any) -> Any:
            if type(cb).__name__ != "Drain":
                return original(cb, *args, **kw)
            delattr(loop, "call_soon_threadsafe")
            return original(intercept, cb, lambda: None)

        setattr(loop, "call_soon_threadsafe", hook)  # noqa: B010

    async def call() -> Any:
        return await start()

    task = asyncio.ensure_future(call())
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(asyncio.shield(task), 5)
    assert task.cancelled()
    if waiter is not None:
        assert len(blocked) == 1
        return blocked[0]
    return None


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
        await cancelled_as_it_completes(s.accept_bi, order)
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        assert await recv.read_exact(5) == b"first"


@pytest.mark.parametrize("order", ORDERS)
async def test_accept_bi_by_iteration(order: str) -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"first")
        await cancelled_as_it_completes(s.__anext__, order)
        _, recv = await asyncio.wait_for(s.__anext__(), 5)
        assert await recv.read_exact(5) == b"first"


@pytest.mark.parametrize("order", ORDERS)
async def test_accept_uni(order: str) -> None:
    async with sessions() as (c, s):
        send = await c.open_uni()
        await send.write(b"uni")
        await cancelled_as_it_completes(s.accept_uni, order)
        recv = await asyncio.wait_for(s.accept_uni(), 5)
        assert await recv.read_exact(3) == b"uni"


@pytest.mark.parametrize("order", ORDERS)
async def test_read_datagram(order: str) -> None:
    async with sessions(enable_datagrams=True) as (c, s):
        c.send_datagram(b"one")
        c.send_datagram(b"two")
        await cancelled_as_it_completes(s.read_datagram, order)
        # Shared with the datagram iterator; the order is kept.
        assert await asyncio.wait_for(s.datagrams().__anext__(), 5) == b"one"
        assert await asyncio.wait_for(s.read_datagram(), 5) == b"two"


@pytest.mark.parametrize("order", ORDERS)
async def test_listener_accept(order: str) -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.Session.connect(await zmux.dial_tcp(*addr)):
            await cancelled_as_it_completes(listener.accept, order)
            again = await asyncio.wait_for(listener.accept(), 5)
            again.close()


@pytest.mark.parametrize("order", ORDERS)
async def test_pipe_end_read(order: str) -> None:
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await stream.write(b"hello world")
    await cancelled_as_it_completes(lambda: end.read(5), order)
    assert await asyncio.wait_for(end.read(3), 5) == b"hel"
    assert await asyncio.wait_for(end.read(), 5) == b"lo"
    assert await asyncio.wait_for(end.read(), 5) == b" world"


@pytest.mark.parametrize("order", ORDERS)
async def test_carrier_stream_read(order: str) -> None:
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await end.write(b"abcdef")
    await cancelled_as_it_completes(lambda: stream.read(4), order)
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
        await cancelled_as_it_completes(end.read, order)
        # The carrier's first write: the session's preface, whole.
        assert await asyncio.wait_for(end.read(), 5)
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
        await cancelled_as_it_completes(s.accept_bi, "complete-first")
        _, recv = await asyncio.wait_for(s.pipes()[0].session.accept_bi(), 5)
        assert await recv.read_exact(1) == b"x"


@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize("by_iteration", [False, True])
async def test_events(order: str, by_iteration: bool) -> None:
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
        async with (
            await zmux.connect_tcp(*addr, config=config) as c,
            await asyncio.wait_for(listener.accept(), 5),
        ):
            first = c.events().__anext__ if by_iteration else c.next_event
            await c.add_pipe(await zmux.dial_tcp(*addr))
            await asyncio.sleep(0.1)  # the events are queued
            await cancelled_as_it_completes(first, order)
            # The taken-back event comes first, from either reader.
            again = await asyncio.wait_for(c.next_event(), 5)
            assert type(again).__name__ == "PipeAdded"


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
        blocked = await cancelled_as_it_completes(s.accept_bi, order, s.accept_bi)
        assert blocked is not None
        _, recv = await asyncio.wait_for(blocked, 5)
        assert await recv.read_exact(1) == b"x"


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_accept_uni_gets_the_result(order: str) -> None:
    async with sessions() as (c, s):
        send = await c.open_uni()
        await send.write(b"x")
        blocked = await cancelled_as_it_completes(s.accept_uni, order, s.accept_uni)
        assert blocked is not None
        recv = await asyncio.wait_for(blocked, 5)
        assert await recv.read_exact(1) == b"x"


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_read_datagram_gets_the_result(order: str) -> None:
    async with sessions(enable_datagrams=True) as (c, s):
        c.send_datagram(b"only")
        blocked = await cancelled_as_it_completes(
            s.read_datagram, order, s.datagrams().__anext__
        )
        assert blocked is not None
        assert await asyncio.wait_for(blocked, 5) == b"only"


@pytest.mark.parametrize("order", ORDERS)
async def test_read_cancelled_as_bytes_arrive_takes_nothing(order: str) -> None:
    # A read waits for readiness, which takes nothing: cancelled as the
    # bytes arrive, it leaves them all to the next read.
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        assert await recv.read(1) == b"x"

        async def later() -> None:
            await asyncio.sleep(0.05)
            await send.write(b"chunk")

        writing = asyncio.ensure_future(later())
        await cancelled_as_it_completes(recv.read_chunk, order)
        await writing
        assert bytes(await asyncio.wait_for(recv.read_chunk(), 5)) == b"chunk"


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_next_event_gets_the_result(order: str) -> None:
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
        async with (
            await zmux.connect_tcp(*addr, config=config) as c,
            await asyncio.wait_for(listener.accept(), 5),
        ):
            await c.add_pipe(await zmux.dial_tcp(*addr))
            await asyncio.sleep(0.2)  # the events are queued
            # Added, joined, committed: the commit is the last one.
            for _ in range(2):
                await asyncio.wait_for(c.next_event(), 5)
            blocked = await cancelled_as_it_completes(
                c.next_event, order, c.events().__anext__
            )
            assert blocked is not None
            again = await asyncio.wait_for(blocked, 5)
            assert type(again).__name__ == "EpochCommitted"


async def bytes_written(send: zmux.SendStream) -> int:
    """The part's `bytes_written`, once a cancelled write let go of it: the
    native side does so just after the cancellation."""
    async with asyncio.timeout(5):
        while True:
            try:
                return send.stats().bytes_written
            except zmux.StreamBusyError:
                await asyncio.sleep(0.001)


async def fill(send: zmux.SendStream) -> None:
    """Writes until the part takes nothing more, even after the bytes it
    holds went to the carrier."""
    while True:
        while send.try_write(b"x" * 65536):
            pass
        await asyncio.sleep(0.1)
        if not send.try_write(b"x"):
            return


async def test_write_some_cancelled_while_waiting_takes_nothing() -> None:
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, _s):
        send, _ = await c.open_bi()
        send.send_buffer = 1
        await fill(send)
        before = await bytes_written(send)
        blocked = asyncio.ensure_future(send.write_some(b"y" * 100))
        await asyncio.sleep(0.05)
        assert not blocked.done()
        blocked.cancel()
        (outcome,) = await asyncio.gather(blocked, return_exceptions=True)
        assert isinstance(outcome, asyncio.CancelledError)
        assert await bytes_written(send) == before


@pytest.mark.parametrize("order", ORDERS)
async def test_write_some_cancelled_as_capacity_arrives_takes_nothing(
    order: str,
) -> None:
    # The cancellation lands as the capacity wait completes: the write
    # itself never ran.
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, s):
        send, _ = await c.open_bi()
        send.send_buffer = 1
        await fill(send)
        before = await bytes_written(send)
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)

        async def drain() -> None:
            await asyncio.sleep(0.05)  # the write waits
            await recv.read_exact(before)

        drained = asyncio.ensure_future(drain())
        await cancelled_as_it_completes(lambda: send.write_some(b"y" * 100), order)
        await drained
        assert await bytes_written(send) == before


@pytest.mark.parametrize("vectored", [False, True])
async def test_cancelled_writes_lose_and_duplicate_nothing(vectored: bool) -> None:
    # Writes cancelled at every point of their progress: what the stream
    # carries is exactly the prefixes the completed calls returned.
    rng = random.Random(7)
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, s):
        send, _ = await c.open_bi()
        send.send_buffer = 1
        await send.flush()
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        got = bytearray()

        async def read() -> None:
            while chunk := await recv.read(rng.randint(1, 4096)):
                got.extend(chunk)
                await asyncio.sleep(rng.choice((0, 0, 0.001)))

        reader = asyncio.ensure_future(read())
        expected = bytearray()
        cancelled = 0
        for i in range(200):
            data = i.to_bytes(2, "big") * rng.randint(1, 3000)
            if vectored:
                cut = rng.randint(0, len(data))
                call = send.writev([data[:cut], memoryview(data)[cut:]])
            else:
                call = send.write_some(bytearray(data))
            task = asyncio.ensure_future(call)
            for _ in range(i % 8):
                await asyncio.sleep(0)
            if i % 3:
                await asyncio.sleep(rng.choice((0, 0.0005, 0.002)))
            task.cancel()
            try:
                n = await task
            except asyncio.CancelledError:
                cancelled += 1
                continue
            assert 0 < n <= len(data)
            expected += data[:n]
        await send.finish()
        await asyncio.wait_for(reader, 10)
        assert got == expected
        assert 0 < cancelled < 200


async def test_writable_never_spins() -> None:
    # A writer loop of `writable` and `try_write` takes bytes after every
    # wake-up: no retry returns 0, so it never spins.
    total = 2 << 20
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        send.send_buffer = 1 << 14
        await send.flush()
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)

        async def read() -> int:
            got = 0
            while chunk := await recv.read(65536):
                got += len(chunk)
                await asyncio.sleep(0)
            return got

        reader = asyncio.ensure_future(read())
        data = b"z" * 20000
        taken = wakes = empty = 0
        async with asyncio.timeout(30):
            while taken < total:
                room = await send.writable()
                assert room > 0
                wakes += 1
                n = send.try_write(data[: total - taken])
                if not n:
                    empty += 1
                taken += n
        await send.finish()
        assert await asyncio.wait_for(reader, 10) == total
        assert empty == 0, (empty, wakes)


async def test_writable_follows_buffer_room_not_credit() -> None:
    # The peer's credit is used up while the send buffer has room:
    # `writable` is ready and `try_write` takes bytes, while
    # `wait_send_capacity` still waits. Once the buffer is full as well,
    # `writable` waits until the peer reads.
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, s):
        send, _ = await c.open_bi()
        send.send_buffer = 1 << 20
        await send.flush()
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        assert await asyncio.wait_for(send.writable(), 5) > 0
        taken = send.try_write(b"x" * 65536)
        assert taken > 4096
        await asyncio.sleep(0.05)
        assert send.send_capacity() == 0, "no credit left"
        assert await asyncio.wait_for(send.writable(), 5) > 0, "room is left"
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(send.wait_send_capacity(1), 0.1)
        send.send_buffer = 1
        assert send.try_write(b"x") == 0
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(send.writable(), 0.1)
        blocked = asyncio.ensure_future(send.write_some(b"y"))
        await asyncio.sleep(0.05)
        assert not blocked.done()
        await recv.read_exact(taken)
        assert await asyncio.wait_for(blocked, 5) == 1
        assert await asyncio.wait_for(send.writable(), 5) > 0


async def test_writable_after_reset_raises() -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.flush()
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        recv.stop(5)
        with pytest.raises(zmux.StreamError):
            async with asyncio.timeout(5):
                while True:
                    await send.writable()
                    send.try_write(b"x")
                    await asyncio.sleep(0.01)


async def test_huge_read_size_allocates_nothing_up_front() -> None:
    """A read returns what is there, up to `n`; a huge `n` sizes no buffer."""
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await stream.write(b"hello")
    assert await asyncio.wait_for(end.read(sys.maxsize), 5) == b"hello"
    await end.write(b"world")
    assert await asyncio.wait_for(stream.read(sys.maxsize), 5) == b"world"
