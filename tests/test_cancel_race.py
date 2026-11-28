"""A result that arrives as its awaiter is cancelled is taken back for the
next call, never lost. Each test fixes the interleaving: the result is
ready before the call, and the cancellation lands either just before or
just after the loop runs the completions, the call's among them."""

import asyncio
import sys
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager
from typing import Any

import pytest

import zmux
from support import (
    ORDERS,
    QUIET_LIVENESS,
    WATCHDOG,
    cancelled_as_it_completes,
    session_pair,
    start_pending,
    until,
)


@asynccontextmanager
async def sessions(**config: Any) -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    async with session_pair(zmux.Config(**config)) as pair:
        yield pair


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

    async def capture(
        layer: Any, stream: Any, layer_end: Any, server_side: bool
    ) -> None:
        # No pump: the test reads the carrier's writes itself.
        ends.put_nowait(layer_end)

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
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=8)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
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
        blocked = await start_pending(lambda: send.write(b"x" * 65536))
        with pytest.raises(RuntimeError):
            async with asyncio.timeout(WATCHDOG):
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

        await cancelled_as_it_completes(
            recv.read_chunk, order, on_pending=lambda: send.write(b"chunk")
        )
        assert bytes(await asyncio.wait_for(recv.read_chunk(), 5)) == b"chunk"


@pytest.mark.parametrize("order", ORDERS)
async def test_blocked_next_event_gets_the_result(order: str) -> None:
    async with sessions(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=8)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        liveness=QUIET_LIVENESS,
    ) as (c, _):
        (pipe,) = c.pipes()

        async def change_weight() -> None:
            pipe.update(weight=2)

        # A local weight change produces one event without starting a join.
        blocked = await cancelled_as_it_completes(
            c.next_event, order, c.events().__anext__, on_pending=change_weight
        )
        assert blocked is not None
        again = await asyncio.wait_for(blocked, WATCHDOG)
        assert isinstance(again, zmux.PipePriorityChanged)
        assert (again.pipe, again.weight) == (pipe.id, 2)


def fill(send: zmux.SendStream) -> bytes:
    """Queue more data than the peer can take and leave its credit exhausted."""
    prefix = b"x" * 65536
    assert send.try_write(prefix) == len(prefix)
    send.send_buffer = 1
    assert send.try_write(b"extra") == 0
    return prefix


def write_call(send: zmux.SendStream, data: bytes, vectored: bool) -> Awaitable[int]:
    if vectored:
        return send.writev([data[:3], memoryview(data)[3:]])
    return send.write_some(bytearray(data))


@pytest.mark.parametrize("vectored", [False, True])
async def test_write_cancelled_while_waiting_takes_nothing(vectored: bool) -> None:
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, s):
        send, _ = await c.open_bi()
        prefix = fill(send)
        blocked = await start_pending(lambda: write_call(send, b"discard", vectored))
        blocked.cancel()
        with pytest.raises(asyncio.CancelledError):
            await blocked
        assert send.stats().bytes_written == len(prefix)

        _, recv = await s.accept_bi()
        assert await recv.read_exact(len(prefix)) == prefix
        send.send_buffer = 4096
        data = b"accepted"
        n = await write_call(send, data, vectored)
        assert n == len(data)
        await send.finish()
        assert await recv.read_to_end() == data


@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize("vectored", [False, True])
async def test_write_cancelled_as_capacity_arrives_takes_nothing(
    order: str, vectored: bool
) -> None:
    async with sessions(
        initial_stream_receive_window=4096, max_stream_receive_window=4096
    ) as (c, s):
        send, _ = await c.open_bi()
        prefix = fill(send)
        _, recv = await s.accept_bi()

        async def drain() -> None:
            assert await recv.read_exact(len(prefix)) == prefix

        await cancelled_as_it_completes(
            lambda: write_call(send, b"discard", vectored), order, on_pending=drain
        )
        assert send.stats().bytes_written == len(prefix)
        await send.finish()
        assert await recv.read_to_end() == b""


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
        await until(c, lambda: send.send_capacity() == 0)
        assert await send.writable() > 0
        capacity = await start_pending(lambda: send.wait_send_capacity(1))
        capacity.cancel()
        with pytest.raises(asyncio.CancelledError):
            await capacity
        send.send_buffer = 1
        assert send.try_write(b"x") == 0
        blocked = await start_pending(lambda: send.write_some(b"y"))
        await recv.read_exact(taken)
        assert await asyncio.wait_for(blocked, 5) == 1
        assert await asyncio.wait_for(send.writable(), 5) > 0


async def test_writable_after_reset_raises() -> None:
    async with sessions() as (c, s):
        send, _ = await c.open_bi()
        await send.flush()
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        recv.stop(5)
        assert await send.stopped() == 5
        with pytest.raises(zmux.StreamError):
            await send.writable()


async def test_huge_read_size_allocates_nothing_up_front() -> None:
    """A read returns what is there, up to `n`; a huge `n` sizes no buffer."""
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await stream.write(b"hello")
    assert await asyncio.wait_for(end.read(sys.maxsize), 5) == b"hello"
    await end.write(b"world")
    assert await asyncio.wait_for(stream.read(sys.maxsize), 5) == b"world"
