"""Waits, cancellation and release of what the binding holds."""

import asyncio
import contextlib
import sys
from functools import partial

import pytest
import zmux
from support import start_pending, until
from support import session_pair as pair


@pytest.mark.skipif(
    not hasattr(zmux._zmux, "_panic"),
    reason="the module is built without the test-hooks feature",
)
async def test_a_panic_reaches_the_awaiter() -> None:
    with pytest.raises(RuntimeError, match="internal error: deliberate"):
        await asyncio.wait_for(zmux._zmux._panic(), 10)


async def test_a_cancelled_long_read_keeps_what_it_read() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        await send.flush()
        _, recv = await s.accept_bi()
        reading = await start_pending(lambda: recv.read_exact(sys.maxsize + 1))
        reading.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reading
        assert await asyncio.wait_for(recv.read(1), 10) == b"x"


async def test_stopped_lets_a_write_go_on() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        stopped = await start_pending(send.stopped)
        await asyncio.wait_for(send.write(b"hello"), 5)
        await asyncio.wait_for(send.finish(), 5)
        _, recv = await s.accept_bi()
        assert await asyncio.wait_for(recv.read_to_end(), 5) == b"hello"
        assert await asyncio.wait_for(stopped, 10) is None


async def test_read_datagram_lets_a_read_go_on() -> None:
    config = zmux.Config(enable_datagrams=True)
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        c = await zmux.Session.connect(await zmux.dial_tcp(*addr), config=config)
        s = await listener.accept()
        send, _ = await c.open_bi()
        await send.flush()
        _, recv = await s.accept_bi()
        waiting = await start_pending(recv.read_datagram)
        await send.write(b"data")
        assert await asyncio.wait_for(recv.read(4), 5) == b"data"
        waiting.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await waiting
        c.abort(0)
        s.abort(0)


async def test_a_cancelled_read_leaves_the_stream_usable() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.flush()
        _, recv = await s.accept_bi()
        for read in (recv.read, recv.read_chunk):
            waiting = await start_pending(partial(read, 16))
            waiting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiting
        await send.write(b"ok")
        assert await asyncio.wait_for(recv.read_exact(2), 5) == b"ok"


async def test_a_cancelled_blocked_write_releases_the_part() -> None:
    config = zmux.Config(
        initial_stream_receive_window=4096,
        max_stream_receive_window=4096,
        send_buffer=4096,
        send_buffer_max=4096,
    )
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        c = await zmux.Session.connect(await zmux.dial_tcp(*addr), config=config)
        s = await listener.accept()
        send, _ = await c.open_bi()
        blocked = await start_pending(lambda: send.write(bytes(1 << 22)))
        assert not blocked.done()
        blocked.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await blocked
        send.reset(1)
        c.abort(0)
        s.abort(0)


def test_a_binding_call_is_a_coroutine() -> None:
    async def main() -> None:
        async with pair() as (c, _):
            task = asyncio.create_task(c.open_bi())
            await asyncio.wait_for(task, 5)

    asyncio.run(main())


async def test_a_cancelled_exact_read_returns_the_prefix_it_collected() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"ab")
        _, recv = await s.accept_bi()
        await recv.wait_readable()
        reading = await start_pending(lambda: recv.read_exact(4))
        assert recv.stats().bytes_read == 2
        reading.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reading
        await send.write(b"cd")
        await send.finish()
        assert await recv.read_to_end() == b"abcd"


def release_while_loop_is_blocked(held: list[object]) -> None:
    """Drops `held` and collects on another thread while this one, the
    event loop's, blocks and cannot run a callback. A finalizer that waited
    for the loop (or for the session to answer through it) would never
    return, so the join times out: a deterministic failure, and no pass
    depends on how fast the collection is."""
    import gc
    import threading

    def work() -> None:
        held.clear()
        gc.collect()

    t = threading.Thread(target=work)
    t.start()
    t.join(30)
    assert not t.is_alive(), "a finalizer waits for the event loop"


async def test_dropped_streams_are_released_after_pipe_0_went() -> None:
    # A finalizer only lets go of the handle: the session collects the stream, promptly,
    # whatever pipe carries it.

    key = b"lifecycle-drops-0123456789abcdef"
    c = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=4)
        ),
        pipe_auth=zmux.PipeAuth.psk(key).with_end_to_end(),
    )
    async with zmux.Listener(config=c) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.Session.connect(
            await zmux.dial_tcp(*addr), config=c
        ) as client:
            server = await asyncio.wait_for(listener.accept(), 5)
            await asyncio.wait_for(client.add_pipe(await zmux.dial_tcp(*addr)), 10)
            client.pipes()[0].abort()
            for _ in range(3):
                send, recv = await client.open_bi()
                await send.write(b"unfinished")
                ssend, srecv = await asyncio.wait_for(server.accept_bi(), 5)
                assert await asyncio.wait_for(srecv.read(10), 5) == b"unfinished"
                held: list[object] = [send, recv, ssend, srecv]
                del send, recv, ssend, srecv
                release_while_loop_is_blocked(held)
                await until(client, lambda: client.stats().streams_active == 0)
                await until(server, lambda: server.stats().streams_active == 0)
            server.close()
