"""Waits, cancellation and release of what the binding holds: a panic reaches the awaiter,
callbacks and releases run clear of the session's lock, and a wait holds no part."""

import asyncio
import contextlib
import subprocess
import sys
import textwrap
from collections.abc import AsyncIterator

import zmux


@contextlib.asynccontextmanager
async def pair() -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        c = await zmux.Session.connect(await zmux.dial_tcp(*addr))
        s = await listener.accept()
        try:
            yield c, s
        finally:
            c.abort(0)
            s.abort(0)


def run_bounded(body: str) -> None:
    """Runs `body` in its own interpreter: a deadlock holds the interpreter lock, which no
    timeout in this process could end."""
    code = "import faulthandler\nfaulthandler.dump_traceback_later(25, exit=True)\n"
    code += textwrap.dedent(body)
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 0, r.stderr[-2000:]


def test_a_lent_buffer_is_released_clear_of_the_session() -> None:
    # The peer's acknowledgements free chunks under the session's lock while this thread,
    # holding the interpreter, asks the session again and again.
    run_bounded(
        """
        import asyncio
        import zmux
        async def main():
            async with zmux.Listener() as l:
                addr = await l.serve_tcp("127.0.0.1", 0)
                c = await zmux.Session.connect(await zmux.dial_tcp(*addr))
                s = await l.accept()
                send, _ = await c.open_bi()
                await send.flush()
                _, recv = await s.accept_bi()
                async def drain():
                    while await recv.read():
                        pass
                d = asyncio.create_task(drain())
                buffer = bytearray(1 << 16)
                for _ in range(200):
                    await send.write(buffer)
                    for _ in range(20):
                        c.stats()
                await send.finish()
                await d
                # Every export ended: the buffer can change size again.
                for _ in range(2000):
                    try:
                        buffer.append(0)
                        break
                    except BufferError:
                        await asyncio.sleep(0.005)
                else:
                    raise SystemExit("still exported")
                c.abort(0)
                s.abort(0)
        asyncio.run(main())
        """
    )


async def test_a_panic_reaches_the_awaiter() -> None:
    _, end = zmux.adapter.pipe_pair()
    try:
        # A length no allocation takes panics in the future.
        await asyncio.wait_for(end.read(2**63 + 1), 10)
    except RuntimeError as e:
        assert "internal error" in str(e)
    else:
        raise AssertionError("no exception")


async def test_a_cancelled_long_read_keeps_what_it_read() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        await send.flush()
        _, recv = await s.accept_bi()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(recv.read_exact(2**63 + 1), 0.05)
        assert await asyncio.wait_for(recv.read(1), 10) == b"x"


async def test_stopped_lets_a_write_go_on() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        stopped = asyncio.ensure_future(send.stopped())
        await asyncio.sleep(0.01)
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
        waiting = asyncio.ensure_future(recv.read_datagram())
        await asyncio.sleep(0.01)
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
            try:
                await asyncio.wait_for(read(16), 0.02)
            except TimeoutError:
                pass
            else:
                raise AssertionError("nothing was written")
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
        blocked = asyncio.ensure_future(send.write(bytes(1 << 22)))
        await asyncio.sleep(0.05)
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


async def test_a_read_cancelled_as_it_completes_loses_nothing() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        await send.flush()
        _, recv = await s.accept_bi()
        assert await recv.read_exact(1) == b"x"
        sent = bytearray()
        got = bytearray()
        for i in range(300):
            data = i.to_bytes(4, "big")
            sent += data
            read = asyncio.create_task(recv.read_exact(4))
            await asyncio.sleep(0)
            await send.write(data)
            await send.flush()
            # Cancel on every timing around the completion.
            for _ in range(i % 7):
                await asyncio.sleep(0)
            read.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                got += await read
        await send.finish()
        got += await asyncio.wait_for(recv.read_to_end(), 5)
        assert got == sent


async def test_dropped_streams_are_released_after_pipe_0_went() -> None:
    # A finalizer only lets go of the handle: the session collects the stream, promptly,
    # whatever pipe carries it.
    import gc
    import time

    key = b"lifecycle-drops-0123456789abcdef"
    c = zmux.Config(max_pipes=4, pipe_auth=zmux.PipeAuth.psk(key).with_end_to_end())
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
                begun = time.monotonic()
                del send, recv, ssend, srecv
                gc.collect()
                assert time.monotonic() - begun < 0.1
                deadline = time.monotonic() + 3
                while client.stats().streams_active + server.stats().streams_active:
                    assert time.monotonic() < deadline, "streams still active"
                    await asyncio.sleep(0.01)
            server.close()
