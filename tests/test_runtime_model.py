"""The runtime's threads never wait for Python: a Python limiter, a busy
interpreter, fork and exit."""

import asyncio
import os
import subprocess
import sys
import textwrap
import threading

import pytest

import zmux
from support import TEST_HOOKS, start_pending
from support import session_pair as pair


class GatedLimiter:
    """A limiter whose acquire can pause independently of another session."""

    max_burst_bytes = (1 << 64) - 1

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.released = asyncio.Event()

    async def acquire(self, least: int, most: int, /) -> int:
        self.entered.set()
        await self.released.wait()
        return most

    def try_acquire(self, least: int, most: int, /) -> int:
        return most if self.released.is_set() else 0

    def refund(self, n: int, /) -> None:
        pass


async def test_blocked_splice_limiter_leaves_other_sessions_alive() -> None:
    limiter = GatedLimiter()
    async with (
        pair() as (c, relay_in),
        pair() as (relay_out, server),
        pair() as (x, _y),
    ):

        async def relay() -> zmux.helpers.SpliceResult:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice(a, b, chunk=4096, a_to_b=limiter)

        async def sink() -> int:
            back, incoming = await server.accept_bi()
            n = len(await incoming.read_to_end())
            await back.finish()
            return n

        async with asyncio.TaskGroup() as tasks:
            relaying = tasks.create_task(relay())
            sinking = tasks.create_task(sink())
            send, recv = await c.open_bi()
            await send.write(b"x" * 50_000)
            await send.finish()
            await limiter.entered.wait()
            assert not relaying.done()
            await x.ping()
            limiter.released.set()
            assert await sinking == 50_000
            assert await recv.read_to_end() == b""
            assert (await relaying).a_to_b.bytes == 50_000


if sys.platform != "win32":

    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    async def test_a_child_forked_after_use_raises() -> None:
        async with pair() as (c, _s):
            await c.ping()
            r, w = os.pipe()
            pid = os.fork()
            if pid == 0:  # pragma: no cover - the child
                os.close(r)
                code = 1
                try:
                    asyncio.run(asyncio.wait_for(zmux.dial_tcp("127.0.0.1", 1), 2))
                except RuntimeError as e:
                    code = 0 if "fork" in str(e) else 2
                except Exception:
                    code = 3
                finally:
                    try:
                        os.write(w, bytes([code]))
                    finally:
                        os._exit(0)
            os.close(w)
            try:
                got = await asyncio.wait_for(asyncio.to_thread(os.read, r, 1), 10)
            finally:
                os.close(r)
                os.waitpid(pid, 0)
            assert got == b"\x00"


def run_child(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_exit_with_sessions_open_and_hooks_firing() -> None:
    # Hooks of the runtime (a logger) still fire as the interpreter exits.
    r = run_child(
        """
        import asyncio, zmux

        class Log:
            def log(self, level, message):
                pass

        async def main():
            listener = zmux.Listener(config=zmux.Config(logger=Log()))
            addr = await listener.serve_tcp("127.0.0.1", 0)
            c = await zmux.Session.connect(await zmux.dial_tcp(*addr))
            s = await listener.accept()
            send, recv = await c.open_bi()
            await send.write(b"x" * 100000)
            globals()["kept"] = (listener, c, s, send, recv)

        asyncio.run(main())
        """
    )
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(not TEST_HOOKS, reason="requires the test-hooks build")
def test_exit_with_operations_pending() -> None:
    r = run_child(
        """
        import asyncio, zmux

        async def main():
            listener = zmux.Listener()
            addr = await listener.serve_tcp("127.0.0.1", 0)
            c = await zmux.Session.connect(await zmux.dial_tcp(*addr))
            s = await listener.accept()
            loop = asyncio.get_running_loop()
            original = loop.create_future
            signals = asyncio.Queue()

            def future():
                f = original()
                f._zmux_test_pending = lambda: signals.put_nowait(None)
                return f

            loop.create_future = future
            pending = [asyncio.ensure_future(s.accept_bi()) for _ in range(10)]
            for _ in pending:
                await signals.get()
            assert all(not task.done() for task in pending)
            globals()["kept"] = (listener, c, s, pending)
            loop.stop()

        loop = asyncio.new_event_loop()
        loop.create_task(main())
        loop.run_forever()
        """
    )
    assert r.returncode == 0, r.stderr


async def test_a_write_copies_a_mutable_buffer() -> None:
    # The caller may reuse a mutable buffer as soon as a write returned.
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        buf = bytearray(b"a" * 4096)
        await send.write(buf)
        buf[:] = b"b"
        view = memoryview(bytearray(b"c" * 10))
        send.try_write(view)
        view[:] = b"d" * 10
        await send.finish()
        _, recv = await asyncio.wait_for(s.accept_bi(), 5)
        assert await recv.read_to_end() == b"a" * 4096 + b"c" * 10


async def test_pipe_end_read_raises_instead_of_ending() -> None:
    pipe, end = zmux.adapter.pipe_pair()
    stream = pipe.into_stream()
    await stream.write(memoryview(b"xyz")[1:])
    assert await asyncio.wait_for(end.read(), 5) == b"yz"


def test_loops_on_threads_of_their_own() -> None:
    # Each loop drains its own completions, with or without the GIL.
    async def work() -> int:
        async with pair() as (c, s):
            for _ in range(20):
                await c.ping()
            send, _ = await c.open_bi()
            await send.write(b"t" * 1000)
            await send.finish()
            _, recv = await asyncio.wait_for(s.accept_bi(), 5)
            return len(await recv.read_to_end())

    results: list[int] = []
    threads = [
        threading.Thread(target=lambda: results.append(asyncio.run(work())))
        for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert results == [1000] * 4


async def test_metadata_while_a_read_waits() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi(info=b"meta")
        await send.write(b"x")
        out, recv = await asyncio.wait_for(s.accept_bi(), 5)
        assert await recv.read(1) == b"x"
        reading = await start_pending(recv.read)
        writing = asyncio.ensure_future(out.writable())
        assert not reading.done()
        assert recv.id == out.id is not None
        assert recv.stats().bytes_read == 1
        assert recv.preamble.info == b"meta"
        assert not recv.is_replayable
        assert recv.preamble_priority is None
        assert out.stats().bytes_written == 0
        await writing
        reading.cancel()
        await asyncio.gather(reading, return_exceptions=True)


async def test_try_write_right_after_cancelled_waits() -> None:
    async with pair() as (c, s):
        send, recv = await c.open_bi()
        await send.write(b"x")
        out, inbound = await asyncio.wait_for(s.accept_bi(), 5)
        await inbound.read(1)
        reading = await start_pending(recv.read)
        waiting = asyncio.ensure_future(send.writable())
        reading.cancel()
        await asyncio.gather(reading, waiting, return_exceptions=True)
        # Nothing is busy: the cancelled read and the readiness wait hold no part.
        assert send.try_write(b"y") == 1
        assert recv.stats().bytes_read == 0
        await send.finish()
        assert await asyncio.wait_for(inbound.read_to_end(), 5) == b"y"
        await out.write(b"z")
        assert await asyncio.wait_for(recv.read(), 5) == b"z"
