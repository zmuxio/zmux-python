"""`Session.abort` and `Session.close` hand CONNECTION_CLOSE to the carriers
in the background and `wait_closed` waits for it; `add_pipe` returns once the
peer attached the pipe unless `return_on_reply`."""

import asyncio
import sys
import textwrap
import time
from typing import Any

import pytest
import zmux

KEY = b"close-handoff---0123456789abcdef"


def config(**kw: Any) -> zmux.Config:
    return zmux.Config(
        max_pipes=6, pipe_auth=zmux.PipeAuth.psk(KEY).with_end_to_end(), **kw
    )


async def test_a_process_that_exits_after_wait_closed_reaches_the_peer() -> None:
    # The peer holds a session whose carrier ended for its resume timeout:
    # only the CONNECTION_CLOSE that the exiting process handed off ends it.
    c = config(resume_timeout=60.0)
    async with zmux.Listener(config=c) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        for _ in range(3):
            script = textwrap.dedent(
                f"""
                import asyncio, zmux
                async def main():
                    c = zmux.Config(max_pipes=6, resume_timeout=60.0,
                                    pipe_auth=zmux.PipeAuth.psk({KEY!r}).with_end_to_end())
                    s = await zmux.connect_tcp(*{addr!r}, config=c)
                    send, _ = await s.open_bi()
                    await send.write(b"hello")
                    s.abort(7, b"bye")
                    await s.wait_closed()
                asyncio.run(main())
                """
            )
            proc = await asyncio.create_subprocess_exec(sys.executable, "-c", script)
            server = await asyncio.wait_for(listener.accept(), 10)
            assert await asyncio.wait_for(proc.wait(), 20) == 0
            info = await asyncio.wait_for(server.wait_closed(), 5)
            assert (info.code, info.reason, info.remote) == (7, b"bye", True)


async def test_close_does_not_block_and_wait_closed_follows_the_hand_off() -> None:
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        start = time.monotonic()
        session.abort(3, b"x")
        session.abort(4, b"again")
        session.close()  # the first call decides
        assert time.monotonic() - start < 0.1
        info = await asyncio.wait_for(session.wait_closed(), 3)
        assert (info.code, info.remote) == (3, False)
        peer = await asyncio.wait_for(server.wait_closed(), 3)
        assert (peer.code, peer.reason, peer.remote) == (3, b"x", True)
        # An ended session: at once.
        session.close()
        session.abort(9)
        await asyncio.wait_for(session.wait_closed(), 0.5)


async def test_a_graceful_close_reaches_the_peer_and_async_with_aborts_on_error() -> (
    None
):
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        session.close()
        session.close()
        info = await asyncio.wait_for(session.wait_closed(), 3)
        assert info.remote is False
        peer = await asyncio.wait_for(server.wait_closed(), 3)
        assert peer.remote is True and peer.code == info.code

        # A normal exit closes and waits; an exception exit closes with ZMUX_CANCELLED.
        async with await zmux.connect_tcp(*addr, config=config()):
            ok_server = await asyncio.wait_for(listener.accept(), 5)
        await asyncio.wait_for(ok_server.wait_closed(), 3)
        with pytest.raises(RuntimeError):
            async with await zmux.connect_tcp(*addr, config=config()) as bad:
                bad_server = await asyncio.wait_for(listener.accept(), 5)
                raise RuntimeError("boom")
        peer = await asyncio.wait_for(bad_server.wait_closed(), 3)
        assert (
            peer.code == zmux.ApplicationErrorCode.ZMUX_CANCELLED
            and peer.remote is True
        )
        await asyncio.wait_for(bad.wait_closed(), 3)


def test_return_on_reply_is_an_option_fixed_at_add() -> None:
    assert zmux.PipeOptions().return_on_reply is False
    assert zmux.PipeOptions(return_on_reply=True).return_on_reply is True


async def test_add_pipe_waits_for_the_attachment() -> None:
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr, config=config()) as session:
            pipe = await asyncio.wait_for(
                session.add_pipe(await zmux.dial_tcp(*addr)), 10
            )
            # Attached at return.
            await asyncio.wait_for(pipe.attached(), 0.05)
            o = pipe.options
            assert o is not None and o.return_on_reply is False
            options = zmux.PipeOptions(return_on_reply=True, label="n")
            quick = await asyncio.wait_for(
                session.add_pipe(await zmux.dial_tcp(*addr), options=options), 10
            )
            o = quick.options
            assert o is not None and o.return_on_reply is True
            with pytest.raises(TypeError):
                # Fixed when the pipe is added: not updatable.
                quick.update(return_on_reply=False)  # type: ignore[call-arg]
            await asyncio.wait_for(quick.attached(), 10)


async def test_add_pipe_times_out_and_leaves_no_pipe() -> None:
    # A carrier to a server that never answers the Hello.
    held: list[asyncio.StreamWriter] = []

    async def hold(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        held.append(w)
        await r.read()

    silent = await asyncio.start_server(hold, "127.0.0.1", 0)
    host, port = silent.sockets[0].getsockname()[:2]
    try:
        async with zmux.Listener(config=config()) as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            c = config(handshake_timeout=None, join_timeout=0.5)
            async with await zmux.connect_tcp(*addr, config=c) as session:
                start = time.monotonic()
                with pytest.raises(zmux.DeadlineExceededError):
                    await session.add_pipe(await zmux.dial_tcp(host, port))
                took = time.monotonic() - start
                assert 0.45 <= took < 2, took
                live = (zmux.OutboundState.JOINING, zmux.OutboundState.ACTIVE)
                assert all(
                    s.pipe == 0 or s.outbound not in live for s in session.pipe_stats()
                )
                # A cancelled call aborts its pipe too.
                task = asyncio.create_task(
                    session.add_pipe(await zmux.dial_tcp(host, port))
                )
                await asyncio.sleep(0.1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert await session.ping() >= 0
    finally:
        for w in held:
            w.close()
        silent.close()
        await silent.wait_closed()


async def test_close_takes_a_code_and_reason_and_the_first_call_decides() -> None:
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        session.close(0x2A, b"replaced")
        session.close(5, b"later")  # the first call decides
        session.abort(6, b"later")
        info = await asyncio.wait_for(session.wait_closed(), 3)
        assert (info.code, info.reason, info.remote) == (0x2A, b"replaced", False)
        peer = await asyncio.wait_for(server.wait_closed(), 3)
        assert (peer.code, peer.reason, peer.remote) == (0x2A, b"replaced", True)

        # A plain close is the coded one with code 0 and an empty reason.
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        session.close()
        peer = await asyncio.wait_for(server.wait_closed(), 3)
        assert (peer.code, peer.reason, peer.remote) == (0, b"", True)
        await asyncio.wait_for(session.wait_closed(), 3)

        with pytest.raises(ValueError):
            session.close(1 << 62)


async def test_wait_closed_is_bounded_by_the_callers_timeout() -> None:
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr, config=config()) as session:
            server = await asyncio.wait_for(listener.accept(), 5)
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await session.wait_closed()  # nothing closed it
            # The timeout changed nothing: the session is usable.
            assert await session.ping() >= 0
            session.close(7)
            async with asyncio.timeout(3):
                info = await session.wait_closed()
            assert info.code == 7
            assert (await server.wait_closed()).code == 7


async def test_a_slow_reader_still_reads_everything_ahead_of_the_close() -> None:
    # The peer closes with a code right after writing; this side's reader
    # pauses (for less than the linger timeout) before it reads, and still
    # gets all the data and then the code.
    data = bytes(range(256)) * 1024  # 256 KiB
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        send, _ = await session.open_bi()
        await send.write(b"x")
        _, recv = await asyncio.wait_for(server.accept_bi(), 5)
        first = await asyncio.wait_for(recv.read_exact(1), 5)
        await send.write(data)
        session.close(0x2A, b"done")
        await asyncio.sleep(0.1)
        got = bytearray()
        with pytest.raises(zmux.ApplicationClosedError) as err:
            while True:
                chunk = await asyncio.wait_for(recv.read(4096), 5)
                assert chunk, "the stream ended without the close's error"
                got += chunk
        assert first + bytes(got) == b"x" + data
        assert err.value.code == 0x2A and err.value.reason == b"done"
        assert err.value.remote is True
        await asyncio.wait_for(server.wait_closed(), 5)
        await asyncio.wait_for(session.wait_closed(), 5)


async def test_stop_and_reset_in_the_read_drain_raise_exits_stay_quiet() -> None:
    # The peer closes with a code while two streams of this side hold unread
    # data: this side is in the read drain. An explicit stop/reset raises a
    # session error, while the automatic cleanup of `async with` swallows it.
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        opened = []
        kept = []
        for _ in range(2):
            send, recv = await session.open_bi()
            await send.write(b"hello")
            reply, request = await asyncio.wait_for(server.accept_bi(), 5)
            await reply.write(b"unread")
            opened.append((send, recv))
            kept.append((reply, request))  # dropped, they would stop the peer
        await asyncio.sleep(0.1)  # the replies arrived and nothing read them
        server.close(0x2A, b"done")
        await asyncio.sleep(0.1)
        (send_a, recv_a), (send_b, recv_b) = opened
        with pytest.raises(zmux.ZmuxError):
            send_a.reset(1)
        with pytest.raises(zmux.ZmuxError):
            recv_a.stop(1)  # discards A's data; B's keeps the drain
        # The drain is still on: B's exits raise nothing, on an exception
        # or, for the receiving part, on a normal exit.
        with pytest.raises(RuntimeError):
            async with recv_b:
                raise RuntimeError("boom")
        with pytest.raises(RuntimeError):
            async with send_b:
                raise RuntimeError("boom")
        async with recv_b:  # a normal exit of a receiving part does nothing
            pass
