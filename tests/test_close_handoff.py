"""`Session.abort` and `Session.close` hand CONNECTION_CLOSE to the carriers
in the background and `wait_closed` waits for it; `add_pipe` returns once the
peer attached the pipe."""

import asyncio
import contextlib
import sys
import textwrap
from typing import Any

import pytest
import zmux
from support import LOOPBACK, QUIET_LIVENESS, TEST_HOOKS, WATCHDOG, manual_clock
from support import start_pending, until

KEY = b"close-handoff---0123456789abcdef"


def config(**kw: Any) -> zmux.Config:
    return zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=6)
        ),
        pipe_auth=zmux.PipeAuth.psk(KEY).with_end_to_end(),
        **kw,
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
                    c = zmux.Config(session_policy=zmux.SessionPolicy(limits=zmux.CapacityLimits(steady_attachments=6)), resume_timeout=60.0,
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
        closing = await start_pending(session.wait_closed)
        session.abort(3, b"x")
        session.abort(4, b"again")
        session.close()  # the first call decides
        info = await asyncio.wait_for(closing, WATCHDOG)
        assert (info.code, info.remote) == (3, False)
        peer = await asyncio.wait_for(server.wait_closed(), 3)
        assert (peer.code, peer.reason, peer.remote) == (3, b"x", True)
        # An ended session: at once.
        session.close()
        session.abort(9)
        await asyncio.wait_for(session.wait_closed(), WATCHDOG)


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


@pytest.mark.parametrize(
    "cancel",
    [
        pytest.param(
            False,
            marks=pytest.mark.skipif(
                not TEST_HOOKS, reason="requires the test-hooks build"
            ),
        ),
        True,
    ],
)
async def test_failed_add_pipe_leaves_no_live_pipe(cancel: bool) -> None:
    clock = None if cancel else manual_clock()
    join_timeout = 7
    async with asyncio.timeout(WATCHDOG), zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp(LOOPBACK, 0)
        c = config(
            handshake_timeout=None,
            join_timeout=60 if cancel else join_timeout,
            clock_domain=clock.domain if clock else None,
            liveness=QUIET_LIVENESS,
        )
        async with await zmux.connect_tcp(*addr, config=c) as session:
            pipe, silent = zmux.adapter.pipe_pair()
            joining = asyncio.create_task(session.add_pipe(pipe))
            try:
                # The Hello reached the carrier. Hold the Reply indefinitely.
                assert await silent.read()
                (unconfirmed,) = [pipe for pipe in session.pipes() if pipe.id != 0]
                if clock is None:
                    joining.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await joining
                    with contextlib.suppress(zmux.PipeError):
                        await unconfirmed.wait_closed()
                else:
                    await clock.wait_for_timer(join_timeout)
                    clock.advance(join_timeout)
                    with pytest.raises(zmux.DeadlineExceededError):
                        await joining
                    with pytest.raises(zmux.DeadlineExceededError):
                        await unconfirmed.wait_closed()
                assert await silent.read() == b""
                live = (zmux.OutboundState.JOINING, zmux.OutboundState.ACTIVE)
                assert all(
                    s.pipe == 0 or s.outbound not in live for s in session.pipe_stats()
                )
                await session.ping()
            finally:
                joining.cancel()
                await asyncio.gather(joining, return_exceptions=True)


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
            loop = asyncio.get_running_loop()
            scheduled: asyncio.Future[asyncio.Timeout] = loop.create_future()

            async def wait() -> zmux.SessionClosedError:
                async with asyncio.timeout(None) as timeout:
                    scheduled.set_result(timeout)
                    return await session.wait_closed()

            waiting = await start_pending(wait)
            scheduled.result().reschedule(loop.time())
            async with asyncio.timeout(WATCHDOG):
                with pytest.raises(TimeoutError):
                    await waiting
            # The timeout changed nothing: the session is usable.
            assert await session.ping() >= 0
            session.close(7)
            async with asyncio.timeout(3):
                info = await session.wait_closed()
            assert info.code == 7
            assert (await server.wait_closed()).code == 7


async def test_a_slow_reader_still_reads_everything_ahead_of_the_close() -> None:
    # The peer closes with a code right after writing; this side's reader
    # can read all the queued data and then the close code.
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
        for _, recv in opened:
            await recv.wait_readable()
        server.close(0x2A, b"done")
        await until(session, lambda: session.state is zmux.SessionState.CLOSING)
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


async def test_an_unread_fin_keeps_the_read_drain_open_for_a_late_read() -> None:
    # The peer sends nothing but the end of its stream and then closes the
    # session. The FIN is received and not yet read: a late read still ends
    # with EOF, not with the session's error.
    async with zmux.Listener(config=config()) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        session = await zmux.connect_tcp(*addr, config=config())
        server = await asyncio.wait_for(listener.accept(), 5)
        send, recv = await session.open_bi()
        await send.write(b"x")
        reply, request = await asyncio.wait_for(server.accept_bi(), 5)
        await asyncio.wait_for(request.read_exact(1), 5)
        await asyncio.wait_for(reply.finish(), 5)
        await recv.wait_readable()
        server.close(0x2A, b"done")
        await until(session, lambda: session.state is zmux.SessionState.CLOSING)
        assert await asyncio.wait_for(recv.read(4096), 5) == b""
        await asyncio.wait_for(server.wait_closed(), 5)
        await asyncio.wait_for(session.wait_closed(), 5)
