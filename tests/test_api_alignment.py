"""Read readiness, the non-blocking read, the stream and
session getters, the pipe options read back, `PipeAbortedError` and the
priority defaults."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import math
import threading
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
import zmux

CANCELLED = zmux.ApplicationErrorCode.ZMUX_CANCELLED


@contextlib.asynccontextmanager
async def pair(
    config: zmux.Config | None = None,
) -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    async with zmux.Listener(config=config) as listener:
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        c = await zmux.connect_tcp(host, port, config=config)
        s = await listener.accept()
        try:
            yield c, s
        finally:
            c.abort(0)
            s.abort(0)
            await asyncio.gather(c.wait_closed(), s.wait_closed())


async def until(cond: Callable[[], object], limit: float = 5.0) -> None:
    async with asyncio.timeout(limit):
        while not cond():
            await asyncio.sleep(0.005)


# ---- read readiness and the non-blocking read ----------------------------------


async def test_wait_readable_is_ready_for_data_and_returns_nothing() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"hello")
        _, recv = await s.accept_bi()
        assert await recv.wait_readable() is None  # type: ignore[func-returns-value]
        # It takes nothing: the read still gets the data.
        assert await recv.read() == b"hello"


async def test_wait_readable_waits_only_for_its_own_bound() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        _, recv = await s.accept_bi()
        assert await recv.read() == b"x"
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.1):
                await recv.wait_readable()
        # Any number of waiters, each cancellable; the stream stays usable.
        waiters = [asyncio.ensure_future(recv.wait_readable()) for _ in range(3)]
        await asyncio.sleep(0.05)
        waiters[0].cancel()
        assert not any(w.done() for w in waiters[1:])
        await send.write(b"y")
        await asyncio.gather(*waiters[1:])
        assert await recv.read() == b"y"


async def test_wait_readable_reports_every_end_as_success() -> None:
    """A FIN, a reset, a stop by this endpoint and the session's end make the
    next read return at once, so the wait succeeds; the read reports the end,
    once, in its own form."""
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.finish()
        _, recv = await s.accept_bi()
        assert await recv.wait_readable() is None  # type: ignore[func-returns-value]
        assert await recv.read() == b""
        assert await recv.wait_readable() is None  # type: ignore[func-returns-value]

        send, _ = await c.open_bi()
        await send.write(b"z")
        send.reset(7)
        _, reset = await s.accept_bi()
        assert await reset.wait_readable() is None  # type: ignore[func-returns-value]
        with pytest.raises(zmux.StreamResetError) as e:
            await reset.read_to_end()
        assert e.value.code == 7

        send, _ = await c.open_bi()
        await send.write(b"z")
        _, stopped = await s.accept_bi()
        stopped.stop(3)
        assert await stopped.wait_readable() is None  # type: ignore[func-returns-value]
        with pytest.raises(zmux.StreamError):
            await stopped.read()

        send, _ = await c.open_bi()
        await send.write(b"w")
        _, last = await s.accept_bi()
        assert await last.read() == b"w"
        c.abort(0)
        await s.wait_closed()
        assert await last.wait_readable() is None  # type: ignore[func-returns-value]
        with pytest.raises(zmux.SessionClosedError):
            await last.read()


async def test_try_read_tells_nothing_now_from_the_end() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"abcdef")
        _, recv = await s.accept_bi()
        await recv.wait_readable()
        assert recv.try_read(4) == b"abcd"
        assert recv.try_read() == b"ef"
        # Nothing now, and the stream has not ended: None, not b"".
        assert recv.try_read() is None
        await send.finish()
        await recv.wait_readable()
        assert recv.try_read() == b""
        assert recv.try_read() == b""
        with pytest.raises(ValueError):
            recv.try_read(0)


async def test_try_read_reports_a_reset_as_a_read_does() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"a")
        _, recv = await s.accept_bi()
        send.reset(9)
        await recv.wait_readable()
        with pytest.raises(zmux.StreamResetError) as e:
            while recv.try_read() is not None:
                await asyncio.sleep(0)
        assert e.value.code == 9


async def test_try_read_gives_back_what_a_limited_read_put_back() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"0123456789")
        await send.finish()
        _, recv = await s.accept_bi()
        with pytest.raises(zmux.LimitExceededError):
            await recv.read_to_end(4)
        # What the limited read took goes back in front of the stream.
        assert recv.try_read(100) == b"01234"
        assert await recv.read_to_end() == b"56789"


async def test_wait_readable_then_try_read_is_a_read_that_loses_nothing() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        _, recv = await s.accept_bi()
        await recv.wait_readable()
        assert recv.try_read() == b"x"
        # Waits cancelled while nothing is readable take nothing ...
        for _ in range(3):
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.01):
                    await recv.wait_readable()
        # ... so the data that comes after them is all there for the read.
        await send.write(b"first")
        got = bytearray()
        async with asyncio.timeout(10):
            while bytes(got) != b"first":
                await recv.wait_readable()
                chunk = recv.try_read()
                if chunk:
                    got += chunk
        assert bytes(got) == b"first"


# ---- priorities ---------------------------------------------------------------------


def test_the_priority_defaults_have_names() -> None:
    assert zmux.Priority.LOCAL_DEFAULT == (3, True)
    assert zmux.Priority.WIRE_DEFAULT == (3, False)
    assert isinstance(zmux.Priority.LOCAL_DEFAULT, zmux.Priority)
    assert zmux.Priority.LOCAL_DEFAULT != zmux.Priority.WIRE_DEFAULT
    # No default without a name: the urgency is required.
    assert not hasattr(zmux.Priority, "DEFAULT")
    with pytest.raises(TypeError):
        zmux.Priority()  # type: ignore[call-arg]


async def test_a_new_sending_part_holds_the_local_default() -> None:
    async with pair() as (c, _s):
        send, recv = await c.open_bi()
        assert send.priority == zmux.Priority.LOCAL_DEFAULT
        assert recv.peer_priority is None
        send.priority = (1, False)
        assert send.priority == zmux.Priority(1, False)


async def test_the_peer_adjusts_the_priority_a_getter_reads() -> None:
    """The local priority is the last value set by the application or the peer."""
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        _, recv = await s.accept_bi()
        assert send.priority == zmux.Priority.LOCAL_DEFAULT
        recv.peer_priority = (0, False)
        await until(lambda: send.priority == zmux.Priority(0, False))
        send.priority = (5, True)
        assert send.priority == zmux.Priority(5, True)


# ---- getters ----------------------------------------------------------------------------


async def test_stream_getters_read_what_the_part_holds() -> None:
    async with pair() as (c, s):
        send, recv = await c.open_bi()
        # Following the session, or not requested: None.
        assert send.scheduler is None and send.redundant is None
        assert recv.peer_priority is None
        # A value copied from the configuration reads as the value it holds.
        assert send.send_buffer == zmux.Config().send_buffer
        # The session's initial window, and 0 for the automatic cap.
        assert recv.receive_window == (zmux.Config().initial_stream_receive_window, 0)
        send.scheduler = zmux.sched.Scheduler.SPREAD_ETA
        send.redundant = False
        assert send.scheduler is zmux.sched.Scheduler.SPREAD_ETA
        assert send.redundant is False
        # None goes back to following the session.
        send.scheduler = None
        send.redundant = None
        assert (send.scheduler, send.redundant) == (None, None)
        _ = s


async def test_getters_answer_after_the_session_ended_with_the_last_value() -> None:
    async with pair() as (c, s):
        send, recv = await c.open_bi()
        send.priority = (2, False)
        send.send_buffer = 1 << 16
        send.scheduler = zmux.sched.Scheduler.SPREAD_ETA
        send.redundant = True
        recv.peer_priority = (1, True)
        window, _ = recv.receive_window
        recv.receive_window = (window + 4096, window + 8192)
        c.scheduler = zmux.sched.Scheduler.SESSION_AFFINITY
        band = zmux.QualityBand(rtt=0.05)
        c.quality_band = band
        floor = zmux.CapacityFloor(rate=1000)
        c.capacity_floor = floor
        live = zmux.Liveness(probe_interval=3)
        c.liveness = live
        limits = zmux.shaping.ShapingLimits()
        c.shaping_limits = limits
        c.abort(0)
        await asyncio.gather(c.wait_closed(), s.wait_closed())
        # A getter never fails and never waits: it answers on an ended object.
        assert send.priority == zmux.Priority(2, False)
        assert send.send_buffer == 1 << 16
        assert send.scheduler is zmux.sched.Scheduler.SPREAD_ETA
        assert send.redundant is True
        assert recv.peer_priority == zmux.Priority(1, True)
        assert recv.receive_window == (window + 4096, window + 8192)
        assert c.scheduler is zmux.sched.Scheduler.SESSION_AFFINITY
        assert c.quality_band == band and c.capacity_floor == floor
        assert c.liveness == live and c.shaping_limits == limits


async def test_receive_window_assignment_rules() -> None:
    config = zmux.Config(
        initial_stream_receive_window=32 << 10, max_stream_receive_window=64 << 10
    )
    async with pair(config) as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        _, recv = await s.accept_bi()
        assert recv.receive_window == (32 << 10, 64 << 10)
        # A maximum of 0 is the automatic cap, not the previous or the session's.
        recv.receive_window = (48 << 10, 128 << 10)
        assert recv.receive_window == (48 << 10, 128 << 10)
        recv.receive_window = (48 << 10, 0)
        assert recv.receive_window == (48 << 10, 0)
        # A maximum equal to the initial window is valid.
        recv.receive_window = (64 << 10, 64 << 10)
        assert recv.receive_window == (64 << 10, 64 << 10)
        # A nonzero maximum below the initial window is invalid; nothing changes.
        for bad in ((128 << 10, 64 << 10), (1 << 20, 1)):
            with pytest.raises(zmux.InvalidArgumentError):
                recv.receive_window = bad
        assert recv.receive_window == (64 << 10, 64 << 10)
        # Credit is never withdrawn: a lower initial window only changes the
        # setting read back.
        recv.receive_window = (1 << 20, 0)
        recv.receive_window = (4096, 0)
        assert recv.receive_window == (4096, 0)
        assert recv.stats().recv_window >= 1 << 20
        # An initial window below 4 KiB is invalid and changes nothing.
        for low in (0, 4095):
            with pytest.raises(zmux.InvalidArgumentError):
                recv.receive_window = (low, 0)
        assert recv.receive_window == (4096, 0)


async def test_session_getters_read_unset_as_none() -> None:
    async with pair() as (c, _s):
        assert c.quality_band is None and c.capacity_floor is None
        assert c.scheduler is zmux.sched.Scheduler.SPREAD_ETA or c.scheduler
        assert isinstance(c.liveness, zmux.Liveness)
        assert isinstance(c.shaping_limits, zmux.shaping.ShapingLimits)
        c.quality_band = zmux.QualityBand(rate_ratio=2)
        c.quality_band = None
        assert c.quality_band is None


# ---- pipes ---------------------------------------------------------------------------------

POOL_CONFIG = zmux.Config(
    max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
)
LISTENER = zmux.ListenerConfig(instance_id=b"instance", max_suspended=16)


@contextlib.asynccontextmanager
async def multipath() -> AsyncIterator[tuple[zmux.Session, zmux.Session, Any]]:
    async with zmux.Listener(config=POOL_CONFIG, listener_config=LISTENER) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr, config=POOL_CONFIG) as client:
            server = await listener.accept()
            yield client, server, addr


async def test_pipe_options_read_back_what_was_given_and_the_join_fixed() -> None:
    async with multipath() as (client, _server, addr):
        band = zmux.QualityBand(rtt=0.05)
        given = zmux.PipeOptions(
            direction=zmux.Direction.BIDI,
            send_priority=1,
            receive_standby=True,
            weight=2,
            probation=None,
            liveness=zmux.PipeLiveness(dead_timeout=20.0),
            quality_band=band,
            label="b",
            fate_group=5,
            return_on_reply=True,
        )
        pipe = await client.add_pipe(await zmux.dial_tcp(*addr), options=given)
        await pipe.wait_attached()
        o = pipe.options
        # Given, field by field; what was left unset is inherit.
        assert (o.send_priority, o.receive_priority) == (1, zmux.INHERIT)
        assert (o.send_standby, o.receive_standby) == (zmux.INHERIT, True)
        assert (o.weight, o.probation) == (2, None)
        assert o.liveness == zmux.PipeLiveness(dead_timeout=20.0)
        assert o.quality_band == band
        assert (o.label, o.fate_group, o.return_on_reply) == ("b", 5, True)
        # Fixed at creation: the values the join used, never inherit.
        assert o.direction is zmux.Direction.BIDI
        assert o.record_mode is not zmux.INHERIT
        assert o.key_group is not zmux.INHERIT
        assert o.record_mode == pipe.options.record_mode

        # After an update it reads exactly what the update set or cleared.
        pipe.update(
            send_priority=zmux.CLEAR,
            weight=zmux.CLEAR,
            probation=zmux.AUTO,
            liveness=zmux.CLEAR,
            quality_band=zmux.CLEAR,
            receive_priority=4,
        )
        o = pipe.options
        assert (o.send_priority, o.receive_priority, o.weight) == (
            zmux.INHERIT,
            4,
            zmux.INHERIT,
        )
        assert o.probation is zmux.AUTO
        assert o.liveness is zmux.INHERIT and o.quality_band is zmux.INHERIT
        # Only an update clears; INHERIT is a PipeOptions value.
        with pytest.raises(TypeError):
            pipe.update(weight=zmux.INHERIT)  # type: ignore[arg-type]
        pipe.update(quality_band=None)
        assert pipe.options.quality_band is None

        # The options read from a pipe, given to add_pipe, add it the same way.
        again = await client.add_pipe(await zmux.dial_tcp(*addr), options=pipe.options)
        await again.wait_attached()
        assert again.options == dataclasses.replace(
            pipe.options, key_group=again.options.key_group
        )


async def test_a_pipe_the_peer_added_reads_as_the_join_made_it() -> None:
    async with multipath() as (client, server, addr):
        added = await client.add_pipe(
            await zmux.dial_tcp(*addr),
            options=zmux.PipeOptions(
                send_priority=2, label="mine", fate_group=3, weight=4
            ),
        )
        await added.wait_attached()
        await until(lambda: len(server.pipes()) == 2)
        mine = added.options
        theirs = next(p for p in server.pipes() if p.id == added.id).options
        # The handshake decides these, and both ends read the same facts.
        assert theirs.record_mode == mine.record_mode
        assert theirs.key_group == mine.key_group
        assert theirs.direction is zmux.Direction.BIDI
        # What only this endpoint can set (the tiers, the weight, the label,
        # the bands) is what a `PipeOptions` has by default, until an update
        # of this endpoint sets it.
        d = zmux.PipeOptions()
        for name in (
            "send_priority",
            "receive_priority",
            "send_standby",
            "receive_standby",
            "weight",
            "probation",
            "liveness",
            "quality_band",
            "label",
            "return_on_reply",
        ):
            assert getattr(theirs, name) == getattr(d, name), name
        assert theirs.send_priority is zmux.INHERIT and theirs.label is None


async def test_pipe_options_answer_after_the_pipe_ended() -> None:
    async with multipath() as (client, _server, addr):
        pipe = await client.add_pipe(
            await zmux.dial_tcp(*addr), options=zmux.PipeOptions(weight=3, label="x")
        )
        await pipe.wait_attached()
        before = pipe.options
        pipe.close()
        await asyncio.wait_for(pipe.wait_closed(), 10)
        await until(lambda: pipe.stats() is None)
        # Never fails: the options held last.
        assert pipe.options == before


async def test_a_pipe_this_endpoint_aborted_is_reported_as_aborted() -> None:
    """The end is stable: a wait registered before the abort, and one made
    after the session forgot the pipe, report the same aborted error."""
    async with multipath() as (client, _server, addr):
        pipe = await client.add_pipe(await zmux.dial_tcp(*addr))
        await pipe.wait_attached()
        waiting = asyncio.ensure_future(pipe.wait_closed())
        await asyncio.sleep(0)
        pipe.abort()
        with pytest.raises(zmux.PipeAbortedError) as e:
            await asyncio.wait_for(waiting, 10)
        assert isinstance(e.value, zmux.PipeError)
        assert not isinstance(e.value, zmux.PipeGoneError)
        assert e.value.kind == zmux.ErrorKind.FAILED
        await until(lambda: pipe.stats() is None)
        for _ in range(2):
            with pytest.raises(zmux.PipeAbortedError):
                await asyncio.wait_for(pipe.wait_closed(), 10)


async def test_a_pipe_closed_gracefully_reads_as_closed_to_a_late_wait() -> None:
    async with multipath() as (client, _server, addr):
        pipe = await client.add_pipe(await zmux.dial_tcp(*addr))
        await pipe.wait_attached()
        pipe.close()
        await asyncio.wait_for(pipe.wait_closed(), 10)
        await until(lambda: pipe.stats() is None)
        await asyncio.wait_for(pipe.wait_closed(), 10)


# ---- stream setting getters -------------------------------------------------------------------


async def test_stream_getters_answer_while_a_write_and_a_read_hold_the_parts() -> None:
    async with pair() as (c, _s):
        send, recv = await c.open_bi(priority=(5, False))
        # The peer reads nothing: the write never ends and holds its part.
        blocked = asyncio.ensure_future(send.write(b"x" * (16 << 20)))
        reading = asyncio.ensure_future(recv.read())
        await asyncio.sleep(0.05)
        assert not blocked.done() and not reading.done()
        assert send.priority == zmux.Priority(5, False)
        assert send.send_buffer > 0
        assert send.scheduler is None
        assert send.redundant is None
        assert recv.receive_window[0] > 0
        assert recv.peer_priority is None
        # The setters do not take the part: they work meanwhile, and the
        # getters read what they set.
        send.priority = (1, True)
        assert send.priority == zmux.Priority(1, True)
        send.send_buffer = 1 << 20
        assert send.send_buffer == 1 << 20
        send.scheduler = zmux.sched.Scheduler.SPREAD_ETA
        assert send.scheduler is zmux.sched.Scheduler.SPREAD_ETA
        send.redundant = True
        assert send.redundant is True
        send.redundant = None
        assert send.redundant is None
        window = recv.receive_window[0]
        recv.receive_window = (window + 8192, window + 16384)
        assert recv.receive_window == (window + 8192, window + 16384)
        assert not blocked.done() and not reading.done()
        for t in (blocked, reading):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t


async def test_a_receive_window_set_during_a_read_reaches_the_peer() -> None:
    async with pair() as (c, s):
        send, recv = await c.open_bi()
        await send.write(b"x")
        peer_send, _peer_recv = await s.accept_bi()
        initial = recv.receive_window[0]
        reading = asyncio.ensure_future(recv.read())
        await asyncio.sleep(0.05)
        assert not reading.done()
        # The read holds the part; the setter does not need it, and the
        # credit it advertises arrives at the peer's sending part.
        recv.receive_window = (initial + 8192, initial + 16384)
        async with asyncio.timeout(10):
            await peer_send.wait_send_capacity(initial + 8192)
        assert not reading.done()
        reading.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reading


async def test_stream_getters_keep_answering_once_the_part_was_taken() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"x")
        _, recv = await s.accept_bi()
        window = recv.receive_window
        recv.reject()
        assert recv.receive_window == window
        assert recv.peer_priority is None


# ---- pool policy ------------------------------------------------------------------------------


async def test_a_slow_decide_is_waited_for_and_not_rejected() -> None:
    """The pool's maintainer waits for the loop's answer without a bound: a
    `decide` that blocks the loop for a while is answered, not rejected."""
    rejected: list[BaseException] = []
    asked: list[int] = []

    class Slow:
        def decide(self, view: zmux.helpers.PoolView) -> zmux.helpers.PoolDecision:
            if not asked:
                time.sleep(0.4)
            asked.append(threading.get_ident())
            return zmux.helpers.PoolDecision(count=2, recheck=0.05)

    async with zmux.Listener(config=POOL_CONFIG, listener_config=LISTENER) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(*addr)

        async with await zmux.connect_tcp(*addr, config=POOL_CONFIG) as session:
            first = session.pipes()[0].id
            pool = zmux.helpers.PipePool(
                1, dial, policy=Slow(), decision_rejected=rejected.append
            )
            handle = session.maintain_pipes(pool)
            await until(
                lambda: len([s for s in session.pipe_stats() if s.pipe != first]) >= 2,
                10,
            )
            assert not rejected
            assert set(asked) == {threading.get_ident()}
            handle.stop()
            await until(lambda: handle.finished)


async def test_stuck_policies_hold_no_thread_and_stop_ends_the_wait() -> None:
    """A `decide` that never returns waits on its own pool's task: pools
    beyond the policy executor's threads, all stuck, leave another pool's
    policy answered, and stopping a pool cancels the call it waits for."""
    stuck = 6
    asked: list[int] = []
    cancelled: list[int] = []

    class Stuck:
        def __init__(self, n: int) -> None:
            self.n = n

        async def decide(
            self, view: zmux.helpers.PoolView
        ) -> zmux.helpers.PoolDecision:
            asked.append(self.n)
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.append(self.n)
                raise
            raise AssertionError("unreachable")

    async with contextlib.AsyncExitStack() as stack:
        listener = await stack.enter_async_context(
            zmux.Listener(config=POOL_CONFIG, listener_config=LISTENER)
        )
        addr = await listener.serve_tcp("127.0.0.1", 0)

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(*addr)

        handles = []
        for n in range(stuck):
            session = await stack.enter_async_context(
                await zmux.connect_tcp(*addr, config=POOL_CONFIG)
            )
            pool = zmux.helpers.PipePool(1, dial, policy=Stuck(n))
            handles.append(session.maintain_pipes(pool))
        await until(lambda: len(asked) == stuck, 10)

        # Another pool, on the policy executor's side, is still answered.
        other = await stack.enter_async_context(
            await zmux.connect_tcp(*addr, config=POOL_CONFIG)
        )
        first = other.pipes()[0].id
        pool = zmux.helpers.PipePool(
            1, dial, policy=zmux.helpers.MachinePoolPolicy({"count": 2})
        )
        handle = other.maintain_pipes(pool)

        def extra() -> bool:
            return len([p for p in other.pipe_stats() if p.pipe != first]) >= 2

        await until(extra, 10)
        handle.stop()

        # Stopping a pool ends its wait: the call on the loop is cancelled.
        for h in handles:
            h.stop()
        await until(lambda: sorted(cancelled) == list(range(stuck)), 10)
        for h in [handle, *handles]:
            async with asyncio.timeout(10):
                while not h.finished:
                    await asyncio.sleep(0.005)


# ---- the tracer backlog ------------------------------------------------------------------------


async def test_a_blocked_loop_costs_a_session_its_newest_events_and_never_the_end() -> (
    None
):
    """With delivery held the session's backlog of 256 events fills: the events
    that arrive are counted in the session's own `dropped`, told before the
    next event delivered, and `established` and `closed` still come."""
    seen: list[tuple[str, int, int]] = []
    logged: list[str] = []
    changes = 300
    entered = threading.Event()
    gate = threading.Event()

    class Log:
        def log(self, level: int, message: str) -> None:
            logged.append(message)

    class Trace(zmux.Tracer):
        def established(self, session: zmux.SessionId) -> None:
            seen.append(("established", session, 0))

        def event(self, session: zmux.SessionId, event: zmux.Event) -> None:
            if isinstance(event, zmux.PipePriorityChanged):
                seen.append(("change", session, 0))
                if not entered.is_set():
                    # Delivery stands in this call, on the loop, until the
                    # test opens the gate.
                    entered.set()
                    assert gate.wait(30)
            else:
                seen.append(("event", session, 0))

        def dropped(self, session: zmux.SessionId, count: int) -> None:
            seen.append(("dropped", session, count))

        def closed(self, session: zmux.SessionId, reason: BaseException) -> None:
            seen.append(("closed", session, 0))

    config = zmux.Config(
        max_pipes=8,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        tracer=Trace(),
        logger=Log(),
    )
    async with zmux.Listener(config=POOL_CONFIG, listener_config=LISTENER) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        client = await zmux.connect_tcp(*addr, config=config)
        server = await listener.accept()
        pipe = await client.add_pipe(await zmux.dial_tcp(*addr))
        await pipe.wait_attached()
        await until(lambda: ("established", client.id, 0) in seen)

        def produce() -> None:
            # The first change reaches the tracer, which holds delivery in its
            # call; the rest are produced while it does, then it is released.
            pipe.update(send_priority=3)
            assert entered.wait(30)
            for i in range(1, changes):
                pipe.update(send_priority=3 + i % 2)
            gate.set()

        try:
            await asyncio.to_thread(produce)
        finally:
            gate.set()
        # The tracer was told the change it held and, once delivery resumed, what
        # the backlog of 256 kept; the rest were lost in place. (Another event of
        # the session may take a backlog place too, so the count is a bound.)
        kept = 1 + 256
        # The next event accepted is told after the count of what was lost.
        pipe.update(send_priority=9)
        await until(lambda: any(k == "dropped" for k, _, _ in seen))
        at = next(i for i, (k, _, _) in enumerate(seen) if k == "dropped")
        told = [k for k, _, _ in seen[:at]].count("change")
        assert seen[at][1] == client.id
        assert told <= kept
        assert seen[at][2] >= changes - told
        await until(lambda: any(k == "change" for k, _, _ in seen[at + 1 :]))
        assert [k for k, _, _ in seen].count("dropped") == 1
        # The lost events are the tracer's: the logger is told nothing of them.
        assert not any("dropped" in m for m in logged)
        server.close()
        await until(lambda: ("closed", client.id, 0) in seen)
        # `closed` is the last call.
        assert seen[-1] == ("closed", client.id, 0)
        assert [k for k, _, _ in seen].count("closed") == 1
        server.abort(0)
        await server.wait_closed()


# ---- argument ranges -----------------------------------------------------------------------------


async def test_an_out_of_range_integer_argument_is_value_error() -> None:
    async with pair() as (c, _s):
        send, _recv = await c.open_bi()
        for bad in (-1, 2**64):
            with pytest.raises(ValueError):
                send.reset(bad)
            with pytest.raises(ValueError):
                c.close(bad)
        with pytest.raises(ValueError):
            send.priority = (256, False)
        with pytest.raises(ValueError):
            send.priority = (-1, False)


def test_a_quality_band_and_a_pool_decision_are_checked_by_the_core() -> None:
    for bad in (0.0, -1.0, 1e-10, math.nan):
        with pytest.raises(ValueError):
            zmux.QualityBand(rtt=bad)
    with pytest.raises(ValueError):
        zmux.QualityBand()
    for bad_count in (True, False, 0, -1, 1.5, "2"):
        with pytest.raises(ValueError):
            zmux.helpers.PoolDecision(count=bad_count)  # type: ignore[arg-type]
    assert zmux.helpers.PoolDecision(count=2).count == 2


async def test_a_stream_datagram_takes_any_buffer() -> None:
    async with pair(zmux.Config(enable_datagrams=True)) as (c, _s):
        send, _recv = await c.open_bi()
        for payload in (b"abc", bytearray(b"abc"), memoryview(b"abc")):
            send.send_datagram(payload)


async def test_log_lines_dropped_is_a_session_statistic() -> None:
    async with pair() as (c, _s):
        assert c.stats().log_lines_dropped == 0
