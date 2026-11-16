"""Hooks whose event loop closed answer at once instead of waiting for it,
and the next use from a running loop binds them to that loop."""

import asyncio
from collections.abc import Callable

import pytest

import zmux
from zmux._zmux import pipe_pair


async def until(cond: Callable[[], object], limit: float = 5.0) -> None:
    async with asyncio.timeout(limit):
        while not cond():
            await asyncio.sleep(0.005)


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_a_decider_of_a_closed_loop_refuses_at_once() -> None:
    calls: list[zmux.SessionCarrier] = []

    def session_config(carrier: zmux.SessionCarrier) -> zmux.Config | None:
        calls.append(carrier)
        return None

    li = zmux.Listener(
        listener_config=zmux.ListenerConfig(
            session_config=session_config, handshake_timeout=30
        )
    )

    async def serve() -> tuple[str, int]:
        return await li.serve_tcp("127.0.0.1", 0)

    # Binds the listener's hooks to this loop, which closes on return.
    addr = asyncio.run(serve())

    async def refused() -> None:
        pipe = await zmux.dial_tcp(*addr)
        with pytest.raises(zmux.ZmuxError):
            async with asyncio.timeout(5):
                await zmux.Session.connect(
                    pipe, config=zmux.Config(handshake_timeout=20)
                )

    asyncio.run(refused())
    assert calls == []

    async def rebound() -> None:
        async with li:
            async with asyncio.timeout(5):
                async with (
                    await zmux.connect_tcp(*addr) as _c,
                    await li.accept() as _s,
                ):
                    pass

    asyncio.run(rebound())
    assert len(calls) == 1


def test_events_of_a_closed_loop_are_dropped_and_counted() -> None:
    seen: list[tuple[str, int | None, int]] = []

    class Trace(zmux.Tracer):
        def established(self, session: int) -> None:
            seen.append(("established", session, 0))

        def dropped(self, session: int | None, count: int) -> None:
            seen.append(("dropped", session, count))

        def closed(self, session: int, reason: BaseException) -> None:
            seen.append(("closed", session, 0))

    config = zmux.Config(tracer=Trace())
    li = zmux.Listener()
    held: dict[str, zmux.Session] = {}

    async def first() -> tuple[str, int]:
        addr = await li.serve_tcp("127.0.0.1", 0)
        held["c"] = await zmux.connect_tcp(*addr, config=config)
        held["s"] = await asyncio.wait_for(li.accept(), 5)
        await until(lambda: seen)
        return addr

    addr = asyncio.run(first())
    c1 = held["c"].id
    assert seen == [("established", c1, 0)]

    async def close() -> None:
        held["s"].close()
        await asyncio.wait_for(held["c"].wait_closed(), 5)

    # The client's close is traced with its loop closed.
    asyncio.run(close())

    async def again() -> int:
        # `li` first: its use binds it to this loop.
        async with (
            li,
            await zmux.connect_tcp(*addr, config=config) as c,
            await asyncio.wait_for(li.accept(), 5),
        ):
            await until(lambda: ("established", c.id, 0) in seen)
            return c.id

    c2 = asyncio.run(again())
    rest = seen[1 : seen.index(("established", c2, 0))]
    # The close reached the closed loop and was counted, or (should the
    # next loop bind before it was read) delivered there.
    assert rest in ([("dropped", None, 1)], [("closed", c1, 0)])


def test_min_recheck() -> None:
    assert zmux.helpers.MIN_RECHECK == 0.01
    # As in the crate: shorter is lengthened by the pool, not refused.
    assert zmux.helpers.PoolPolicyDecision(recheck=0).recheck == 0


def test_hooks_outside_a_running_loop_say_so() -> None:
    pipe, _end = pipe_pair()

    async def layer(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return r, w

    with pytest.raises(zmux.NoRunningLoopError, match=r"PipeIo\.wrap"):
        coro = pipe.wrap(layer)
        coro.close()
