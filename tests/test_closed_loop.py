"""Hooks whose event loop closed answer at once instead of waiting for it,
and the next use from a running loop binds them to that loop."""

import asyncio

import pytest

import zmux
from support import LOOPBACK, CallbackSignal, until
from zmux._zmux import pipe_pair


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


def test_events_of_a_closed_loop_are_dropped_and_not_reported() -> None:
    seen: list[tuple[str, int]] = []
    notifications = CallbackSignal()

    class Trace(zmux.Tracer):
        def established(self, session: zmux.SessionId) -> None:
            seen.append(("established", session))
            notifications.notify()

        def dropped(self, session: zmux.SessionId, count: int) -> None:
            seen.append(("dropped", session))
            notifications.notify()

        def closed(self, session: zmux.SessionId, reason: BaseException) -> None:
            seen.append(("closed", session))
            notifications.notify()

    config = zmux.Config(tracer=Trace())
    li = zmux.Listener()
    held: dict[str, zmux.Session] = {}

    async def first() -> tuple[str, int]:
        address = await li.serve_tcp(LOOPBACK, 0)
        held["c"] = await zmux.connect_tcp(*address, config=config)
        held["s"] = await asyncio.wait_for(li.accept(), 5)
        await until(notifications, lambda: seen)
        return address

    addr = asyncio.run(first())
    c1 = held["c"].id
    assert seen == [("established", c1)]

    # The client's session ends with its loop closed: its `closed` is not
    # told, and nothing is reported later.
    held["s"].close()

    async def again() -> int:
        await held["s"].wait_closed()
        await held["c"].wait_closed()
        # `li` first: its use binds it to this loop.
        async with (
            li,
            await zmux.connect_tcp(*addr, config=config) as c,
            await asyncio.wait_for(li.accept(), 5),
        ):
            await until(notifications, lambda: ("established", c.id) in seen)
            return c.id

    asyncio.run(again())
    # Nothing of the first session was reported after its loop closed.
    assert [e for e in seen[1:] if e[1] == c1] == []
    assert all(k != "dropped" for k, _ in seen)


def test_hooks_outside_a_running_loop_say_so() -> None:
    pipe, _end = pipe_pair()

    async def layer(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return r, w

    with pytest.raises(zmux.NoRunningLoopError, match=r"PipeIo\.wrap"):
        coro = pipe.wrap(layer)
        coro.close()
