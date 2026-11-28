"""Test fixtures and synchronization for binding integration tests."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import (
    AbstractContextManager,
    asynccontextmanager,
    contextmanager,
    nullcontext,
    suppress,
)
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest

import zmux
from zmux import _zmux

WATCHDOG = 45
TEST_HOOKS = hasattr(_zmux, "_panic")
LOOPBACK = IPv4Address(0x7F00_0001)
Tls = tuple[zmux.TlsConfig, zmux.TlsConfig]
ORDERS = ("cancel-first", "complete-first")
# Leave Join control in flight without turning an injected clock jump into
# an unrelated liveness failure before the health observation windows end.
QUIET_LIVENESS = zmux.Liveness(
    keep_alive_period=None, probe_interval=None, standby_probe=None, suspect_floor=30
)


def read_shaping_fixture(path: Path) -> str:
    """Read a development fixture or skip when it is missing."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        pytest.skip(f"shaping fixture {path} is missing")


def manual_clock() -> _zmux._TestClock:
    """Returns a manually advanced native clock for integration scenarios."""
    if not TEST_HOOKS:
        pytest.skip("requires the test-hooks build")
    return _zmux._TestClock()


@asynccontextmanager
async def tcp_pair(
    client: zmux.Config | None = None,
    server: zmux.Config | None = None,
    max_record: int = 0,
) -> AsyncIterator[tuple[zmux.Session, zmux.Session, zmux.Listener]]:
    async with asyncio.timeout(WATCHDOG), zmux.Listener(config=server) as listener:
        addr = await listener.serve_tcp(LOOPBACK, 0)
        pipe = await zmux.dial_tcp(*addr)
        if max_record:
            pipe.set_max_record(max_record)
        c = await zmux.Session.connect(pipe, config=client)
        s: zmux.Session | None = None
        try:
            s = await listener.accept()
            yield c, s, listener
        finally:
            c.abort(0)
            if s is None:
                await c.wait_closed()
            else:
                s.abort(0)
                await asyncio.gather(c.wait_closed(), s.wait_closed())


@asynccontextmanager
async def session_pair(
    config: zmux.Config | None = None,
) -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    async with tcp_pair(config, config) as (client, server, _):
        yield client, server


class CallbackSignal:
    """Notify waiters on the event loop when a Python callback records an event."""

    def __init__(self) -> None:
        self._observers: set[asyncio.Event] = set()

    def notify(self) -> None:
        for observer in self._observers:
            observer.set()

    @contextmanager
    def observe(self) -> Iterator[Callable[[], Awaitable[None]]]:
        event = asyncio.Event()
        self._observers.add(event)

        async def changed() -> None:
            await event.wait()
            event.clear()

        try:
            yield changed
        finally:
            self._observers.remove(event)


async def until(
    source: zmux.Session | zmux.Listener | CallbackSignal, cond: Callable[[], object]
) -> None:
    """Check a predicate after each observed callback or native owner commit."""
    observation: AbstractContextManager[Callable[[], Awaitable[None]]]
    if isinstance(source, CallbackSignal):
        observation = source.observe()
    else:
        if not TEST_HOOKS:
            pytest.skip("requires the test-hooks build")
        observation = nullcontext(source._test_revision().changed)
    with observation as changed:
        async with asyncio.timeout(WATCHDOG):
            while not cond():
                await changed()


async def no_dial() -> zmux.PipeIo:
    raise AssertionError("unexpected dial")


async def echo(listener: zmux.Listener) -> None:
    async for session in listener:
        await echo_session(session)


async def echo_session(session: zmux.Session) -> None:
    async for send, recv in session:
        await send.write(await recv.read_to_end())
        await send.finish()


async def round_trip(
    session: zmux.Session, data: bytes = b"hello", **open_args: Any
) -> None:
    send, recv = await session.open_bi(**open_args)
    await send.write(data)
    await send.finish()
    assert await recv.read_to_end() == data


async def native_call[T](
    start: Callable[[], Awaitable[T]],
    *,
    on_create: Callable[[], None] | None = None,
    **notifications: Callable[..., None],
) -> T:
    """Intercept the first native future before Rust spawns the operation."""
    loop = asyncio.get_running_loop()
    owner = asyncio.current_task()
    original = loop.create_future
    saved = vars(loop).get("create_future")

    def restore() -> None:
        if loop.create_future is capture:
            if saved is None:
                delattr(loop, "create_future")
            else:
                vars(loop)["create_future"] = saved

    def capture() -> asyncio.Future[Any]:
        target = original()
        if asyncio.current_task() is owner:
            restore()
            for name, callback in notifications.items():
                setattr(target, name, callback)
            if on_create is not None:
                on_create()
        return target

    vars(loop)["create_future"] = capture
    try:
        return await start()
    finally:
        restore()


async def start_pending[T](start: Callable[[], Awaitable[T]]) -> asyncio.Task[T]:
    """Start a native operation and wait until Rust has polled it as pending."""
    if not TEST_HOOKS:
        pytest.skip("requires the test-hooks build")
    loop = asyncio.get_running_loop()
    pending: asyncio.Future[None] = loop.create_future()

    def notify() -> None:
        if not pending.done():
            pending.set_result(None)

    task = asyncio.create_task(native_call(start, _zmux_test_pending=notify))
    try:
        async with asyncio.timeout(WATCHDOG):
            await asyncio.wait((pending, task), return_when=asyncio.FIRST_COMPLETED)
        if not pending.done():
            task.result()
            raise AssertionError("native operation completed before pending")
    except BaseException:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise
    finally:
        pending.cancel()
    return task


async def cancelled_as_it_completes(
    start: Callable[[], Awaitable[Any]],
    order: str,
    waiter: Callable[[], Awaitable[Any]] | None = None,
    *,
    on_pending: Callable[[], Awaitable[Any]] | None = None,
) -> asyncio.Task[Any] | None:
    """Cancel on either side of delivery, with an optional waiting receiver."""
    if not TEST_HOOKS:
        pytest.skip("requires the test-hooks build")
    loop = asyncio.get_running_loop()
    arrived: asyncio.Future[Callable[[], None]] = loop.create_future()
    pending: asyncio.Future[None] = loop.create_future()

    def hold(complete: Callable[[], None]) -> None:
        if not arrived.done():
            arrived.set_result(complete)

    def notify() -> None:
        if not pending.done():
            pending.set_result(None)

    task = asyncio.create_task(
        native_call(start, _zmux_test_complete=hold, _zmux_test_pending=notify)
    )
    blocked: asyncio.Task[Any] | None = None
    try:
        async with asyncio.timeout(WATCHDOG):
            if on_pending is not None:
                await pending
                await on_pending()
            deliver = await arrived
            if waiter is not None:
                blocked = await start_pending(waiter)
            if order == "cancel-first":
                task.cancel()
                deliver()
            else:
                deliver()
                task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        assert task.cancelled()
    except BaseException:
        for unfinished in (task, blocked):
            if unfinished is not None:
                unfinished.cancel()
                await asyncio.gather(unfinished, return_exceptions=True)
        raise
    finally:
        pending.cancel()
        arrived.cancel()
    return blocked
