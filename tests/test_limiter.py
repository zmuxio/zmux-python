"""The limiter contract of the splice helpers: reserve, then refund."""

import asyncio
import contextlib

import pytest
import zmux
from zmux.helpers import SendPolicy, Sent, SpliceEnd

from test_api import pair, until
from test_packet import DGRAM, accept_packets


class Recording:
    """Grants what is asked (or `grant(min, max)`), records every call and
    counts what it granted and got back."""

    def __init__(self, grant: object = None) -> None:
        self.calls: list[tuple[str, int, int]] = []
        self.granted = 0
        self.refunded = 0
        self.grant = grant

    def _grant(self, lo: int, hi: int) -> int:
        n = hi if self.grant is None else self.grant(lo, hi)  # type: ignore[operator]
        if isinstance(n, int) and 0 < n <= hi:
            self.granted += n
        return n

    async def acquire(self, lo: int, hi: int, /) -> int:
        self.calls.append(("acquire", lo, hi))
        return self._grant(lo, hi)

    def try_acquire(self, lo: int, hi: int, /) -> int:
        self.calls.append(("try_acquire", lo, hi))
        return self._grant(lo, hi)

    def refund(self, n: int, /) -> None:
        self.calls.append(("refund", n, n))
        self.refunded += n

    @property
    def used(self) -> int:
        return self.granted - self.refunded


async def relay_one(
    limiter: object, payload: bytes, chunk: int = 256, packets: bool = False
) -> zmux.helpers.SpliceResult:
    """Sends `payload` through a splice limited by `limiter` from client to
    server; the server answers with nothing."""
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):

        async def relay() -> zmux.helpers.SpliceResult:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            await b[0].flush()  # the server sees the stream before any reset
            f = zmux.helpers.splice_packets if packets else zmux.helpers.splice
            return await f(a, b, chunk=chunk, a_to_b=limiter)  # type: ignore[arg-type]

        async def sink() -> bytes:
            send, recv = await server.accept_bi()
            try:
                return await recv.read_to_end()
            finally:
                await send.finish()

        tasks = asyncio.gather(relay(), sink(), return_exceptions=True)
        send, recv = await c.open_bi()
        await send.write(payload)
        await send.finish()
        with contextlib.suppress(zmux.ZmuxError):
            await asyncio.wait_for(recv.read_to_end(), 10)
        done, got = await asyncio.wait_for(tasks, 10)
        assert isinstance(done, zmux.helpers.SpliceResult)
        if done.a_to_b.end is SpliceEnd.FINISHED:
            assert got == payload
        return done


def assert_clamped(calls: list[tuple[str, int, int]], chunk: int) -> None:
    for kind, lo, hi in calls:
        if kind != "refund":
            assert 1 <= lo <= hi <= chunk, (kind, lo, hi)
        else:
            assert lo > 0


async def test_stream_splice_reserves_and_refunds() -> None:
    lim = Recording()
    done = await relay_one(lim, b"x" * 3000, chunk=256)
    assert done.a_to_b.end is SpliceEnd.FINISHED and done.a_to_b.bytes == 3000
    assert_clamped(lim.calls, 256)
    assert {k for k, _, _ in lim.calls} >= {"acquire"}
    await until(lambda: lim.used == 3000)


async def test_packet_splice_takes_each_capsule_whole() -> None:
    lim = Recording()
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):

        async def relay() -> zmux.helpers.SpliceResult:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice_packets(a, b, chunk=1024, a_to_b=lim)

        task = asyncio.ensure_future(relay())
        p = await c.open_packet_stream(policy=SendPolicy.STREAM_ONLY)
        for i in range(4):
            assert await p.send(bytes([i]) * 10) is Sent.CAPSULE
        await p.close()
        q = await asyncio.wait_for(accept_packets(server), 5)
        assert [x.payload async for x in q] == [bytes([i]) * 10 for i in range(4)]
        await q.close()
        assert await asyncio.wait_for(p.recv(), 5) is None
        done = await asyncio.wait_for(task, 10)
    assert done.a_to_b.end is SpliceEnd.FINISHED
    asks = [(lo, hi) for k, lo, hi in lim.calls if k == "acquire"]
    # Type (1) + Length (1) + Context ID (1) + 10 payload bytes.
    assert asks.count((13, 13)) == 4
    assert_clamped(lim.calls, 1024)


async def test_burst_grant_below_min_still_forwards_the_capsule() -> None:
    lim = Recording(grant=lambda lo, hi: 1)
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):

        async def relay() -> zmux.helpers.SpliceResult:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice_packets(a, b, a_to_b=lim)

        task = asyncio.ensure_future(relay())
        p = await c.open_packet_stream(policy=SendPolicy.STREAM_ONLY)
        assert await p.send(b"whole capsule") is Sent.CAPSULE
        await p.close()
        q = await asyncio.wait_for(accept_packets(server), 5)
        assert [x.payload async for x in q] == [b"whole capsule"]
        await q.close()
        assert await asyncio.wait_for(p.recv(), 5) is None
        done = await asyncio.wait_for(task, 10)
    assert done.a_to_b.end is SpliceEnd.FINISHED


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
@pytest.mark.parametrize("bad", [0, "over", -1, "text"])
async def test_invalid_acquire_grant_fails_the_direction(bad: object) -> None:
    lim = Recording(grant=lambda lo, hi: hi + 1 if bad == "over" else bad)
    done = await relay_one(lim, b"y" * 100)
    assert done.a_to_b.end is SpliceEnd.LIMITER_FAILED
    assert done.a_to_b.bytes == 0 and done.a_to_b.code is None
    if bad == "over":
        # The grant above max was taken back at once.
        await until(lambda: lim.refunded > 0)


class Raising(Recording):
    def __init__(self, where: str) -> None:
        super().__init__()
        self.where = where

    async def acquire(self, lo: int, hi: int, /) -> int:
        if self.where == "acquire":
            raise RuntimeError("budget exhausted")
        return await super().acquire(lo, hi)

    def try_acquire(self, lo: int, hi: int, /) -> int:
        if self.where == "try_acquire":
            raise RuntimeError("no")
        return super().try_acquire(lo, hi)

    def refund(self, n: int, /) -> None:
        super().refund(n)
        if self.where == "refund":
            raise RuntimeError("ignored")


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_raising_acquire_fails_the_direction() -> None:
    done = await relay_one(Raising("acquire"), b"z" * 100)
    assert done.a_to_b.end is SpliceEnd.LIMITER_FAILED and done.a_to_b.bytes == 0


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_raising_refund_is_ignored() -> None:
    # Large grants leave something to refund after each chunk.
    lim = Raising("refund")
    done = await relay_one(lim, b"r" * 2000, chunk=4096)
    assert done.a_to_b.end is SpliceEnd.FINISHED and done.a_to_b.bytes == 2000


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_raising_try_acquire_grants_nothing() -> None:
    lim = Raising("try_acquire")
    async with (
        pair(DGRAM, DGRAM) as (c, relay_in, _l1),
        pair(DGRAM, DGRAM) as (relay_out, server, _l2),
    ):

        async def relay() -> zmux.helpers.SpliceResult:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice_packets(a, b, a_to_b=lim)

        task = asyncio.ensure_future(relay())
        p = await c.open_packet_stream()
        for _ in range(3):
            assert await p.send(b"dgram") is Sent.DATAGRAM
            await asyncio.sleep(0.05)
        await p.close()
        q = await asyncio.wait_for(accept_packets(server), 5)
        assert [x async for x in q] == []
        await q.close()
        assert await asyncio.wait_for(p.recv(), 5) is None
        done = await asyncio.wait_for(task, 10)
    f = done.a_to_b
    assert f.end is SpliceEnd.FINISHED
    assert f.datagrams_limited == 3 == f.datagrams_dropped
    assert all(lo == hi == 6 for k, lo, hi in lim.calls if k == "try_acquire")


class Budget:
    """A shared budget of `left` bytes: grants only what is left, waits
    for a top-up when nothing is."""

    def __init__(self, left: int) -> None:
        self.left = left
        self.granted = 0
        self.refunded = 0
        self.waiting = 0
        self._more = asyncio.Event()

    def _take(self, lo: int, hi: int) -> int:
        if self.left < lo:
            return 0
        n = min(self.left, hi)
        self.left -= n
        self.granted += n
        return n

    async def acquire(self, lo: int, hi: int, /) -> int:
        while (n := self._take(lo, hi)) == 0:
            self._more.clear()
            self.waiting += 1
            try:
                await self._more.wait()
            finally:
                self.waiting -= 1
        return n

    def try_acquire(self, lo: int, hi: int, /) -> int:
        return self._take(lo, hi)

    def refund(self, n: int, /) -> None:
        self.refunded += n
        self.add(n)

    def add(self, n: int) -> None:
        self.left += n
        self._more.set()


async def test_shared_limiter_never_over_grants() -> None:
    budget = Budget(1500)
    received = [0, 0]
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):

        async def relay() -> zmux.helpers.SpliceResult:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice(a, b, chunk=128, a_to_b=budget)

        async def sink(i: int) -> None:
            send, recv = await server.accept_bi()
            while data := await recv.read(4096):
                received[i] += len(data)
            await send.finish()

        relays = [asyncio.ensure_future(relay()) for _ in range(2)]
        sinks = [asyncio.ensure_future(sink(i)) for i in range(2)]
        streams = [await c.open_bi() for _ in range(2)]
        for send, _ in streams:
            await send.write(b"s" * 1000)
            await send.finish()
        await until(lambda: budget.waiting > 0 and budget.left == 0)
        await asyncio.sleep(0.2)
        assert sum(received) <= budget.granted - budget.refunded <= 1500
        budget.add(500)
        for _, recv in streams:
            assert await asyncio.wait_for(recv.read_to_end(), 10) == b""
        done = await asyncio.wait_for(asyncio.gather(*relays), 10)
        await asyncio.wait_for(asyncio.gather(*sinks), 10)
    assert received == [1000, 1000]
    assert sum(d.a_to_b.bytes for d in done) == 2000
    await until(lambda: budget.granted - budget.refunded == 2000)
