"""The stream, session and helper calls of the API and their statistics."""

import asyncio
import contextlib
import datetime
import math
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
import zmux


@contextlib.asynccontextmanager
async def pair(
    client: zmux.Config | None = None, server: zmux.Config | None = None
) -> AsyncIterator[tuple[zmux.Session, zmux.Session, zmux.Listener]]:
    """A connected session pair over TCP, and the server's listener."""
    async with zmux.Listener(server) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        c = await zmux.Session.connect(await zmux.dial_tcp(addr), client)
        s = await listener.accept()
        try:
            yield c, s, listener
        finally:
            c.close()
            s.close()


async def until(cond: Callable[[], object], limit: float = 5.0) -> None:
    async with asyncio.timeout(limit):
        while not cond():
            await asyncio.sleep(0.005)


def test_config_fields() -> None:
    c = zmux.Config(
        max_idle_timeout=datetime.timedelta(seconds=20),
        keep_alive_period=None,
        enable_datagrams=True,
        max_stream_receive_window=1 << 20,
        memory_budget=math.inf,
        max_incoming_uni_streams=0,
        send_buffer_max=1 << 22,
        max_pipes=4,
        pipe_headroom=2,
        replay_window=64,
        max_lanes=1,
        scheduler="spread-eta",
        spread_chunk=8192,
        overflow_delay=0.5,
        standby_probe=None,
        redundancy="off",
        pipe_auth=zmux.PipeAuth.exporter().with_psk(b"k" * 32),
        early_data=False,
        carrier_early_data=False,
        latency_budget=0.001,
    )
    assert c.replace(max_pipes=2).max_pipes == 2
    with pytest.raises(TypeError):
        zmux.Config(idle_timeout=5)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        zmux.Config(scheduler="fastest")  # type: ignore[arg-type]  # an invalid value on purpose
    with pytest.raises(ValueError):
        zmux.Config(redundancy="always")


async def test_keep_alive_and_standby_probe_values() -> None:
    # The timers and periods default to their values and take None for no
    # timeout or off; math.inf makes the budget unlimited, 0 is no byte.
    c = zmux.Config()
    assert (
        c.handshake_timeout,
        c.max_idle_timeout,
        c.keep_alive_period,
        c.standby_probe,
        c.probe_interval,
    ) == (
        10,
        30,
        15,
        1,
        15,
    )
    off: dict[str, Any] = {
        "handshake_timeout": None,
        "max_idle_timeout": None,
        "keep_alive_period": None,
        "memory_budget": math.inf,
        "standby_probe": None,
        "probe_interval": None,
    }
    async with pair(client=zmux.Config(**off)):
        pass
    async with pair(client=zmux.Config(keep_alive_period=1, memory_budget=0)):
        pass
    bad: dict[str, Any]
    for bad in (
        {"standby_probe": 0.5},
        {"standby_probe": 0},
        {"probe_interval": 0},
        {"max_idle_timeout": 0},
        {"max_idle_timeout": 0.0005},
        {"keep_alive_period": 0},
        {"keep_alive_period": 0.999},
        {"keep_alive_period": -1},
        {"standby_probe": -1},
        {"keep_alive_period": math.inf},
        {"handshake_timeout": math.inf},
        {"handshake_timeout": -math.inf},
        {"memory_budget": -1},
        {"memory_budget": 1.5},
    ):
        with pytest.raises((ValueError, zmux.ZmuxError)):
            async with pair(client=zmux.Config(**bad)):
                pass


def test_pipe_auth_is_immutable() -> None:
    a = zmux.PipeAuth.psk(b"k" * 32)
    b = a.with_psk(b"j" * 32)
    assert a != b and b == zmux.PipeAuth.psk(b"j" * 32)
    assert zmux.PipeAuth.exporter().with_psk(b"k" * 32) != a
    with pytest.raises(AttributeError):
        a._psk = None
    assert "kkkk" not in repr(a)


async def test_try_open_bi_without_credit_raises() -> None:
    async with pair(server=zmux.Config(max_incoming_streams=0)) as (c, _s, _l):
        await c.ping()
        with pytest.raises(zmux.OpenError):
            c.try_open_bi()
    async with pair() as (c, s, _l):
        send, _recv = c.try_open_bi(info=b"i", priority=(1, True))
        await send.write(b"x")
        _ss, sr = await s.accept_bi()
        assert sr.preamble.info == b"i" and not sr.preamble.pipe_carrier


async def test_chunks_without_copying() -> None:
    async with pair() as (c, s, _l):
        send, _recv = await c.open_bi()
        await send.write_chunk(bytearray(b"ab"))
        await send.write_chunk(memoryview(b"xcdx")[1:3])
        await send.finish()
        _ss, recv = await s.accept_bi()
        got = b""
        while True:
            chunk = await recv.read_chunk(3)
            assert isinstance(chunk, memoryview) and chunk.readonly and len(chunk) <= 3
            if not chunk:
                break
            got += chunk.tobytes()
        assert got == b"abcd"


async def test_send_capacity_and_stream_settings() -> None:
    small = zmux.Config(initial_stream_receive_window=4096)
    async with pair(server=small) as (c, s, _l):
        send, recv = await c.open_bi()
        await send.write(b"x")
        await c.ping()
        cap = send.send_capacity()
        assert 0 < cap <= 4096
        assert await asyncio.wait_for(send.wait_send_capacity(1), 5) >= 1
        send.set_send_buffer(1 << 16)
        send.set_scheduler("spread-round-robin")
        send.set_scheduler(None)
        with pytest.raises(ValueError):
            send.set_scheduler("fastest")  # type: ignore[arg-type]  # an invalid value on purpose
        send.set_redundant(True)
        send.set_redundant(False)
        # None follows the session's `redundancy` again.
        send.set_redundant(None)
        send.set_reliable_boundary()
        recv.set_receive_window(1 << 16, 1 << 20)
        recv.set_peer_priority(zmux.Priority(1, False))
        with pytest.raises(ValueError):
            await send.wait_send_capacity(0)
        # The peer's window bounds the capacity: 4096 minus what is unsent.
        _ss, sr = await s.accept_bi()
        assert await sr.read(1) == b"x"


async def test_stream_datagrams_and_their_counts() -> None:
    config = zmux.Config(enable_datagrams=True)
    async with pair(config, config) as (c, s, _l):
        send, _recv = await c.open_bi()
        await send.write(b"open")
        _ss, sr = await s.accept_bi()
        send.send_datagram(b"payload", context=3)
        assert await asyncio.wait_for(sr.read_datagram(), 5) == (3, b"payload")
        st = send.stats()
        assert (st.datagrams_sent, st.datagram_bytes_sent) == (1, 7)
        rt = sr.stats()
        assert (rt.datagrams_received, rt.datagram_bytes_received) == (1, 7)
        assert c.stats().datagram_bytes_sent == 7
        assert s.stats().datagram_bytes_received == 7


async def test_stream_and_session_byte_counts() -> None:
    async with pair() as (c, s, _l):
        send, recv = await c.open_bi()
        await send.write(b"hello")
        await send.finish()
        _ss, sr = await s.accept_bi()
        assert await sr.read_to_end() == b"hello"
        st = send.stats()
        assert isinstance(st, zmux.StreamStats)
        assert st.bytes_written == 5 and st.bytes_sent >= 5
        assert recv.stats() == st  # both parts: one snapshot of the stream
        rt = sr.stats()
        assert (rt.bytes_received, rt.bytes_read) == (5, 5)
        cs, ssn = c.stats(), s.stats()
        assert (cs.bytes_written, ssn.bytes_read) == (5, 5)
        assert cs.bytes_sent > cs.bytes_written and cs.records_sent > 0
        assert cs.mean_deviation is None or cs.mean_deviation >= 0


async def test_reject_and_final_stream_stats() -> None:
    async with pair() as (c, s, _l):
        send, recv = await c.open_bi()
        await send.write(b"abc")
        await send.finish()
        keep, sr = await s.accept_bi()
        await until(lambda: keep.stats().bytes_received == 3)
        sr.reject()
        with pytest.raises(zmux.StreamError):
            await sr.read()
        with pytest.raises(zmux.StreamError):
            sr.reject()
        await until(lambda: s.stats().streams_active == 0)
        # The session released the stream; the handle keeps its last values.
        assert keep.stats().bytes_received == 3
        with pytest.raises(zmux.StreamError):
            await recv.read_to_end()


async def test_pipe_and_listener_stats() -> None:
    async with pair() as (c, _s, listener):
        await c.ping()
        (st,) = c.pipe_stats()
        assert (
            st.pipe == 0
            and st.lanes == ()
            and isinstance(st.send_priority_source, zmux.PrioritySource)
        )
        assert st.bytes_sent > 0 and st.records_sent > 0 and st.request_seq == 0
        assert st.rtt_source is None or isinstance(st.rtt_source, zmux.RttSource)
        assert st.since_last_traffic is not None
        await asyncio.sleep(0.2)
        # Measured at the time of the snapshot.
        later = c.pipes()[0].stats()
        assert later is not None and later.since_last_traffic is not None
        assert later.since_last_traffic >= 0.2
        ls = listener.stats()
        assert isinstance(ls, zmux.ListenerStats)
        assert (ls.sessions, ls.joins, ls.rejected) == (1, 0, 0)
        # Each direction's state is of its own type.
        assert st.outbound is zmux.OutboundState.ACTIVE
        assert st.inbound is zmux.InboundState.OPEN
        pipe = c.pipes()[0]
        assert pipe.state is zmux.OutboundState.ACTIVE
        # The TCP adapter reports no unsent count: absent, as the delay.
        assert st.queued_bytes is None and st.queue_delay is None


def test_direction_states_follow_the_half() -> None:
    out = zmux._types._event(
        "PipeState", {"pipe": 2, "half": "Outbound", "state": "Failed", "failure": "x"}
    )
    assert (
        isinstance(out, zmux.PipeStateChanged)
        and out.state is zmux.OutboundState.FAILED
    )
    inb = zmux._types._event(
        "PipeState", {"pipe": 2, "half": "Inbound", "state": "Open", "failure": None}
    )
    assert (
        isinstance(inb, zmux.PipeStateChanged) and inb.state is zmux.InboundState.OPEN
    )
    assert "RETIRED" not in zmux.OutboundState.__members__
    assert "ACTIVE" not in zmux.InboundState.__members__


async def test_datagram_queue_sizes() -> None:
    zmux.Config(
        datagram_send_queue=8, datagram_stream_queue=4, datagram_receive_bytes=1 << 16
    )
    server = zmux.Config(enable_datagrams=True, datagram_receive_queue=2)
    async with pair(client=zmux.Config(enable_datagrams=True), server=server) as (
        c,
        s,
        _l,
    ):
        for i in range(3):
            c.send_datagram(bytes([i]))
        await until(lambda: s.stats().datagrams_dropped_recv == 1)
        # The receive queue keeps the newest two.
        assert await asyncio.wait_for(s.read_datagram(), 5) == b"\x01"
        assert await asyncio.wait_for(s.read_datagram(), 5) == b"\x02"
        assert s.stats().datagrams_dropped_recv == 1
    with pytest.raises(zmux.ZmuxError):
        async with pair(
            client=zmux.Config(enable_datagrams=True, datagram_send_queue=0)
        ):
            pass


async def test_quality_band_and_capacity_floor() -> None:
    async with pair() as (c, _s, _l):
        c.set_quality_band(
            zmux.QualityBand(
                rtt=0.05, rate_ratio=2.0, min_interval=datetime.timedelta(seconds=1)
            )
        )
        c.set_quality_band(None)
        c.set_capacity_floor(zmux.CapacityFloor(rate=1000))
        c.set_capacity_floor(None)
        with contextlib.suppress(zmux.PipeError):
            c.pipes()[0].set_quality_band(zmux.QualityBand(rtt=0.01))
        with pytest.raises(ValueError):
            c.set_quality_band(zmux.QualityBand(rtt=-1))
    for bad in (float("nan"), -1.0):
        with pytest.raises(ValueError):
            zmux.QualityBand(rate_ratio=bad)
        with pytest.raises(ValueError):
            zmux.CapacityFloor(rate=1, rate_ratio=bad)


async def test_nested_session_over_a_carrier_stream() -> None:
    async with pair() as (c, s, _l):

        async def inner_server() -> zmux.Session:
            send, recv = await s.accept_bi()
            assert recv.preamble.pipe_carrier
            assert recv.preamble.tlvs == (zmux.Tlv(0x1000, b"route"),)
            inner = await zmux.Session.accept(zmux.stream_pipe(send, recv))
            with pytest.raises(zmux.StreamError):
                send.stats()  # used up by stream_pipe
            a, b = await inner.accept_bi()
            await a.write(await b.read_to_end())
            await a.finish()
            return inner

        task = asyncio.create_task(inner_server())
        inner = await zmux.Session.connect(
            await c.open_pipe_stream([(0x1000, b"route")])
        )
        send, recv = await inner.open_bi()
        await send.write(b"nested")
        await send.finish()
        assert await recv.read_to_end() == b"nested"
        (await task).close()
        inner.close()


class Counting:
    """A limiter that allows everything and counts what it was charged."""

    def __init__(self) -> None:
        self.charged = 0
        self.waits = 0

    async def ready(self, min: int, max: int, /) -> int:
        self.waits += 1
        return max

    def try_ready(self, max: int, /) -> int:
        return max

    def charge(self, n: int, /) -> None:
        self.charged += n


async def test_splice_forwards_and_charges() -> None:
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):

        async def relay() -> tuple[zmux.Spliced, Counting]:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            limiter = Counting()
            with pytest.raises(ValueError):
                await zmux.splice(a, a)
            done = await zmux.splice(a, b, chunk=4096, a_to_b=limiter)
            return done, limiter

        async def echo() -> None:
            send, recv = await server.accept_bi()
            await send.write(await recv.read_to_end())
            await send.finish()

        tasks = asyncio.gather(relay(), echo())
        send, recv = await c.open_bi()
        await send.write(b"spliced" * 100)
        await send.finish()
        assert await recv.read_to_end() == b"spliced" * 100
        (done, limiter), _ = await asyncio.wait_for(tasks, 10)
        assert isinstance(done, zmux.Spliced)
        assert done.a_to_b.end is zmux.SpliceEnd.FINISHED and done.a_to_b.code is None
        assert done.a_to_b.bytes == 700 == limiter.charged
        assert done.b_to_a.bytes == 700


async def test_resolve_duplicate() -> None:
    async with zmux.Listener() as lx, zmux.Listener() as ly:
        ax, ay = await lx.serve_tcp("127.0.0.1:0"), await ly.serve_tcp("127.0.0.1:0")
        x1 = await zmux.Session.connect(await zmux.dial_tcp(ay))  # X dialed
        y1 = await ly.accept()
        y2 = await zmux.Session.connect(await zmux.dial_tcp(ax))  # Y dialed
        x2 = await lx.accept()
        with pytest.raises(ValueError):
            zmux.resolve_duplicate(x1, x2)  # nothing decides
        with pytest.raises(ValueError):
            zmux.resolve_duplicate(x1, x1, local_identity=b"x", peer_identity=b"y")
        r = zmux.resolve_duplicate(x1, x2, local_identity=b"x", peer_identity=b"y")
        assert isinstance(r, zmux.Resolved) and r.rule is zmux.DuplicateRule.IDENTITY
        assert not r.rejoin_started
        assert {r.survivor.role, r.loser.role} <= {
            zmux.Role.INITIATOR,
            zmux.Role.RESPONDER,
        }
        for sess in (x1, x2, y1, y2):
            sess.close()


def test_negative_durations_raise() -> None:
    for make in (
        lambda: zmux.Listener(handshake_timeout=-1),
        lambda: zmux.Listener(first_record_timeout=float("nan")),
        lambda: zmux.CarrierCache(success_ttl=-1),
        lambda: zmux.ExchangeOptions(idle_timeout=-1),
        lambda: zmux.Admission.prefix_auth(
            zmux.PrefixAuth(b"k" * 32, slot=30), skew=1, peek_timeout=-1
        ),
    ):
        with pytest.raises(ValueError):
            make()
