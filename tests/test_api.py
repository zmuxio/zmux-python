"""The stream, session and helper calls of the API and their statistics."""

import asyncio
import threading
import contextlib
import dataclasses
import datetime
import math
from collections.abc import AsyncIterator, Callable
from typing import Any, cast

import pytest
import zmux


@contextlib.asynccontextmanager
async def pair(
    client: zmux.Config | None = None,
    server: zmux.Config | None = None,
    max_record: int = 0,
) -> AsyncIterator[tuple[zmux.Session, zmux.Session, zmux.Listener]]:
    """A connected session pair over TCP, and the server's listener; the
    client's carrier takes records of at most `max_record` (0: the
    default)."""
    async with zmux.Listener(config=server) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        pipe = await zmux.dial_tcp(*addr)
        pipe.set_max_record(max_record)
        c = await zmux.Session.connect(pipe, config=client)
        s = await listener.accept()
        try:
            yield c, s, listener
        finally:
            c.abort(0)
            s.abort(0)
            await asyncio.gather(c.wait_closed(), s.wait_closed())


async def until(cond: Callable[[], object], limit: float = 5.0) -> None:
    async with asyncio.timeout(limit):
        while not cond():
            await asyncio.sleep(0.005)


def test_config_fields() -> None:
    c = zmux.Config(
        max_idle_timeout=20,
        liveness=zmux.Liveness(keep_alive_period=None, standby_probe=None),
        enable_datagrams=True,
        max_stream_receive_window=1 << 20,
        memory_budget=None,
        max_incoming_uni_streams=0,
        send_buffer_max=1 << 22,
        max_pipes=4,
        pipe_headroom=2,
        replay_window=64,
        max_lanes=1,
        scheduler="spread-eta",
        spread_chunk=8192,
        overflow_delay=0.5,
        redundancy="off",
        pipe_auth=zmux.PipeAuth.exporter().with_psk(b"k" * 32),
        early_data=False,
        carrier_early_data=False,
        latency_budget=0.001,
    )
    assert c.replace(max_pipes=2).max_pipes == 2
    assert c.memory_budget is None and c.liveness.keep_alive_period is None
    with pytest.raises(TypeError):
        zmux.Config(idle_timeout=5)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        zmux.Config(scheduler="fastest")
    with pytest.raises(ValueError):
        zmux.Config(redundancy="always")


async def test_keep_alive_and_standby_probe_values() -> None:
    # The timers default to their values; None is no timeout, off or
    # unlimited where the field has such a setting and ValueError elsewhere.
    c = zmux.Config()
    assert (c.handshake_timeout, c.max_idle_timeout) == (10, 30)
    lv = c.liveness
    assert (lv.keep_alive_period, lv.standby_probe, lv.probe_interval) == (15, 1, 15)
    assert lv.dead_timeout is zmux.AUTO
    assert c.max_stream_receive_window is zmux.AUTO
    assert c.max_incoming_uni_streams is zmux.STAGED
    off: dict[str, Any] = {
        "handshake_timeout": None,
        "max_idle_timeout": None,
        "memory_budget": None,
        "liveness": zmux.Liveness(
            keep_alive_period=None, standby_probe=None, probe_interval=None
        ),
    }
    async with pair(client=zmux.Config(**off)):
        pass
    async with pair(
        client=zmux.Config(liveness=zmux.Liveness(keep_alive_period=1), memory_budget=0)
    ):
        pass
    bad: dict[str, Any]
    for bad in (
        {"liveness": zmux.Liveness(standby_probe=0.5)},
        {"liveness": zmux.Liveness(standby_probe=0)},
        {"liveness": zmux.Liveness(probe_interval=0)},
        {"liveness": zmux.Liveness(keep_alive_period=0)},
        {"liveness": zmux.Liveness(keep_alive_period=0.999)},
        {"liveness": zmux.Liveness(keep_alive_period=-1)},
        {"liveness": zmux.Liveness(standby_probe=-1)},
        {"liveness": zmux.Liveness(keep_alive_period=math.inf)},
        {"max_idle_timeout": 0},
        {"max_idle_timeout": 0.0005},
        {"handshake_timeout": math.inf},
        {"handshake_timeout": -math.inf},
        {"memory_budget": -1},
        {"memory_budget": 1.5},
    ):
        with pytest.raises((ValueError, zmux.ZmuxError)):
            async with pair(client=zmux.Config(**bad)):
                pass


def test_none_only_where_a_field_has_an_off_setting() -> None:
    for field in ("join_timeout", "max_pipes", "latency_budget", "scheduler"):
        with pytest.raises(ValueError):
            zmux.Config(**cast("dict[str, Any]", {field: None}))
    zmux.Config(join_early_hello=None, resume_timeout=None, probation=None)
    zmux.Config(probation=zmux.AUTO)
    with pytest.raises((TypeError, ValueError)):
        zmux.Config(max_idle_timeout=datetime.timedelta(seconds=20))  # type: ignore[arg-type]  # removed on purpose
    # The removed fields moved into `liveness`.
    for gone in (
        "keep_alive_period",
        "standby_probe",
        "probe_interval",
        "dead_timeout",
    ):
        with pytest.raises(TypeError):
            zmux.Config(**cast("dict[str, Any]", {gone: 1}))


async def test_listener_set_limits() -> None:
    lc = zmux.ListenerConfig(
        limits=zmux.ListenerLimits(max_suspended=3, max_pending=None)
    )
    async with zmux.Listener(listener_config=lc) as listener:
        lim = listener.limits()
        assert lim == zmux.ListenerLimits(max_suspended=3, max_pending=None)
        with pytest.raises(zmux.InvalidArgumentError):
            listener.set_limits(dataclasses.replace(lim, max_pending_per_source=1))
        assert listener.limits() == lim
        new = dataclasses.replace(
            lim, max_pending=7, first_record_timeout=0.5, memory_budget=None
        )
        listener.set_limits(new)
        assert listener.limits() == new


async def test_hold_first_flight() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        c = await zmux.Session.connect(
            await zmux.dial_tcp(*addr),
            config=zmux.Config(early_data=True, hold_first_flight=True),
        )
        send, _recv = await c.open_bi()
        await send.write(b"first flight")
        await asyncio.wait_for(send.flush(), 1)
        accepted = asyncio.ensure_future(listener.accept())
        await asyncio.sleep(0.05)
        assert not accepted.done()
        assert c.stats().bytes_sent == 0
        c.release_first_flight()
        c.release_first_flight()
        s = await asyncio.wait_for(accepted, 5)
        _send, recv = await s.accept_bi()
        assert await recv.read_exact(12) == b"first flight"
        assert c.stats().first_flight_timeouts == 0
        c.abort(0)
        s.abort(0)
        await asyncio.gather(c.wait_closed(), s.wait_closed())


async def test_hold_first_flight_needs_client_early_data() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        with pytest.raises(Exception, match="hold_first_flight"):
            await zmux.Session.connect(
                await zmux.dial_tcp(*addr), config=zmux.Config(hold_first_flight=True)
            )


def test_pipe_auth_is_immutable() -> None:
    a = zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    b = a.with_psk(b"j" * 32)
    assert a != b and b == zmux.PipeAuth.psk(b"j" * 32).with_end_to_end()
    assert zmux.PipeAuth.exporter().with_psk(b"k" * 32) != a
    with pytest.raises(AttributeError):
        a._psk = None
    assert "kkkk" not in repr(a)


async def test_try_open_bi_without_credit_raises() -> None:
    async with pair(server=zmux.Config(max_incoming_streams=0)) as (c, _s, _l):
        await c.ping()
        with pytest.raises(zmux.StreamError) as blocked:
            c.try_open_bi()
        assert blocked.value.kind == zmux.ErrorKind.BLOCKED and blocked.value.retryable
    async with pair() as (c, s, _l):
        send, _recv = c.try_open_bi(info=b"i", priority=(1, True))
        await send.write(b"x")
        _ss, sr = await s.accept_bi()
        assert sr.preamble.info == b"i" and not sr.preamble.pipe_carrier


async def test_chunks_without_copying() -> None:
    async with pair() as (c, s, _l):
        send, _recv = await c.open_bi()
        await send.write(bytearray(b"ab"))
        await send.write(memoryview(b"xcdx")[1:3])
        await send.finish()
        _ss, recv = await s.accept_bi()
        got = b""
        while True:
            chunk = await recv.read_chunk(n=3)
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
        assert await asyncio.wait_for(send.wait_send_capacity(minimum=1), 5) >= 1
        send.send_buffer = 1 << 16
        send.scheduler = "spread-round-robin"
        send.scheduler = None
        with pytest.raises(ValueError):
            send.scheduler = "fastest"
        send.redundant = True
        send.redundant = False
        # None follows the session's `redundancy` again.
        send.redundant = None
        send.set_reliable_boundary()
        recv.receive_window = (1 << 16, 1 << 20)
        recv.peer_priority = zmux.Priority(1, False)
        with pytest.raises(ValueError):
            await send.wait_send_capacity(minimum=0)
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


def test_pipe_state_events_are_six_kinds() -> None:
    failed = zmux._types._event(
        "PipeFailed", {"pipe": 2, "failure": "x", "carrier": "websocket"}
    )
    assert failed == zmux.PipeFailed(zmux.PipeId(2), "x", zmux.CarrierKind.WEBSOCKET)
    assert failed.kind is zmux.EventKind.PIPE_FAILED
    closed = zmux._types._event("PipeClosed", {"pipe": 2, "half": "Inbound"})
    assert closed == zmux.PipeClosed(zmux.PipeId(2), zmux.PipeHalf.INBOUND)
    for kind, cls in (
        ("PipeAdded", zmux.PipeAdded),
        ("PipeJoined", zmux.PipeJoined),
        ("PipeSuspect", zmux.PipeSuspect),
        ("PipeRecovered", zmux.PipeRecovered),
    ):
        assert zmux._types._event(kind, {"pipe": 4}) == cls(zmux.PipeId(4))
    goaway = zmux._types._event(
        "GoAwayReceived", {"max_bidi": 1, "max_uni": 2, "code": 3}
    )
    assert goaway == zmux.GoAwayReceived(1, 2, 3)
    assert "RETIRED" not in zmux.OutboundState.__members__
    assert "ACTIVE" not in zmux.InboundState.__members__


async def test_negotiation_results() -> None:
    async with pair(client=zmux.Config(enable_datagrams=True)) as (c, s, _l):
        assert c.is_established and s.is_established
        assert c.qmux_version == "draft-02"
        assert c.tls is None
        assert c.datagram_support == zmux.Support(local=True, peer=False)
        assert s.datagram_support == zmux.Support(local=False, peer=True)
        assert isinstance(c.reset_stream_at_support, zmux.Support)
        assert c.multipath is zmux.Multipath.OFF
        assert not c.resume_in_use and isinstance(c.pipe_ack_in_use, bool)
        assert c.goaway is None
        send, _recv = await c.open_bi()
        assert send.max_datagram_size() is None
        closing = asyncio.ensure_future(c.shutdown())
        await until(lambda: s.goaway is not None)
        assert isinstance(s.goaway, zmux.GoAwayReceived)
        closing.cancel()
        with contextlib.suppress(asyncio.CancelledError, zmux.ZmuxError):
            await closing


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
    with pytest.raises(ValueError):
        async with pair(
            client=zmux.Config(enable_datagrams=True, datagram_send_queue=0)
        ):
            pass


async def test_quality_band_and_capacity_floor() -> None:
    async with pair() as (c, _s, _l):
        band = zmux.QualityBand(rtt=0.05, rate_ratio=2.0, min_interval=1.0)
        c.quality_band = band
        assert c.quality_band == band
        c.quality_band = None
        c.capacity_floor = zmux.CapacityFloor(rate=1000)
        c.capacity_floor = None
        with contextlib.suppress(zmux.NotNegotiatedError):
            c.pipes()[0].update(quality_band=zmux.QualityBand(rtt=0.01))
    # `min_interval=None` is no minimum, and survives the session's band.
    async with pair() as (c, _s, _l):
        c.quality_band = zmux.QualityBand(rate_ratio=1.0, min_interval=None)
        assert c.quality_band == zmux.QualityBand(rate_ratio=1.0, min_interval=None)
        assert c.quality_band is not None and c.quality_band.min_interval is None
        c.quality_band = zmux.QualityBand(rtt=0.1)
        assert c.quality_band is not None
        assert c.quality_band.min_interval == zmux.DEFAULT_MIN_INTERVAL == 1.0
    for ok in (1.0, 1.5, 2.0, None):
        zmux.QualityBand(rate_ratio=ok, rtt=0.1)
    bad_ratios = (0, 0.5, 0.999, -1.0, float("nan"), math.inf)
    for ratio in bad_ratios:
        with pytest.raises(ValueError):
            zmux.QualityBand(rate_ratio=ratio)
    for bad in (0, -1.0, float("nan"), math.inf, 1e30):
        with pytest.raises(ValueError):
            zmux.QualityBand(rtt=bad)
        with pytest.raises(ValueError):
            zmux.QualityBand(rate_ratio=2, min_interval=bad)
    with pytest.raises(ValueError, match="both halves off"):
        zmux.QualityBand()
    with pytest.raises(ValueError, match="both halves off"):
        zmux.QualityBand(min_interval=None)
    assert zmux.CapacityFloor(rate=1).recovery_ratio == zmux.DEFAULT_RECOVERY_RATIO
    assert zmux.DEFAULT_RECOVERY_RATIO == 1.25
    for bad in (0, 0.5, -1.0, float("nan"), math.inf):
        with pytest.raises(ValueError):
            zmux.CapacityFloor(rate=1, recovery_ratio=bad)
    assert zmux.CapacityFloor(rate=1, recovery_ratio=1).recovery_ratio == 1
    with pytest.raises(ValueError):
        zmux.CapacityFloor(rate=0)


async def test_quality_band_every_change_reports_every_change() -> None:
    """A `rate_ratio` of 1 with no minimum interval reports every change of
    the delivery rate."""
    async with pair() as (c, s, _l):
        c.quality_band = zmux.QualityBand(rate_ratio=1.0, min_interval=None)

        async def drain() -> None:
            _send, recv = await s.accept_bi()
            while await recv.read(65536):
                pass

        async def watch() -> None:
            async for e in c.events():
                if isinstance(e, zmux.PipeQualityChanged):
                    return

        tasks = [asyncio.create_task(drain()), asyncio.create_task(watch())]
        send, _recv = await c.open_bi()
        try:
            async with asyncio.timeout(15):
                while not tasks[1].done():
                    await send.write(b"x" * 65536)
                    await asyncio.sleep(0)
                await tasks[1]
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def test_nested_session_over_a_carrier_stream() -> None:
    async with pair() as (c, s, _l):

        async def inner_server() -> zmux.Session:
            send, recv = await s.accept_bi()
            assert recv.preamble.pipe_carrier
            assert recv.preamble.tlvs == (zmux.Tlv(0x1000, b"route"),)
            inner = await zmux.Session.accept(zmux.adapter.stream_pipe(send, recv))
            with pytest.raises(zmux.StreamError):
                send.send_capacity()  # used up by stream_pipe
            a, b = await inner.accept_bi()
            await a.write(await b.read_to_end())
            await a.finish()
            return inner

        task = asyncio.create_task(inner_server())
        carrier = await c.open_pipe_stream(tlvs=[(0x1000, b"route")])
        # A stream of an outer session reports its own failure.
        assert carrier.reports_failure
        carrier.reports_failure = False
        assert not carrier.reports_failure
        carrier.reports_failure = True
        inner = await zmux.Session.connect(carrier)
        send, recv = await inner.open_bi()
        await send.write(b"nested")
        await send.finish()
        assert await recv.read_to_end() == b"nested"
        (await task).abort(0)
        inner.abort(0)


class Counting:
    """A limiter that allows everything and counts what it handed out and
    got back."""

    def __init__(self) -> None:
        self.taken = 0
        self.released = 0
        self.waits = 0

    async def acquire(self, least: int, most: int, /) -> int:
        self.waits += 1
        self.taken += most
        return most

    def try_acquire(self, least: int, most: int, /) -> int:
        self.taken += most
        return most

    def refund(self, n: int, /) -> None:
        self.released += n

    @property
    def used(self) -> int:
        return self.taken - self.released


async def test_splice_forwards_and_takes_what_it_forwards() -> None:
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):

        async def relay() -> tuple[zmux.helpers.SpliceResult, Counting]:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            limiter = Counting()
            with pytest.raises(ValueError):
                await zmux.helpers.splice(a, a)
            done = await zmux.helpers.splice(a, b, chunk=4096, a_to_b=limiter)
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
        assert isinstance(done, zmux.helpers.SpliceResult)
        assert (
            done.a_to_b.end is zmux.helpers.SpliceEnd.FINISHED
            and done.a_to_b.code is None
        )
        assert done.a_to_b.bytes == 700 == limiter.used
        assert done.b_to_a.bytes == 700


async def test_resolve_duplicate() -> None:
    async with zmux.Listener() as lx, zmux.Listener() as ly:
        ax, ay = await lx.serve_tcp("127.0.0.1", 0), await ly.serve_tcp("127.0.0.1", 0)
        x1 = await zmux.Session.connect(await zmux.dial_tcp(*ay))  # X dialed
        y1 = await ly.accept()
        y2 = await zmux.Session.connect(await zmux.dial_tcp(*ax))  # Y dialed
        x2 = await lx.accept()
        with pytest.raises(zmux.DuplicateUndecidedError) as undecided:
            zmux.helpers.resolve_duplicate(x1, x2)  # nothing decides
        assert isinstance(undecided.value, ValueError)
        assert isinstance(undecided.value, zmux.ZmuxError)
        with pytest.raises(zmux.DuplicateUndecidedError):
            zmux.helpers.resolve_duplicate(
                x1, x1, local_identity=b"x", peer_identity=b"y"
            )
        r = zmux.helpers.resolve_duplicate(
            x1, x2, local_identity=b"x", peer_identity=b"y"
        )
        assert (
            isinstance(r, zmux.helpers.Resolved)
            and r.rule is zmux.helpers.DuplicateRule.IDENTITY
        )
        assert not r.rejoin_started
        assert {r.survivor.role, r.loser.role} <= {
            zmux.Role.CLIENT,
            zmux.Role.SERVER,
        }
        for sess in (x1, x2, y1, y2):
            sess.abort(0)
        await asyncio.gather(*(x.wait_closed() for x in (x1, x2, y1, y2)))


def test_negative_durations_raise() -> None:
    for make in (
        lambda: zmux.Listener(
            listener_config=zmux.ListenerConfig(handshake_timeout=-1)
        ),
        lambda: zmux.Listener(
            listener_config=zmux.ListenerConfig(
                limits=zmux.ListenerLimits(first_record_timeout=float("nan"))
            )
        ),
        lambda: zmux.CarrierCache(success_ttl=-1),
        lambda: zmux.ExchangeOptions(idle_timeout=-1),
        lambda: zmux.Admission.prefix_auth(
            zmux.PrefixAuth(b"k" * 32, slot=30), skew=1, peek_timeout=-1
        ),
    ):
        with pytest.raises(ValueError):
            make()


def test_pipe_options_defaults_and_sentinels() -> None:
    o = zmux.PipeOptions()
    assert (o.record_mode, o.key_group, o.probation) == (
        zmux.INHERIT,
        zmux.INHERIT,
        zmux.INHERIT,
    )
    assert (o.send_priority, o.send_standby, o.receive_priority, o.weight) == (
        zmux.INHERIT,
        zmux.INHERIT,
        zmux.INHERIT,
        zmux.INHERIT,
    )
    assert o.liveness is zmux.INHERIT and o.quality_band is zmux.INHERIT
    assert zmux.PipeLiveness().dead_timeout is zmux.INHERIT and o.fate_group == 0
    assert zmux.shaping.ShapingSizeLimits().max_slots == zmux.shaping.DEFAULT_MAX_SLOTS
    with pytest.raises(ValueError):
        zmux.QualityBand(rtt=-1)
    with pytest.raises(ValueError):
        zmux.adapter.ReplayFilter(1.0, 0)


async def test_stream_credit_maximum_and_datagram_stream_bytes() -> None:
    assert zmux.MAX_STREAM_CREDIT == 1 << 60
    c = zmux.Config()
    assert c.datagram_stream_bytes == 512 * 1024
    assert zmux.Config(datagram_stream_bytes=None).datagram_stream_bytes is None
    assert c.replace(datagram_stream_bytes=1 << 20).datagram_stream_bytes == 1 << 20
    big = zmux.Config(
        max_incoming_streams=zmux.MAX_STREAM_CREDIT,
        max_incoming_uni_streams=zmux.MAX_STREAM_CREDIT,
        enable_datagrams=True,
        datagram_stream_bytes=None,
    )
    async with pair(client=big, server=big) as (client, server, _):
        client.raise_incoming_streams(bidi=zmux.MAX_STREAM_CREDIT)
        with pytest.raises(ValueError):
            client.raise_incoming_streams(bidi=zmux.MAX_STREAM_CREDIT + 1)
        send, _ = await client.open_bi()
        await send.write(b"x")
        assert await server.accept_bi()
    invalid: list[dict[str, Any]] = [
        {"datagram_stream_bytes": 0},
        {"max_incoming_streams": zmux.MAX_STREAM_CREDIT + 1},
        {"max_incoming_uni_streams": zmux.MAX_STREAM_CREDIT + 1},
    ]
    for bad in invalid:
        with pytest.raises((ValueError, zmux.ZmuxError)):
            async with pair(client=zmux.Config(**bad)):
                pass
    with pytest.raises(ValueError):
        zmux.Config(datagram_stream_bytes=-1)


async def test_the_stream_datagram_queue_is_bounded_by_its_bytes() -> None:
    cfg = zmux.Config(enable_datagrams=True, datagram_stream_bytes=4096)
    async with pair(client=cfg, server=cfg) as (client, server, _):
        send, _ = await client.open_bi()
        await send.write(b"x")
        _, recv = await server.accept_bi()
        await recv.read_exact(1)
        for i in range(8):
            send.send_datagram(bytes([i]) * 1500)
        await asyncio.sleep(0.2)
        got = []
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(0.3):
                while True:
                    got.append(await recv.read_datagram())
        # Two 1500-byte datagrams fit in 4096 bytes: the oldest made room.
        assert len(got) <= 2 and got[-1][1] == bytes([7]) * 1500


async def test_listener_source_prefixes() -> None:
    good: list[dict[str, Any]] = [
        {"source_prefix_v4": 24, "source_prefix_v6": 56},
        {"source_prefix_v4": 1, "source_prefix_v6": 128},
        {"source_prefix_v4": 32, "source_prefix_v6": 64},
    ]
    for kw in good:
        async with zmux.Listener(listener_config=zmux.ListenerConfig(**kw)) as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            session = await zmux.connect_tcp(*addr)
            await asyncio.wait_for(listener.accept(), 5)
            session.abort(0)
            await session.wait_closed()
    refused: list[dict[str, Any]] = [
        {"source_prefix_v4": 0},
        {"source_prefix_v4": 33},
        {"source_prefix_v4": -1},
        {"source_prefix_v6": 0},
        {"source_prefix_v6": 129},
    ]
    for bad in refused:
        with pytest.raises(ValueError):
            zmux.Listener(listener_config=zmux.ListenerConfig(**bad))


async def test_resolve_duplicate_returns_the_given_objects() -> None:
    async with zmux.Listener() as lx, zmux.Listener() as ly:
        ax, ay = await lx.serve_tcp("127.0.0.1", 0), await ly.serve_tcp("127.0.0.1", 0)
        x1 = await zmux.Session.connect(await zmux.dial_tcp(*ay))
        y1 = await ly.accept()
        y2 = await zmux.Session.connect(await zmux.dial_tcp(*ax))
        x2 = await lx.accept()
        r = zmux.helpers.resolve_duplicate(
            x1, x2, local_identity=b"x", peer_identity=b"y"
        )
        assert {id(r.survivor), id(r.loser)} == {id(x1), id(x2)}
        assert r.survivor is x1 or r.survivor is x2
        assert r.loser is (x2 if r.survivor is x1 else x1)
        for sess in (x1, x2, y1, y2):
            sess.abort(0)
        await asyncio.gather(*(x.wait_closed() for x in (x1, x2, y1, y2)))


async def _abort_relay(
    relay_in: zmux.Session,
    relay_out: zmux.Session,
    abort: zmux.helpers.SpliceAbort,
    *,
    packets: bool = False,
) -> zmux.helpers.SpliceResult:
    a = await relay_in.accept_bi()
    b = await relay_out.open_bi()
    run = zmux.helpers.splice_packets if packets else zmux.helpers.splice
    return await run(a, b, abort=abort)


@pytest.mark.parametrize("packets", [False, True])
async def test_splice_abort_ends_with_the_code(packets: bool) -> None:
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, server, _l2):
        abort = zmux.helpers.SpliceAbort()
        assert abort.code is None
        task = asyncio.ensure_future(
            _abort_relay(relay_in, relay_out, abort, packets=packets)
        )
        send, recv = await c.open_bi()
        await send.write(b"hello")
        _s_send, s_recv = await server.accept_bi()
        assert await s_recv.read_exact(5) == b"hello"
        await asyncio.sleep(0.05)
        abort.abort(0x77)
        abort.abort(0x99)  # the first code stays
        assert abort.code == 0x77
        done = await asyncio.wait_for(task, 10)
        for d in (done.a_to_b, done.b_to_a):
            assert d.end is zmux.helpers.SpliceEnd.CANCELLED and d.code == 0x77
        with pytest.raises(zmux.StreamResetError) as r:
            await asyncio.wait_for(recv.read_to_end(), 5)
        assert r.value.code == 0x77
        with pytest.raises(zmux.StreamResetError) as r:
            await asyncio.wait_for(s_recv.read_to_end(), 5)
        assert r.value.code == 0x77
        with pytest.raises(zmux.StreamStoppedError) as w:
            await until_raises(send)
        assert w.value.code == 0x77


async def until_raises(*sends: zmux.SendStream) -> None:
    async with asyncio.timeout(5):
        while True:
            for s in sends:
                await s.write(b"x")
            await asyncio.sleep(0.01)


async def test_splice_abort_before_start_ends_at_once() -> None:
    async with pair() as (c, relay_in, _l1), pair() as (relay_out, _server, _l2):
        abort = zmux.helpers.SpliceAbort()
        abort.abort(0)
        assert abort.code == 0
        task = asyncio.ensure_future(_abort_relay(relay_in, relay_out, abort))
        send, _recv = await c.open_bi()
        await send.flush()
        done = await asyncio.wait_for(task, 5)
        assert done.a_to_b.end is zmux.helpers.SpliceEnd.CANCELLED
        assert done.b_to_a.code == 0
        with pytest.raises(ValueError):
            abort.abort(-1)
        with pytest.raises(ValueError):
            abort.abort(2**62)


async def test_flush_succeeds_once_data_left_and_the_stop_comes_after() -> None:
    async with pair() as (c, s, _l):
        send, _recv = await c.open_bi()
        await send.write(b"data")
        await asyncio.wait_for(send.flush(), 5)
        _s_send, s_recv = await s.accept_bi()
        assert await s_recv.read_exact(4) == b"data"
        s_recv.stop(0x55)
        assert await asyncio.wait_for(send.stopped(), 5) == 0x55
        await asyncio.wait_for(send.flush(), 5)
        with pytest.raises(zmux.StreamStoppedError) as w:
            await send.write(b"more")
        assert w.value.code == 0x55


def test_hooks_bind_to_the_loop_of_first_use() -> None:
    seen: list[tuple[int, int]] = []

    class Trace(zmux.Tracer):
        def established(self, session: int) -> None:
            seen.append((session, threading.get_ident()))

    # Made with no loop running: bound when the connect uses it.
    config = zmux.Config(tracer=Trace())

    async def main() -> tuple[int, int]:
        async with zmux.Listener() as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            async with await zmux.connect_tcp(*addr, config=config) as c:
                await until(lambda: bool(seen))
                return c.id, threading.get_ident()

    assert seen == [asyncio.run(main())]


def test_record_policy_and_budget_are_data() -> None:
    with pytest.raises(ValueError):
        zmux.Config(record_policy=zmux.RecordPolicy(default=zmux.RecordMode.UNMANAGED))
    with pytest.raises(ValueError):
        zmux.Config(record_policy=zmux.RecordPolicy(by_label={"x": "nonsense"}))
    zmux.Config(
        record_policy=zmux.RecordPolicy(secure="bound", by_label={"lan": "trusted"}),
        shaping_budget=zmux.shaping.ShapingBudget(no_injection=True),
    )
