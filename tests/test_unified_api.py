"""Closing, errors, settings and addresses as the cross-language conventions
define them."""

import asyncio
import contextlib
import math
from collections.abc import AsyncIterator

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


async def test_serve_reports_host_and_port() -> None:
    async with zmux.Listener() as listener:
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        assert host == "127.0.0.1" and isinstance(port, int) and port > 0


async def test_streams_unpack_and_name_their_parts() -> None:
    async with pair() as (c, s):
        opened = await c.open_bi()
        assert isinstance(opened, zmux.BiStream)
        send, recv = opened
        assert opened.send is send and opened.recv is recv
        await send.write(b"abc")
        await send.write(memoryview(b"de"))
        assert await send.write_some(bytearray(b"fg")) == 2
        assert await send.writev([b"h", memoryview(b"xijx")[1:3], b""]) == 3
        assert await send.write_some(b"") == 0
        assert await send.writev([]) == 0
        await send.finish()
        accepted = await s.accept_bi()
        assert await accepted.recv.read_to_end() == b"abcdefghij"


async def test_a_stream_exit_by_an_exception_resets_with_cancelled() -> None:
    async with pair() as (c, s):
        with pytest.raises(RuntimeError):
            async with (await c.open_bi()).send as send:
                await send.write(b"x")
                raise RuntimeError("boom")
        _, recv = await s.accept_bi()
        with pytest.raises(zmux.StreamResetError) as e:
            await recv.read_to_end()
        assert e.value.code == CANCELLED


async def test_a_session_exit_by_an_exception_closes_with_cancelled() -> None:
    async with zmux.Listener() as listener:
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        with pytest.raises(RuntimeError):
            async with await zmux.connect_tcp(host, port):
                server = await listener.accept()
                raise RuntimeError("boom")
        end = await asyncio.wait_for(server.wait_closed(), 5)
        assert isinstance(end, zmux.ApplicationClosedError)
        assert (end.code, end.reason, end.remote) == (CANCELLED, b"", True)


async def test_wait_closed_returns_the_error_that_describes_the_end() -> None:
    async with pair() as (c, s):
        s.close(5, b"done")
        end = await asyncio.wait_for(c.wait_closed(), 5)
        assert isinstance(end, zmux.SessionClosedError)
        assert (end.code, end.reason, end.remote) == (5, b"done", True)
        # The same end, repeated and as an operation's error.
        assert (await c.wait_closed()).code == 5
        with pytest.raises(zmux.SessionClosedError):
            await c.open_bi()


async def test_iteration_ends_silently_only_on_a_clean_end() -> None:
    async with pair() as (c, s):
        c.close()
        async for _ in s:
            raise AssertionError("no stream was opened")
        assert (await s.wait_closed()).code == 0
    async with pair() as (c, s):
        c.close(9)
        with pytest.raises(zmux.ApplicationClosedError) as e:
            async for _ in s:
                raise AssertionError("no stream was opened")
        assert e.value.code == 9
    async with pair(zmux.Config(enable_datagrams=True)) as (c, s):
        c.abort(3)
        with pytest.raises(zmux.ApplicationClosedError):
            async for _ in s.datagrams():
                raise AssertionError("no datagram was sent")


async def test_reset_and_stop_take_the_code_explicitly() -> None:
    async with pair() as (c, s):
        send, recv = await c.open_bi()
        await send.write(b"x")
        _, remote = await s.accept_bi()
        with pytest.raises(TypeError):
            send.reset()  # type: ignore[call-arg]  # the code is required
        with pytest.raises(TypeError):
            recv.stop()  # type: ignore[call-arg]  # the code is required
        send.reset(77)
        with pytest.raises(zmux.StreamResetError) as e:
            await remote.read_to_end()
        assert e.value.code == 77
        with pytest.raises(zmux.StreamClosedError):
            await send.write(b"y")


async def test_an_open_stream_pair_writer_aborts_with_a_code() -> None:
    async with pair() as (c, s):
        reader, writer = await c.open_stream_pair(limit=1 << 10)
        writer.write(b"x")
        await writer.flush()
        with pytest.raises(TypeError):
            writer.abort()  # type: ignore[call-arg]  # the code is required
        writer.abort(12)
        _, remote = await s.accept_bi()
        with pytest.raises(zmux.StreamResetError) as e:
            await remote.read_to_end()
        assert e.value.code == 12
        del reader


async def test_stream_pair_reader_raises_the_one_incomplete_read_error() -> None:
    async with pair() as (c, s):
        reader, writer = await c.open_stream_pair(limit=1 << 10)
        writer.write(b"abc")
        writer.close()
        remote_send, remote_recv = await s.accept_bi()
        assert await remote_recv.read_exact(3) == b"abc"
        await remote_send.finish()
        with pytest.raises(asyncio.IncompleteReadError) as e:
            await reader.readexactly(5)
        assert isinstance(e.value, zmux.IncompleteReadError)
        assert isinstance(e.value, zmux.StreamError)
        assert e.value.partial == b"" and e.value.expected == 5


async def test_read_exact_raises_the_one_incomplete_read_error() -> None:
    async with pair() as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"ab")
        await send.finish()
        _, recv = await s.accept_bi()
        with pytest.raises(zmux.IncompleteReadError) as e:
            await recv.read_exact(5)
        assert (e.value.partial, e.value.expected) == (b"ab", 5)
        assert isinstance(e.value, asyncio.IncompleteReadError)


async def test_errors_are_classified_by_what_happened() -> None:
    async with pair() as (c, _s):
        await c.ping()
        send, recv = await c.open_bi()
        await send.finish()
        with pytest.raises(zmux.StreamClosedError):
            await send.finish()
        with pytest.raises(zmux.InvalidArgumentError) as e:
            await c.open_bi(tlvs=[(1, b"reserved")])
        assert isinstance(e.value, ValueError)
        # The stream part takes one operation at a time.
        read = asyncio.ensure_future(recv.read())
        await asyncio.sleep(0.05)
        with pytest.raises(zmux.StreamBusyError):
            recv.reject()
        read.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await read


async def test_an_unestablished_peer_is_not_a_pipe_error() -> None:
    async with pair() as (c, _s):
        with pytest.raises(zmux.NotNegotiatedError) as e:
            c.pipes()[0].update(weight=2)
        assert not isinstance(e.value, zmux.PipeError)


async def test_the_join_bound_is_a_deadline_not_a_session_end() -> None:
    assert issubclass(zmux.DeadlineExceededError, TimeoutError)
    assert not issubclass(zmux.DeadlineExceededError, zmux.SessionClosedError)
    assert not issubclass(zmux.SessionClosedError, TimeoutError)


async def test_session_settings_are_readable_properties() -> None:
    async with pair(zmux.Config(scheduler=zmux.sched.Scheduler.SPREAD_ETA)) as (c, s):
        assert c.scheduler is zmux.sched.Scheduler.SPREAD_ETA
        c.scheduler = "session-affinity"
        assert c.scheduler is zmux.sched.Scheduler.SESSION_AFFINITY
        with pytest.raises(ValueError):
            c.scheduler = "fastest"
        assert c.scheduler is zmux.sched.Scheduler.SESSION_AFFINITY
        assert c.quality_band is None and c.capacity_floor is None
        band = zmux.QualityBand(rtt=0.05)
        c.quality_band = band
        assert c.quality_band == band
        with pytest.raises(ValueError):
            c.quality_band = zmux.QualityBand(rtt=-1)
        assert c.quality_band == band
        c.quality_band = None
        assert c.quality_band is None
        floor = zmux.CapacityFloor(rate=1000)
        c.capacity_floor = floor
        assert c.capacity_floor == floor
        assert c.shaper is None
        shaper = zmux.shaping.Shaper(
            definition='{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'
        )
        with pytest.raises(ValueError):
            c.shaper = zmux.shaping.Shaper(definition="not json")
        assert c.shaper is None
        c.shaper = shaper
        installed = c.shaper
        assert isinstance(installed, zmux.shaping.InstalledShaper)
        s.shaper = installed
        assert isinstance(s.shaper, zmux.shaping.InstalledShaper)
        c.shaper = None
        assert c.shaper is None
        with pytest.raises(ValueError):
            zmux.shaping.Shaper(definition="{}", by_kind={None: "{}"})
        assert s.liveness == zmux.Liveness()


async def test_stream_settings_read_back_as_in_force() -> None:
    async with pair() as (c, s):
        send, recv = await c.open_bi()
        assert (send.scheduler, send.redundant) == (None, None)
        assert send.send_buffer != 1 << 16
        send.send_buffer = 1 << 16
        send.scheduler = zmux.sched.Scheduler.SPREAD_ROUND_ROBIN
        send.redundant = True
        assert send.send_buffer == 1 << 16
        assert send.scheduler is zmux.sched.Scheduler.SPREAD_ROUND_ROBIN
        assert send.redundant is True
        send.scheduler = None
        send.redundant = None
        assert (send.scheduler, send.redundant) == (None, None)
        assert recv.peer_priority is None
        window, _ = recv.receive_window
        recv.receive_window = (window + 4096, window + 8192)
        recv.peer_priority = (1, True)
        assert recv.receive_window == (window + 4096, window + 8192)
        assert recv.peer_priority == zmux.Priority(1, True)
        await send.write(b"x")
        _ = s


def test_pipe_options_take_the_form_update_takes() -> None:
    o = zmux.PipeOptions()
    for name in (
        "send_priority",
        "receive_priority",
        "send_standby",
        "receive_standby",
        "weight",
        "probation",
        "liveness",
        "quality_band",
    ):
        assert getattr(o, name) is zmux.CLEAR, name
    assert zmux.PipeOptions(probation=None).probation is None


def test_backoff_is_one_top_level_type() -> None:
    b = zmux.Backoff()
    assert (b.min, b.max, b.jitter) == (
        zmux.DEFAULT_MIN_BACKOFF,
        zmux.DEFAULT_MAX_BACKOFF,
        zmux.DEFAULT_BACKOFF_JITTER,
    )
    assert b.jitter == 0.2
    assert zmux.Config().redial_backoff == b
    zmux.Config(redial_backoff=zmux.Backoff(0.1, 1.0, jitter=0))
    for bad in (
        zmux.Backoff(jitter=-0.1),
        zmux.Backoff(jitter=1.0),
        zmux.Backoff(jitter=math.nan),
        zmux.Backoff(5.0, 1.0),
        zmux.Backoff(0.0, 1.0),
    ):
        with pytest.raises(ValueError):
            zmux.Config(redial_backoff=bad)
        with pytest.raises(ValueError):
            zmux.helpers.PipePool(1, _no_dial, backoff=bad)
        with pytest.raises(ValueError):
            zmux.ExchangeOptions(backoff=bad, unauthenticated=True)
    zmux.helpers.PipePool(1, _no_dial, backoff=zmux.Backoff(jitter=0))
    zmux.ExchangeOptions(backoff=zmux.Backoff(0.01, 1.0), unauthenticated=True)


async def _no_dial() -> zmux.PipeIo:
    raise AssertionError("not dialled")


def test_listener_takes_its_configuration_as_a_dataclass() -> None:
    lc = zmux.ListenerConfig(max_suspended=5, instance_id=b"a")
    assert lc.max_pending == 1024 and lc.first_record_timeout == 2.0
    with pytest.raises(TypeError):
        zmux.Listener(zmux.Config())  # type: ignore[call-arg]  # keyword-only
    with pytest.raises(TypeError):
        zmux.Listener(max_suspended=1)  # type: ignore[call-arg]  # in ListenerConfig
    with pytest.raises(ValueError):
        zmux.Listener(listener_config=zmux.ListenerConfig(instance_id=bytes(9)))


async def test_adapter_entries_are_in_their_namespace() -> None:
    async with pair() as (c, _s), zmux.Listener() as listener:
        assert zmux.adapter.join_ready(c) is False
        kind, need = zmux.adapter.join_prefix(listener, b"\x02")
        assert kind is zmux.adapter.JoinPrefix.NEED_MORE and need > 1
    for name in ("join_ready", "join_prefix", "open_carrier", "pipe_pair"):
        assert name not in zmux.__all__ and name in zmux.adapter.__all__
    assert not hasattr(zmux.Session, "join_ready")
    assert not hasattr(zmux.Listener, "join_prefix")


def test_the_namespaces_hold_what_they_say() -> None:
    assert {"Scheduler", "Redundancy"} == set(zmux.sched.__all__)
    assert "ShapingBundle" in zmux.shaping.__all__
    assert {"PipePool", "splice", "Limiter"} <= set(zmux.helpers.__all__)
    for ns in (zmux.adapter, zmux.sched, zmux.shaping, zmux.helpers):
        for name in ns.__all__:
            assert name not in zmux.__all__, name
            assert hasattr(ns, name), name
    for name in zmux.__all__:
        assert hasattr(zmux, name), name
    assert isinstance(zmux.__version__, str)


def test_a_pipe_input_takes_its_carrier_inputs_when_built() -> None:
    count = zmux.adapter.UnsentCount(7)
    pipe, _end = zmux.adapter.pipe_pair(
        unsent=count, max_record=1024, exporter=lambda *_: None
    )
    assert not hasattr(pipe, "unsent") and not hasattr(pipe, "exporter")
    with pytest.raises(ValueError):
        zmux.adapter.pipe_pair(max_record=0)


async def test_a_pipe_input_is_used_once() -> None:
    pipe, _end = zmux.adapter.pipe_pair()
    pipe.declare_secure()
    stream = pipe.into_stream()
    assert stream is not None
    with pytest.raises(zmux.PipeUsedError):
        pipe.declare_secure()
    with pytest.raises(zmux.PipeUsedError):
        _ = pipe.variant


async def test_stream_datagrams_are_named() -> None:
    config = zmux.Config(enable_datagrams=True)
    async with pair(config) as (c, s):
        send, _ = await c.open_bi()
        await send.write(b"open")
        _, remote = await s.accept_bi()
        send.send_datagram(b"dg", 3)
        got = await asyncio.wait_for(remote.read_datagram(), 5)
        assert isinstance(got, zmux.StreamDatagram)
        assert (got.context, got.payload) == (3, b"dg")


def test_carrier_kinds_name_their_dial_and_candidate_functions() -> None:
    for name in ("dial_streaming", "dial_split", "connect_streaming", "connect_split"):
        assert name in zmux.__all__
    for gone in ("dial_http", "dial_http_split", "connect_http", "connect_http_split"):
        assert gone not in zmux.__all__
    assert not hasattr(zmux.Candidate, "http")
    assert zmux.Candidate.streaming("127.0.0.1", 1).kind is zmux.CarrierKind.STREAMING
    assert zmux.Candidate.split("127.0.0.1", 1).kind is zmux.CarrierKind.SPLIT
    assert hasattr(zmux.Http2Connection, "dial") and hasattr(
        zmux.Http2Connection, "open_pipe"
    )


async def test_try_open_uni_and_send_datagram_wait() -> None:
    async with pair(zmux.Config(enable_datagrams=True)) as (c, s):
        send = c.try_open_uni(priority=(2, False))
        assert send.priority.urgency == 2
        await send.write(b"uni")
        await send.finish()
        recv = await s.accept_uni()
        assert await recv.read_to_end() == b"uni"
        await c.send_datagram_wait(memoryview(b"xdgx")[1:3])
        assert await asyncio.wait_for(s.read_datagram(), 5) == b"dg"


async def test_hosts_take_ip_addresses() -> None:
    import ipaddress

    async with zmux.Listener() as listener:
        _, port = await listener.serve_tcp(ipaddress.IPv4Address("127.0.0.1"), 0)
        async with await zmux.connect_tcp(ipaddress.ip_address("127.0.0.1"), port):
            (await asyncio.wait_for(listener.accept(), 5)).close()
    with pytest.raises(TypeError):
        await zmux.dial_tcp(1, 1)  # type: ignore[arg-type]
