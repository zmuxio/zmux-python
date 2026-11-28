"""Deferred join secrets, runtime settings, carrier hooks and variants."""

from typing import Any, cast
import asyncio
import dataclasses
import json
import pathlib
import sys
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import zmux
from support import session_pair
from support import until

KEY = b"k" * 32
SHAPE = '{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'


def exporter(label: str, context: bytes, length: int) -> bytes:
    return (label.encode() + context + bytes(length))[:length]


@pytest_asyncio.fixture
async def sessions() -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    async with session_pair() as pair:
        yield pair


def test_pipe_auth_deferred() -> None:
    a = zmux.PipeAuth.deferred_psk()
    assert a == zmux.PipeAuth(deferred_psk=True) != zmux.PipeAuth()
    assert "deferred_psk" in repr(zmux.PipeAuth.exporter().with_deferred_psk())
    assert a.with_psk(KEY) != zmux.PipeAuth.psk(KEY).with_end_to_end()


async def test_deferred_secret_joins_after_set() -> None:
    cfg = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=4)
        ),
        pipe_auth=zmux.PipeAuth.deferred_psk().with_end_to_end(),
    )
    async with zmux.Listener(config=cfg) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr), config=cfg) as c,
            await listener.accept() as s,
        ):
            assert c.join_pending and s.join_pending
            with pytest.raises(zmux.InvalidArgumentError) as short:
                c.set_join_secret(b"short")
            assert short.value.kind == zmux.ErrorKind.INVALID_ARGUMENT
            c.set_join_secret(KEY)
            s.set_join_secret(KEY)
            assert not c.join_pending
            with pytest.raises(zmux.PipeError) as e:
                c.set_join_secret(KEY)
            assert e.value.kind == zmux.ErrorKind.JOIN_SECRET_SET
            assert c.session_binding == s.session_binding
            assert len(c.session_binding or b"") == 32
            pipe = await c.add_pipe(await zmux.dial_tcp(*addr))
            async with asyncio.timeout(5):
                await pipe.joined()
            pipe.update(liveness=zmux.PipeLiveness(dead_timeout=5, probe_interval=None))
            pipe.update(liveness=zmux.PipeLiveness())
            with pytest.raises(ValueError):
                pipe.update(liveness=zmux.PipeLiveness(dead_timeout=0.1))
            # Off, derived, or following the carrier and the session.
            for dead in (None, zmux.AUTO, 1e9):
                pipe.update(liveness=zmux.PipeLiveness(dead_timeout=dead))
                assert pipe.options.liveness == zmux.PipeLiveness(dead_timeout=dead)


async def test_runtime_settings(sessions: tuple[zmux.Session, zmux.Session]) -> None:
    c, s = sessions
    assert c.session_binding is None
    assert c.liveness == zmux.Liveness()
    changed = dataclasses.replace(c.liveness, keep_alive_period=None, dead_timeout=5)
    c.liveness = changed
    assert c.liveness == changed
    with pytest.raises(ValueError):
        c.liveness = dataclasses.replace(changed, suspect_floor=0.001)
    assert c.liveness == changed
    # A dead timeout of None turns stall-based failure off.
    off = dataclasses.replace(changed, dead_timeout=None)
    c.liveness = off
    assert c.liveness.dead_timeout is None
    with pytest.raises(ValueError):
        c.liveness = dataclasses.replace(changed, dead_timeout=0.5)
    assert c.liveness == off

    limits = zmux.shaping.ShapingLimits(
        wire=zmux.shaping.ShapingAccount(ceiling=9, initial=9),
        profile=zmux.shaping.ShapingProfileLimits(max_added_delay=0.5),
    )
    assert c.shaping_limits == zmux.shaping.ShapingLimits()
    c.shaping_limits = limits
    assert c.shaping_limits == limits

    with pytest.raises(zmux.InvalidArgumentError, match="memory_budget"):
        c.raise_incoming_streams(bidi=1 << 20)
    c.raise_incoming_streams(bidi=zmux.Config().max_incoming_streams + 1)
    c.raise_incoming_streams()
    for bad in (-1, (1 << 60) + 1):
        with pytest.raises(ValueError):
            c.raise_incoming_streams(uni=bad)

    with pytest.raises(zmux.ExportError) as e:
        c.export_keying_material("label")
    assert e.value.kind == zmux.ErrorKind.NO_EXPORTER
    assert not s.join_pending


async def test_flush_opens_at_once(sessions: tuple[zmux.Session, zmux.Session]) -> None:
    c, s = sessions
    send, _ = await c.open_bi()
    async with asyncio.timeout(5):
        await send.flush()
        s_send, s_recv = await s.accept_bi()
    assert send.id == s_recv.id
    await s_send.finish()
    await send.finish()
    writer = zmux.StreamPairWriter(c.try_open_bi()[0])
    writer.write(b"x")
    async with asyncio.timeout(5):
        await writer.flush()
        _, r = await s.accept_bi()
        assert await r.read(1) == b"x"


async def test_python_exporter_on_both_sides() -> None:
    seen: list[zmux.adapter.PipeHint] = []

    async def transform(
        accepted_pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint
    ) -> zmux.PipeIo:
        seen.append(hint)
        incoming, outgoing = await zmux.adapter.open_carrier(accepted_pipe)
        out = zmux.pipe_from_streams(incoming, outgoing, exporter=exporter)
        out.terminated_tls = zmux.TlsState(b"zmux", "a.test")
        return out

    cfg = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=2)
        ),
        pipe_auth=zmux.PipeAuth.exporter().with_end_to_end(),
    )
    async with zmux.Listener(
        config=cfg, listener_config=zmux.ListenerConfig(inbound_transform=transform)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(*addr)
        pipe = zmux.pipe_from_streams(reader, writer, exporter=exporter)
        assert pipe.terminated_tls is None
        async with (
            await zmux.Session.connect(pipe, config=cfg) as c,
            await listener.accept() as s,
        ):
            # An exporter answering later holds zmux's own labels only.
            with pytest.raises(zmux.ExportError):
                c.export_keying_material("app", context=b"c", length=8)
            with pytest.raises(zmux.ExportError):
                s.export_keying_material("app", context=b"c", length=8)
            with pytest.raises(zmux.ExportError) as e:
                c.export_keying_material(zmux.adapter.RESERVED_EXPORTER_PREFIX + "x")
            assert e.value.kind == zmux.ErrorKind.RESERVED_LABEL
            await until(c, lambda: c.session_binding is not None)
            await until(c, lambda: zmux.adapter.join_ready(c))
            assert c.stats().pipes_active == 1
    assert seen


def test_pipe_io_labels() -> None:
    pipe, _ = zmux.adapter.pipe_pair()
    pipe.variant = "sealed"
    pipe.terminated_tls = zmux.TlsState(b"h2", "a.test")
    assert pipe.variant == "sealed"
    assert pipe.terminated_tls == zmux.TlsState(b"h2", "a.test")


async def test_decision_variant_more_and_session_config() -> None:
    prefixes: list[bytes] = []
    carriers: list[zmux.SessionCarrier] = []
    chosen = zmux.Config(max_idle_timeout=20, scheduler=zmux.sched.Scheduler.SPREAD_ETA)

    def decide(
        info: zmux.CarrierInfo, prefix: bytes
    ) -> zmux.AdmissionVerdict | zmux.Decision:
        prefixes.append(prefix)
        if len(prefix) == 1:
            return zmux.AdmissionVerdict.more(2)
        return zmux.AdmissionVerdict.accept(2, value="v").labelled("plain")

    def session_config(carrier: zmux.SessionCarrier) -> zmux.Config | None:
        carriers.append(carrier)
        return chosen

    admission = zmux.Admission(decide, peek=1, max_peek=4, peek_timeout=5)
    assert (admission.peek, admission.max_peek) == (1, 4)
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            admission=admission, session_config=session_config
        )
    ) as li:

        def entered(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            pending.append(
                asyncio.ensure_future(li.handle_pipe(zmux.pipe_from_streams(r, w)))
            )

        pending: list[asyncio.Future[None]] = []
        server = await asyncio.start_server(entered, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"ab")
        await writer.drain()
        pipe = zmux.pipe_from_streams(reader, writer)
        async with asyncio.timeout(5):
            async with await zmux.Session.connect(pipe) as c, await li.accept() as s:
                assert s.admitted == "v"
                # The listener's callback chose the scheduler: read from the core.
                assert s.scheduler is zmux.sched.Scheduler.SPREAD_ETA
                assert c.scheduler is zmux.sched.Scheduler.AFFINITY
                assert [p.variant for p in s.pipe_stats()] == ["plain"]
                assert c.pipe_stats()[0].variant is None
        server.close()
        stats = li.variant_stats()
    assert prefixes == [b"a", b"ab"]
    assert stats.variants == {"plain": zmux.VariantStats(accepted=1)}
    assert carriers[0].admitted == "v" and carriers[0].tls is None


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_session_config_failure_rejects() -> None:
    def boom(_: zmux.SessionCarrier) -> zmux.Config | None:
        raise RuntimeError("no")

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(session_config=boom, handshake_timeout=10)
    ) as li:
        addr = await li.serve_tcp("127.0.0.1", 0)
        pipe = await zmux.dial_tcp(*addr)
        with pytest.raises(zmux.ZmuxError):
            async with asyncio.timeout(5):
                await zmux.Session.connect(
                    pipe, config=zmux.Config(handshake_timeout=2)
                )
        await until(li, lambda: li.stats().rejected == 1)


def test_verdict_forms() -> None:
    assert (
        zmux.AdmissionVerdict.more(3)
        == zmux.AdmissionVerdict.more(3)
        != zmux.AdmissionVerdict.more(4)
    )
    assert (
        zmux.AdmissionVerdict.more(3).need == 3
        and zmux.AdmissionVerdict.CLOSE.need is None
    )
    assert repr(zmux.AdmissionVerdict.more(3)) == "AdmissionVerdict.more(3)"
    assert repr(zmux.AdmissionVerdict.DEFER) == "AdmissionVerdict.DEFER"
    assert zmux.AdmissionVerdict.DEFER == zmux.AdmissionVerdict.DEFER
    assert zmux.AdmissionVerdict.DEFER != zmux.AdmissionVerdict.CLOSE

    def close(_: zmux.CarrierInfo, __: bytes) -> zmux.AdmissionVerdict:
        return zmux.AdmissionVerdict.CLOSE

    a = zmux.Admission(close, peek=1, max_peek=2)
    assert (a.max_peek, a.max_message) == (2, zmux.MAX_ADMISSION_MESSAGE)
    assert zmux.Admission(close, max_message=100).max_message == 100
    with pytest.raises(ValueError, match="max_message"):
        zmux.Admission(close, max_message=zmux.MAX_ADMISSION_MESSAGE + 1)
    d = zmux.Decision(zmux.AdmissionVerdict.CLOSE, variant="x")
    assert d == zmux.AdmissionVerdict.CLOSE.labelled("x")
    assert (d.verdict, d.variant) == (zmux.AdmissionVerdict.CLOSE, "x")


def test_replay_filter() -> None:
    f = zmux.adapter.ReplayFilter(1.0, 2)
    assert f.check_at(b"a", 1000, 1000) == zmux.adapter.ReplayVerdict.FRESH
    assert f.check_at(b"a", 1000, 1000) == zmux.adapter.ReplayVerdict.SEEN
    assert f.check_at(b"b", 5000, 1000) == zmux.adapter.ReplayVerdict.OUTSIDE
    assert f.check_at(b"c", 1000, 1000) == zmux.adapter.ReplayVerdict.FRESH
    assert f.check_at(b"d", 1000, 1000) == zmux.adapter.ReplayVerdict.FULL
    assert len(f) == 2
    late = zmux.adapter.ReplayFilter(1.0, 1, not_before=2.0)
    assert late.check_at(b"a", 1000, 1000) == zmux.adapter.ReplayVerdict.OUTSIDE
    assert late.check(b"a", 1000) == zmux.adapter.ReplayVerdict.OUTSIDE
    for bad in ((0.0, 1), (1.0, 0), (-1.0, 1)):
        with pytest.raises(ValueError):
            zmux.adapter.ReplayFilter(*bad)


def test_classify_first_bytes() -> None:
    first_bytes = zmux.adapter.FirstBytes
    assert zmux.adapter.classify_first_bytes(b"") == (first_bytes.NEED_MORE, 1)
    assert zmux.adapter.classify_first_bytes(b"\x16\x03") == (first_bytes.OTHER, 0)
    assert zmux.adapter.classify_first_bytes(b"\x20") == (first_bytes.NEED_MORE, 2)
    assert zmux.adapter.MAX_FIRST_BYTES == 5
    framing = zmux.adapter.Framing.RECORDS
    assert zmux.adapter.classify_first_bytes(b"\x16", framing=framing) == (
        first_bytes.OTHER,
        0,
    )
    with pytest.raises(ValueError):
        zmux.adapter.classify_first_bytes(b"", framing="nope")


async def test_listener_timeouts_are_floats() -> None:
    no_first = zmux.ListenerLimits(
        **cast("dict[str, Any]", {"first_record_timeout": None})
    )
    for lc in (
        zmux.ListenerConfig(limits=no_first),
        zmux.ListenerConfig(**cast("dict[str, Any]", {"handshake_timeout": None})),
    ):
        with pytest.raises(ValueError):  # no off setting
            zmux.Listener(listener_config=lc)
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            limits=zmux.ListenerLimits(first_record_timeout=1.0), handshake_timeout=5.0
        )
    ) as li:
        addr = await li.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr)),
            await li.accept(),
        ):
            pass


async def test_shaper_by_variant(sessions: tuple[zmux.Session, zmux.Session]) -> None:
    c, _ = sessions
    c.shaper = zmux.shaping.Shaper(by_variant={"sealed": SHAPE}, by_kind={None: SHAPE})
    c.shaper = None
    with pytest.raises(ValueError):
        c.shaper = zmux.shaping.Shaper(definition=SHAPE, by_variant={"sealed": SHAPE})
    with pytest.raises(ValueError):
        c.shaper = zmux.shaping.Shaper(by_variant={"sealed": "{"})
    zmux.Config(shaping_by_variant={"sealed": SHAPE}, shaping={None: SHAPE})


async def test_shaper_picks_the_variant() -> None:
    async with zmux.Listener() as li:
        addr = await li.serve_tcp("127.0.0.1", 0)
        for variant, padded in (("sealed", True), ("plain", False)):
            pipe = await zmux.dial_tcp(*addr)
            pipe.variant = variant
            async with await zmux.Session.connect(pipe) as c, await li.accept() as s:
                assert c.pipe_stats()[0].variant == variant
                c.shaper = zmux.shaping.Shaper(by_variant={"sealed": SHAPE})
                send, _ = await c.open_bi()
                await send.write(b"x" * 10)
                await send.finish()
                _, recv = await s.accept_bi()
                assert await recv.read_to_end() == b"x" * 10
                stats = c.shaping_stats()
                assert (stats["ledger"]["measured_bytes"] > 0) == padded
                assert stats["wire_spent"] == stats["faults"] == 0


TESTDATA = pathlib.Path(__file__).parent / "testdata"


def test_classify_first_bytes_follows_the_shared_vectors() -> None:
    vectors = json.loads((TESTDATA / "firstbytes.json").read_text())["vectors"]
    assert vectors
    framings = {"stream": "byte_stream", "records": "records"}
    classes = {
        "need_more": zmux.adapter.FirstBytes.NEED_MORE,
        "record": zmux.adapter.FirstBytes.RECORD,
        "other": zmux.adapter.FirstBytes.OTHER,
    }
    for t in vectors:
        got = zmux.adapter.classify_first_bytes(
            bytes.fromhex(t["hex"]), framing=framings[t["framing"]]
        )
        assert got == (classes[t["class"]], t["need"]), t


def test_replay_filter_follows_the_shared_vectors() -> None:
    cases = json.loads((TESTDATA / "replay.json").read_text())["cases"]
    assert cases
    verdicts = {
        "fresh": zmux.adapter.ReplayVerdict.FRESH,
        "seen": zmux.adapter.ReplayVerdict.SEEN,
        "outside": zmux.adapter.ReplayVerdict.OUTSIDE,
        "full": zmux.adapter.ReplayVerdict.FULL,
    }
    for c in cases:
        not_before = c["not_before_ms"] / 1000 if c["not_before_ms"] else None
        f = zmux.adapter.ReplayFilter(
            c["window_ms"] / 1000, c["max"], not_before=not_before
        )
        for i, s in enumerate(c["steps"]):
            got = f.check_at(bytes.fromhex(s["key_hex"]), s["t_ms"], s["now_ms"])
            assert got == verdicts[s["verdict"]], (c["name"], i)


async def test_huge_read_sizes_on_a_stream(
    sessions: tuple[zmux.Session, zmux.Session],
) -> None:
    """The size of a read bounds what it returns, never what it allocates."""
    c, s = sessions
    send, _ = await c.open_bi()
    await send.write(b"hello")
    await send.flush()
    _, recv = await s.accept_bi()
    async with asyncio.timeout(5):
        assert await recv.read(sys.maxsize) == b"hello"
        await send.write(b"world")
        assert bytes(await recv.read_chunk(sys.maxsize)) == b"world"
        await send.write(b"xy")
        await send.finish()
        with pytest.raises(zmux.IncompleteReadError) as e:
            await recv.read_exact(sys.maxsize)
    assert e.value.partial == b"xy"
