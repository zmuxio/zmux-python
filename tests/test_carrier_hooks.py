"""Deferred join secrets, runtime settings, carrier hooks and variants."""

from typing import Any, cast
import asyncio
import dataclasses
import json
import pathlib
import socket
import time
from collections.abc import AsyncIterator, Callable

import pytest
import pytest_asyncio
import zmux

KEY = b"k" * 32
SHAPE = '{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'


def exporter(label: str, context: bytes, length: int) -> bytes:
    return (label.encode() + context + bytes(length))[:length]


async def until(cond: Callable[[], object], limit: float = 5.0) -> None:
    async with asyncio.timeout(limit):
        while not cond():
            await asyncio.sleep(0.005)


@pytest_asyncio.fixture
async def sessions() -> AsyncIterator[tuple[zmux.Session, zmux.Session]]:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        c = await zmux.Session.connect(await zmux.dial_tcp(addr))
        s = await listener.accept()
        try:
            yield c, s
        finally:
            c.close()
            s.close()


def test_pipe_auth_deferred() -> None:
    a = zmux.PipeAuth.deferred_psk()
    assert a == zmux.PipeAuth(deferred_psk=True) != zmux.PipeAuth()
    assert "deferred_psk" in repr(zmux.PipeAuth.exporter().with_deferred_psk())
    assert a.with_psk(KEY) != zmux.PipeAuth.psk(KEY).with_end_to_end()


async def test_deferred_secret_joins_after_set() -> None:
    cfg = zmux.Config(
        max_pipes=4, pipe_auth=zmux.PipeAuth.deferred_psk().with_end_to_end()
    )
    async with zmux.Listener(cfg) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(addr), cfg) as c,
            await listener.accept() as s,
        ):
            await until(lambda: c.join_pending and s.join_pending)
            with pytest.raises(zmux.PipeError) as e:
                await c.add_pipe(await zmux.dial_tcp(addr))
            assert e.value.kind == zmux.ErrorKind.JOIN_PENDING
            with pytest.raises(zmux.PipeError) as e:
                c.set_join_secret(b"short")
            assert e.value.kind == zmux.ErrorKind.INVALID_ARGUMENT
            c.set_join_secret(KEY)
            s.set_join_secret(KEY)
            assert not c.join_pending
            with pytest.raises(zmux.PipeError) as e:
                c.set_join_secret(KEY)
            assert e.value.kind == zmux.ErrorKind.JOIN_SECRET_SET
            assert c.session_binding == s.session_binding
            assert len(c.session_binding or b"") == 32
            await until(lambda: c.join_ready)
            pipe = await c.add_pipe(await zmux.dial_tcp(addr))
            async with asyncio.timeout(5):
                await pipe.joined()
            pipe.update(liveness=zmux.PipeLiveness(dead_timeout=5, probe_interval=None))
            pipe.update(liveness=zmux.PipeLiveness())
            with pytest.raises(ValueError):
                pipe.update(liveness=zmux.PipeLiveness(dead_timeout=0.1))


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

    limits = zmux.ShapingLimits(wire=zmux.ShapingAccount(initial=9), max_delay=0.5)
    assert c.shaping_limits == zmux.ShapingLimits()
    c.shaping_limits = limits
    assert c.shaping_limits == limits

    c.raise_incoming_streams(bidi=1 << 20)
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
    seen: list[zmux.PipeHint] = []

    def transform(pipe: zmux.PipeIo, hint: zmux.PipeHint) -> zmux.PipeIo:
        seen.append(hint)
        pipe.exporter = exporter
        pipe.terminated_tls = zmux.TlsState(b"zmux", "a.test")
        return pipe

    cfg = zmux.Config(max_pipes=2, pipe_auth=zmux.PipeAuth.exporter().with_end_to_end())
    async with zmux.Listener(cfg, inbound_transform=transform) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        pipe = await zmux.dial_tcp(addr)
        pipe.exporter = exporter
        assert pipe.terminated_tls is None
        async with (
            await zmux.Session.connect(pipe, cfg) as c,
            await listener.accept() as s,
        ):
            got = c.export_keying_material("app", context=b"c", length=8)
            assert got == s.export_keying_material("app", context=b"c", length=8)
            assert got == b"appc" + bytes(4)
            with pytest.raises(zmux.ExportError) as e:
                c.export_keying_material(zmux.RESERVED_EXPORTER_PREFIX + "x")
            assert e.value.kind == zmux.ErrorKind.RESERVED_LABEL
            await until(lambda: c.session_binding is not None)
            await until(lambda: c.join_ready)
            assert c.stats().pipes_active == 1
    assert seen


def test_pipe_io_labels() -> None:
    pipe, _ = zmux.pipe_pair()
    pipe.variant = "sealed"
    pipe.terminated_tls = zmux.TlsState(b"h2", "a.test")
    assert pipe.variant == "sealed"
    assert pipe.terminated_tls == zmux.TlsState(b"h2", "a.test")


async def test_decision_variant_more_and_session_config() -> None:
    prefixes: list[bytes] = []
    carriers: list[zmux.SessionCarrier] = []
    chosen = zmux.Config(max_idle_timeout=20)

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
    async with zmux.Listener(admission=admission, session_config=session_config) as li:

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

    async with zmux.Listener(session_config=boom, handshake_timeout=10) as li:
        addr = await li.serve_tcp("127.0.0.1:0")
        pipe = await zmux.dial_tcp(addr)
        with pytest.raises(zmux.ZmuxError):
            async with asyncio.timeout(5):
                await zmux.Session.connect(pipe, zmux.Config(handshake_timeout=2))
        await until(lambda: li.stats().rejected == 1)


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
    d = zmux.Decision(zmux.AdmissionVerdict.CLOSE, variant="x")
    assert d == zmux.AdmissionVerdict.CLOSE.labelled("x")
    assert (d.verdict, d.variant) == (zmux.AdmissionVerdict.CLOSE, "x")


def test_cache_report_and_snapshot() -> None:
    cache = zmux.CarrierCache()
    cache.report("k", "websocket", zmux.CacheOutcome.USABLE)
    cache.report("k", "quic", "rejected", variant="sealed")
    assert cache.is_usable("k", "websocket")
    entries = json.loads(cache.snapshot())["entries"]
    assert {e.get("variant") for e in entries} == {None, "sealed"}
    other = zmux.CarrierCache()
    other.restore(cache.snapshot())
    restored = json.loads(other.snapshot())["entries"]
    assert {e.get("variant") for e in restored} == {None, "sealed"}
    with pytest.raises(ValueError):
        cache.report("k", "quic", "maybe")


def _free_port() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{s.getsockname()[1]}"


async def test_candidate_variant_reported() -> None:
    async with zmux.Listener() as li:
        addr = await li.serve_http("127.0.0.1:0")
        good = zmux.Candidate.http(addr).with_variant("plain")
        dead = zmux.Candidate.http_split(_free_port()).with_variant("sealed")
        assert (good.variant, zmux.Candidate.http(addr).variant) == ("plain", None)
        cache = zmux.CarrierCache()
        choice = zmux.CarrierChoice.auto([dead, good])
        policy = zmux.CarrierChoicePolicy(cache=cache, key="k")
        async with (
            await zmux.connect_choice(choice, choice_policy=policy) as c,
            await li.accept(),
        ):
            results = c.stats().carrier_candidates
            assert ("streaming", "plain") in {(r.carrier, r.variant) for r in results}
            async with asyncio.timeout(5):
                while True:
                    ev = await c.next_event()
                    if isinstance(ev, zmux.CarrierChosen):
                        break
            assert ev.variant == "plain"
        assert any(e.get("variant") for e in json.loads(cache.snapshot())["entries"])


def test_replay_filter() -> None:
    f = zmux.ReplayFilter(1.0, 2)
    assert f.check_at(b"a", 1000, 1000) == zmux.ReplayVerdict.FRESH
    assert f.check_at(b"a", 1000, 1000) == zmux.ReplayVerdict.SEEN
    assert f.check_at(b"b", 5000, 1000) == zmux.ReplayVerdict.OUTSIDE
    assert f.check_at(b"c", 1000, 1000) == zmux.ReplayVerdict.FRESH
    assert f.check_at(b"d", 1000, 1000) == zmux.ReplayVerdict.FULL
    assert len(f) == 2
    now = int(time.time() * 1000)
    assert zmux.ReplayFilter(1.0, 1).check(b"a", now) == zmux.ReplayVerdict.FRESH
    late = zmux.ReplayFilter(1.0, 1, not_before=time.time() + 100)
    assert late.check(b"a", now) == zmux.ReplayVerdict.OUTSIDE
    for bad in ((0.0, 1), (1.0, 0), (-1.0, 1)):
        with pytest.raises(ValueError):
            zmux.ReplayFilter(*bad)


def test_classify_first_bytes() -> None:
    F = zmux.FirstBytes
    assert zmux.classify_first_bytes(b"") == (F.NEED_MORE, 1)
    assert zmux.classify_first_bytes(b"\x16\x03") == (F.OTHER, 0)
    assert zmux.classify_first_bytes(b"\x20") == (F.NEED_MORE, 2)
    assert zmux.MAX_FIRST_BYTES == 5
    framing = zmux.Framing.RECORDS
    assert zmux.classify_first_bytes(b"\x16", framing=framing) == (F.OTHER, 0)
    with pytest.raises(ValueError):
        zmux.classify_first_bytes(b"", framing="nope")


async def test_listener_timeouts_are_floats() -> None:
    for name in ("first_record_timeout", "handshake_timeout"):
        with pytest.raises(ValueError):  # no off setting
            zmux.Listener(**cast("dict[str, Any]", {name: None}))
    async with zmux.Listener(first_record_timeout=1.0, handshake_timeout=5.0) as li:
        addr = await li.serve_tcp("127.0.0.1:0")
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(addr)),
            await li.accept(),
        ):
            pass


async def test_shaper_by_variant(sessions: tuple[zmux.Session, zmux.Session]) -> None:
    c, _ = sessions
    c.set_shaper(by_variant={"sealed": SHAPE}, by_kind={None: SHAPE})
    c.set_shaper()
    with pytest.raises(ValueError):
        c.set_shaper(definition=SHAPE, by_variant={"sealed": SHAPE})
    with pytest.raises(ValueError):
        c.set_shaper(by_variant={"sealed": "{"})
    zmux.Config(shaping_by_variant={"sealed": SHAPE}, shaping={None: SHAPE})


async def test_shaper_picks_the_variant() -> None:
    async with zmux.Listener() as li:
        addr = await li.serve_tcp("127.0.0.1:0")
        for variant, padded in (("sealed", True), ("plain", False)):
            pipe = await zmux.dial_tcp(addr)
            pipe.variant = variant
            async with await zmux.Session.connect(pipe) as c, await li.accept() as s:
                assert c.pipe_stats()[0].variant == variant
                c.set_shaper(by_variant={"sealed": SHAPE})
                send, _ = await c.open_bi()
                await send.write(b"x" * 10)
                await send.finish()
                _, recv = await s.accept_bi()
                assert await recv.read_to_end() == b"x" * 10
                assert (c.shaping_stats()["wire_spent"] > 0) == padded


TESTDATA = pathlib.Path(__file__).parent / "testdata"


def test_classify_first_bytes_follows_the_shared_vectors() -> None:
    vectors = json.loads((TESTDATA / "firstbytes.json").read_text())["vectors"]
    assert vectors
    framings = {"stream": "byte_stream", "records": "records"}
    classes = {
        "need_more": zmux.FirstBytes.NEED_MORE,
        "record": zmux.FirstBytes.RECORD,
        "other": zmux.FirstBytes.OTHER,
    }
    for t in vectors:
        got = zmux.classify_first_bytes(
            bytes.fromhex(t["hex"]), framing=framings[t["framing"]]
        )
        assert got == (classes[t["class"]], t["need"]), t


def test_replay_filter_follows_the_shared_vectors() -> None:
    cases = json.loads((TESTDATA / "replay.json").read_text())["cases"]
    assert cases
    verdicts = {
        "fresh": zmux.ReplayVerdict.FRESH,
        "seen": zmux.ReplayVerdict.SEEN,
        "outside": zmux.ReplayVerdict.OUTSIDE,
        "full": zmux.ReplayVerdict.FULL,
    }
    for c in cases:
        not_before = c["not_before_ms"] / 1000 if c["not_before_ms"] else None
        f = zmux.ReplayFilter(c["window_ms"] / 1000, c["max"], not_before=not_before)
        for i, s in enumerate(c["steps"]):
            got = f.check_at(bytes.fromhex(s["key_hex"]), s["t_ms"], s["now_ms"])
            assert got == verdicts[s["verdict"]], (c["name"], i)


def test_cache_queries_take_the_variant() -> None:
    cache = zmux.CarrierCache()
    cache.report("k", "streaming", "usable", variant="v")
    assert cache.is_usable("k", "streaming", variant="v")
    assert not cache.is_usable("k", "streaming")
    cache.report("k", "split", "failed", variant="v")
    assert cache.is_failed("k", "split", variant="v")
    assert not cache.is_failed("k", "split")
