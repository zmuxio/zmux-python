import asyncio
import json
import pathlib
from collections.abc import Callable
from typing import Any

import pytest
import zmux

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "testdata" / "pool_policy.json").read_text()
)


def test_vector_version() -> None:
    assert VECTORS["version"] == 3


@pytest.mark.parametrize("case", VECTORS["parse"], ids=lambda c: c["name"])
def test_parse(case: dict[str, Any]) -> None:
    text = case["raw"] if "raw" in case else json.dumps(case["policy"])
    if case["ok"]:
        zmux.PoolPolicy.from_json(text)
        if "policy" in case:
            zmux.PoolPolicy(case["policy"])
    else:
        with pytest.raises(ValueError) as e:
            zmux.PoolPolicy.from_json(text.encode())
        assert case.get("error", "").lower() in str(e.value).lower()


async def _until(cond: Callable[[], object]) -> None:
    while not cond():
        await asyncio.sleep(0.05)


async def _no_dial() -> zmux.PipeIo:
    raise AssertionError("not dialled")


def test_not_json() -> None:
    with pytest.raises(ValueError, match="pool"):
        zmux.PoolPolicy("{")
    with pytest.raises(ValueError):
        zmux.PipePool(
            1,
            _no_dial,
            pool_policy={"retire": [{"metric": "nope", "above": {"const": 1}}]},
        )


@pytest.mark.parametrize("case", VECTORS["decide"], ids=lambda c: c["name"])
def test_decide(case: dict[str, Any]) -> None:
    p = zmux.PoolPolicy(case["policy"])
    got: list[zmux.PoolPolicyDecision] = []
    for step in case["steps"]:
        d = p.decide(
            step.get("failures", 0),
            step.get("members", []),
            since_dial=step.get("since_dial"),
        )
        got.append(d)
        want = step.get("want", {})
        if "same_as" in want:
            assert d == got[want["same_as"]]
        for key in ("count", "retire"):
            if key in want:
                assert getattr(d, key) == want[key]
        if "dial_after_same_as" in want:
            assert d.dial_after == got[want["dial_after_same_as"]].dial_after
        if "dial_after_redrawn_from" in want:
            assert d.dial_after != got[want["dial_after_redrawn_from"]].dial_after
        for key in ("dial_after", "recheck", "probe_interval", "probe_jitter"):
            if key in want:
                if want[key] is None:
                    assert getattr(d, key) is None
                else:
                    assert getattr(d, key) == pytest.approx(want[key], abs=1e-6)
        if "count_in" in want:
            lo, hi = want["count_in"]
            assert lo <= d.count <= hi
        if "dial_after_in" in want:
            lo, hi = want["dial_after_in"]
            assert lo <= d.dial_after <= hi
        if "probe_interval_in" in want:
            lo, hi = want["probe_interval_in"]
            assert d.probe_interval is not None and lo <= d.probe_interval <= hi
        if "recheck_in" in want:
            lo, hi = want["recheck_in"]
            assert d.recheck is not None and d.recheck > 0 and lo <= d.recheck <= hi


def test_since_dial_is_checked() -> None:
    p = zmux.PoolPolicy({"dial_after": [{"const": 1}]})
    with pytest.raises(ValueError):
        p.decide(since_dial=-1)
    assert repr(p.decide(since_dial=0.5)) == (
        "PoolPolicyDecision(count=None, dial_after=1, retire=[], recheck=0.5, probe_interval=None, probe_jitter=None)"
    )


async def test_pool_count_and_age_retire() -> None:
    config = zmux.Config(max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32))
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        dials: list[int] = []

        async def dial() -> zmux.PipeIo:
            dials.append(1)
            return await zmux.dial_tcp(addr)

        policy = {
            "count": {"const": 2},
            "retire": [{"metric": "age", "above": {"const": 1}}],
        }
        async with await zmux.connect_tcp(addr, config=config) as session:
            first = session.pipes()[0].id
            pool = zmux.PipePool(1, dial, pool_policy=policy)
            handle = session.maintain_pipes(pool)

            def usable() -> list[zmux.PipeStats]:
                return [
                    s
                    for s in session.pipe_stats()
                    if s.pipe != first and s.outbound is zmux.OutboundState.ACTIVE
                ]

            # The policy's count (2) overrides the pool's (1).
            await asyncio.wait_for(_until(lambda: len(usable()) >= 2), 10)
            ids = {s.pipe for s in usable()}
            # Pipes older than a second are replaced make before break.
            await asyncio.wait_for(
                _until(lambda: len(ids & {s.pipe for s in usable()}) == 0), 15
            )
            assert len(dials) >= 4
            handle.stop()
            await asyncio.wait_for(_until(lambda: handle.finished), 5)


def test_pipe_options_are_checked() -> None:
    async def dial() -> zmux.PipeIo:
        raise AssertionError("not dialled")

    for bad in (
        zmux.PipeOptions(probe_interval=0.5),
        zmux.PipeOptions(probe_jitter=1.0),
        zmux.PipeOptions(probe_jitter=-0.1),
        zmux.PipeOptions(probe_interval=-1),
        zmux.PipeOptions(probe_interval=0),
    ):
        with pytest.raises(ValueError):
            zmux.PipePool(1, dial, options=bad)
    zmux.PipePool(1, dial, options=zmux.PipeOptions(probe_interval=1, probe_jitter=0))
    zmux.PipePool(1, dial, options=zmux.PipeOptions(idle_probes=False))
    with pytest.raises(ValueError):
        zmux.PipePool(
            1, dial, options=zmux.PipeOptions(probe_interval=2, idle_probes=False)
        )


async def test_sub_second_probe_interval_rejects_the_decision() -> None:
    config = zmux.Config(max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32))
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(addr)

        policy = {"count": {"const": 2}, "probe_interval": {"const": 0.5}}
        assert zmux.PoolPolicy(policy).decide().probe_interval == 0.5
        reasons: list[str] = []
        async with await zmux.connect_tcp(addr, config=config) as session:
            first = session.pipes()[0].id
            pool = zmux.PipePool(
                1, dial, pool_policy=policy, decision_rejected=reasons.append
            )
            handle = session.maintain_pipes(pool)

            await asyncio.wait_for(_until(lambda: len(reasons) >= 3), 10)
            await asyncio.sleep(0.5)
            # The pool's own count of 1, not the rejected 2.
            assert len([s for s in session.pipe_stats() if s.pipe != first]) == 1
            assert "probe_interval" in reasons[0]
            handle.stop()
            await asyncio.wait_for(_until(lambda: handle.finished), 5)


async def test_pool_policy_probe_settings_reach_new_pipes() -> None:
    config = zmux.Config(
        max_pipes=8,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32),
        probe_interval=2,
        probe_jitter=0.3,
    )
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(addr)

        policy = {"probe_interval": {"const": 1}, "probe_jitter": 0}
        d = zmux.PoolPolicy(policy).decide()
        assert (d.probe_interval, d.probe_jitter) == (1, 0)
        async with await zmux.connect_tcp(addr, config=config) as session:
            first = session.pipes()[0].id
            options = zmux.PipeOptions(probe_interval=5)
            handle = session.maintain_pipes(
                zmux.PipePool(1, dial, pool_policy=policy, options=options)
            )

            def pool_pipe() -> list[zmux.PipeStats]:
                return [s for s in session.pipe_stats() if s.pipe != first]

            await asyncio.wait_for(_until(lambda: len(pool_pipe()) == 1), 10)
            # A quiet pipe probed every second: its traffic clock runs on.
            await asyncio.sleep(2.5)
            s = pool_pipe()[0]
            assert s.since_last_traffic is not None and s.since_last_traffic >= 2
            handle.stop()
            await asyncio.wait_for(_until(lambda: handle.finished), 5)


def test_pool_takes_one_of_dial_and_join() -> None:
    async def join(session: zmux.Session, options: zmux.PipeOptions) -> list[zmux.Pipe]:
        raise AssertionError("not joined")

    with pytest.raises(TypeError):
        zmux.PipePool(1)
    with pytest.raises(TypeError):
        zmux.PipePool(1, _no_dial, join=join)
    zmux.PipePool(1, join=join)


def test_handwritten_decisions_are_checked() -> None:
    bad: dict[str, Any]
    for bad in (
        {"probe_interval": 0.5},
        {"probe_interval": -1},
        {"probe_jitter": 1.0},
        {"probe_jitter": -0.1},
        {"dial_after": -1},
        {"recheck": float("nan")},
    ):
        with pytest.raises(ValueError):
            zmux.PoolPolicyDecision(**bad)
    assert zmux.PoolPolicyDecision(probe_interval=0).probe_interval == 0
    d = zmux.PoolPolicyDecision(count=2, probe_interval=1, probe_jitter=0)
    assert (d.count, d.probe_interval, d.probe_jitter) == (2, 1, 0)


async def test_join_pool_keeps_groups_up_whole() -> None:
    config = zmux.Config(max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32))
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        joins: list[list[zmux.Pipe]] = []

        async def join(
            session: zmux.Session, options: zmux.PipeOptions
        ) -> list[zmux.Pipe]:
            assert isinstance(options, zmux.PipeOptions) and options.label == "group"
            pipes = [
                session.add_pipe(await zmux.dial_tcp(addr), options=options)
                for _ in range(2)
            ]
            for p in pipes:
                await p.joined()
            joins.append(pipes)
            return pipes

        async with await zmux.connect_tcp(addr, config=config) as session:
            pool = zmux.PipePool(
                1, join=join, options=zmux.PipeOptions(label="group", probation=0)
            )
            handle = session.maintain_pipes(pool)
            await asyncio.wait_for(_until(lambda: len(joins) == 1), 10)
            # One member of two pipes counts once: nothing more is joined.
            await asyncio.sleep(0.5)
            assert len(joins) == 1
            # A pipe of the member fails: the member is closed and joined again.
            joins[0][0].abort()
            await asyncio.wait_for(_until(lambda: len(joins) == 2), 10)
            await asyncio.wait_for(joins[0][1].closed(), 10)
            handle.stop()
            await asyncio.wait_for(_until(lambda: handle.finished), 5)


def test_negative_member_metrics_and_rotate_age_raise() -> None:
    p = zmux.PoolPolicy({"count": {"const": 1}})
    for m in (
        {"id": 1, "age": -1},
        {"id": 1, "idle": float("nan")},
        {"id": 1, "pipes": -2},
    ):
        with pytest.raises(ValueError):
            p.decide(0, [m])
    with pytest.raises(ValueError):
        zmux.PipePool(1, _no_dial, rotate_max_age=-1)
