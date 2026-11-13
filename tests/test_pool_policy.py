import asyncio
from collections.abc import Callable
from typing import Any

import pytest
import zmux


async def _until(cond: Callable[[], object]) -> None:
    while not cond():
        await asyncio.sleep(0.05)


async def _no_dial() -> zmux.PipeIo:
    raise AssertionError("not dialled")


def test_not_json() -> None:
    with pytest.raises(ValueError, match="syntax"):
        zmux.PoolPolicy("{")
    with pytest.raises(ValueError):
        zmux.PipePool(
            1,
            _no_dial,
            pool_policy={"retire": [{"metric": "nope", "above": 1}]},
        )


def test_since_dial_is_checked() -> None:
    p = zmux.PoolPolicy({"dial_after": [1000000]})
    with pytest.raises(ValueError):
        p.decide(since_dial=-1)
    assert repr(p.decide(since_dial=0.5)) == (
        "PoolPolicyDecision(count=None, dial_after=1, retire=[], recheck=0.5, probe_interval=None, probe_jitter=None)"
    )


async def test_pool_count_and_age_retire() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        dials: list[int] = []

        async def dial() -> zmux.PipeIo:
            dials.append(1)
            return await zmux.dial_tcp(addr)

        policy = {
            "count": 2,
            "retire": [{"metric": "age", "above": 1000000}],
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

    PL = zmux.PipeLiveness
    for bad in (
        zmux.PipeOptions(liveness=PL(probe_interval=0.5)),
        zmux.PipeOptions(liveness=PL(probe_jitter=1.0)),
        zmux.PipeOptions(liveness=PL(probe_jitter=-0.1)),
        zmux.PipeOptions(liveness=PL(probe_interval=-1)),
        zmux.PipeOptions(liveness=PL(probe_interval=0)),
    ):
        with pytest.raises(ValueError):
            zmux.PipePool(1, dial, options=bad)
    zmux.PipePool(
        1,
        dial,
        options=zmux.PipeOptions(liveness=PL(probe_interval=1, probe_jitter=0)),
    )
    # None turns the idle probes off.
    zmux.PipePool(1, dial, options=zmux.PipeOptions(liveness=PL(probe_interval=None)))


async def test_sub_second_probe_interval_rejects_the_decision() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(addr)

        policy = {"count": 2, "probe_interval": 500000}
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
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        liveness=zmux.Liveness(probe_interval=2, probe_jitter=0.3),
    )
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(addr)

        policy = {"probe_interval": 1000000, "probe_jitter": 0}
        d = zmux.PoolPolicy(policy).decide()
        assert (d.probe_interval, d.probe_jitter) == (1, 0)
        async with await zmux.connect_tcp(addr, config=config) as session:
            first = session.pipes()[0].id
            options = zmux.PipeOptions(liveness=zmux.PipeLiveness(probe_interval=5))
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
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
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
                await session.add_pipe(await zmux.dial_tcp(addr), options=options)
                for _ in range(2)
            ]
            for p in pipes:
                await p.joined()
            joins.append(pipes)
            return pipes

        async with await zmux.connect_tcp(addr, config=config) as session:
            pool = zmux.PipePool(
                1, join=join, options=zmux.PipeOptions(label="group", probation=None)
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
    p = zmux.PoolPolicy({"count": 1})
    for m in (
        {"id": 1, "age": -1},
        {"id": 1, "idle": float("nan")},
        {"id": 1, "pipes": -2},
    ):
        with pytest.raises(ValueError):
            p.decide(0, [m])
    with pytest.raises(ValueError):
        zmux.PipePool(1, _no_dial, rotate_max_age=-1)
