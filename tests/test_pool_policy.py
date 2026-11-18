import asyncio
import dataclasses
import logging
import threading
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
        zmux.helpers.MachinePoolPolicy("{")
    with pytest.raises(ValueError):
        zmux.helpers.MachinePoolPolicy({"retire": [{"metric": "nope", "above": 1}]})


def test_a_policy_is_an_object_with_decide() -> None:
    # The JSON is read by `MachinePoolPolicy`; a pool takes no JSON or function.
    for bad in ({"count": 1}, '{"count": 1}', lambda view: zmux.helpers.PoolDecision()):
        with pytest.raises(TypeError):
            zmux.helpers.PipePool(1, _no_dial, policy=bad)  # type: ignore[arg-type]
    zmux.helpers.PipePool(1, _no_dial, policy=zmux.helpers.MachinePoolPolicy({}))
    zmux.helpers.PipePool(1, _no_dial, policy=Fixed(zmux.helpers.PoolDecision()))
    assert not hasattr(zmux.helpers, "PoolPolicyDecision")
    with pytest.raises(TypeError):
        zmux.helpers.PipePool(1, _no_dial, pool_policy={})  # type: ignore[call-arg]


def test_since_last_dial_is_checked() -> None:
    p = zmux.helpers.MachinePoolPolicy({"dial_after": [1000000]})
    with pytest.raises(ValueError):
        p.decide(zmux.helpers.PoolView(since_last_dial=-1))
    d = p.decide(zmux.helpers.PoolView(since_last_dial=0.5))
    assert d == zmux.helpers.PoolDecision(dial_after=1.0, recheck=0.5)
    assert zmux.helpers.PoolDecision().count is zmux.INHERIT


class Fixed:
    """A policy of a fixed decision, remembering the views it was asked."""

    def __init__(self, decision: zmux.helpers.PoolDecision) -> None:
        self.decision = decision
        self.views: list[zmux.helpers.PoolView] = []
        self.threads: set[int] = set()

    def decide(self, view: zmux.helpers.PoolView) -> zmux.helpers.PoolDecision:
        self.views.append(view)
        self.threads.add(threading.get_ident())
        return self.decision


async def test_pool_count_and_age_retire() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        dials: list[int] = []

        async def dial() -> zmux.PipeIo:
            dials.append(1)
            return await zmux.dial_tcp(*addr)

        policy = {
            "count": 2,
            "retire": [{"metric": "age", "above": 1000000}],
        }
        async with await zmux.connect_tcp(*addr, config=config) as session:
            first = session.pipes()[0].id
            pool = zmux.helpers.PipePool(
                1, dial, policy=zmux.helpers.MachinePoolPolicy(policy)
            )
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
            zmux.helpers.PipePool(1, dial, options=bad)
    zmux.helpers.PipePool(
        1,
        dial,
        options=zmux.PipeOptions(liveness=PL(probe_interval=1, probe_jitter=0)),
    )
    # None turns the idle probes off.
    zmux.helpers.PipePool(
        1, dial, options=zmux.PipeOptions(liveness=PL(probe_interval=None))
    )


async def test_sub_second_probe_interval_rejects_the_decision() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(*addr)

        policy = zmux.helpers.MachinePoolPolicy({"count": 2, "probe_interval": 500000})
        with pytest.raises(ValueError, match="probe_interval"):
            policy.decide(zmux.helpers.PoolView())
        reasons: list[BaseException] = []
        async with await zmux.connect_tcp(*addr, config=config) as session:
            first = session.pipes()[0].id
            pool = zmux.helpers.PipePool(
                1, dial, policy=policy, decision_rejected=reasons.append
            )
            handle = session.maintain_pipes(pool)

            await asyncio.wait_for(_until(lambda: len(reasons) >= 3), 10)
            await asyncio.sleep(0.5)
            # The pool's own count of 1, not the rejected 2.
            assert len([s for s in session.pipe_stats() if s.pipe != first]) == 1
            assert isinstance(reasons[0], ValueError)
            assert "probe_interval" in str(reasons[0])
            handle.stop()
            await asyncio.wait_for(_until(lambda: handle.finished), 5)


async def test_pool_policy_probe_settings_reach_new_pipes() -> None:
    config = zmux.Config(
        max_pipes=8,
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        liveness=zmux.Liveness(probe_interval=2, probe_jitter=0.3),
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(*addr)

        policy = zmux.helpers.MachinePoolPolicy(
            {"probe_interval": 1000000, "probe_jitter": 0}
        )
        live = policy.decide(zmux.helpers.PoolView()).liveness
        assert (live.probe_interval, live.probe_jitter) == (1, 0)
        async with await zmux.connect_tcp(*addr, config=config) as session:
            first = session.pipes()[0].id
            options = zmux.PipeOptions(liveness=zmux.PipeLiveness(probe_interval=5))
            handle = session.maintain_pipes(
                zmux.helpers.PipePool(1, dial, policy=policy, options=options)
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
        zmux.helpers.PipePool(1)
    with pytest.raises(TypeError):
        zmux.helpers.PipePool(1, _no_dial, join=join)
    zmux.helpers.PipePool(1, join=join)


def test_handwritten_decisions_are_checked() -> None:
    bad: dict[str, Any]
    PL = zmux.PipeLiveness
    for bad in (
        {"count": 0},
        {"count": -1},
        {"count": 1.5},
        {"dial_after": -1},
        {"dial_after": float("nan")},
        {"recheck": 0},
        {"recheck": -1},
        {"recheck": float("nan")},
        {"liveness": PL(probe_interval=0.5)},
        {"liveness": PL(probe_jitter=1.0)},
        {"liveness": PL(probe_jitter=-0.1)},
    ):
        with pytest.raises(ValueError):
            zmux.helpers.PoolDecision(**bad)
    d = zmux.helpers.PoolDecision()
    assert (d.count, d.dial_after, d.retire_pipes, d.recheck) == (
        zmux.INHERIT,
        zmux.INHERIT,
        (),
        None,
    )
    assert d.liveness == PL()
    d = zmux.helpers.PoolDecision(
        count=2,
        dial_after=0,
        retire_pipes=[zmux.PipeId(3), zmux.PipeId(0)],
        recheck=0.001,
        liveness=PL(probe_interval=None),
    )
    assert (d.count, d.dial_after, d.retire_pipes, d.recheck) == (2, 0, (3, 0), 0.001)
    assert d.liveness.probe_interval is None


def test_views_and_members_are_built_directly() -> None:
    m = zmux.helpers.PoolMember(pipe=zmux.PipeId(4), idle=2.5, usable=True)
    assert (m.pipe, m.age, m.idle, m.pipes, m.usable, m.replacing) == (
        4,
        0.0,
        2.5,
        0,
        True,
        False,
    )
    assert zmux.helpers.PoolMember().pipe == 0
    v = zmux.helpers.PoolView(members=[m], failures=2, dialing=1)  # type: ignore[arg-type]
    assert v.members == (m,) and v.since_last_dial is None
    zmux.helpers.PoolView()


def test_machine_policy_decides_on_a_built_view() -> None:
    p = zmux.helpers.MachinePoolPolicy(
        {"count": 3, "retire": [{"metric": "age", "above": 2000000}]}
    )
    old, young = (
        zmux.helpers.PoolMember(pipe=zmux.PipeId(7), age=5.0),
        zmux.helpers.PoolMember(pipe=zmux.PipeId(8), age=1.0),
    )
    d = p.decide(zmux.helpers.PoolView(members=(old, young)))
    assert d.count == 3 and d.retire_pipes == (7,)
    # A metric out of range is a ValueError.
    for bad in (
        zmux.helpers.PoolMember(age=-1),
        zmux.helpers.PoolMember(idle=float("nan")),
    ):
        with pytest.raises(ValueError):
            p.decide(zmux.helpers.PoolView(members=(bad,)))


async def _session_pool(
    config: zmux.Config,
    run: Callable[[zmux.Session, zmux.PipeId, Callable[[], Any]], Any],
) -> None:
    """Runs `run(session, first_pipe, dial)` on a client of a listener."""
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)

        async def dial() -> zmux.PipeIo:
            return await zmux.dial_tcp(*addr)

        async with await zmux.connect_tcp(*addr, config=config) as session:
            await run(session, session.pipes()[0].id, dial)


POOL_CONFIG = zmux.Config(
    max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
)


async def test_a_python_policy_runs_on_the_event_loop() -> None:
    async def run(session: zmux.Session, first: zmux.PipeId, dial: Any) -> None:
        policy = Fixed(zmux.helpers.PoolDecision(count=2, recheck=0.02))
        handle = session.maintain_pipes(zmux.helpers.PipePool(1, dial, policy=policy))

        def usable() -> list[zmux.PipeStats]:
            return [
                s
                for s in session.pipe_stats()
                if s.pipe != first and s.outbound is zmux.OutboundState.ACTIVE
            ]

        # The policy's count (2) overrides the pool's (1).
        await asyncio.wait_for(_until(lambda: len(usable()) >= 2), 10)
        # Asked on the event loop's thread, never a runtime thread.
        assert policy.threads == {threading.get_ident()}
        views = list(policy.views)
        assert views[0].members == () and views[0].failures == 0
        assert views[0].since_last_dial is None
        later = [v for v in views if len(v.members) == 2]
        assert later and all(
            isinstance(m, zmux.helpers.PoolMember) and m.pipes == 1
            for m in later[-1].members
        )
        assert {m.pipe for m in later[-1].members} == {s.pipe for s in usable()}
        # A view during the first dial counts it.
        assert any(v.dialing >= 1 for v in views)
        # Its recheck of 20 ms makes it look far more often than every 100 ms.
        before = len(policy.views)
        await asyncio.sleep(1.0)
        assert len(policy.views) - before >= 20
        handle.stop()
        await asyncio.wait_for(_until(lambda: handle.finished), 5)

    await _session_pool(POOL_CONFIG, run)


async def test_a_python_policy_retires_a_member_and_sets_liveness() -> None:
    class Retire:
        def __init__(self) -> None:
            self.done = False
            self.first: zmux.PipeId | None = None

        def decide(self, view: zmux.helpers.PoolView) -> zmux.helpers.PoolDecision:
            live = zmux.PipeLiveness(probe_interval=3.0, probe_jitter=0.0)
            members = [m for m in view.members if m.usable]
            if members and not self.done:
                self.done = True
                self.first = members[0].pipe
                return zmux.helpers.PoolDecision(
                    retire_pipes=[members[0].pipe], liveness=live
                )
            return zmux.helpers.PoolDecision(liveness=live)

    async def run(session: zmux.Session, first: zmux.PipeId, dial: Any) -> None:
        policy = Retire()
        handle = session.maintain_pipes(zmux.helpers.PipePool(1, dial, policy=policy))

        def pool_pipes() -> set[zmux.PipeId]:
            return {
                s.pipe
                for s in session.pipe_stats()
                if s.pipe != first and s.outbound is zmux.OutboundState.ACTIVE
            }

        await asyncio.wait_for(_until(lambda: policy.first is not None), 10)
        old = policy.first
        # Replaced now, make before break: another pipe takes over.
        await asyncio.wait_for(
            _until(lambda: pool_pipes() and old not in pool_pipes()), 15
        )
        handle.stop()
        await asyncio.wait_for(_until(lambda: handle.finished), 5)

    await _session_pool(POOL_CONFIG, run)


class Rejecting:
    def __init__(self, what: object) -> None:
        self.what = what
        self.looks = 0

    def decide(self, view: zmux.helpers.PoolView) -> zmux.helpers.PoolDecision:
        self.looks += 1
        if isinstance(self.what, BaseException):
            raise self.what
        return self.what  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("what", "kind"),
    [
        (RuntimeError("no way"), RuntimeError),
        ("not a decision", TypeError),
    ],
)
async def test_a_rejected_look_goes_to_decision_rejected(
    what: object, kind: type[BaseException]
) -> None:
    async def run(session: zmux.Session, first: zmux.PipeId, dial: Any) -> None:
        policy = Rejecting(what)
        reasons: list[BaseException] = []
        threads: set[int] = set()

        def rejected(e: BaseException) -> None:
            threads.add(threading.get_ident())
            reasons.append(e)

        pool = zmux.helpers.PipePool(1, dial, policy=policy, decision_rejected=rejected)
        handle = session.maintain_pipes(pool)
        await asyncio.wait_for(_until(lambda: len(reasons) >= 3), 10)
        # The pool's own behaviour went on: its one member is up.
        await asyncio.wait_for(
            _until(
                lambda: len([s for s in session.pipe_stats() if s.pipe != first]) == 1
            ),
            10,
        )
        assert isinstance(reasons[0], kind)
        if isinstance(what, BaseException):
            assert reasons[0] is what
        assert threads == {threading.get_ident()}
        handle.stop()
        await asyncio.wait_for(_until(lambda: handle.finished), 5)

    await _session_pool(POOL_CONFIG, run)


async def test_a_rejected_look_without_a_callback_is_logged() -> None:
    messages: list[str] = []

    class Log(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    logger = logging.getLogger("zmux-test-pool")
    logger.addHandler(Log())
    logger.setLevel(logging.DEBUG)
    config = dataclasses.replace(POOL_CONFIG, logger=logger)

    async def run(session: zmux.Session, first: zmux.PipeId, dial: Any) -> None:
        policy = Rejecting(RuntimeError("no way"))
        handle = session.maintain_pipes(zmux.helpers.PipePool(1, dial, policy=policy))
        await asyncio.wait_for(
            _until(lambda: any("pool decision rejected" in m for m in messages)), 10
        )
        assert any("no way" in m for m in messages)
        handle.stop()
        await asyncio.wait_for(_until(lambda: handle.finished), 5)

    await _session_pool(config, run)


async def test_join_pool_keeps_groups_up_whole() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(instance_id=b"instance", max_suspended=16),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        joins: list[list[zmux.Pipe]] = []

        async def join(
            session: zmux.Session, options: zmux.PipeOptions
        ) -> list[zmux.Pipe]:
            assert isinstance(options, zmux.PipeOptions) and options.label == "group"
            pipes = [
                await session.add_pipe(await zmux.dial_tcp(*addr), options=options)
                for _ in range(2)
            ]
            for p in pipes:
                await p.joined()
            joins.append(pipes)
            return pipes

        async with await zmux.connect_tcp(*addr, config=config) as session:
            pool = zmux.helpers.PipePool(
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
            await asyncio.wait_for(joins[0][1].wait_closed(), 10)
            handle.stop()
            await asyncio.wait_for(_until(lambda: handle.finished), 5)


def test_rotate_age_raises() -> None:
    with pytest.raises(ValueError):
        zmux.helpers.PipePool(1, _no_dial, rotate_max_age=-1)
