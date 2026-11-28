"""Splice bindings driven by stream events and the splice-hooks contract vectors."""

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Literal, cast

import pytest
import zmux
from zmux.helpers import (
    SpliceCommandError,
    SpliceDecision,
    SpliceEnd,
    SpliceEvent,
    SpliceHandoffStats,
    SpliceHooks,
    SpliceLimits,
    SpliceMirror,
    SpliceSignal,
    SpliceUnit,
    controlled_splice,
    controlled_splice_packets,
    splice,
)

from support import LOOPBACK, QUIET_LIVENESS, WATCHDOG, tcp_pair
from test_limiter import Recording
from test_packet import DGRAM


def vector(name: str) -> dict[str, Any]:
    path = Path(__file__).parent / "testdata" / "contracts" / "splice-hooks.json"
    contract = json.loads(path.read_text(encoding="utf-8"))
    cases = cast("list[dict[str, Any]]", contract["cases"])
    return next(case for case in cases if case["id"] == name)


@asynccontextmanager
async def hops(
    config: zmux.Config | None = None,
) -> AsyncIterator[tuple[zmux.BiStream, zmux.BiStream, zmux.BiStream, zmux.BiStream]]:
    async with (
        tcp_pair(config, config) as (source, relay_in, _),
        tcp_pair(config, config) as (relay_out, sink, _),
    ):
        client = await source.open_bi(info=b"splice")
        await client.send.flush()
        inbound = await relay_in.accept_bi()
        outbound = await relay_out.open_bi()
        await outbound.send.flush()
        server = await sink.accept_bi()
        yield client, inbound, outbound, server


async def finish(client: zmux.BiStream, server: zmux.BiStream) -> None:
    await client.send.finish()
    await server.send.finish()


async def test_detach_keeps_admitted_generation_and_revokes_views() -> None:
    case = vector("detach-keeps-admitted-generation")
    setup, steps = case["setup"], case["steps"]
    ready = asyncio.Event()
    resume = SpliceSignal()
    escaped: list[SpliceUnit] = []
    events: list[SpliceEvent] = []
    scope = ContextVar("splice-test", default="unset")
    loop = asyncio.get_running_loop()

    def hold(input_unit: SpliceUnit) -> SpliceDecision:
        assert scope.get() == "captured"
        assert asyncio.get_running_loop() is loop
        assert input_unit.meta.preamble.info == b"splice"
        assert input_unit.meta.label == "outgoing"
        assert input_unit.meta.source_offset == 0
        assert input_unit.meta.generation == setup["hook_generation"]
        assert input_unit.byte_at(0) == bytes.fromhex(steps[0]["args"]["hex"])[0]
        escaped.append(input_unit)
        input_unit.append(bytes.fromhex(setup["hook"]["replace_payloads_hex"][0]))
        ready.set()
        return SpliceDecision.replace(resume=resume)

    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        token = scope.set("captured")
        try:
            ctl, run = controlled_splice(
                left,
                right,
                a_to_b_hooks=SpliceHooks(stream=(hold,)),
                a_to_b_label="outgoing",
                on_event=events.append,
            )
        finally:
            scope.reset(token)
        relay = tasks.create_task(run)
        await a.send.write(bytes.fromhex(steps[0]["args"]["hex"]))
        await ready.wait()
        unit = escaped[0]
        assert unit.meta.route == "a_to_b"
        for access in (lambda: len(unit), unit.read, unit.append_slice):
            with pytest.raises(RuntimeError, match="hook has returned"):
                access()
        with pytest.raises(TypeError):
            memoryview(unit)  # type: ignore[arg-type]
        assert (
            await ctl.a_to_b.replace_hooks(SpliceHooks())
            == steps[4]["values"]["events"][0]["generation"]
        )
        resume.resume()
        await a.send.write(bytes.fromhex(steps[7]["args"]["hex"]))
        await finish(a, b)
        assert (await b.recv.read_to_end()).hex() == steps[9]["values"][
            "received_reliable_hex"
        ]
        assert await a.recv.read_to_end() == b""
        done = await relay
    assert done.a_to_b.replacements == 1
    assert [(e.kind, e.generation) for e in events if e.route == "a_to_b"] == [
        ("hooks_replaced", 2),
        ("direction_finished", None),
    ]
    assert len(escaped) == steps[10]["values"]["hook_calls"]


async def test_stop_rejects_paused_injection_and_keeps_reverse_direction() -> None:
    case = vector("stop-wins-over-resume")
    steps = case["steps"]
    code = steps[4]["args"]["code"]
    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        ctl, run = controlled_splice(left, right)
        relay = tasks.create_task(run)
        pause = await ctl.a_to_b.pause()
        await pause.acknowledged()
        with pytest.raises(SpliceCommandError) as error:
            await ctl.a_to_b.inject(bytes.fromhex(steps[2]["args"]["hex"]))
        assert error.value.reason == steps[3]["values"]["reason"]
        b.recv.stop(code)
        assert await a.send.stopped() == code
        with pytest.raises(SpliceCommandError) as closed:
            await ctl.a_to_b.resume(pause)
        assert closed.value.reason == "closed"
        assert await ctl.a_to_b.finished() == (SpliceEnd.STOPPED, code)
        await b.send.write(b"reverse")
        await b.send.finish()
        assert await a.recv.read_to_end() == b"reverse"
        result = await relay
    assert result.a_to_b.enqueued_items == steps[7]["values"]["enqueued_items"]


async def test_one_to_many_datagrams_take_exact_credit_for_the_current_items() -> None:
    case = vector("one-to-many-logical-charge-on-first-handoff")
    setup = case["setup"]
    outputs = [bytes.fromhex(p) for p in setup["hook"]["replace_payloads_hex"]]
    args = case["steps"][0]["args"]
    limiter = Recording()

    def replace(unit: SpliceUnit) -> SpliceDecision:
        assert not unit.meta.injected
        assert unit.meta.context == args["context"]
        assert unit.read().hex() == args["hex"]
        for output in outputs:
            unit.append(output)
        return SpliceDecision.replace()

    async with hops(DGRAM) as (a, left, right, b), asyncio.TaskGroup() as tasks:
        control, run = controlled_splice_packets(
            left, right, a_to_b_hooks=SpliceHooks(datagram=(replace,)), a_to_b=limiter
        )
        relay = tasks.create_task(run)
        a.send.send_datagram(bytes.fromhex(args["hex"]), context=args["context"])
        got = [(await b.recv.read_datagram()).payload for _ in outputs]
        assert sorted(got) == sorted(outputs)
        await finish(a, b)
        assert await a.recv.read_to_end() == await b.recv.read_to_end() == b""
        result = await relay
    assert result.a_to_b.replacements == 1
    assert result.a_to_b.datagram_bytes == setup["exact_credit"]
    total = sum(map(len, outputs))
    assert limiter.calls == [("try_acquire", total, total)]
    handoffs = result.a_to_b.handoffs
    assert handoffs is not None
    assert handoffs.snapshot() == control.a_to_b.handoffs.snapshot()
    assert handoffs.snapshot() == SpliceHandoffStats(
        accepted_bytes=total,
        first_carrier_bytes=total,
        unsent_bytes=0,
        pending_bytes=0,
        unsent_refunded_bytes=0,
        native_count=0,
        record_count=len(outputs),
    )


async def test_complete_capsules_take_exact_credit_and_stop_discards_waiting_unit() -> (
    None
):
    case = vector("capsule-write-prefix-and-receipt")
    steps = case["steps"]
    wire = bytes.fromhex(steps[0]["args"]["hex"])
    args = steps[2]["args"]
    first = wire[slice(*args["accepted_output_ranges"][0])]
    held = SpliceSignal()
    seen = asyncio.Event()
    limiter = Recording()
    shapes: list[tuple[int | None, bytes]] = []

    def inspect(unit: SpliceUnit) -> SpliceDecision:
        shapes.append((unit.meta.capsule_type, unit.read()))
        unit.append_slice()
        if len(shapes) == 2:
            seen.set()
            return SpliceDecision.replace(resume=held)
        return SpliceDecision.replace()

    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        ctl, run = controlled_splice_packets(
            left, right, a_to_b_hooks=SpliceHooks(capsule=(inspect,)), a_to_b=limiter
        )
        relay = tasks.create_task(run)
        await a.send.write(wire)
        await seen.wait()
        assert await b.recv.read_exact(len(first)) == first
        b.recv.stop(args["code"])
        assert await a.send.stopped() == args["code"]
        assert await ctl.a_to_b.finished() == (SpliceEnd.STOPPED, args["code"])
        held.resume()
        await b.send.finish()
        assert await a.recv.read_to_end() == b""
        result = await relay
    assert shapes == [(wire[0], b"a"), (wire[len(first)], b"b")]
    assert result.a_to_b.bytes == len(first)
    assert limiter.calls == [("acquire", len(first), len(first))]


@pytest.mark.parametrize("mode", ["copy", "lease"])
async def test_replacement_chain_and_bounded_mirror(
    mode: Literal["copy", "lease"],
) -> None:
    mirror = SpliceMirror(1, prefix=1, mode=mode, backing_bytes=16)
    seen: list[tuple[int, int]] = []

    def split(unit: SpliceUnit) -> SpliceDecision:
        seen.append((unit.meta.sequence, unit.meta.generation))
        unit.append_slice(0, stop=1)
        unit.append_slice(1)
        return SpliceDecision.replace()

    def reorder(unit: SpliceUnit) -> SpliceDecision:
        assert (unit.meta.sequence, unit.meta.generation) == seen[-1]
        assert len(unit) == 2
        unit.append_slice(item=1)
        unit.append_slice(item=0)
        return SpliceDecision.replace()

    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        ctl, run = controlled_splice(
            left,
            right,
            a_to_b_hooks=SpliceHooks(stream=(split, reorder)),
            a_to_b_mirror=mirror,
        )
        relay = tasks.create_task(run)
        first = await ctl.a_to_b.inject(bytearray(b"ab"))
        second = await ctl.a_to_b.inject(b"cd")
        first_result = await first.disposition()
        assert first_result.status == "submitted"
        assert first_result.sequence == first.sequence
        assert first_result.generation == first.generation
        assert first_result.accepted_bytes == first_result.enqueued_items == 2
        assert first_result == await first.disposition()
        assert (await second.disposition()).enqueued_items == 2
        sample = await mirror.recv()
        assert (
            sample is not None
            and sample.prefix == b"a"
            and sample.sequence == first.sequence
        )
        if mode == "lease":
            assert isinstance(sample.prefix, memoryview) and sample.prefix.readonly
            sample.prefix.release()
        else:
            assert isinstance(sample.prefix, bytes)
        await finish(a, b)
        assert await b.recv.read_to_end() == b"badc"
        assert await a.recv.read_to_end() == b""
        done = await relay
        assert await mirror.recv() is None
    assert done.a_to_b.mirror_misses == 1


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
@pytest.mark.parametrize("action", ["reset", "budget", "raise"])
async def test_hook_failure_and_reset_finish_only_one_direction(action: str) -> None:
    def hook(unit: SpliceUnit) -> SpliceDecision:
        if action == "reset":
            return SpliceDecision.reset(0)
        if action == "budget":
            unit.append(b"x")
            with pytest.raises(ValueError):
                unit.append(b"y")
            return SpliceDecision.pass_()
        raise LookupError("hook failed")

    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        _, run = controlled_splice(
            left,
            right,
            a_to_b_hooks=SpliceHooks(stream=(hook,)),
            limits=SpliceLimits(group_items=1),
        )
        relay = tasks.create_task(run)
        await a.send.write(b"trigger")
        code = 0 if action == "reset" else zmux.ApplicationErrorCode.ZMUX_CANCELLED
        with pytest.raises(zmux.StreamResetError) as error:
            await b.recv.read_to_end()
        assert error.value.code == code
        assert await a.send.stopped() == code
        await b.send.write(b"reverse")
        await b.send.finish()
        assert await a.recv.read_to_end() == b"reverse"
        result = await relay
    want = SpliceEnd.HOOK_RESET if action == "reset" else SpliceEnd.HOOK_FAILED
    assert (result.a_to_b.end, result.a_to_b.code) == (
        want,
        code if action == "reset" else None,
    )


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
@pytest.mark.parametrize("refund_raises", [False, True])
async def test_cancel_splice_refunds_a_late_limiter_grant(refund_raises: bool) -> None:
    asked = asyncio.Event()
    refunded = asyncio.Event()

    class Late(Recording):
        async def acquire(self, lo: int, hi: int, /) -> int:
            asked.set()
            with suppress(asyncio.CancelledError):
                await asyncio.Future[None]()
            return await super().acquire(lo, hi)

        def refund(self, n: int, /) -> None:
            super().refund(n)
            refunded.set()
            if refund_raises:
                raise RuntimeError("refund callback failed")

    limiter = Late()
    async with (
        asyncio.timeout(WATCHDOG),
        hops() as (a, left, right, b),
        asyncio.TaskGroup() as tasks,
    ):
        relay = tasks.create_task(splice(left, right, a_to_b=limiter))
        await a.send.write(b"grant")
        await asked.wait()
        relay.cancel()
        with pytest.raises(asyncio.CancelledError):
            await relay
        await refunded.wait()
        with pytest.raises(zmux.StreamResetError):
            await b.recv.read_to_end()
        assert limiter.used == 0


async def test_controlled_splice_counts_late_grant_before_admission() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class Late(Recording):
        async def acquire(self, lo: int, hi: int, /) -> int:
            entered.set()
            with suppress(asyncio.CancelledError):
                await asyncio.Future[None]()
            await release.wait()
            return await super().acquire(lo, hi)

    limiter = Late()
    async with hops() as (a, left, right, _), asyncio.TaskGroup() as tasks:
        control, run = controlled_splice(left, right, a_to_b=limiter)
        relay = tasks.create_task(run)
        try:
            await a.send.write(b"grant")
            await entered.wait()
            control.abort(0)
            result = await relay
            assert result.a_to_b.pre_admission_refunded_bytes == 0
            assert control.a_to_b.pre_admission_refunded_bytes == 0
            release.set()
            await limiter.wait_for(lambda: limiter.refunded == 5)
            assert limiter.granted == 5 and limiter.used == 0
            assert control.a_to_b.pre_admission_refunded_bytes == 5
            assert result.a_to_b.pre_admission_refunded_bytes == 0
            assert control.a_to_b.handoffs.snapshot() == SpliceHandoffStats(
                0, 0, 0, 0, 0, 0, 0
            )
        finally:
            release.set()


async def test_splice_refunds_accepted_bytes_before_first_handoff() -> None:
    config = zmux.Config(
        pipe_auth=zmux.PipeAuth.psk(bytes(32)).with_end_to_end(),
        liveness=QUIET_LIVENESS,
        resume_timeout=60,
    )
    limiter = Recording()
    async with (
        tcp_pair() as (source, relay_in, _),
        zmux.Listener(config=config) as listener,
        asyncio.TaskGroup() as tasks,
    ):
        address = await listener.serve_tcp(LOOPBACK, 0)
        async with (
            await zmux.connect_tcp(*address, config=config) as relay_out,
            await listener.accept() as sink,
        ):
            try:
                client = await source.open_bi()
                await client.send.flush()
                inbound = await relay_in.accept_bi()
                outbound = await relay_out.open_bi()
                await outbound.send.flush()
                server = await sink.accept_bi()
                assert server.recv.id == outbound.send.id
                await relay_out.ping()
                relay_out.pipes()[0].abort()
                async for event in relay_out.events():
                    if isinstance(event, zmux.SessionSuspended):
                        break
                else:
                    pytest.fail("target did not suspend")

                control, run = controlled_splice(inbound, outbound, a_to_b=limiter)
                relay = tasks.create_task(run)
                receipt = await control.a_to_b.inject(b"prepaid")
                disposition = await receipt.disposition()
                assert (disposition.status, disposition.accepted_bytes) == (
                    "submitted",
                    7,
                )
                handoffs = control.a_to_b.handoffs
                assert handoffs.snapshot() == SpliceHandoffStats(7, 0, 0, 7, 0, 0, 0)

                control.abort(0)
                result = await relay
                await limiter.wait_for(lambda: limiter.refunded == 7)
                assert limiter.used == 0
                result_handoffs = result.a_to_b.handoffs
                assert result_handoffs is not None
                assert result_handoffs.snapshot() == handoffs.snapshot()
                assert handoffs.snapshot() == SpliceHandoffStats(7, 0, 7, 0, 7, 0, 0)
                assert control.a_to_b.pre_admission_refunded_bytes == 0
            finally:
                relay_out.abort(0)
                sink.abort(0)


async def test_invalid_splice_leaves_all_halves_available() -> None:
    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        with pytest.raises(ValueError, match="different streams"):
            await splice(left, (right.send, b.recv))
        relay = tasks.create_task(splice(left, right))
        await a.send.write(b"left")
        await b.send.write(b"right")
        await finish(a, b)
        assert await b.recv.read_to_end() == b"left"
        assert await a.recv.read_to_end() == b"right"
        await relay


async def test_splice_limiter_must_declare_a_whole_group_burst() -> None:
    limiter = Recording()
    limiter.max_burst_bytes = 1
    async with hops() as (_, left, right, _):
        with pytest.raises(ValueError, match="invalid_parameter"):
            await splice(left, right, a_to_b=limiter)
    assert not limiter.calls


async def test_dropping_pause_token_releases_admission() -> None:
    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        ctl, run = controlled_splice(left, right)
        relay = tasks.create_task(run)
        pause = await ctl.a_to_b.pause()
        await pause.acknowledged()
        del pause
        receipt = await ctl.a_to_b.inject(b"released")
        assert (await receipt.disposition()).enqueued_items == 1
        await finish(a, b)
        assert await b.recv.read_to_end() == b"released"
        assert await a.recv.read_to_end() == b""
        await relay


async def test_unready_datagram_can_be_overtaken() -> None:
    resume = SpliceSignal()

    def defer_first(unit: SpliceUnit) -> SpliceDecision:
        if unit.meta.context == 1:
            return SpliceDecision.pass_(resume=resume)
        return SpliceDecision.pass_()

    async with hops(DGRAM) as (a, left, right, b), asyncio.TaskGroup() as tasks:
        ctl, run = controlled_splice(
            left,
            right,
            a_to_b_hooks=SpliceHooks(datagram=(defer_first,)),
            limits=SpliceLimits(datagram_delay=True),
        )
        relay = tasks.create_task(run)
        first = await ctl.a_to_b.inject(b"first", kind="datagram", context=1)
        second = await ctl.a_to_b.inject(b"second", kind="datagram", context=2)
        assert (await second.disposition()).enqueued_items == 1
        assert await b.recv.read_datagram() == (2, b"second")
        resume.resume()
        assert (await first.disposition()).enqueued_items == 1
        assert await b.recv.read_datagram() == (1, b"first")
        await finish(a, b)
        assert await a.recv.read_to_end() == await b.recv.read_to_end() == b""
        await relay


async def test_cancelled_pause_before_admission_does_not_pause_direction() -> None:
    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        ctl, run = controlled_splice(left, right)
        try:
            pause = tasks.create_task(ctl.a_to_b.pause())
            next_turn = asyncio.Event()
            asyncio.get_running_loop().call_soon(next_turn.set)
            await next_turn.wait()
            pause.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pause
        except BaseException:
            run.close()
            raise
        relay = tasks.create_task(run)
        receipt = await ctl.a_to_b.inject(b"still running")
        assert (await receipt.disposition()).enqueued_items == 1
        await finish(a, b)
        assert await b.recv.read_to_end() == b"still running"
        assert await a.recv.read_to_end() == b""
        await relay


async def test_immediate_wait_expiry_ends_only_reliable_direction() -> None:
    resume = SpliceSignal()

    def expire(_: SpliceUnit) -> SpliceDecision:
        return SpliceDecision.pass_(resume=resume, timeout=0)

    async with hops() as (a, left, right, b), asyncio.TaskGroup() as tasks:
        _, run = controlled_splice(
            left, right, a_to_b_hooks=SpliceHooks(stream=(expire,))
        )
        relay = tasks.create_task(run)
        await a.send.write(b"blocked")
        code = zmux.ApplicationErrorCode.ZMUX_CANCELLED
        with pytest.raises(zmux.StreamResetError) as error:
            await b.recv.read_to_end()
        assert error.value.code == code
        assert await a.send.stopped() == code
        await b.send.finish()
        assert await a.recv.read_to_end() == b""
        assert (await relay).a_to_b.end is SpliceEnd.WAIT_TIMEOUT
