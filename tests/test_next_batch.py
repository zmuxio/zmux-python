"""Host API scenarios through the extension and its real carriers."""

import asyncio
import dataclasses
import sys
import threading
from collections.abc import Iterator
from contextlib import AsyncExitStack, contextmanager

import pytest
import zmux
from support import (
    LOOPBACK,
    QUIET_LIVENESS,
    TEST_HOOKS,
    WATCHDOG,
    Tls,
    manual_clock,
    start_pending,
    tcp_pair,
    until,
)


def config(**options: object) -> zmux.Config:
    return zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=4)
        ),
        pipe_auth=zmux.PipeAuth.psk(bytes(32)).with_end_to_end(),
        probation=None,
    ).replace(**options)


def addition(session: zmux.Session) -> zmux.CapacityChange:
    capacity = session.capacity()
    return session.begin_change(
        zmux.ChangeRequest(
            observed=capacity.observed,
            policy_revision=capacity.policy_revision,
            add=(zmux.MemberSpec((zmux.AttachmentSpec(zmux.Directions.BOTH),)),),
        )
    )


@pytest.mark.skipif(not TEST_HOOKS, reason="needs the pending-poll test hook")
async def test_next_batch_h_attempt_and_final_accounting() -> None:
    tickets = zmux.AccountingTickets()
    cfg = config(accounting_tickets=tickets)
    async with tcp_pair(cfg, cfg) as (client, server, listener):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        entered: asyncio.Future[zmux.OpenRequest] = (
            asyncio.get_running_loop().create_future()
        )
        release = asyncio.Event()
        first = client.pipes()[0]
        first_ticket = first.accounting()
        assert first_ticket is not None

        async def open_pipe(open_request: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
            entered.set_result(open_request)
            await release.wait()
            io = await zmux.dial_tcp(*addr)
            io.set_accounting_sources(
                send=zmux.CarrierHalfSource(kind="streaming", route="send"),
                receive=zmux.CarrierHalfSource(kind="streaming", route="receive"),
            )
            return (io,)

        change = addition(client)
        try:
            attempt = change.start_member(0, open=open_pipe)
            request = await entered
            assert request.stage == "Join" and request.need == zmux.Directions.BOTH
            waiter = await start_pending(attempt.wait)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            assert attempt.snapshot().result is None
            release.set()
            result = await attempt.wait()
            assert result.reason == "Confirmed"
            assert result.id == request.attempt > 0
            assert result.generation is None and result.batch > 0
            assert result.error is result.open_error is None
            again = await attempt.wait()
            snapshot = attempt.snapshot()
            assert snapshot.result is not None
            assert snapshot.generation is result.generation
            assert snapshot.batch == snapshot.result.batch == result.batch
            assert result._replace(tickets=()) == again._replace(tickets=())
            assert result.pipes == snapshot.result.pipes
            assert result.member is not None
            assert len(result.pipes) == len(result.tickets) == 1
            assert change.commit().draining == ()
            assert result.member == client.member_for_pipe(result.pipes[0])
            joined = next(pipe for pipe in client.pipes() if pipe.id == result.pipes[0])
            health = joined.health()
            assert health is not None and health.peer_attached
            assert joined.stats() is not None
            claimed = tickets.take(client.id, pipe=first.id)
            assert claimed is not None
            assert tickets.take(client.id, pipe=first.id) is None
            send, _ = await client.open_bi()
            await send.write(b"account")
            await send.finish()
            _, receive = await server.accept_bi()
            assert await receive.read_to_end() == b"account"
            ticket = result.tickets[0]
            cancelled = await start_pending(ticket.wait)
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            client.abort(0)
            await client.wait_closed()
            retired = tickets.take(client.id, pipe=joined.id)
            assert retired is not None
            assert tickets.take(client.id, pipe=joined.id) is None
            assert tickets.take(zmux.SessionId(0), pipe=first.id) is None
            totals, bootstrap = await asyncio.gather(ticket.wait(), first_ticket.wait())
            assert bootstrap == await claimed
            assert totals == await retired
            assert {session for session, _, _ in tickets.drain()} == {server.id}
            assert tickets.drain() == ()
            assert totals == await ticket == await again.tickets[0]
            assert totals.pipe == joined.id and bootstrap.pipe == first.id
            assert sum(t.bytes for t in (*totals.send, *bootstrap.send)) > 0
            for direction, rows in (("send", totals.send), ("receive", totals.receive)):
                assert rows
                assert all(row.source.route == direction for row in rows)
                assert all(row.active_complete_record_bytes == 0 for row in rows)
                assert all(
                    row.retired_complete_record_bytes == row.bytes for row in rows
                )
        finally:
            change.cancel()


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
async def test_next_batch_h_settle_uses_current_round_proof_and_hold() -> None:
    clock = manual_clock()
    cfg = config(clock_domain=clock.domain, liveness=QUIET_LIVENESS)
    async with tcp_pair(cfg, cfg) as (client, _, listener):
        client.subscribe_pipe_health()
        addr = await listener.serve_tcp(LOOPBACK, 0)
        pipe = await client.add_pipe(await zmux.dial_tcp(*addr))
        initial = pipe.health()
        assert initial is not None
        assert not initial.settled and initial.send.reason == "ObserveJoin"
        assert initial.send.evidence is not None
        assert initial.send.evidence == initial.send_evidence
        pipe.observe_stability()
        # Keep the clock at the join time until the probe's ACK commits.
        # Advancing with a probe in flight would exercise an ACK stall.
        events = client.events()
        async for event in events:
            if (
                isinstance(event, zmux.PipeHealthChanged)
                and event.change.pipe == pipe.id
                and event.change.half is zmux.PipeHalf.OUTBOUND
                and event.change.after.proof_kind == "ProbeRoundTrip"
            ):
                assert event.change.since_join == 0
                assert not event.change.after.settled
                assert event.change.after.evidence == initial.send.evidence
                break
        else:
            pytest.fail("the requested probe did not supply current-round evidence")
        clock.advance(4)
        during_hold = pipe.health()
        assert during_hold is not None
        assert during_hold.send.proof_kind == "ProbeRoundTrip"
        assert not during_hold.send.settled
        clock.advance(1)
        async for event in events:
            if (
                isinstance(event, zmux.PipeHealthChanged)
                and event.change.pipe == pipe.id
                and event.change.half is zmux.PipeHalf.OUTBOUND
                and event.change.after.settled
            ):
                assert event.change.since_join == 5
                assert event.change.before.proof_kind == "ProbeRoundTrip"
                assert event.change.before.evidence == event.change.after.evidence
                assert event.change.after.evidence == initial.send.evidence
                break
        else:
            pytest.fail("missing the committed stability transition")


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
async def test_next_batch_h_observation_grace_expires_without_probes() -> None:
    clock = manual_clock()
    cfg = config(clock_domain=clock.domain, liveness=QUIET_LIVENESS)
    async with tcp_pair(cfg, cfg) as (client, _, listener):
        client.subscribe_pipe_health()
        addr = await listener.serve_tcp(LOOPBACK, 0)
        pipe = await client.add_pipe(await zmux.dial_tcp(*addr))
        initial = pipe.health()
        assert initial is not None
        assert initial.send.reason == initial.receive.reason == "ObserveJoin"
        clock.advance(10)
        pending = {zmux.PipeHalf.OUTBOUND, zmux.PipeHalf.INBOUND}
        async for event in client.events():
            if (
                isinstance(event, zmux.PipeHealthChanged)
                and event.change.pipe == pipe.id
                and event.change.reason == "Idle"
            ):
                change = event.change
                assert change.before.reason == "ObserveJoin"
                assert change.after.state == "Unknown"
                assert change.after.proof_kind is change.failure is None
                assert change.since_join == 10
                pending.remove(change.half)
                if not pending:
                    break
        assert not pending


async def test_next_batch_h_opener_exception_is_retained() -> None:
    cfg = config()
    async with tcp_pair(cfg, cfg) as (client, _, _):
        change = addition(client)
        cause = LookupError("carrier unavailable")

        async def fail(_: zmux.OpenRequest) -> tuple[zmux.PipeIo, ...]:
            raise cause

        try:
            attempt = change.start_member(0, open=fail)
            result = await attempt.wait()
            assert result.reason == "DialFailed"
            assert result.open_error is cause
            assert await attempt.wait() == result
            assert not result.pipes and not result.tickets
            assert len(client.pipes()) == 1
        finally:
            change.cancel()


@pytest.mark.parametrize("revoke", [False, True])
async def test_next_batch_h_authorization_facts_and_denial(revoke: bool) -> None:
    entered: asyncio.Future[zmux.JoinAuthorization] = (
        asyncio.get_running_loop().create_future()
    )
    release = asyncio.Event()

    async def authorize(info: zmux.JoinAuthorization) -> bool:
        entered.set_result(info)
        await release.wait()
        return revoke

    limits = zmux.CapacityLimits(steady_attachments=4)
    client_cfg = config()
    server_cfg = config(
        session_policy=zmux.SessionPolicy(
            auth_generation=3, limits=limits, authorize_join=authorize
        )
    )
    async with tcp_pair(client_cfg, server_cfg) as (client, server, listener):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        change = addition(client)

        async def dial(_: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
            return (await zmux.dial_tcp(*addr),)

        try:
            attempt = change.start_member(0, open=dial)
            facts = await entered
            assert facts.session == server.id
            assert facts.auth_generation == 3
            assert facts.direction == zmux.Direction.BIDI
            assert facts.record_mode is zmux.RecordMode.SEALED
            assert facts.first_batch == zmux.JoinFirstBatch(0, 0, 0, False)
            assert facts.pipe_id != server.pipes()[0].id
            with pytest.raises(AttributeError):
                facts.join_epoch += 1  # type: ignore[misc]
            assert len(server.pipes()) == 1
            if revoke:
                server.set_session_policy(
                    zmux.SessionPolicy(
                        revision=1,
                        auth_generation=4,
                        limits=limits,
                        join_source_routes=(),
                    )
                )
            release.set()
            result = await attempt.wait()
            assert result.reason == "ConfirmationFailed"
            assert isinstance(result.error, zmux.PipeError)
            assert not isinstance(result.error, zmux.JoinRefusedError)
            assert len(server.pipes()) == 1
            await client.ping()
        finally:
            release.set()
            change.cancel()


async def test_next_batch_h_authenticated_reply_reports_join_refused() -> None:
    server_config = config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=2, join_headroom=0)
        )
    )
    async with tcp_pair(config(), server_config) as (client, server, listener):
        address = await listener.serve_tcp(LOOPBACK, 0)
        await client.add_pipe(await zmux.dial_tcp(*address))
        change = addition(client)

        async def dial(_: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
            return (await zmux.dial_tcp(*address),)

        try:
            result = await change.start_member(0, open=dial).wait()
            assert result.reason == "JoinRefused"
            assert isinstance(result.error, zmux.JoinRefusedError)
            assert len(server.pipes()) == 2
        finally:
            change.cancel()


async def test_next_batch_h_controller_bootstrap_and_revision() -> None:
    cfg = config()
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(config=cfg) as listener,
    ):
        address = await listener.serve_tcp(LOOPBACK, 0)
        requests: list[zmux.OpenRequest] = []

        async def dial(request: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
            requests.append(request)
            return (await zmux.dial_tcp(*address),)

        candidate = zmux.Candidate.custom(
            "streaming",
            layout=(zmux.AttachmentSpec(zmux.Directions.BOTH),),
            open=dial,
        ).with_identity("direct", cache_key="direct")
        cache = zmux.CarrierCache()
        ctrl = zmux.SessionController(
            "bootstrap-test", candidates=[candidate], cache=cache
        )
        next_controller = zmux.SessionController(
            "takeover-test", candidates=[candidate]
        )
        target = zmux.SessionTarget(
            1,
            groups=(
                zmux.GroupTarget(
                    "primary",
                    quotas=(
                        zmux.MemberQuota(
                            "direct",
                            count=1,
                            directions=zmux.Directions.BOTH,
                            candidates=(zmux.TargetCandidate("direct"),),
                        ),
                    ),
                ),
            ),
        )
        try:
            client, control = await ctrl.open(target, config=cfg)
            async with client, await listener.accept():
                assert control is not None
                assert [(r.stage, r.cause) for r in requests] == [
                    ("Bootstrap", "Initial")
                ]
                assert client.members()[0].candidate == "direct"
                metrics = cache.retry_metrics("direct", kind="streaming")
                assert metrics.recovery_retry_at is None
                assert metrics.recovery_nominal == metrics.recovery_sampled == 0
                assert metrics.faults == 0
                assert control.snapshot().revision == target.revision
                control.set_target(target)
                control.set_target(dataclasses.replace(target, revision=2))
                with pytest.raises(zmux.SessionControllerError) as conflict:
                    control.set_target(target)
                assert conflict.value.kind == "Conflict"
                before = control.snapshot()
                assert before.paths and before.predecessor is None
                path = before.paths[0]
                assert path.stats.pipe == 0
                assert path.member is not None
                evidence = path.evidence()
                assert path.stats.health.send.evidence is not None
                assert evidence.sampled_at == path.stats.health.send.evidence.since
                assert evidence.valid_until is None
                with pytest.raises(ValueError, match="no evidence"):
                    path.evidence("delivery", direction=zmux.PipeHalf.INBOUND)
                successor = next_controller.take_over(
                    control, target=dataclasses.replace(target, revision=3)
                )
                await control.done()
                after = successor.snapshot()
                assert after.predecessor == before.generation
                assert after.generation > before.generation
                with pytest.raises(zmux.SessionControllerError, match="StaleBinding"):
                    control.release()
                with pytest.raises(zmux.SessionControllerError, match="StaleDecision"):
                    successor.set_target(
                        zmux.SessionTarget(
                            4,
                            replace=(
                                zmux.ReplaceIntent(
                                    "stale",
                                    members=(path.member,),
                                    evidence=(evidence,),
                                ),
                            ),
                        )
                    )
                successor.release()
                await successor.done()
        finally:
            ctrl.close()
            next_controller.close()
            await ctrl.done()
            await next_controller.done()


async def test_controller_open_with_empty_target_without_multipath() -> None:
    async with asyncio.timeout(WATCHDOG), zmux.Listener() as listener:
        address = await listener.serve_tcp(LOOPBACK, 0)

        async def dial(_: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
            return (await zmux.dial_tcp(*address),)

        candidate = zmux.Candidate.custom(
            "streaming",
            layout=(zmux.AttachmentSpec(zmux.Directions.BOTH),),
            open=dial,
        ).with_identity("plain", cache_key="plain")
        controller = zmux.SessionController("plain-open", candidates=[candidate])
        try:
            session, control = await controller.open(zmux.SessionTarget())
            async with session, await listener.accept():
                assert control is None
                await session.ping()
        finally:
            controller.close()
            await controller.done()


async def test_controller_takeover_fences_an_open_batch() -> None:
    cfg = config()
    async with tcp_pair(cfg, cfg) as (client, _, _):
        opened: asyncio.Future[zmux.OpenRequest] = (
            asyncio.get_running_loop().create_future()
        )
        release_opener = asyncio.Event()

        async def dial(request: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
            opened.set_result(request)
            await release_opener.wait()
            raise OSError("scripted opener failure after takeover")

        candidate = zmux.Candidate.custom(
            "streaming",
            layout=(zmux.AttachmentSpec(zmux.Directions.BOTH),),
            open=dial,
        ).with_identity("held", cache_key="held")
        target = zmux.SessionTarget(
            1,
            groups=(
                zmux.GroupTarget(
                    "paths",
                    quotas=(
                        zmux.MemberQuota(
                            "both",
                            count=1,
                            directions=zmux.Directions.BOTH,
                            candidates=(zmux.TargetCandidate("held"),),
                        ),
                    ),
                ),
            ),
        )
        predecessor = zmux.SessionController("batch-before", candidates=[candidate])
        replacement = zmux.SessionController("batch-after", candidates=[])
        try:
            control = predecessor.manage(client, target=target)
            request = await opened
            before = control.snapshot()
            assert before.host_calls_in_flight == before.domain_openers == 1
            assert before.cleanup_in_flight == before.domain_cleanup
            assert request.stage == "Join" and request.attempt > 0

            successor = replacement.take_over(control, target=zmux.SessionTarget(2))
            after = successor.snapshot()
            assert after.capacity.covered == zmux.Directions.BOTH
            assert after.domain_openers == after.domain_cleanup == 0

            changes: list[zmux.Event] = []
            async for event in client.events():
                if isinstance(event, zmux.TargetChanged) and (
                    event.generation == after.generation
                ):
                    assert event.predecessor == before.generation
                    break
                if isinstance(
                    event,
                    (
                        zmux.BatchReserved,
                        zmux.AttemptStarted,
                        zmux.AttemptFinished,
                        zmux.BatchRolledBack,
                    ),
                ):
                    assert event.generation == before.generation
                    changes.append(event)
            else:
                pytest.fail("missing takeover event")
            reserved, started, finished, rolled_back = changes
            assert isinstance(reserved, zmux.BatchReserved)
            assert isinstance(started, zmux.AttemptStarted)
            assert isinstance(finished, zmux.AttemptFinished)
            assert isinstance(rolled_back, zmux.BatchRolledBack)
            assert reserved.revision == target.revision and reserved.batch > 0
            assert (
                reserved.batch == started.batch == finished.batch == rolled_back.batch
            )
            assert started.attempt == finished.attempt == request.attempt
            assert finished.reason == "Cancelled"
            release_opener.set()
            await control.done()
            assert client.capacity().reserved_attachments == 0
            successor.release()
            await successor.done()
        finally:
            release_opener.set()
            predecessor.close()
            replacement.close()
            await asyncio.gather(predecessor.done(), replacement.done())


async def test_next_batch_e1_same_family_datagram_and_flow() -> None:
    cfg = config(enable_datagrams=True)
    async with tcp_pair(cfg, cfg) as (client, server, _):
        client.send_datagram(b"session")
        assert await server.read_datagram() == b"session"
        send, _ = await client.open_bi()
        await send.write(b"open")
        _, receive = await server.accept_bi()
        assert await receive.read_exact(4) == b"open"
        send.send_datagram(b"flow", context=1 << 14)
        assert await receive.read_datagram() == zmux.StreamDatagram(1 << 14, b"flow")


async def test_next_batch_e2_original_path_and_context_varint() -> None:
    cfg = config(enable_datagrams=True)
    async with tcp_pair(cfg, cfg) as (client, server, _):
        send, _ = await client.open_bi()
        await send.write(b"open")
        _, receive = await server.accept_bi()
        assert await receive.read_exact(4) == b"open"
        short = send.max_datagram_size(context=63)
        long = send.max_datagram_size(context=64)
        assert short is not None and long == short - 1
        assert client.datagram_path().native_payload is None
        send.send_datagram_with(b"flow", context=64, options=zmux.DatagramSendOptions())
        assert await receive.read_datagram() == zmux.StreamDatagram(64, b"flow")
        with pytest.raises(zmux.DatagramError) as error:
            send.send_datagram(bytes(short + 1), context=63)
        assert error.value.kind == "TooLarge"


@pytest.mark.skipif(not TEST_HOOKS, reason="needs the pending-poll test hook")
async def test_next_batch_e2_path_during_blocked_stream_write() -> None:
    cfg = config(
        enable_datagrams=True,
        initial_stream_receive_window=4096,
        max_stream_receive_window=4096,
    )
    async with tcp_pair(cfg, cfg) as (client, server, _):
        send, _ = await client.open_bi()
        await send.write(b"open")
        _, receive = await server.accept_bi()
        assert await receive.read_exact(4) == b"open"
        send.send_buffer = 1
        path = send.datagram_path(context=64)
        assert path.payload is not None
        blocked = await start_pending(lambda: send.write(b"x" * 65536))
        try:
            assert send.datagram_path(context=64) == path
        finally:
            blocked.cancel()
            await asyncio.gather(blocked, return_exceptions=True)


async def test_next_batch_e3_explicit_single_and_hard_limit() -> None:
    cfg = config(
        enable_datagrams=True,
        datagram=zmux.DatagramConfig(
            copy_limit=1, defaults=zmux.DatagramSendOptions(copies=zmux.Duplicate(2))
        ),
    )
    async with tcp_pair(cfg, cfg) as (client, server, listener):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        await client.add_pipe(await zmux.dial_tcp(*addr))
        client.send_datagram_with(
            b"single",
            options=zmux.DatagramSendOptions(copies=zmux.DatagramCopyPolicy.SINGLE),
        )
        assert await server.read_datagram() == b"single"
        client.send_datagram(b"inherited")
        assert await server.read_datagram() == b"inherited"
        stats = client.datagram_stats()
        assert stats.record.replicas == stats.native.replicas == 0


async def test_next_batch_e3_duplicate_arrives_once() -> None:
    cfg = config(enable_datagrams=True)
    async with tcp_pair(cfg, cfg) as (client, server, listener):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        (original,) = client.pipes()
        extra = await client.add_pipe(await zmux.dial_tcp(*addr))
        client.send_datagram_with(
            b"copied", options=zmux.DatagramSendOptions(copies=zmux.Duplicate(2))
        )
        assert await server.read_datagram() == b"copied"
        await until(server, lambda: server.datagram_stats().duplicates_dropped == 1)
        assert client.datagram_stats().record.replicas_accepted == 1
        assert server.datagram_stats().duplicates_dropped == 1
        for pipe in (original, extra):
            arrivals = server.datagram_arrivals(pipe.id, native=False)
            assert arrivals is not None and arrivals.frames == 1 and arrivals.bytes == 6
        empty = await start_pending(server.read_datagram)
        empty.cancel()
        await asyncio.gather(empty, return_exceptions=True)


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
async def test_next_batch_e4_deadline_and_require_native() -> None:
    clock = manual_clock()
    cfg = config(enable_datagrams=True, clock_domain=clock.domain)
    async with tcp_pair(cfg, cfg) as (client, server, _):
        with pytest.raises(zmux.DatagramDroppedError) as expired:
            client.send_datagram_with(
                b"expired", options=zmux.DatagramSendOptions(deadline=0.0)
            )
        assert expired.value.reason is zmux.DatagramDrop.DEADLINE
        client.send_datagram_with(
            b"requires native",
            options=zmux.DatagramSendOptions(
                carrier=zmux.DatagramCarrier.REQUIRE_NATIVE, deadline=1.0
            ),
        )
        client.send_datagram_with(
            b"live", options=zmux.DatagramSendOptions(deadline=None)
        )
        clock.advance(1)
        assert await server.read_datagram() == b"live"
        stats = client.datagram_stats()
        assert stats.drops.deadline == 2
        assert stats.record.originals_accepted == 1
        assert stats.native.originals == 0


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
async def test_next_batch_e5_feedback_is_scoped_by_carrier_mode() -> None:
    clock, peer_clock = manual_clock(), manual_clock()
    cfg = zmux.Config(enable_datagrams=True, clock_domain=clock.domain)
    release_report = asyncio.Event()
    release_report.set()

    async def pump(
        source: zmux.adapter.PipeEnd,
        target: zmux.adapter.PipeEnd,
        *,
        gate: asyncio.Event | None = None,
    ) -> None:
        while data := await source.read():
            if gate is not None:
                await gate.wait()
            await target.write(data)

    async with asyncio.timeout(WATCHDOG), asyncio.TaskGroup() as tasks:
        client_pipe, near = zmux.adapter.pipe_pair()
        server_pipe, far = zmux.adapter.pipe_pair()
        up = tasks.create_task(pump(near, far))
        down = tasks.create_task(pump(far, near, gate=release_report))
        accept = tasks.create_task(
            zmux.Session.accept(
                server_pipe, config=cfg.replace(clock_domain=peer_clock.domain)
            )
        )
        client = await zmux.Session.connect(client_pipe, config=cfg)
        server = await accept
        try:
            pipe = client.pipes()[0]
            assert client.datagram_feedback(pipe.id, native=False) is None
            release_report.clear()
            client.send_datagram(b"observed")
            assert await server.read_datagram() == b"observed"
            # With neither clock advancing, an ACK establishes arrival but
            # supplies no positive RTT sample. Hold it for 125 ms of sender time.
            clock.advance(0.125)
            release_report.set()
            await until(
                client,
                lambda: (
                    (report := client.datagram_feedback(pipe.id, native=False))
                    is not None
                    and report.arrived == 1
                ),
            )
            feedback = client.datagram_feedback(pipe.id, native=False)
            assert feedback is not None
            assert client.stats().datagrams_sent == 1
            assert client.datagram_feedback(pipe.id, native=True) is None
            assert feedback.tracking == feedback.arrived == 1
            assert feedback.awaiting == feedback.expired == 0
            assert feedback.samples == 1
            assert feedback.report_rtt == 0.125
            assert feedback.sample_source is zmux.DatagramEvidenceSource.DATAGRAM_ACK
            assert feedback.sampled_at is not None and feedback.sample_age == 0
            clock.advance(10)
            stale = client.datagram_feedback(pipe.id, native=False)
            assert stale is not None and stale.tracking == stale.expired == 1
            assert stale.report_rtt is None
            assert stale.sampled_at is None
            assert stale.sample_source is None
        finally:
            client.abort(0)
            server.abort(0)
            up.cancel()
            down.cancel()
            await near.write(b"")
            await far.write(b"")
            await asyncio.gather(client.wait_closed(), server.wait_closed())


async def test_next_batch_t_tcp_sample_provenance() -> None:
    async with tcp_pair() as (client, server, _):
        for session in (client, server):
            stats = session.pipes()[0].stats()
            assert stats is not None
            if sample := stats.carrier_sample:
                assert sample.direction is zmux.Direction.OUT
                assert sample.sampled_at > 0


async def test_next_batch_t_quic_connection_outlives_its_pipes(tls: Tls) -> None:
    server_tls, client_tls = tls
    cfg = config(enable_datagrams=True, accounting=zmux.AccountingPolicy(enabled=True))
    async with asyncio.timeout(WATCHDOG), zmux.Listener(config=cfg) as listener:
        address = await listener.serve_quic(LOOPBACK, 0, tls=server_tls)
        client = zmux.QuicClient(client_tls)
        connection = await client.open_connection(*address)

        async def connect(
            resources: AsyncExitStack,
        ) -> tuple[zmux.Session, zmux.Session]:
            session = await resources.enter_async_context(
                await zmux.Session.connect(await connection.open_pipe(), config=cfg)
            )
            return session, await resources.enter_async_context(await listener.accept())

        def identity(session: zmux.Session) -> int:
            totals = session.pipe_stats()[0].accounting
            assert totals is not None
            (send,) = totals.send
            connection_id = send.source.connection
            assert connection_id is not None
            return connection_id

        try:
            async with AsyncExitStack() as stack:
                first, _ = await connect(stack)
                second, peer = await connect(stack)
                carrier = identity(first)
                assert identity(second) == carrier
                first.close()
                await first.wait_closed()
                assert second.datagram_path().native_payload is not None
                second.send_datagram_with(
                    b"quic",
                    options=zmux.DatagramSendOptions(
                        carrier=zmux.DatagramCarrier.REQUIRE_NATIVE
                    ),
                )
                assert await peer.read_datagram() == b"quic"
                assert second.stats().datagrams_sent_channel == 1
            async with AsyncExitStack() as stack:
                third, _ = await connect(stack)
                assert identity(third) == carrier
        finally:
            connection.close()


async def test_next_batch_t_h3_requests_share_native_connection(tls: Tls) -> None:
    server_tls, client_tls = tls
    cfg = config(enable_datagrams=True, accounting=zmux.AccountingPolicy(enabled=True))
    async with asyncio.timeout(WATCHDOG), zmux.Listener(config=cfg) as listener:
        address = await listener.serve_http3(LOOPBACK, 0, tls=server_tls)
        url = f"https://{LOOPBACK}:{address[1]}/zmux"
        conn = await zmux.Http3Connection.dial(url, tls=client_tls, addr=address)
        try:
            async with AsyncExitStack() as sessions:

                async def request() -> tuple[zmux.Session, zmux.Session]:
                    client = await zmux.Session.connect(
                        await conn.open_pipe(), config=cfg
                    )
                    await sessions.enter_async_context(client)
                    peer = await listener.accept()
                    await sessions.enter_async_context(peer)
                    return client, peer

                first, _ = await request()
                second, receiver = await request()
                stats = [session.pipe_stats()[0] for session in (first, second)]
                accounting = [stat.accounting for stat in stats]
                assert all(accounting)
                identities = {
                    row.source.connection
                    for totals in accounting
                    if totals is not None
                    for row in totals.send
                }
                assert len(identities) == 1
                assert None not in identities
                first.close()
                await first.wait_closed()
                await second.ping()
                assert conn.http_datagrams
                second.send_datagram_with(
                    b"native",
                    options=zmux.DatagramSendOptions(
                        carrier=zmux.DatagramCarrier.REQUIRE_NATIVE
                    ),
                )
                assert await receiver.read_datagram() == b"native"
                assert second.stats().datagrams_sent_channel == 1
        finally:
            conn.close()


async def test_next_batch_h_shaping_profile_bounds_padding() -> None:
    pad = '{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'
    cfg = config(
        shaping={None: pad},
        shaping_limits=zmux.shaping.ShapingLimits(
            profile=zmux.shaping.ShapingProfileLimits(
                extra_bytes_ppm=0, floor_bytes=0, max_added_delay=0
            )
        ),
    )
    async with tcp_pair(cfg, cfg) as (client, server, _):
        tx, _ = await client.open_bi()
        await tx.write(b"shaped")
        await tx.finish()
        _, rx = await server.accept_bi()
        assert await rx.read_to_end() == b"shaped"
        stats = client.shaping_stats()
        assert stats["ledger"]["baseline_bytes"] > 0
        assert stats["wire_spent"] == stats["max_added_delay"] == 0
        local = stats["ledger"]["local"]
        assert local is not None and local["allowance_bytes"] == 0
        assert local["consumed_bytes"] == 0


@contextmanager
def gil_check() -> Iterator[None]:
    if hasattr(sys, "_is_gil_enabled") and sys._is_gil_enabled():
        pytest.skip("requires a free-threaded interpreter")
    yield
    if hasattr(sys, "_is_gil_enabled"):
        assert not sys._is_gil_enabled()


async def test_next_batch_f_concurrent_datagrams_copy_reusable_buffers() -> None:
    cfg = config(enable_datagrams=True)
    async with tcp_pair(cfg, cfg) as (client, server, _):
        barrier = threading.Barrier(2)

        def send(value: bytes) -> None:
            buffer = bytearray(value)
            barrier.wait(timeout=WATCHDOG)
            client.send_datagram(buffer)
            buffer[:] = b"overwritten"

        with gil_check():
            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(asyncio.to_thread(send, b"one"))
                tasks.create_task(asyncio.to_thread(send, b"two"))
            assert {await server.read_datagram(), await server.read_datagram()} == {
                b"one",
                b"two",
            }
