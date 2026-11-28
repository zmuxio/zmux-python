"""Pipes through a TCP relay that fails in controlled ways: a black hole,
a cut of every connection, and pool retirement."""

import asyncio
from contextlib import suppress
from typing import Any, TypedDict

import pytest
import zmux
from support import (
    LOOPBACK,
    QUIET_LIVENESS,
    TEST_HOOKS,
    WATCHDOG,
    manual_clock,
)

PSK = b"fault-relay-psk-0123456789abcdef"


def _config(**kw: Any) -> zmux.Config:
    return zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=6)
        ),
        pipe_auth=zmux.PipeAuth.psk(PSK).with_end_to_end(),
        max_idle_timeout=None,
        resume_timeout=120,
        **kw,
    )


class _Conn(TypedDict):
    blackhole: bool
    writers: tuple[asyncio.StreamWriter, asyncio.StreamWriter]


class Relay:
    """Forwards TCP connections to `target`; each can be black-holed (bytes
    taken, none forwarded, ends kept open) or cut (both ends closed)."""

    def __init__(self, target: tuple[str, int]) -> None:
        self.target = target
        self.conns: list[_Conn] = []
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self._uplink: tuple[asyncio.Event, asyncio.Event] | None = None

    async def start(self) -> tuple[str, int]:
        server = await asyncio.start_server(self._start, str(LOOPBACK), 0)
        self.server = server
        host, port = server.sockets[0].getsockname()[:2]
        return host, port

    def _start(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(self._serve(reader, writer))
        self.tasks.add(task)

    async def _serve(self, r1: asyncio.StreamReader, w1: asyncio.StreamWriter) -> None:
        try:
            r2, w2 = await asyncio.open_connection(*self.target)
            conn: _Conn = {"blackhole": False, "writers": (w1, w2)}
            self.conns.append(conn)

            async def pump(
                r: asyncio.StreamReader, w: asyncio.StreamWriter, *, uplink: bool
            ) -> None:
                with suppress(OSError):
                    try:
                        while data := await r.read(65536):
                            if uplink and self._uplink is not None:
                                held, release = self._uplink
                                held.set()
                                await release.wait()
                            if not conn["blackhole"]:
                                w.write(data)
                                await w.drain()
                    finally:
                        w.close()
                        await w.wait_closed()

            await asyncio.gather(pump(r1, w2, uplink=True), pump(r2, w1, uplink=False))
        finally:
            if not w1.is_closing():
                w1.close()
                with suppress(OSError):
                    await w1.wait_closed()

    def hold_uplink(self) -> asyncio.Event:
        assert self._uplink is None
        held = asyncio.Event()
        self._uplink = (held, asyncio.Event())
        return held

    def cut(self) -> None:
        for c in self.conns:
            for w in c["writers"]:
                w.transport.abort()
        if self._uplink is not None:
            self._uplink[1].set()
            self._uplink = None

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
        self.cut()
        # Include accepts that had started but had yet to connect upstream.
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.server is not None:
            await self.server.wait_closed()


async def joined_pipe(session: zmux.Session, first: zmux.PipeId) -> zmux.Pipe:
    async for event in session.events():
        if isinstance(event, zmux.PipeJoined) and event.pipe != first:
            (joined,) = [pipe for pipe in session.pipes() if pipe.id == event.pipe]
            await joined.wait_attached()
            return joined
    raise AssertionError("session ended without joining the pool pipe")


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
async def test_probe_failover_preserves_preamble_and_takeover_coverage() -> None:
    clock = manual_clock()
    config = _config(clock_domain=clock.domain, probation=None, liveness=QUIET_LIVENESS)
    async with asyncio.timeout(WATCHDOG), zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp(LOOPBACK, 0)
        relay = Relay(addr)
        sessions: list[zmux.Session] = []
        initial = zmux.SessionController(
            "before-probe-failover", candidates=[], clock_domain=clock.domain
        )
        replacement = zmux.SessionController(
            "after-probe-failover", candidates=[], clock_domain=clock.domain
        )
        try:
            raddr = await relay.start()
            session = await zmux.connect_tcp(*addr, config=config)
            sessions.append(session)
            peer = await listener.accept()
            sessions.append(peer)
            pipe = await session.add_pipe(
                await zmux.dial_tcp(*raddr),
                options=zmux.PipeOptions(
                    liveness=zmux.PipeLiveness(
                        suspect_floor=0.25,
                        probe_interval=1,
                        probe_jitter=0,
                        dead_timeout=1,
                    )
                ),
            )
            target = zmux.SessionTarget(1)
            control = initial.manage(session, target=target)
            before = control.snapshot()
            assert before.capacity.covered == zmux.Directions.BOTH
            health = pipe.health()
            assert health is not None and health.send.evidence is not None
            assert health.send.evidence == health.send_evidence
            assert health.send.can_carry and health.eligible_for_new_data
            session.subscribe_pipe_health()
            session.pipes()[0].update(send_standby=True)
            held = relay.hold_uplink()
            relay.conns[0]["blackhole"] = True
            send, _ = await session.open_bi(
                info=b"repair prefix", tlvs=[zmux.Tlv(0x1000, b"route")]
            )
            await send.write(b"fail over")
            await held.wait()
            clock.advance(5)
            async for event in session.events():
                if (
                    isinstance(event, zmux.PipeHealthChanged)
                    and event.change.pipe == pipe.id
                    and event.change.half is zmux.PipeHalf.OUTBOUND
                    and event.change.reason == "AckStall"
                ):
                    assert not event.change.after.can_carry
                    assert event.change.after.evidence is None
                    break
            else:
                raise AssertionError("the blocked path did not lose service")
            successor = replacement.take_over(control, target=zmux.SessionTarget(2))
            after = successor.snapshot()
            assert after.predecessor == before.generation
            assert (
                after.capacity.covered
                == session.capacity().covered
                == zmux.Directions.BOTH
            )
            survivor = next(p.stats.health for p in after.paths if p.stats.pipe == 0)
            assert survivor.send.can_carry and survivor.receive.can_carry
            assert survivor.send.evidence == survivor.send_evidence
            async for event in session.events():
                if (
                    isinstance(event, zmux.TargetChanged)
                    and event.generation == after.generation
                ):
                    assert event.initial and event.predecessor == before.generation
                    assert event.revision == after.revision
                    break
            else:
                pytest.fail("missing the committed takeover target")

            await send.finish()
            reply, recv = await peer.accept_bi()
            await reply.finish()
            assert recv.preamble == zmux.Preamble(
                info=b"repair prefix", tlvs=(zmux.Tlv(0x1000, b"route"),)
            )
            assert await recv.read_to_end() == b"fail over"
            successor.release()
            await asyncio.gather(control.done(), successor.done())
        finally:
            initial.close()
            replacement.close()
            for session in sessions:
                # Retire the carriers first so a protocol close cannot wait
                # for handoff or linger on the frozen clock.
                for attachment in session.pipes():
                    with suppress(zmux.PipeGoneError):
                        attachment.abort()
                session.abort(0)
            await relay.close()
            await asyncio.gather(
                initial.done(),
                replacement.done(),
                *(session.wait_closed() for session in sessions),
            )


async def test_the_last_pipe_cut_resumes_without_loss() -> None:
    config = _config()
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            config=config,
            listener_config=zmux.ListenerConfig(
                instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
            ),
        ) as listener,
    ):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        relay = Relay(addr)
        raddr = await relay.start()
        try:
            async with await zmux.Session.connect(
                await zmux.dial_tcp(*raddr), config=config
            ) as client:
                server = await listener.accept()

                async def dial(_: zmux.OpenRequest) -> tuple[zmux.PipeIo]:
                    return (await zmux.dial_tcp(*raddr),)

                candidate = zmux.Candidate.custom(
                    "streaming",
                    layout=(zmux.AttachmentSpec(zmux.Directions.BOTH),),
                    open=dial,
                ).with_identity("relay", cache_key="relay")
                controller = zmux.SessionController(
                    "fault-relay", candidates=[candidate]
                )
                target = zmux.SessionTarget(
                    1,
                    groups=(
                        zmux.GroupTarget(
                            "relay",
                            quotas=(
                                zmux.MemberQuota(
                                    "relay",
                                    count=1,
                                    directions=zmux.Directions.BOTH,
                                    candidates=(zmux.TargetCandidate("relay"),),
                                ),
                            ),
                        ),
                    ),
                )
                controller.manage(client, target=target)
                first = client.pipes()[0].id
                await joined_pipe(client, first)
                total = 2 << 20
                chunk = 16 * 1024
                held = relay.hold_uplink()

                async def write() -> None:
                    send, _ = await client.open_bi()
                    for off in range(0, total, chunk):
                        await send.write(
                            bytes((i % 251) for i in range(off, off + chunk))
                        )
                    await send.finish()

                async def read() -> int:
                    _, recv = await server.accept_bi()
                    got = 0
                    while data := await recv.read():
                        assert data == bytes(
                            (i % 251) for i in range(got, got + len(data))
                        )
                        got += len(data)
                    return got

                try:
                    async with asyncio.TaskGroup() as tasks:
                        writer = tasks.create_task(write())
                        reader = tasks.create_task(read())
                        await held.wait()
                        relay.cut()
                        # A slow observer may only receive the latest suspension
                        # state; count the suspension independently.
                        resumed = False
                        retired = 0
                        while not (resumed and retired >= 2):
                            event = await client.next_event()
                            if isinstance(event, zmux.SessionResumed):
                                resumed = True
                            elif isinstance(event, zmux.PipesRetired):
                                retired += event.retired
                        assert client.stats().suspensions >= 1
                        assert all(p.id != first for p in client.pipes())
                        assert await reader == total
                        await writer
                finally:
                    controller.close()
                    await controller.done()
        finally:
            await relay.close()
