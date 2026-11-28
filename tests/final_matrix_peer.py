"""Python endpoint for the spec's directed FINAL pair scenarios."""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import AsyncExitStack
from hashlib import sha256
from pathlib import Path
from typing import NamedTuple

import zmux
from zmux import _zmux

SCENARIOS = {
    "relative-stall": "tcp",
    "l15": "tcp",
    "websocket-takeover": "websocket",
    "websocket-first-message-ticket": "websocket",
}
LIMIT = 12
MARK = b"TAKE 1"
SECOND = b"second"
PING = b"ticket-ping"
REJECTED = b"replay-rejected"
UNIX_SECONDS = 120
SLOT_SECONDS = 30


class Failure(Exception):
    """A scenario invariant failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def reply(kind: str, **fields: object) -> None:
    print(json.dumps({"type": kind, **fields}, allow_nan=False), flush=True)


class Request:
    """The driver's initial message and the rest of the control exchange."""

    def __init__(self, control: asyncio.StreamReader, initial: bytes):
        message = json.loads(initial)
        self.control = control
        self.scenario: str = message["scenario"]
        self.carrier: str = message["carrier"]
        self.role: str = message["role"]
        self.client = self.role == "client"
        self.other = "server" if self.client else "client"
        self.addresses: dict[str, str] = message.get("addresses", {})
        self.payloads: dict[str, list[str]] = message["payloads"]
        self.spec_root: str | None = message.get("spec_root")
        require(message["version"] == 1, "unsupported control version")
        require(message["op"] == "pair", "expected a pair request")
        require(self.role in ("client", "server"), "invalid matrix role")
        require(SCENARIOS.get(self.scenario) == self.carrier, "unsupported scenario")

    def stream_payloads(self, role: str, rounds: int) -> list[bytes]:
        items = [bytes.fromhex(item) for item in self.payloads[role]]
        require(
            len(items) == rounds and all(len(item) == 32 for item in items),
            f"expected {rounds} 32-byte payloads for {role}",
        )
        return items

    async def bind(self) -> _zmux._MatrixTcp:
        tcp = await _zmux._MatrixTcp.bind()
        reply("ready", addresses={self.carrier: tcp.address})
        return tcp

    async def attached(self, ids: list[int]) -> None:
        reply("attached", confirmed_pipes=ids)
        require(
            json.loads(await self.control.readline())["type"] == "exercise",
            "expected exercise",
        )

    async def complete(
        self,
        *,
        events: list[str],
        received: list[bytes],
        tx: dict[int, dict[str, int]],
        rx: dict[int, dict[str, int]],
        **fields: object,
    ) -> None:
        reply(
            "result",
            carrier=self.carrier,
            events=events,
            received=[data.hex() for data in received],
            tx=tx,
            rx=rx,
            **fields,
        )
        # Keep the session and listener alive until both results reach the driver.
        require(await self.control.readline() == b"", "expected control EOF")


def counts(records: int) -> dict[str, int]:
    return {"record": records, "native": 0, "capsule": 0}


async def read_expected(recv: zmux.RecvStream, expected: bytes) -> bytes:
    actual = await recv.read_exact(len(expected))
    require(actual == expected, "unexpected stream payload")
    return actual


async def read_fin(recv: zmux.RecvStream) -> None:
    require(await recv.read(1) == b"", "expected stream FIN")


async def close_session(
    session: zmux.Session, *, clock: _zmux._TestClock | None = None
) -> None:
    session.abort(0)
    if clock is not None:
        # Finish the native handoff and linger deadlines even if the other
        # process exits without delivering an orderly carrier shutdown.
        clock.advance(1)
        _zmux._matrix_fire_timers(session)
        clock.advance(2)
        _zmux._matrix_fire_timers(session)
    await session.wait_closed()


async def wait_event(session: zmux.Session) -> None:
    require(
        await session.next_event() is not None, "session ended during pipe exercise"
    )


def health(pipe: zmux.Pipe) -> zmux.PipeHealth:
    state = pipe.health()
    if state is None:
        raise Failure(f"pipe {pipe.id} lost its health observation")
    return state


class WireState(NamedTuple):
    probe: int
    eliciting: int
    acknowledgments: dict[int, int]
    streams: dict[int, bool]
    padding: int
    sent_datagrams: int
    received_datagrams: int


async def wait_reliable_setup(
    session: zmux.Session,
    *,
    wires: list[_zmux._MatrixWire],
    pipes: list[zmux.Pipe],
    prior: list[int],
) -> None:
    revision = session._test_revision()
    while True:
        settled = True
        for wire, pipe, previous in zip(wires, pipes, prior, strict=True):
            state = WireState(*wire.snapshot())
            stats = pipe.stats()
            if stats is None:
                raise Failure("setup pipe disappeared")
            settled &= state.probe > previous and (
                (stats.bytes_acked or 0) >= state.eliciting
            )
        if settled:
            return
        await revision.changed()


async def settle_paths(
    session: zmux.Session, wires: list[_zmux._MatrixWire], clock: _zmux._TestClock
) -> list[zmux.Pipe]:
    while True:
        pipes = sorted(session.pipes(), key=lambda pipe: pipe.id)
        if len(pipes) == 2 and all(
            (state := health(pipe)).peer_attached
            and state.send.can_carry
            and state.receive.can_carry
            for pipe in pipes
        ):
            break
        await wait_event(session)
    clock.advance(0.001)
    prior = [WireState(*wire.snapshot()).probe for wire in wires]
    session.revalidate_pipes()
    await wait_reliable_setup(session, wires=wires, pipes=pipes, prior=prior)
    for pipe in pipes:
        pipe.observe_stability()
        while not health(pipe).send.settled:
            await wait_event(session)
    await wait_reliable_setup(session, wires=wires, pipes=pipes, prior=prior)
    return pipes


async def inject_relative_stall(
    session: zmux.Session,
    *,
    pipes: list[zmux.Pipe],
    wires: list[_zmux._MatrixWire],
    clock: _zmux._TestClock,
) -> None:
    # Freeze incoming evidence across the virtual cuts. The observer sees
    # bytes before the protocol owner commits them, so drain what is already
    # in the driver before injecting the synthetic stall.
    source, backup = pipes
    revision = session._test_revision()
    positions = [wire.hold_reads(True) for wire in wires]
    try:
        for pipe, position in zip(pipes, positions, strict=True):
            while True:
                stats = pipe.stats()
                if stats is None:
                    raise Failure("setup pipe disappeared")
                if stats.bytes_received >= position:
                    break
                await revision.changed()
        _zmux._matrix_stall_evidence(session, pipe=source.id, cost=6.5, waiting=True)
        clock.advance(0.2)
        _zmux._matrix_stall_evidence(session, pipe=backup.id, cost=0.12, waiting=False)
        clock.advance(0.159)
        _zmux._matrix_fire_timers(session)
        require(
            health(source).send.can_carry, "source became unavailable before 360 ms"
        )
        clock.advance(0.001)
        _zmux._matrix_fire_timers(session)
        stalled = health(source).send
        require(
            not stalled.can_carry and stalled.reason == "AckStall",
            f"missed ACK-stall cut: {stalled}",
        )
    finally:
        for wire in wires:
            wire.hold_reads(False)


async def relative_stall(
    session: zmux.Session,
    *,
    pipes: list[zmux.Pipe],
    wires: list[_zmux._MatrixWire],
    clock: _zmux._TestClock,
    sent: bytes,
    expected: bytes,
) -> bytes:
    source = pipes[0]
    wires[0].hold_writes(True)
    try:
        await inject_relative_stall(session, pipes=pipes, wires=wires, clock=clock)

        send = await session.open_uni()
        await send.write(sent)
        await send.finish()
        recv = await session.accept_uni()
        actual = await read_expected(recv, expected)
        await read_fin(recv)
        while True:
            revision = wires[0].revision
            stream = send.id
            primary, secondary = (WireState(*wire.snapshot()) for wire in wires)
            require(stream not in primary.streams, "stream used the stalled source")
            if stream is not None and secondary.streams.get(stream):
                break
            await wires[0].changed(revision)
    finally:
        wires[0].hold_writes(False)

    while True:
        state = health(source)
        require(state.peer_attached, "source attachment was lost during recovery")
        if state.send.can_carry:
            return actual
        await wait_event(session)


async def l15(
    request: Request,
    session: zmux.Session,
    *,
    wire: _zmux._MatrixWire,
    clock: _zmux._TestClock,
    sent: list[bytes],
    expected: list[bytes],
) -> tuple[list[bytes], int]:
    if request.spec_root is None:
        raise Failure("missing L15 spec root")
    fixture = Path(request.spec_root) / "fixtures-dev" / "shaping" / "l15.json"
    bundle = zmux.shaping.ShapingBundle.from_json(
        fixture.read_bytes(), seed=b"\x35" * 32
    )
    require(bundle.budget("default") is not None, "missing L15 default budget")
    before = session.shaping_stats()["ledger"]["measured_bytes"]
    padding = WireState(*wire.snapshot()).padding
    session.shaper = bundle
    send, recv = await (session.open_bi() if request.client else session.accept_bi())
    received = []
    for round_index, (outgoing, incoming) in enumerate(
        zip(sent, expected, strict=True)
    ):
        if not request.client:
            received.append(await read_expected(recv, incoming))
        if round_index:
            clock.advance(2)
        await send.write(outgoing)
        await send.flush()
        if request.client:
            received.append(await read_expected(recv, incoming))
    await send.finish()
    await read_fin(recv)
    overhead = session.shaping_stats()["ledger"]["measured_bytes"] - before
    require(
        overhead > 0 and WireState(*wire.snapshot()).padding > padding,
        "L15 produced no measured record padding",
    )
    return received, overhead


def session_config() -> zmux.Config:
    return zmux.Config(enable_datagrams=True, max_incoming_uni_streams=16)


async def tcp_pair(request: Request, psk: bytes, stack: AsyncExitStack) -> None:
    relative = request.scenario == "relative-stall"
    rounds = 1 if relative else 8
    sent = request.stream_payloads(request.role, rounds)
    expected = request.stream_payloads(request.other, rounds)
    clock = _zmux._TestClock()
    config = session_config().replace(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=2 if relative else 1)
        ),
        pipe_auth=zmux.PipeAuth.psk(psk).with_end_to_end() if relative else None,
        clock_domain=clock.domain,
        max_lanes=1,
        allow_record_mode=lambda _, proposed, _hint: (
            proposed == zmux.RecordMode.TRUSTED
        ),
        stability_hold=0,
        probation=None,
        epoch_policy=zmux.EpochPolicy.MANUAL,
        liveness=zmux.Liveness(
            keep_alive_period=None,
            standby_probe=None,
            probe_interval=None,
            probe_jitter=0,
        ),
    )
    wire = _zmux._MatrixWire()
    wires = [wire]
    if relative:
        wires.append(_zmux._MatrixWire(join=True, client=request.client, signal=wire))
    if request.client:
        address = request.addresses["tcp"]
        session = await zmux.Session.connect(
            await _zmux._matrix_dial_tcp(address, wire=wire), config=config
        )
    else:
        listener = await stack.enter_async_context(zmux.Listener(config=config))
        tcp = await request.bind()
        pipe, peer = await tcp.accept(wire)
        await listener.handle_pipe(pipe, peer=peer)
        session = await anext(aiter(listener))
    stack.push_async_callback(close_session, session, clock=clock)
    await _zmux._matrix_established(session)
    require(
        (session.multipath == zmux.Multipath.IN_USE) == relative,
        "unexpected multipath negotiation",
    )
    if relative:
        session.subscribe_pipe_health()
        if request.client:
            extra = await _zmux._matrix_dial_tcp(address, wire=wires[1])
            await session.add_pipe(
                extra, options=zmux.PipeOptions(record_mode=zmux.RecordMode.TRUSTED)
            )
        else:
            pipe, peer = await tcp.accept(wires[1])
            await listener.handle_pipe(pipe, peer=peer)
        pipes = await settle_paths(session, wires, clock)
    else:
        pipes = session.pipes()
        require(len(pipes) == 1, "expected only the TCP bootstrap pipe")

    ids = [int(pipe.id) for pipe in pipes]
    await request.attached(ids)
    fields = {}
    if relative:
        data = await relative_stall(
            session,
            pipes=pipes,
            wires=wires,
            clock=clock,
            sent=sent[0],
            expected=expected[0],
        )
        received = [data]
        events = ["ack-stalled", "backup-delivered", "recovered"]
    else:
        received, overhead = await l15(
            request, session, wire=wire, clock=clock, sent=sent, expected=expected
        )
        events = ["l15-shaped"]
        fields["shaping_consumed_bytes"] = overhead
    states = [WireState(*path.snapshot()) for path in wires]
    await request.complete(
        events=events,
        received=received,
        tx={
            pipe: counts(state.sent_datagrams)
            for pipe, state in zip(ids, states, strict=True)
        },
        rx={
            pipe: counts(state.received_datagrams)
            for pipe, state in zip(ids, states, strict=True)
        },
        **fields,
    )


async def dial_websocket(request: Request) -> zmux.PipeIo:
    return await zmux.dial_websocket(f"ws://{request.addresses['websocket']}/zmux")


async def takeover(request: Request, stack: AsyncExitStack) -> None:
    replies = [b"re:" + message for message in (MARK, SECOND)]
    if request.client:
        pipe = await dial_websocket(request)
        await request.attached([])
        pipe = await _zmux._matrix_write_messages(pipe, messages=[MARK, SECOND])
        actual = await _zmux._matrix_read_messages(pipe, count=len(replies) + 1)
        require(actual == replies, "unexpected WebSocket reply boundaries or closure")
        events = ["fallback-echo"]
    else:
        handoff = None

        def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
            if info.stage == zmux.AdmissionStage.HEAD:
                return zmux.AdmissionVerdict.DEFER
            if prefix == MARK:
                return zmux.AdmissionVerdict.takeover(value="relay")
            return zmux.AdmissionVerdict.CLOSE

        def fallback(take: zmux.Takeover) -> None:
            nonlocal handoff
            take.detach()
            handoff = take

        listener = await stack.enter_async_context(
            zmux.Listener(
                config=session_config(),
                listener_config=zmux.ListenerConfig(
                    admission=zmux.Admission(
                        decide, peek=len(MARK), max_message=len(MARK)
                    ),
                    fallback=fallback,
                ),
            )
        )
        tcp = await request.bind()
        upgrade = await tcp.upgrade(listener)
        await request.attached([])
        require(not await upgrade.admit(), "takeover started a session")
        if handoff is None:
            raise Failure("missing detached takeover")
        require(
            handoff.detached and handoff.value == "relay" and handoff.replayed == MARK,
            "invalid detached takeover",
        )
        messages = handoff.into_messages()
        for expected, response in zip((MARK, SECOND), replies, strict=True):
            require(
                await messages.read_message(len(expected)) == expected,
                "takeover lost a message boundary",
            )
            await messages.write_message(response)
        await messages.shutdown()
        del messages
        stats = listener.stats()
        require(
            stats.sessions == 0 and stats.admission.takeover == 1,
            "unexpected takeover counters",
        )
        events = ["detached", "messages-replayed"]
    await request.complete(events=events, received=[], tx={}, rx={})


def ticket_fixture() -> tuple[zmux.PrefixAuth, zmux.MemoryPrefixStore]:
    slots = {"first_slot": 0, "last_slot": (1 << 64) - 1}
    generation = zmux.PrefixGeneration(
        sha256(b"matrix first-message outer key").digest(), **slots
    )
    ticket = zmux.PrefixTicket(
        sha256(b"matrix first-message ticket id").digest()[:16],
        key=sha256(b"matrix first-message ticket key").digest(),
        version=0,
        single_use=False,
        **slots,
    )
    store = zmux.MemoryPrefixStore(
        [generation], window=zmux.PrefixWindow(SLOT_SECONDS, skew=1, skew_limit=1)
    )
    store.add_ticket(ticket)
    auth = zmux.PrefixAuth(
        ticket,
        schedule=zmux.PrefixSchedule([generation]),
        slot_seconds=SLOT_SECONDS,
        binding=zmux.PrefixBinding.ALLOW_CLEARTEXT,
    )
    return auth, store


async def ticket_exchange(request: Request, session: zmux.Session) -> list[int]:
    await _zmux._matrix_established(session)
    ids = [int(pipe.id) for pipe in session.pipes()]
    require(ids == [0], "expected the WebSocket bootstrap pipe")
    await request.attached(ids)
    send, recv = await (session.open_bi() if request.client else session.accept_bi())
    if not request.client:
        await read_expected(recv, PING)
        await read_fin(recv)
    await send.write(PING)
    await send.finish()
    if request.client:
        await read_expected(recv, PING)
        await read_fin(recv)
    return ids


async def first_message_ticket(request: Request, stack: AsyncExitStack) -> None:
    auth, store = ticket_fixture()
    if request.client:
        token = auth._fixture_token(UNIX_SECONDS, nonce=b"\x35" * 16)
        pipe = await dial_websocket(request)
        pipe = await _zmux._matrix_write_messages(pipe, messages=[token])
        session = await zmux.Session.connect(pipe, config=session_config())
        stack.push_async_callback(close_session, session)
        ids = await ticket_exchange(request, session)
        replay = await dial_websocket(request)
        replay = await _zmux._matrix_write_messages(replay, messages=[token])
        require(
            await _zmux._matrix_read_messages(replay, count=2) == [REJECTED],
            "unexpected replay reply or closure",
        )
        events = ["ticket-echo", "replay-fallback"]
    else:
        replayed = False

        async def fallback(take: zmux.Takeover) -> None:
            nonlocal replayed
            token = take.replayed
            require(len(token) == zmux.PREFIX_TOKEN_LEN, "fallback lost the ticket")
            require(
                token == auth._fixture_token(UNIX_SECONDS, nonce=token[:16]),
                "fallback received an invalid fixture ticket",
            )
            messages = take.into_messages()
            require(
                await messages.read_message(len(token)) == token,
                "fallback lost the first message boundary",
            )
            await messages.write_message(REJECTED)
            await messages.shutdown()
            replayed = True

        listener = await stack.enter_async_context(
            zmux.Listener(
                config=session_config(),
                listener_config=zmux.ListenerConfig(
                    admission=zmux.Admission._fixture_first_message_ticket(
                        store, unix_seconds=UNIX_SECONDS
                    ),
                    fallback=fallback,
                ),
            )
        )
        tcp = await request.bind()
        first = await tcp.upgrade(listener)
        require(await first.admit(), "first ticket refused")
        session = await anext(aiter(listener))
        stack.push_async_callback(close_session, session)
        ids = await ticket_exchange(request, session)
        replay_upgrade = await tcp.upgrade(listener)
        require(not await replay_upgrade.admit(), "replayed ticket was accepted")
        require(replayed, "no verified first-message fallback")
        stats = listener.stats()
        require(
            stats.sessions == 1
            and stats.admission.accepted == 1
            and stats.admission.fallback == 1,
            "unexpected ticket admission counters",
        )
        events = ["ticket-accepted", "replay-rejected"]
    session_stats = session.stats()
    await request.complete(
        events=events,
        received=[],
        tx={pipe: counts(session_stats.datagrams_sent) for pipe in ids},
        rx={pipe: counts(session_stats.datagrams_received) for pipe in ids},
    )


async def run(*, psk: bytes) -> None:
    """Runs one JSON-lines pair request with the FINAL deadline."""
    if not hasattr(_zmux, "_MatrixTcp"):
        raise Failure("FINAL pairs require a wheel built with test-hooks")
    control = asyncio.StreamReader()
    async with asyncio.timeout(LIMIT), AsyncExitStack() as stack:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(control), sys.stdin.buffer
        )
        stack.callback(transport.close)
        request = Request(control, await control.readline())
        if request.carrier == "tcp":
            await tcp_pair(request, psk, stack)
        elif request.scenario == "websocket-takeover":
            await takeover(request, stack)
        else:
            await first_message_ticket(request, stack)
