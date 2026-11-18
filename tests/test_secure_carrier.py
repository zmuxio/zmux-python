"""Establish, the unified Join, record modes and on_reject."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable

import pytest
import zmux

NODE = zmux.StaticKey.from_scalar(hashlib.sha256(b"node").digest())
HANDLE, PSK = zmux.adapter.derive_handle_psk(b"s" * 32, b"tests")
CONFIG = zmux.Config(max_pipes=4)


class Gate:
    def __init__(self, psk: bytes = PSK, cred: tuple[int, bytes] | None = None):
        self.psk = psk
        self.cred = cred
        self.committed: list[zmux.Peer] = []

    def resolve(self, handle: bytes, source: object) -> bytes:
        assert handle == HANDLE
        return self.psk

    async def credential(
        self, handle: bytes, profile: int, local_context: bytes, source: object
    ) -> tuple[int, bytes] | None:
        await asyncio.sleep(0)
        return self.cred

    def commit(self, handle: bytes, peer: zmux.Peer, source: object) -> str:
        self.committed.append(peer)
        return "client 1"


class Trusting:
    """A host's verifier, `async`: remembers the input it was shown."""

    seen: zmux.VerifyInput | None = None

    async def verify(self, input: zmux.VerifyInput) -> zmux.VerifyVerdict:
        self.seen = input
        return zmux.VerifyVerdict(zmux.Principal("static_key", input.peer_static))


async def until(cond: Callable[[], object], limit: float = 5.0) -> None:
    async with asyncio.timeout(limit):
        while not cond():
            await asyncio.sleep(0.005)


async def echo(listener: zmux.Listener) -> None:
    tasks: set[asyncio.Future[None]] = set()
    async for session in listener:
        task = asyncio.ensure_future(_serve(session))
        tasks.add(task)
        task.add_done_callback(tasks.discard)


async def _serve(session: zmux.Session) -> None:
    try:
        while True:
            send, recv = await session.accept_bi()
            data = await recv.read_to_end()
            await send.write(data)
            await send.finish()
    except zmux.ZmuxError:
        pass


async def round_trip(session: zmux.Session, data: bytes = b"over it") -> None:
    send, recv = await session.open_bi()
    await send.write(data)
    await send.finish()
    assert await recv.read_to_end() == data


async def test_establish_join_and_modes() -> None:
    gate = Gate()
    async with zmux.Listener(
        config=CONFIG,
        listener_config=zmux.ListenerConfig(
            secure_server=zmux.SecureServer(gate, NODE)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        verifier = Trusting()
        async with asyncio.timeout(10):
            pipe, peer = await zmux.establish(
                await zmux.dial_tcp(*addr), verifier=verifier, handle=HANDLE, psk=PSK
            )
            assert verifier.seen is not None
            assert verifier.seen.role is zmux.Role.SERVER
            assert verifier.seen.psk_identity == HANDLE
            assert peer.static_key == verifier.seen.peer_static
            assert peer.static_key == NODE.public_key
            assert peer.record_mode is zmux.RecordMode.SEALED
            assert peer.pq_confidential and not peer.pq_authenticated
            # A pin of what was seen passes, and a wrong one does not.
            again, _ = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=zmux.PinVerifier(zmux.static_key_id(peer.static_key)),
                handle=HANDLE,
                psk=PSK,
            )
            del again
            with pytest.raises(zmux.CredentialsFailedError) as refused:
                await zmux.establish(
                    await zmux.dial_tcp(*addr),
                    verifier=zmux.PinVerifier(bytes(32)),
                    handle=HANDLE,
                    psk=PSK,
                )
            assert isinstance(refused.value, zmux.SecureCarrierError)
            assert refused.value.kind == "credentials_failed"
            assert refused.value.code is None
            async with await zmux.Session.connect(pipe, config=CONFIG) as session:
                assert session.weakest_record_mode is zmux.RecordMode.SEALED
                await round_trip(session)
                extra = await session.add_pipe(
                    await zmux.dial_tcp(*addr),
                    options=zmux.PipeOptions(
                        record_mode="sealed", key_group=zmux.KeyGroup.X25519
                    ),
                )
                await extra.joined()
                await round_trip(session, b"x" * 100_000)
                stats = session.stats()
                assert stats.join_failures == 0
                assert stats.join_batch_dropped == 0
                assert any(
                    p.record_mode is zmux.RecordMode.SEALED
                    for p in session.pipe_stats()
                )
        server.cancel()
    assert gate.committed


@pytest.mark.parametrize("endpoint", ["serve_websocket", "serve_http"])
@pytest.mark.parametrize("mode", ["sealed", "trusted"])
async def test_a_websocket_join_takes_over_from_the_first_pipe(
    endpoint: str, mode: str
) -> None:
    config = zmux.Config(
        max_pipes=4,
        allow_record_mode=lambda *_: True,
    )
    server = zmux.SecureServer(Gate(), NODE)
    async with zmux.Listener(
        config=config, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        if endpoint == "serve_http":
            addr = await listener.serve_http("127.0.0.1", 0, websocket=True)
        else:
            addr = await listener.serve_websocket("127.0.0.1", 0)
        url = f"ws://{addr[0]}:{addr[1]}/zmux"
        serving = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(20):
            pipe, _ = await zmux.establish(
                await zmux.dial_websocket(url),
                verifier=Trusting(),
                handle=HANDLE,
                psk=PSK,
            )
            async with await zmux.Session.connect(pipe, config=config) as session:
                await round_trip(session)
                first = session.pipes()[0]
                extra = await session.add_pipe(
                    await zmux.dial_websocket(url),
                    options=zmux.PipeOptions(record_mode=mode),
                )
                await extra.joined()
                assert session.stats().join_failures == 0
                # The joiner is ACTIVE once it wrote Confirm; the acceptor
                # attaches the pipe when Confirm arrives. Losing the first
                # pipe before that
                # loses the session.
                async with asyncio.timeout(5):
                    await extra.wait_attached()
                assert listener.stats().joins == 1
                first.abort()
                await round_trip(session, b"x" * 100_000)
        serving.cancel()
    assert listener.stats().joins == 1


async def test_a_server_credential_and_the_shaper() -> None:
    probe = Trusting()
    # Plans for the messages of the default (hybrid) Profiles.
    shaper = zmux.shaping.ShapingBundle.from_json(
        """{"tables":{"a":[[1,600,600]]},"kinds":{"default":[{"handshakes":
        {"establish":{"hello":{"pad_to":{"t":"a"},"delay":1000},
        "reply":{"pad_to":{"t":"a"}},"finish":{"pad_to":{"t":"a"}}}}}]}}"""
    )
    assert shaper.plan("default", "establish", "hello") == zmux.shaping.UnitPlan(
        pad_to=600, delay=0.001
    )

    gate = Gate()
    server = zmux.SecureServer(gate, NODE, shaper=shaper)
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            _, peer = await zmux.establish(
                await zmux.dial_tcp(*addr), verifier=probe, handle=HANDLE, psk=PSK
            )
            assert probe.seen is not None and probe.seen.credential is None
            gate.cred = (7, b"opaque")
            _, peer = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=probe,
                handle=HANDLE,
                psk=PSK,
                shaper=shaper,
            )
            assert probe.seen.credential == (7, b"opaque")
            assert peer.credential == (7, b"opaque")
            assert peer.verdict is not None
            assert peer.verdict.principal == zmux.Principal(
                "static_key", peer.static_key
            )


@pytest.mark.parametrize("profile", [1, 3, 4, 5])
async def test_each_profile(profile: int) -> None:
    """X25519 with ML-KEM-768: each Profile, the ones without a pre-shared key only
    when listed."""
    with_psk = profile in (1, 3)
    handle, psk = (HANDLE, PSK) if with_psk else (b"", b"")
    gate = Gate()
    server = zmux.SecureServer(gate, NODE, accepted_profiles=[profile])
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        served = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(10):
            pipe, peer = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=Trusting(),
                allowed_profiles=[profile],
                handle=handle,
                psk=psk,
            )
            assert peer.profile == profile
            async with await zmux.Session.connect(pipe, config=CONFIG) as session:
                await round_trip(session, b"h" * 50_000)
            # Another Profile is refused, and nothing falls back.
            with pytest.raises(zmux.ZmuxError):
                await zmux.establish(
                    await zmux.dial_tcp(*addr),
                    verifier=Trusting(),
                    allowed_profiles=[profile ^ 2 if with_psk else 9 - profile],
                    reply_timeout=0.3,
                    handle=handle,
                    psk=psk,
                )
        served.cancel()


def test_a_bundle_chooses_a_candidate_and_plans() -> None:
    text = """{"tables":{"a":[[1,100,100]]},"kinds":{"default":[
      {"requires":["later"],"nonsense":1},
      {"handshakes":{"join":{"hello":{"pad_to":{"t":"a"},"delay":2000}}},
       "budget":{"wire":{"initial":500}}}]}}"""
    b = zmux.shaping.ShapingBundle.from_json(text)
    assert b.selected("default") == 1
    assert b.plan("websocket", "join", "hello") == zmux.shaping.UnitPlan(
        pad_to=100, delay=0.002
    )
    assert b.plan("default", "join", "reply") is None
    budget = b.budget("default")
    assert budget is not None and budget.wire.initial == 500
    zmux.Config(shaping_bundle=b)
    with pytest.raises(ValueError, match="no_candidate"):
        zmux.shaping.ShapingBundle.from_json(
            '{"kinds":{"default":[{"requires":["later"]}]}}'
        )
    with pytest.raises(ValueError, match="duplicate_key"):
        zmux.shaping.ShapingBundle.from_json('{"kinds":{"default":[]},"kinds":{}}')


async def test_a_refused_establish_goes_to_on_reject() -> None:
    asked: list[zmux.RejectInfo] = []

    def on_reject(info: zmux.RejectInfo) -> str:
        asked.append(info)
        return "close"

    server = zmux.SecureServer(Gate(psk=b"w" * 32), NODE)
    async with zmux.Listener(
        config=CONFIG,
        listener_config=zmux.ListenerConfig(secure_server=server, on_reject=on_reject),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            with pytest.raises(zmux.ZmuxError):
                await zmux.establish(
                    await zmux.dial_tcp(*addr),
                    verifier=Trusting(),
                    handle=HANDLE,
                    psk=PSK,
                )
        # Counted once the carrier the joiner saw closed is dropped.
        await until(lambda: listener.stats().rejected == 1)
        assert listener.stats().sessions == 0
    assert asked[0].reason == "auth"
    assert asked[0].record_mode is zmux.RecordMode.SEALED


async def test_record_policy_and_declare_end_to_end() -> None:
    seen: list[zmux.RecordPolicyInput] = []

    policy = zmux.RecordPolicy(default=zmux.RecordMode.TRUSTED)

    def allow(c: zmux.RecordPolicyInput, mode: zmux.RecordMode, peer: object) -> bool:
        seen.append(c)
        return mode is zmux.RecordMode.TRUSTED

    auth = zmux.PipeAuth.psk(b"k" * 32)
    config = zmux.Config(
        max_pipes=4, pipe_auth=auth, record_policy=policy, allow_record_mode=allow
    )
    server_config = zmux.Config(
        max_pipes=4, pipe_auth=auth.with_end_to_end(), allow_record_mode=allow
    )
    async with zmux.Listener(config=server_config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(10):
            async with await zmux.connect_tcp(*addr, config=config) as session:
                assert session.weakest_record_mode is zmux.RecordMode.UNMANAGED
                session.declare_end_to_end()
                extra = await session.add_pipe(await zmux.dial_tcp(*addr))
                await extra.joined()
                await round_trip(session)
        server.cancel()
    assert seen and not seen[0].is_first_pipe


async def test_a_secure_carrier_authorized_join_and_tracer() -> None:
    asked: list[int] = []

    class Trace(zmux.Tracer):
        def __init__(self) -> None:
            self.established_ = False
            self.sessions: set[int] = set()
            self.events: list[zmux.Event] = []

        def established(self, session: int) -> None:
            self.established_ = True
            self.sessions.add(session)

        def event(self, session: int, event: zmux.Event) -> None:
            self.sessions.add(session)
            self.events.append(event)

    # The secure carrier takes SEALED; TRUSTED, which the acceptor refuses,
    # would fail the join.
    policy = zmux.RecordPolicy(
        default=zmux.RecordMode.TRUSTED, secure=zmux.RecordMode.SEALED
    )

    async def authorize(pipe: int) -> bool:
        await asyncio.sleep(0)
        asked.append(pipe)
        return True

    trace = Trace()
    auth = zmux.PipeAuth.psk(b"k" * 32)
    config = zmux.Config(
        max_pipes=4, pipe_auth=auth, record_policy=policy, tracer=trace
    )
    server_config = zmux.Config(
        max_pipes=4, pipe_auth=auth.with_end_to_end(), authorize_join=authorize
    )
    async with zmux.Listener(config=server_config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(10):
            async with await zmux.connect_tcp(*addr, config=config) as session:
                session.declare_end_to_end()
                reader, writer = await asyncio.open_connection(*addr)
                carrier = zmux.pipe_from_streams(reader, writer, max_record=16384)
                carrier.declare_carrier_secure()
                extra = await session.add_pipe(carrier)
                await extra.joined()
                await round_trip(session)
                assert session.multipath is zmux.Multipath.IN_USE
                session_id = session.id
        server.cancel()
    assert asked == [extra.id]
    assert trace.established_
    assert trace.sessions == {session_id}
    assert any(
        isinstance(e, zmux.PipeJoined) and e.pipe == extra.id for e in trace.events
    )


def test_removed_names_are_gone() -> None:
    assert not hasattr(zmux.PipeAuth, "insecure")
    assert not hasattr(zmux, "PipeReservation")
    assert not hasattr(zmux.Session, "reserve_pipe")
    assert not hasattr(zmux.Session, "join_secret_pending")
    with pytest.raises(TypeError):
        zmux.Listener(answer_unknown_joins=True)  # type: ignore[call-arg]


def test_a_secure_server_is_checked_when_made() -> None:
    zmux.SecureServer(Gate(), NODE, accepted_profiles=[4, 5])
    with pytest.raises(ValueError, match="unknown or reserved"):
        zmux.SecureServer(Gate(), NODE, accepted_profiles=[1, 6])
    with pytest.raises(ValueError):
        zmux.SecureServer(Gate(), zmux.StaticKey.from_scalar(bytes(32)))


async def test_a_profile_without_a_key_is_accepted_only_when_listed() -> None:
    for listed in (False, True):
        profiles = [4, 5] if listed else None
        server = zmux.SecureServer(Gate(), NODE, accepted_profiles=profiles)
        async with zmux.Listener(
            config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
        ) as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            async with asyncio.timeout(10):
                go = zmux.establish(
                    await zmux.dial_tcp(*addr),
                    verifier=Trusting(),
                    allowed_profiles=[4],
                    reply_timeout=0.3,
                )
                if listed:
                    await go
                else:
                    with pytest.raises(zmux.NoReplyError) as e:
                        await go
                    assert isinstance(e.value.__cause__, OSError)


async def test_configuration_errors_and_names() -> None:
    with pytest.raises(ValueError, match="resume_timeout"):
        zmux.Config(resume_timeout=0)
    assert not hasattr(zmux.PipeAuth, "secure_carrier")
    assert issubclass(zmux.ResumeFailedError, zmux.SessionClosedError)
    assert issubclass(zmux.JoinPendingError, zmux.PipeError)
    assert issubclass(zmux.PipeGoneError, zmux.PipeError)
    assert zmux.EventKind.RESUME_UNATTENDED.value == "ResumeUnattended"
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            for bad in (
                zmux.Config(max_pipes=2),
                zmux.Config(max_pipes=2, pipe_auth=zmux.PipeAuth().with_end_to_end()),
            ):
                with pytest.raises(ValueError):
                    await zmux.connect_tcp(*addr, config=bad)
    # A configuration the core cannot use is refused when it is made.
    with pytest.raises(zmux.InvalidArgumentError):
        zmux.Config(join_timeout=0)
    with pytest.raises(zmux.InvalidArgumentError):
        zmux.Config(
            max_pipes=4,
            session_crypto=zmux.SessionCrypto(suites=(1,), groups=(1,)),
        )


def test_join_psk_derivation() -> None:
    mine = zmux.SessionCrypto(suites=(1,), groups=(zmux.KeyGroup.X25519_MLKEM768,))
    crypto = zmux.adapter.session_crypto(mine, mine)
    secret = b"e" * 32
    i = zmux.adapter.derive_join_psk(
        1, secret, role=zmux.Role.CLIENT, session_crypto=crypto
    )
    r = zmux.adapter.derive_join_psk(
        1, secret, role=zmux.Role.SERVER, session_crypto=crypto
    )
    assert len(i) == 32 and i != r
    assert i == zmux.adapter.expand_join_psk(
        1, secret, role=zmux.Role.CLIENT, session_crypto=crypto, length=32
    )
    with pytest.raises(ValueError):
        zmux.adapter.derive_join_psk(
            1 << 40, secret, role=zmux.Role.CLIENT, session_crypto=crypto
        )
    with pytest.raises(ValueError):
        zmux.adapter.session_crypto(zmux.SessionCrypto(suites=(), groups=(2,)), mine)


class Judge:
    """A host's verifier, synchronous: passes with a value, or raises what it is told."""

    def __init__(
        self, raises: type[Exception] | None = None, proof_key: bytes | None = None
    ):
        self.raises = raises
        self.proof_key = proof_key
        self.inputs: list[zmux.VerifyInput] = []

    def verify(self, input: zmux.VerifyInput) -> zmux.VerifyVerdict:
        self.inputs.append(input)
        if self.raises is not None:
            raise self.raises("no")
        return zmux.VerifyVerdict(
            zmux.Principal("other", b"who", code=9),
            proof_key=self.proof_key,
            value={"name": "host's"},
        )


async def test_application_data_and_the_verdict() -> None:
    """Each side supplies its data by a callable, sync or async; the peer's data comes
    with its message and protection, authenticated only once the peer passed."""
    asked: list[tuple[int, zmux.VerifyInput | None]] = []
    verdicts: list[zmux.VerifyVerdict | None] = []

    def client_data(
        message: int,
        peer: zmux.VerifyInput | None,
        verdict: zmux.VerifyVerdict | None,
    ) -> bytes | None:
        asked.append((message, peer))
        verdicts.append(verdict)
        return b"m1" if message == 1 else b"m3"

    async def server_data(
        message: int,
        peer: zmux.VerifyInput | None,
        verdict: zmux.VerifyVerdict | None,
    ) -> bytes | None:
        assert message == 2 and peer is not None and verdict is None
        assert [a.data for a in peer.peer_app_data] == [b"m1"]
        assert peer.peer_static == b""
        return b"m2"

    judge = Judge()
    gate = Gate()
    server = zmux.SecureServer(
        gate,
        NODE,
        client_verifier=judge,
        app_data=server_data,
        local_context=b"listener",
    )
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        verifier = Judge()
        async with asyncio.timeout(10):
            _, peer = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=verifier,
                handle=HANDLE,
                psk=PSK,
                app_data=client_data,
                local_context=b"dial",
                credential=(5, b"me"),
            )
            await until(lambda: gate.committed)
    assert peer.app_data == (zmux.AppData(2, b"m2", True, True),)
    assert peer.verdict is not None and peer.verdict.value == {"name": "host's"}
    assert peer.verdict.principal == zmux.Principal("other", b"who", 9)
    seen = verifier.inputs[0]
    assert seen.local_context == b"dial"
    assert seen.peer_app_data == (zmux.AppData(2, b"m2", True, False),)
    assert [m for m, _ in asked] == [1, 3]
    # Message 3 sees the client's verdict on the server, value included.
    assert verdicts[0] is None
    assert verdicts[1] is not None and verdicts[1].value == {"name": "host's"}
    assert verdicts[1].principal == zmux.Principal("other", b"who", 9)
    assert asked[1][1] is not None and asked[1][1].peer_app_data == seen.peer_app_data
    client = judge.inputs[0]
    assert client.role is zmux.Role.CLIENT
    assert client.credential == (5, b"me")
    assert client.local_context == b"listener"
    assert all(not a.authenticated for a in client.peer_app_data)
    committed = gate.committed[0]
    assert committed.app_data == (
        zmux.AppData(1, b"m1", False, False),
        zmux.AppData(3, b"m3", True, True),
    )
    assert committed.verdict is not None and committed.verdict.value == {
        "name": "host's"
    }


async def test_too_much_application_data_fails_and_none_is_unbounded() -> None:
    def big(
        message: int,
        peer: zmux.VerifyInput | None,
        verdict: zmux.VerifyVerdict | None,
    ) -> bytes | None:
        return b"x" * 300 if message == 2 else None

    server = zmux.SecureServer(Gate(), NODE, app_data=big)
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            with pytest.raises(zmux.ZmuxError):
                await zmux.establish(
                    await zmux.dial_tcp(*addr), verifier=Judge(), handle=HANDLE, psk=PSK
                )
            _, peer = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=Judge(),
                handle=HANDLE,
                psk=PSK,
                max_app_data=None,
            )
            assert peer.app_data[0].data == b"x" * 300


async def test_a_handshake_message_above_8192_bytes_is_refused_locally() -> None:
    # The client's message 3 would exceed the 8192-byte handshake message
    # floor: nothing is written and the caller's value is at fault.
    server = zmux.SecureServer(Gate(), NODE, client_verifier=Judge())
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            with pytest.raises(zmux.InvalidArgumentError) as e:
                await zmux.establish(
                    await zmux.dial_tcp(*addr),
                    verifier=Judge(),
                    handle=HANDLE,
                    psk=PSK,
                    credential=(5, b"c" * 9000),
                )
            assert e.value.kind is zmux.ErrorKind.TOO_LARGE


async def test_transcript_proofs_and_pq_authentication() -> None:
    """Both ends sign with ML-DSA-44 keys their verdicts name: both are PQ
    authenticated; a pin can name the proof key too."""
    server_key = zmux.SigningKey.generate()
    client_key = zmux.SigningKey.generate(zmux.KeyAlg.MLDSA44)
    assert server_key.proof_key == (zmux.KeyAlg.MLDSA44, server_key.public)
    assert server_key.key_id == zmux.key_id(zmux.KeyAlg.MLDSA44, server_key.public)

    class HostSigner:
        """A host's signer, `async`, here of a key of this process."""

        proof_key = client_key.proof_key

        async def sign(self, message: bytes) -> bytes:
            return client_key.sign(message)

    gate = Gate()
    server = zmux.SecureServer(
        gate,
        NODE,
        signer=server_key,
        client_verifier=Judge(proof_key=client_key.key_id),
        require_pq_auth=True,
    )
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        node_id = zmux.static_key_id((await establish_once(*addr)).static_key)
        async with asyncio.timeout(10):
            _, peer = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=zmux.PinVerifier(node_id, proof_key=server_key.key_id),
                handle=HANDLE,
                psk=PSK,
                signer=HostSigner(),
                require_pq_auth=True,
            )
            assert peer.pq_authenticated and peer.pq_confidential
            await until(lambda: gate.committed)
            assert gate.committed[-1].pq_authenticated
            # A verdict naming another proof key fails the server.
            with pytest.raises(zmux.ZmuxError):
                await zmux.establish(
                    await zmux.dial_tcp(*addr),
                    verifier=Judge(proof_key=bytes(32)),
                    handle=HANDLE,
                    psk=PSK,
                    signer=client_key,
                )
    with pytest.raises(ValueError):
        zmux.SecureServer(Gate(), NODE, require_pq_auth=True)
    with pytest.raises(ValueError):
        zmux.SecureServer(
            Gate(),
            NODE,
            require_pq_auth=True,
            client_verifier=zmux.PinVerifier(bytes(32)),
        )


async def establish_once(host: str, port: int) -> zmux.Peer:
    """The server's static key, as an unpinned client learns it."""
    async with asyncio.timeout(10):
        _, peer = await zmux.establish(
            await zmux.dial_tcp(host, port), verifier=Judge(), handle=HANDLE, psk=PSK
        )
    return peer


@pytest.mark.parametrize(
    ("raises", "rejected"),
    [
        (zmux.VerifyRejectedError, True),
        (ValueError, True),
        (zmux.VerifyUnavailableError, False),
    ],
)
async def test_a_rejection_and_a_temporary_failure(
    raises: type[Exception], rejected: bool
) -> None:
    """Only a rejection goes to the reject policy; any exception but
    `VerifyUnavailable` is one."""
    reasons: list[str] = []

    def on_reject(info: zmux.RejectInfo) -> str:
        reasons.append(info.reason)
        return "close"

    gate = Gate()
    server = zmux.SecureServer(gate, NODE, client_verifier=Judge(raises))
    async with zmux.Listener(
        config=CONFIG,
        listener_config=zmux.ListenerConfig(secure_server=server, on_reject=on_reject),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            pipe, _ = await zmux.establish(
                await zmux.dial_tcp(*addr), verifier=Judge(), handle=HANDLE, psk=PSK
            )
            with pytest.raises(zmux.ZmuxError):
                async with await zmux.Session.connect(pipe, config=CONFIG) as session:
                    await round_trip(session)
            if rejected:
                await until(lambda: reasons)
    assert reasons == (["credentials_failed"] if rejected else [])
    assert not gate.committed


async def test_an_epoch_advance_is_reported() -> None:
    config = zmux.Config(max_pipes=4, epoch_policy=zmux.EpochPolicy.MANUAL)
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            secure_server=zmux.SecureServer(Gate(), NODE)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(10):
            pipe, _ = await zmux.establish(
                await zmux.dial_tcp(*addr), verifier=Judge(), handle=HANDLE, psk=PSK
            )
            async with await zmux.Session.connect(pipe, config=config) as session:
                await round_trip(session)
                extra = await session.add_pipe(
                    await zmux.dial_tcp(*addr),
                    options=zmux.PipeOptions(record_mode="sealed"),
                )
                await extra.joined()
                assert {p.epoch for p in session.pipe_stats()} == {0}
                assert session.epoch == 0
                session.advance_epoch()
                while True:
                    event = await session.next_event()
                    assert not isinstance(event, zmux.EpochDeleted)
                    if isinstance(event, zmux.EpochCommitted):
                        assert event.epoch == 1
                        break
                # The offerer switches as the answer arrives.
                await until(lambda: session.epoch == 1)
                await round_trip(session)
        server.cancel()
    # Zero is a configuration error; a negative value is no duration or count.
    for bad in ({"period": 0}, {"joins": 0}):
        with pytest.raises(ValueError):
            zmux.EpochPolicy(**bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        zmux.Config(epoch_policy=zmux.EpochPolicy(joins=-1))


async def test_replace_pipes_replaces_every_pipe() -> None:
    where: list[tuple[str, int]] = []

    async def redial(direction: zmux.Direction) -> zmux.PipeIo:
        assert direction == "bidi"
        pipe, _ = await zmux.establish(
            await zmux.dial_tcp(*where[0]), verifier=Judge(), handle=HANDLE, psk=PSK
        )
        return pipe

    config = zmux.Config(
        max_pipes=4, epoch_policy=zmux.EpochPolicy.MANUAL, redial=redial
    )
    plain = zmux.Config(max_pipes=4, epoch_policy=zmux.EpochPolicy.MANUAL)
    with pytest.raises(ValueError, match="redial"):
        async with zmux.Listener(
            config=plain,
            listener_config=zmux.ListenerConfig(
                secure_server=zmux.SecureServer(Gate(), NODE)
            ),
        ) as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            server = asyncio.ensure_future(echo(listener))
            try:
                pipe, _ = await zmux.establish(
                    await zmux.dial_tcp(*addr), verifier=Judge(), handle=HANDLE, psk=PSK
                )
                async with await zmux.Session.connect(pipe, config=plain) as session:
                    # Without the redial hook it fails at once.
                    async with asyncio.timeout(5):
                        await session.replace_pipes()
            finally:
                server.cancel()
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            secure_server=zmux.SecureServer(Gate(), NODE)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        where.append(addr)
        server = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(20):
            pipe, _ = await zmux.establish(
                await zmux.dial_tcp(*addr), verifier=Judge(), handle=HANDLE, psk=PSK
            )
            async with await zmux.Session.connect(pipe, config=config) as session:
                await round_trip(session)
                extra = await session.add_pipe(
                    await zmux.dial_tcp(*addr),
                    options=zmux.PipeOptions(record_mode="sealed"),
                )
                await extra.joined()
                before = {p.pipe for p in session.pipe_stats()}
                await session.replace_pipes()
                assert session.epoch == 1
                after = {
                    p.pipe
                    for p in session.pipe_stats()
                    if p.outbound is zmux.OutboundState.ACTIVE
                }
                assert after and not (after & before)
                await round_trip(session)
        server.cancel()


def test_secure_carrier_errors() -> None:
    assert issubclass(zmux.SecureCarrierError, zmux.ZmuxError)
    assert issubclass(zmux.CredentialsFailedError, zmux.SecureCarrierError)
    assert zmux.CredentialsFailedError.kind == "credentials_failed"
    assert zmux.SecureCarrierError().code is None
    # A duplicate that cannot be decided is an argument error the caller mends.
    assert issubclass(zmux.DuplicateUndecidedError, zmux.ZmuxError)
    assert issubclass(zmux.DuplicateUndecidedError, ValueError)


def test_static_key() -> None:
    public = NODE.public_key
    other = zmux.StaticKey.from_scalar(bytes(31) + b"\x01")
    assert len(public) == 32 and public != other.public_key
    assert NODE.scalar == hashlib.sha256(b"node").digest()
    assert zmux.static_key_id(public) == zmux.key_id(zmux.KeyAlg.X25519, public)
    assert repr(NODE) == "StaticKey(..)"
    for bad in (b"short", bytes(33)):
        with pytest.raises(ValueError):
            zmux.StaticKey.from_scalar(bad)
    generated = zmux.StaticKey.generate()
    assert generated.public_key != generated.__class__.generate().public_key
    assert not hasattr(zmux, "static_public")


async def test_a_single_pipe_session_has_no_epoch() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            async with await zmux.connect_tcp(*addr) as session:
                assert session.epoch is None


@pytest.mark.parametrize(
    ("server_args", "reason"),
    [
        # The verdict names a proof key and the client proves nothing.
        ("proof", "proof"),
        # The verifier passes the client without a proof, and the server
        # requires the post-quantum authentication a proof gives.
        ("pq", "pq_auth_required"),
    ],
)
async def test_the_server_names_a_credential_refusal_by_its_own_reason(
    server_args: str, reason: str
) -> None:
    """A server judging a client closes that carrier and reports the reason to
    `on_reject` and its statistics; it raises nothing to the application, and
    the client learns nothing from the wire."""
    reasons: list[str] = []

    def on_reject(info: zmux.RejectInfo) -> str:
        reasons.append(info.reason)
        return "close"

    client_key = zmux.SigningKey.generate(zmux.KeyAlg.MLDSA44)
    if server_args == "proof":
        server = zmux.SecureServer(
            Gate(), NODE, client_verifier=Judge(proof_key=client_key.key_id)
        )
    else:
        server = zmux.SecureServer(
            Gate(),
            NODE,
            client_verifier=Judge(),
            signer=zmux.SigningKey.generate(),
            require_pq_auth=True,
        )
    async with zmux.Listener(
        config=CONFIG,
        listener_config=zmux.ListenerConfig(secure_server=server, on_reject=on_reject),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with asyncio.timeout(10):
            pipe, _ = await zmux.establish(
                await zmux.dial_tcp(*addr),
                verifier=Judge(),
                handle=HANDLE,
                psk=PSK,
            )
            with pytest.raises(zmux.ZmuxError):
                async with await zmux.Session.connect(pipe, config=CONFIG) as session:
                    await round_trip(session)
            await until(lambda: reasons)
        assert reasons == [reason]
        await until(lambda: listener.stats().rejected == 1)
        # Nothing reached the application: no session was accepted.
        assert listener.stats().sessions == 0


async def test_credentials_failed_is_raised_by_the_side_that_judged() -> None:
    """A client whose verifier rejects the server or cannot decide, or whose
    `require_pq_auth` does not hold, fails with `CredentialsFailedError`."""
    server = zmux.SecureServer(Gate(), NODE)
    async with zmux.Listener(
        config=CONFIG, listener_config=zmux.ListenerConfig(secure_server=server)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        for verifier, pq in (
            (Judge(zmux.VerifyRejectedError), False),
            (Judge(zmux.VerifyUnavailableError), False),
            (Judge(), True),
        ):
            async with asyncio.timeout(10):
                with pytest.raises(zmux.CredentialsFailedError) as e:
                    await zmux.establish(
                        await zmux.dial_tcp(*addr),
                        verifier=verifier,
                        handle=HANDLE,
                        psk=PSK,
                        require_pq_auth=pq,
                    )
            assert e.value.kind == "credentials_failed" and e.value.code is None
