import asyncio
import contextlib
import ipaddress
import secrets
import socket
import struct
import sys
from collections import defaultdict
from collections.abc import Awaitable, Callable, Coroutine
from functools import partial
from types import CoroutineType, SimpleNamespace
from typing import Any, Never, cast

import pytest
import zmux
from support import round_trip as exchange
from support import (
    LOOPBACK,
    TEST_HOOKS,
    WATCHDOG,
    manual_clock,
    native_call,
    start_pending,
    until,
)
from support import echo
from support import Tls

StreamPair = tuple[asyncio.StreamReader, asyncio.StreamWriter]
JoinReport = tuple[zmux.PipeId, BaseException | None]
SessionJoinReport = tuple[zmux.SessionId, zmux.PipeId, BaseException | None]


async def round_trip(
    session: zmux.Session, data: bytes = b"hello", **open_args: Any
) -> None:
    await exchange(
        session, data, **(open_args or {"info": b"meta", "priority": zmux.Priority(2)})
    )


@pytest.mark.parametrize(
    "carrier",
    [
        "tcp",
        "tls",
        "quic",
        "websocket",
        "wss",
        "http",
        "http2",
        "http2-tls",
        "h3",
        "webtransport",
    ],
)
# HS-08
async def test_carrier(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        if carrier == "tcp":
            addr = await listener.serve_tcp("127.0.0.1", 0)
            dial = zmux.dial_tcp(*addr)
        elif carrier == "tls":
            addr = await listener.serve_tls("127.0.0.1", 0, tls=server_tls)
            # HS-08. Finish one malformed handshake before opening the good one.
            reader, writer = await asyncio.open_connection(*addr)
            writer.write(b"not a TLS record")
            await writer.drain()
            with contextlib.suppress(ConnectionResetError):
                await reader.read()
            writer.close()
            dial = zmux.dial_tls(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
            dial = zmux.dial_quic(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "websocket":
            addr = await listener.serve_websocket("127.0.0.1", 0)
            dial = zmux.dial_websocket(f"ws://{addr[0]}:{addr[1]}/")
        elif carrier == "wss":
            addr = await listener.serve_websocket("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_websocket(f"wss://localhost:{port}/", tls=client_tls)
        elif carrier == "http2":
            addr = await listener.serve_http("127.0.0.1", 0)
            dial = zmux.dial_http2(*addr)
        elif carrier == "http2-tls":
            addr = await listener.serve_http("127.0.0.1", 0, tls=server_tls)
            dial = zmux.dial_http2(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "h3":
            addr = await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
        elif carrier == "webtransport":
            # The client resolves the URL's host: serve on its first address.
            addr = await listener.serve_webtransport("localhost", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_webtransport(
                f"https://localhost:{port}/zmux", tls=client_tls
            )
        else:
            addr = await listener.serve_http("127.0.0.1", 0)
            dial = zmux.dial_streaming(*addr)
        server = asyncio.create_task(echo(listener))
        async with await zmux.Session.connect(await dial) as session:
            await round_trip(session)
        server.cancel()


async def test_http2_over_tls_has_the_connection_exporter(tls: Tls) -> None:
    """Every bidirectional request of an HTTP/2 connection on TLS both ends
    terminate has that connection's exporter: the session's exporter is the
    same at both ends, and over h2c there is none."""
    server_tls, client_tls = tls
    cfg = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=2)
        ),
        pipe_auth=zmux.PipeAuth.exporter().with_end_to_end(),
    )
    async with zmux.Listener(config=cfg) as listener:
        addr = await listener.serve_http("127.0.0.1", 0, tls=server_tls)
        conn = await zmux.Http2Connection.dial(
            *addr, tls=client_tls, server_name="localhost"
        )
        pipe = await conn.open_pipe()
        assert pipe.terminated_tls is not None
        async with (
            await zmux.Session.connect(pipe, config=cfg) as c,
            await listener.accept() as s,
        ):
            got = c.export_keying_material("app", length=16)
            assert got == s.export_keying_material("app", length=16)
            extra = await conn.open_pipe()
            assert extra.terminated_tls is not None
            await c.add_pipe(extra)
            first, second = c.pipe_stats()
            assert first.carrier_sample is not None
            assert second.carrier_sample is not None
            assert first.carrier_sample.carrier_id == second.carrier_sample.carrier_id
            assert first.carrier_sample.sampled_at == second.carrier_sample.sampled_at
            assert isinstance(first.carrier_sample.sampled_at, int)
        plain = await listener.serve_http("127.0.0.1", 0)
        pipe = await zmux.dial_http2(*plain)
        assert pipe.terminated_tls is None


def prefix_authority() -> tuple[
    zmux.PrefixGeneration, zmux.PrefixTicket, zmux.MemoryPrefixStore
]:
    last = (1 << 64) - 1
    generation = zmux.PrefixGeneration(
        secrets.token_bytes(32), first_slot=0, last_slot=last
    )
    ticket = zmux.PrefixTicket(
        secrets.token_bytes(16),
        key=secrets.token_bytes(32),
        first_slot=0,
        last_slot=last,
        single_use=False,
    )
    store = zmux.MemoryPrefixStore([generation], window=zmux.PrefixWindow(30, skew=1))
    store.add_ticket(ticket)
    return generation, ticket, store


def presenter(
    generation: zmux.PrefixGeneration,
    ticket: zmux.PrefixTicket,
    binding: zmux.PrefixBinding,
    *,
    header: str | None = None,
) -> zmux.PrefixAuth:
    return zmux.PrefixAuth(
        ticket,
        schedule=zmux.PrefixSchedule([generation]),
        slot_seconds=30,
        binding=binding,
        header=header,
    )


async def serve_admitted(
    listener: zmux.Listener, carrier: str, server_tls: zmux.TlsConfig
) -> tuple[str, int]:
    if carrier == "tcp":
        return await listener.serve_tcp("127.0.0.1", 0)
    if carrier == "quic":
        return await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
    if carrier == "http":
        return await listener.serve_http(LOOPBACK, 0, tls=server_tls)
    if carrier == "h3":
        return await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
    if carrier == "websocket":
        return await listener.serve_websocket("127.0.0.1", 0)
    if carrier == "wss":
        return await listener.serve_websocket("127.0.0.1", 0, tls=server_tls)
    if carrier == "webtransport":
        return await listener.serve_webtransport("localhost", 0, tls=server_tls)
    return await listener.serve_tls("127.0.0.1", 0, tls=server_tls)


def dial_with(
    carrier: str,
    addr: tuple[str, int],
    client_tls: zmux.TlsConfig,
    credential: zmux.PrefixAuth | zmux.CarrierCredential | None,
) -> Awaitable[zmux.PipeIo]:
    port = addr[1]
    if carrier == "tcp":
        return zmux.dial_tcp(*addr, carrier_credential=credential)
    if carrier == "quic":
        return zmux.dial_quic(
            *addr,
            tls=client_tls,
            server_name="localhost",
            carrier_credential=credential,
        )
    if carrier == "http":

        async def http2() -> zmux.PipeIo:
            conn = await zmux.Http2Connection.dial(
                *addr,
                tls=client_tls,
                server_name=addr[0],
                carrier_credential=credential,
            )
            return await conn.open_pipe()

        return http2()
    if carrier == "h3":
        return zmux.dial_http3(
            f"https://localhost:{port}/zmux",
            tls=client_tls,
            addr=addr,
            carrier_credential=credential,
        )
    if carrier == "websocket":
        return zmux.dial_websocket(
            f"ws://{addr[0]}:{addr[1]}/", carrier_credential=credential
        )
    if carrier == "wss":
        return zmux.dial_websocket(
            f"wss://localhost:{port}/", tls=client_tls, carrier_credential=credential
        )
    if carrier == "webtransport":
        return zmux.dial_webtransport(
            f"https://localhost:{port}/zmux",
            tls=client_tls,
            carrier_credential=credential,
        )
    return zmux.dial_tls(
        *addr, tls=client_tls, server_name="localhost", carrier_credential=credential
    )


@pytest.mark.parametrize(
    ("carrier", "bind_tls"),
    [
        ("tcp", False),
        ("tls", False),
        ("tls", True),
        ("quic", False),
        ("quic", True),
        ("http", False),
        ("h3", False),
        ("h3", True),
        ("wss", False),
        ("wss", True),
        ("webtransport", False),
        ("webtransport", True),
    ],
)
async def test_prefix_auth(carrier: str, bind_tls: bool, tls: Tls) -> None:
    server_tls, client_tls = tls
    generation, ticket, store = prefix_authority()
    binding = (
        zmux.PrefixBinding.ALLOW_CLEARTEXT
        if carrier == "tcp"
        else zmux.PrefixBinding.BOUND
        if bind_tls
        else zmux.PrefixBinding.ENCRYPTED
    )
    auth = presenter(generation, ticket, binding, header="X-Carrier-Ticket")
    admission = zmux.Admission.prefix_auth(
        store, binding=binding, header=auth.header_name
    )
    assert admission.peek == zmux.PREFIX_TOKEN_LEN == 64
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(
                admission=admission, handshake_timeout=2 * WATCHDOG
            )
        ) as listener,
        asyncio.TaskGroup() as tasks,
    ):
        addr = await serve_admitted(listener, carrier, server_tls)
        server = tasks.create_task(echo(listener))
        try:
            pipe = await dial_with(carrier, addr, client_tls, auth)
            async with await zmux.Session.connect(pipe) as session:
                await round_trip(session)
        finally:
            server.cancel()


async def test_held_carriers_count_per_source() -> None:
    async def close(stream_writer: asyncio.StreamWriter) -> None:
        stream_writer.close()
        with contextlib.suppress(ConnectionResetError):
            await stream_writer.wait_closed()

    async def read_end(stream_reader: asyncio.StreamReader) -> None:
        with contextlib.suppress(ConnectionResetError):
            assert await stream_reader.read() == b""

    admission = zmux.Admission.prefix_auth(
        prefix_authority()[2],
        binding=zmux.PrefixBinding.ALLOW_CLEARTEXT,
        reject=zmux.PrefixRejection.STALL,
        peek_timeout=WATCHDOG,
        stall=(2 * WATCHDOG, 2 * WATCHDOG),
    )
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(
                limits=zmux.ListenerLimits(max_pending_per_source=2),
                admission=admission,
            )
        ) as listener,
        contextlib.AsyncExitStack() as sockets,
        asyncio.TaskGroup() as tasks,
    ):
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        reads = []
        for _ in range(3):
            reader, writer = await asyncio.open_connection(host, port)
            sockets.push_async_callback(close, writer)
            writer.write(bytes(zmux.PREFIX_TOKEN_LEN))
            await writer.drain()
            reads.append(tasks.create_task(read_end(reader)))
        # A source stalls at most max_pending_per_source - 1 carriers: one
        # stalls and holds its slot, the others are refused or closed.
        pending = set(reads)
        while len(pending) > 1:
            _, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
        assert len(pending) == 1
        stats = listener.stats()
        assert stats.admission.stalled == 1
        assert stats.admission.stall_overflow + stats.refused == 2
        pending.pop().cancel()


@pytest.mark.parametrize(
    "carrier", ["tcp", "tls", "quic", "http", "h3", "wss", "webtransport"]
)
@pytest.mark.parametrize("token", ["none", "wrong"])
async def test_prefix_auth_refused(carrier: str, token: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    byte_stream = carrier in ("tcp", "tls", "quic")
    binding = (
        zmux.PrefixBinding.ALLOW_CLEARTEXT
        if carrier == "tcp"
        else zmux.PrefixBinding.ENCRYPTED
    )
    admission = zmux.Admission.prefix_auth(
        prefix_authority()[2],
        binding=binding,
        reject=zmux.PrefixRejection.FALLBACK
        if byte_stream
        else zmux.PrefixRejection.CLOSE,
    )
    replayed: asyncio.Queue[bytes] = asyncio.Queue()

    def fallback(taken: zmux.Takeover) -> None:
        replayed.put_nowait(taken.replayed)

    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(
                admission=admission,
                fallback=fallback if byte_stream else None,
                handshake_timeout=2 * WATCHDOG,
            )
        ) as listener,
    ):
        addr = await serve_admitted(listener, carrier, server_tls)
        other = (
            presenter(*prefix_authority()[:2], binding) if token == "wrong" else None
        )
        if carrier in ("wss", "webtransport"):
            with pytest.raises(zmux.ConnectError):
                await dial_with(carrier, addr, client_tls, other)
        else:
            stream = (await dial_with(carrier, addr, client_tls, other)).into_stream()
            try:
                if other is None:
                    await stream.write(bytes(admission.peek))
                if byte_stream:
                    prefix = await replayed.get()
                    assert len(prefix) == admission.peek
                    if other is None:
                        assert prefix == bytes(admission.peek)
                else:
                    with pytest.raises(zmux.ConnectError):
                        await stream.read()
            finally:
                await stream._release()
        stats = listener.stats()
        assert stats.admission == zmux.AdmissionStats(
            fallback=int(byte_stream), closed=int(not byte_stream)
        )
        assert stats.sessions == 0


async def test_prefix_auth_python_authority() -> None:
    generation, ticket, _ = prefix_authority()
    schedule = zmux.PrefixSchedule([generation], version=7)
    claims: list[zmux.PrefixClaim] = []
    loop = asyncio.get_running_loop()

    class Authority:
        window = zmux.PrefixWindow(30)

        def local_schedule(self) -> tuple[zmux.PrefixSchedule, int]:
            return schedule, 0

        async def floor(self, attempt: zmux.PrefixDeadline, /) -> int:
            assert asyncio.get_running_loop() is loop
            assert not attempt.ended and attempt.deadline is not None
            return 0

        async def lookup(
            self, id: bytes, attempt: zmux.PrefixDeadline, /
        ) -> zmux.PrefixTicket:
            assert len(id) == 16 and not attempt.ended
            return ticket

        async def claim(
            self, claim: zmux.PrefixClaim, attempt: zmux.PrefixDeadline, /
        ) -> bool:
            assert claim.schedule == 7 and not attempt.ended
            claims.append(claim)
            raise OSError("receipt unavailable")

        async def resolve(
            self, claim: zmux.PrefixClaim, attempt: zmux.PrefixDeadline, /
        ) -> bool:
            assert not attempt.ended and claims == [claim]
            return True

    binding = zmux.PrefixBinding.ALLOW_CLEARTEXT
    auth = zmux.PrefixAuth(ticket, schedule=schedule, slot_seconds=30, binding=binding)
    admission = zmux.Admission.prefix_auth(Authority(), binding=binding)
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(admission=admission)
        ) as listener,
    ):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        pipe = await zmux.dial_tcp(*addr, carrier_credential=auth)
        async with await zmux.Session.connect(pipe), await listener.accept():
            assert len(claims) == 1


async def test_prefix_auth_single_use_ticket_is_redeemed_once() -> None:
    last = (1 << 64) - 1
    generation = zmux.PrefixGeneration(
        secrets.token_bytes(32), first_slot=0, last_slot=last
    )
    ticket = zmux.PrefixTicket(
        secrets.token_bytes(16),
        key=secrets.token_bytes(32),
        first_slot=0,
        last_slot=last,
    )
    store = zmux.MemoryPrefixStore([generation], window=zmux.PrefixWindow(30))
    store.add_ticket(ticket)
    binding = zmux.PrefixBinding.ALLOW_CLEARTEXT
    auth = presenter(generation, ticket, binding)
    admission = zmux.Admission.prefix_auth(store, binding=binding)
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(admission=admission)
        ) as listener,
    ):
        addr = await listener.serve_tcp(LOOPBACK, 0)
        pipe = await zmux.dial_tcp(*addr, carrier_credential=auth)
        async with await zmux.Session.connect(pipe), await listener.accept():
            assert listener.stats().admission.accepted == 1
        second = await zmux.dial_tcp(*addr, carrier_credential=auth)
        with pytest.raises(zmux.ZmuxError):
            await zmux.Session.connect(second)
        assert listener.stats().admission.closed == 1


def test_prefix_auth_config() -> None:
    generation, ticket, store = prefix_authority()
    schedule = zmux.PrefixSchedule([generation])
    with pytest.raises(ValueError):
        zmux.PrefixWindow(0)
    with pytest.raises(ValueError):
        zmux.PrefixTicket(
            secrets.token_bytes(16),
            key=secrets.token_bytes(32),
            first_slot=1,
            last_slot=0,
        )
    with pytest.raises(ValueError):
        zmux.PrefixAuth(ticket, schedule=schedule, slot_seconds=0)
    with pytest.raises(ValueError, match="reserved"):
        presenter(generation, ticket, zmux.PrefixBinding.BOUND, header="Authorization")
    with pytest.raises(ValueError, match="skew"):
        zmux.Admission.prefix_auth(store, max_skew=0)
    auth = presenter(generation, ticket, zmux.PrefixBinding.BOUND)
    assert (
        auth.binding is zmux.PrefixBinding.BOUND
        and auth.header_name == "Zmux-Prefix-Auth"
    )
    assert (
        presenter(generation, ticket, auth.binding, header="X-Token").header_name
        == "X-Token"
    )
    with pytest.raises(ValueError):
        _ = zmux.dial_tcp("127.0.0.1", 1, carrier_credential=object())  # type: ignore[arg-type]  # not a credential, on purpose
    a = zmux.Admission(
        lambda info, prefix: zmux.AdmissionVerdict.CLOSE,
        peek=4,
        peek_timeout=1,
        stall=(2, 3),
    )
    assert (a.peek, a.peek_timeout, a.stall) == (4, 1, (2, 3))
    assert (
        zmux.AdmissionVerdict.accept()
        == zmux.AdmissionVerdict.accept(0)
        != zmux.AdmissionVerdict.fallback()
    )
    assert zmux.ExchangeOptions(psk=b"k", time_window=30, max_recorded=16).path


# A label of zmux's own, whose value the carrier metadata holds.
LABEL = "EXPORTER-zmux-prefix-auth"


class ExportedToken:
    """A credential of the application's own: the TLS exporter as the
    prefix, or in a header field."""

    def __init__(self) -> None:
        self.calls: list[zmux.CarrierInfo] = []

    def _value(self, info: zmux.CarrierInfo) -> bytes:
        self.calls.append(info)
        value = info.export(LABEL, b"", 32)
        assert value is not None and len(value) == 32
        return value

    def prefix(self, info: zmux.CarrierInfo) -> bytes:
        return self._value(info)

    def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
        return "x-token", self._value(info).hex()


@pytest.mark.parametrize("carrier", ["tls", "quic", "wss", "webtransport"])
async def test_custom_credential_and_decider(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    seen: list[zmux.CarrierInfo] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append(info)
        expected = info.export(LABEL, b"", 32)
        assert expected is not None
        if info.stage is zmux.AdmissionStage.HEAD:
            assert info.upgrade
            headers = info.headers
            assert prefix == b"" and headers is not None
            fields = dict(headers)
            return (
                zmux.AdmissionVerdict.accept()
                if fields.get("x-token") == expected.hex().encode()
                else zmux.AdmissionVerdict.fallback()
            )
        assert info.headers is None
        return (
            zmux.AdmissionVerdict.accept(32)
            if prefix == expected
            else zmux.AdmissionVerdict.fallback()
        )

    credential = ExportedToken()
    admission = zmux.Admission(decide, peek=32, peek_timeout=5, stall=(0.05, 0.1))
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admission)
    ) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        server = asyncio.create_task(echo(listener))
        pipe = await asyncio.wait_for(
            dial_with(carrier, addr, client_tls, credential), 10
        )
        async with await zmux.Session.connect(pipe) as session:
            await round_trip(session)
        server.cancel()
    assert len(seen) == 1 and seen[0].source is not None and seen[0].peer is not None
    head = carrier in ("wss", "webtransport")
    assert (seen[0].stage is zmux.AdmissionStage.HEAD) == head
    assert seen[0].upgrade == head
    # A TLS listener's metadata holds zmux's own labels only.
    if carrier == "tls":
        assert seen[0].export(LABEL) is not None
        assert seen[0].export("EXPORTER-test") is None


@pytest.mark.parametrize("carrier", ["websocket", "webtransport"])
async def test_a_deferred_decision_on_the_carrier(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    seen: list[tuple[zmux.AdmissionStage, zmux.adapter.Framing, bool, bytes]] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append((info.stage, info.framing, info.upgrade, prefix))
        if info.stage is zmux.AdmissionStage.HEAD:
            return zmux.AdmissionVerdict.DEFER
        kind, need = zmux.adapter.classify_first_bytes(prefix, framing=info.framing)
        if kind is zmux.adapter.FirstBytes.RECORD:
            return zmux.AdmissionVerdict.accept()
        if kind is zmux.adapter.FirstBytes.NEED_MORE:
            return zmux.AdmissionVerdict.more(need)
        return zmux.AdmissionVerdict.CLOSE

    admission = zmux.Admission(
        decide, peek=1, max_peek=zmux.adapter.MAX_FIRST_BYTES, peek_timeout=5
    )
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admission)
    ) as listener:
        addr = await serve_admitted(listener, carrier, server_tls)
        server = asyncio.create_task(echo(listener))
        pipe = await asyncio.wait_for(dial_with(carrier, addr, client_tls, None), 10)
        async with await zmux.Session.connect(pipe) as session:
            await round_trip(session)
        server.cancel()
        stats = listener.stats().admission
    framing = (
        zmux.adapter.Framing.RECORDS
        if carrier == "websocket"
        else zmux.adapter.Framing.BYTE_STREAM
    )
    assert seen[0][:3] == (
        zmux.AdmissionStage.HEAD,
        zmux.adapter.Framing.BYTE_STREAM,
        True,
    )
    assert seen[-1][:3] == (zmux.AdmissionStage.CARRIER, framing, True)
    assert seen[-1][3]
    assert (stats.accepted, stats.closed, stats.too_large) == (1, 0, 0)


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
# HS-07
async def test_a_failing_decider_closes() -> None:
    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        raise RuntimeError("no")

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=zmux.Admission(decide, peek=1))
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        host, port = addr
        r, w = await asyncio.open_connection(host, int(port))
        w.write(b"x")
        await w.drain()
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()


@pytest.mark.parametrize("secure", [False, True])
@pytest.mark.parametrize("reject", [False, True])
async def test_exchange(secure: bool, reject: bool, tls: Tls) -> None:
    server_tls, client_tls = tls
    opts = zmux.ExchangeOptions(
        psk=b"exchange secret",
        encoding="base64",
        path="/up/{instance}",
        down_path="/down/{instance}/{nonce}",
    )
    assert zmux.ExchangeOptions().down_path is zmux.AUTO
    assert (opts.encoding, opts.path, opts.down_path) == (
        "base64",
        "/up/{instance}",
        "/down/{instance}/{nonce}",
    )
    with pytest.raises(ValueError):
        zmux.ExchangeOptions(encoding="hex")  # type: ignore[arg-type]  # an invalid value on purpose
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(
                handshake_timeout=2 * WATCHDOG,
                limits=zmux.ListenerLimits(first_record_timeout=2 * WATCHDOG),
            )
        ) as listener,
        asyncio.TaskGroup() as tasks,
    ):
        if secure:
            addr = await listener.serve_http(
                "127.0.0.1", 0, tls=server_tls, exchange=opts
            )
            port = addr[1]
            target = ("localhost", port)
            dial: dict[str, Any] = {"tls": client_tls}
        else:
            addr = await listener.serve_http("127.0.0.1", 0, exchange=opts)
            target = addr
            dial = {}
        if reject:
            other = zmux.ExchangeOptions(
                psk=b"wrong",
                encoding=opts.encoding,
                path=opts.path,
                down_path=opts.down_path,
                # End on the first unsuccessful response, without a retry window.
                deadline=0,
                request_timeout=2 * WATCHDOG,
            )
            with pytest.raises(zmux.PipesLostError):
                async with await zmux.connect_exchange(
                    *target,
                    **dial,
                    options=other,
                    config=zmux.Config(handshake_timeout=None),
                ):
                    pytest.fail("the exchange accepted an invalid key")
            assert listener.stats().sessions == 0
            return

        server = tasks.create_task(echo(listener))
        try:
            async with await zmux.connect_exchange(
                *target, **dial, options=opts
            ) as session:
                await round_trip(session)
                await round_trip(session, bytes(range(256)) * 1024)
        finally:
            server.cancel()


async def test_preamble_and_errors() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            send, _ = await client.open_bi(info=b"route", tlvs=[(0x1000, b"x")])
            await send.write(b"a")
            _, recv = await server.accept_bi()
            assert recv.preamble == zmux.Preamble(b"route", (zmux.Tlv(0x1000, b"x"),))
            send.reset(7)
            with pytest.raises(zmux.StreamResetError) as e:
                await recv.read_to_end()
            assert (
                e.value.code == 7
                and e.value.kind == zmux.ErrorKind.RESET
                and isinstance(e.value, zmux.ZmuxError)
            )
            server.abort(3)
            with pytest.raises(zmux.SessionClosedError) as closed:
                await client.accept_bi()
            assert closed.value.code == 3 and not e.value.retryable
            info = await client.wait_closed()
            assert (
                info.code == 3
                and info.remote
                and isinstance(info, zmux.ApplicationClosedError)
            )


async def test_cancellation() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            _, recv = await client.open_bi()
            task = await start_pending(recv.read)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            recv.stop(1)  # the cancelled read released the stream
            accept = await start_pending(server.accept_uni)
            accept.cancel()
            with pytest.raises(asyncio.CancelledError):
                await accept
            assert await client.ping() >= 0  # the session is still healthy


async def test_a_pipes_quality_band_follows_is_own_or_off() -> None:
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=8)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    own = zmux.QualityBand(rtt=0.1)
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            session.quality_band = zmux.QualityBand(rate_ratio=2.0)

            async def added(**options: Any) -> zmux.Pipe:
                p = await session.add_pipe(
                    await zmux.dial_tcp(*addr), options=zmux.PipeOptions(**options)
                )
                await p.joined()
                return p

            def band(p: zmux.Pipe) -> object:
                o = p.options
                assert o is not None
                return o.quality_band

            follows, off, mine = (
                await added(),
                await added(quality_band=None),
                await added(quality_band=own),
            )
            assert band(follows) is zmux.INHERIT
            assert band(off) is None
            assert band(mine) == own
            # An update sets an own band, off for the pipe, or clears to the
            # session's; a band that is not one is refused.
            for value in (own, None, zmux.CLEAR):
                follows.update(quality_band=value)
            for bad in (zmux.INHERIT, 0.5, "off"):
                with pytest.raises(TypeError):
                    follows.update(quality_band=bad)  # type: ignore[arg-type]
            assert band(mine) == own
        server.cancel()


async def test_multipath() -> None:
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=8)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
        ),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            options = zmux.PipeOptions(
                send_priority=1, receive_priority=1, send_standby=True, label="b"
            )
            pipe = await session.add_pipe(await zmux.dial_tcp(*addr), options=options)
            await pipe.joined()
            stats = session.pipe_stats()
            assert len(stats) == 2 and all(isinstance(s, zmux.PipeStats) for s in stats)
            o = pipe.options
            assert (o.send_priority, o.receive_priority, o.send_standby, o.label) == (
                1,
                1,
                True,
                "b",
            )
            # update: left out keeps, CLEAR clears, a value sets.
            pipe.update(weight=3, receive_standby=True, send_priority=zmux.CLEAR)
            o = pipe.options
            assert (
                o.send_priority,
                o.receive_priority,
                o.weight,
                o.receive_standby,
            ) == (zmux.INHERIT, 1, 3, True)
            bad: dict[str, Any]
            for bad in (
                {"label": "x"},
                {"direction": "in"},
                {"probe_interval": 2},
                {"nope": 1},
            ):
                with pytest.raises(TypeError):
                    pipe.update(**bad)
            with pytest.raises(ValueError):
                pipe.update(weight=None)  # type: ignore[arg-type]  # no off setting
            with pytest.raises(ValueError):
                pipe.update(weight=2, receive_priority=-1)
            o = pipe.options
            assert o.weight == 3
            with pytest.raises(ValueError):
                await session.add_pipe(
                    await zmux.dial_tcp(*addr),
                    options=zmux.PipeOptions(
                        liveness=zmux.PipeLiveness(suspect_floor=0.01)
                    ),
                )
            await round_trip(session, b"x" * 100_000)
            assert session.stats().streams_opened_local == 1
            assert pipe.session.pipe_stats()[1].pipe == pipe.id
            pipe.close()
            await asyncio.wait_for(pipe.wait_closed(), 10)
            ev = await asyncio.wait_for(anext(session.events()), 5)
            assert isinstance(ev, zmux.Event) and isinstance(ev.kind, zmux.EventKind)
        server.cancel()


async def test_zmux_family_does_not_authorize_quic_zero_rtt(tls: Tls) -> None:
    server_tls, client_tls = tls
    config = zmux.Config(carrier_early_data=True)
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls, zero_rtt=True)
        server = asyncio.create_task(echo(listener))
        client = zmux.QuicClient(client_tls, zero_rtt=True)
        session = await client.connect(*addr, server_name="localhost", config=config)
        zero = session.zero_rtt
        assert zero is not None
        async with session:
            await round_trip(session)
            assert session.early_data is zmux.EarlyDataState.NOT_SENT
        assert not zero.sent and not client.remembers("localhost")
        session = await client.connect(*addr, server_name="localhost", config=config)
        zero = session.zero_rtt
        assert zero is not None
        async with session:
            await round_trip(session)
        assert not zero.sent
        server.cancel()
        await asyncio.gather(server, return_exceptions=True)


async def test_resume_controls() -> None:
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=8)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        resume_timeout=5,
        liveness=zmux.Liveness(dead_timeout=2, suspect_floor=0.1),
        probation=None,
    )
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr, config=config) as session:
            assert zmux.adapter.join_ready(session)
            session.revalidate_pipes()
            await round_trip(session)
        server.cancel()


@pytest.mark.parametrize("field", ["peer", "source"])
@pytest.mark.parametrize(
    ("address", "error"),
    [(("!", 0), ValueError), ((str(ipaddress.IPv4Address(0)), 65536), OverflowError)],
)
async def test_handle_pipe_consumes_the_carrier_on_invalid_address(
    field: str, address: tuple[str, int], error: type[Exception]
) -> None:
    async with zmux.Listener() as listener:
        pipe, peer = zmux.adapter.pipe_pair()
        with pytest.raises(error):
            await listener.handle_pipe(pipe, **{field: address})
        with pytest.raises(zmux.PipeUsedError):
            await listener.handle_pipe(pipe)
        assert await asyncio.wait_for(peer.read(), timeout=2) == b""


async def test_stream_pair() -> None:
    # Multipath, where the carrier's unsent count feeds the scheduler.
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=2)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    async with zmux.Listener(config=config) as listener:
        server = asyncio.create_task(echo(listener))

        handed_off = asyncio.Event()

        async def handle(
            incoming: asyncio.StreamReader, outgoing: asyncio.StreamWriter
        ) -> None:
            await listener.handle_pipe(zmux.pipe_from_streams(incoming, outgoing))
            handed_off.set()

        tcp = await asyncio.start_server(handle, "127.0.0.1", 0)
        host, port = tcp.sockets[0].getsockname()[:2]
        reader, writer = await asyncio.open_connection(host, port)
        async with await zmux.Session.connect(
            zmux.pipe_from_streams(reader, writer), config=config
        ) as session:
            await asyncio.wait_for(handed_off.wait(), timeout=5)
            await round_trip(session)
            listener.close()
            await round_trip(session)
            # The transport's write buffer is the carrier's unsent count.
            await until(
                session, lambda: session.pipe_stats()[0].queued_bytes is not None
            )
            (st,) = session.pipe_stats()
            assert st.queued_bytes is not None and st.queued_bytes >= 0
        server.cancel()
        tcp.close()


# HS-02
async def test_stream_bridge_keeps_reading_after_inbound_join_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    async def pair() -> tuple[StreamPair, StreamPair]:
        near_socket, far_socket = socket.socketpair()
        return await asyncio.open_connection(
            sock=near_socket
        ), await asyncio.open_connection(sock=far_socket)

    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=3)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    async with asyncio.timeout(8), zmux.Listener(config=config) as listener:
        near, far = await pair()
        boot = asyncio.ensure_future(listener.handle_pipe(zmux.pipe_from_streams(*far)))
        async with await zmux.Session.connect(
            zmux.pipe_from_streams(*near), config=config
        ) as client:
            server = await listener.accept()
            await boot
            (bootstrap,) = client.pipes()
            near, far = await pair()
            half_closed = asyncio.Event()
            end_write = far[1].write_eof

            def finish_write() -> None:
                end_write()
                half_closed.set()

            monkeypatch.setattr(far[1], "write_eof", finish_write)
            handled = asyncio.ensure_future(
                listener.handle_pipe(zmux.pipe_from_streams(*far))
            )
            added = await client.add_pipe(
                zmux.pipe_from_streams(*near),
                options=zmux.PipeOptions(direction=zmux.Direction.OUT),
            )
            await handled
            await half_closed.wait()
            # Keep a return path for acknowledgements, then remove the only
            # other sending pipe. Scheduling policy cannot mask a broken half.
            rnear, rfar = await pair()
            handling = asyncio.ensure_future(
                listener.handle_pipe(zmux.pipe_from_streams(*rfar))
            )
            reverse = await client.add_pipe(
                zmux.pipe_from_streams(*rnear),
                options=zmux.PipeOptions(direction=zmux.Direction.IN),
            )
            await handling
            await reverse.wait_attached()
            await added.wait_attached()
            bootstrap.abort()
            stats = added.stats()
            assert stats is not None
            sent = stats.bytes_sent
            payload = b"after outbound EOF" * 2048
            send = await client.open_uni()
            await send.write(payload)
            await send.finish()
            recv = await server.accept_uni()
            assert await recv.read_to_end() == payload
            stats = added.stats()
            assert stats is not None
            assert stats.bytes_sent - sent >= len(payload)


@pytest.fixture
def bridge_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[asyncio.Future[None], asyncio.Queue[asyncio.Timeout]]:
    """Expose the bridge's timeout contexts so tests can expire them at a barrier."""
    from zmux import _streams

    deadlines: dict[asyncio.Future[None], asyncio.Queue[asyncio.Timeout]] = defaultdict(
        asyncio.Queue
    )

    def timeout_at(when: float | None) -> asyncio.Timeout:
        task = asyncio.current_task()
        assert task is not None
        timeout = asyncio.timeout(None)
        deadlines[task].put_nowait(timeout)
        return timeout

    bridge_asyncio = SimpleNamespace(**vars(asyncio))
    bridge_asyncio.timeout_at = timeout_at
    monkeypatch.setattr(_streams, "asyncio", bridge_asyncio)
    return deadlines


# HS-50
async def test_stream_bridge_bounds_a_blocked_final_drain(
    bridge_timeouts: dict[asyncio.Future[None], asyncio.Queue[asyncio.Timeout]],
) -> None:
    from zmux import _streams

    entered, closed = asyncio.Event(), asyncio.Event()

    class Transport:
        def abort(self) -> None:
            aborted.set()

    aborted = asyncio.Event()

    class Writer:
        transport = Transport()

        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            entered.set()
            await asyncio.Future()

        async def wait_closed(self) -> None:
            await closed.wait()

        def close(self) -> None:
            closed.set()

    before = set(_streams._bridges)
    pipe = zmux.pipe_from_streams(
        asyncio.StreamReader(), cast(asyncio.StreamWriter, Writer())
    )
    (bridge,) = _streams._bridges - before
    async with asyncio.timeout(WATCHDOG), asyncio.TaskGroup() as tasks:
        task = tasks.create_task(zmux.Session.connect(pipe))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        deadline = await bridge_timeouts[bridge].get()
        deadline.reschedule(asyncio.get_running_loop().time())
        await bridge
        assert closed.is_set()
        assert bridge not in _streams._bridges
        assert aborted.is_set()


@pytest.mark.parametrize("blocked_on", ["read", "drain", "wait_closed"])
async def test_bridge_release_revokes_host_pumps(
    blocked_on: str,
    bridge_timeouts: dict[asyncio.Future[None], asyncio.Queue[asyncio.Timeout]],
) -> None:
    from zmux import _streams

    loop = asyncio.get_running_loop()
    released = asyncio.Event()
    resuming = asyncio.Event()
    cancelled = asyncio.Event()
    closing = asyncio.Event()
    suspended: asyncio.Future[asyncio.Task[Any]] = loop.create_future()
    done: asyncio.Future[None] = loop.create_future()
    output: list[bytes] = []
    input_: list[bytes] = []
    teardown: list[str] = []

    async def block() -> None:
        task = asyncio.current_task()
        assert task is not None
        suspended.set_result(task)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            await resuming.wait()

    async def read(n: int) -> bytes:
        if blocked_on == "read":
            await block()
            return b"late input"
        await asyncio.Event().wait()
        return b""

    async def write(data: bytes) -> None:
        input_.append(data)

    outgoing = iter((b"pending output", b"late output"))

    async def read_output() -> bytes:
        if blocked_on == "drain":
            return next(outgoing, b"")
        await released.wait()
        return b""

    class Writer:
        def write(self, data: bytes) -> None:
            output.append(data)

        async def drain(self) -> None:
            if blocked_on == "drain":
                await block()

        def close(self) -> None:
            teardown.append("close")
            closing.set()

        async def wait_closed(self) -> None:
            if blocked_on == "wait_closed":
                await block()

        def abort(self) -> None:
            teardown.append("abort")

    writer = Writer()

    async def finish() -> None:
        teardown.append("finish")

    async def wait_released() -> None:
        await released.wait()

    before = set(_streams._bridges)
    _streams._start_bridge(
        lambda revoked: _streams._pump_inbound(read, write, revoked),
        lambda revoked: _streams._pump_outbound(read_output, writer, revoked),
        wait_released,
        writer.close,
        writer.wait_closed,
        writer.abort,
        lambda: done.set_result(None),
        finish,
    )
    (bridge,) = _streams._bridges - before
    deadlines = bridge_timeouts[bridge]
    async with asyncio.timeout(WATCHDOG):
        try:
            if blocked_on != "wait_closed":
                await asyncio.shield(suspended)
            released.set()
            flush_deadline = await deadlines.get()
            if blocked_on == "drain":
                flush_deadline.reschedule(loop.time())
            await closing.wait()
            close_deadline = await deadlines.get()
            task = await asyncio.shield(suspended)
            if blocked_on == "wait_closed":
                close_deadline.reschedule(loop.time())
            await cancelled.wait()
            await asyncio.shield(done)
            assert not task.done()
        finally:
            released.set()
            resuming.set()
            if not bridge.done():
                await asyncio.gather(bridge, return_exceptions=True)
            if suspended.done():
                await asyncio.gather(suspended.result(), return_exceptions=True)
    assert input_ == []
    if blocked_on == "drain":
        assert output == [b"pending output"]
        assert teardown == ["abort", "close", "finish"]
    else:
        assert output == []
        expected = ["close", "finish"]
        if blocked_on == "wait_closed":
            expected.insert(1, "abort")
        assert teardown == expected


@pytest.mark.parametrize("ending", ["normal", "both_timeouts", "cancel"])
async def test_bridge_settles_host_close(
    ending: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zmux import _streams

    release, waiting, cancelled, done = (asyncio.Event() for _ in range(4))
    aborts: list[None] = []
    host_close: asyncio.Task[None] | None = None

    async def inbound(revoked: asyncio.Event) -> None:
        await asyncio.Future()

    async def outbound(revoked: asyncio.Event) -> None:
        if ending == "both_timeouts":
            await asyncio.Future()

    async def released() -> None:
        await release.wait()

    async def wait_closed() -> None:
        nonlocal host_close
        host_close = asyncio.current_task()
        waiting.set()
        if ending == "normal":
            return
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    # An expired deadline schedules cancellation once cleanup next yields.
    if ending == "both_timeouts":
        monkeypatch.setattr(_streams, "_BRIDGE_FLUSH_TIMEOUT", 0.0)

    before = set(_streams._bridges)
    _streams._start_bridge(
        inbound,
        outbound,
        released,
        lambda: None,
        wait_closed,
        lambda: aborts.append(None),
        done.set,
    )
    (bridge,) = _streams._bridges - before
    try:
        async with asyncio.timeout(WATCHDOG):
            release.set()
            await waiting.wait()
            if ending == "cancel":
                bridge.cancel()
            await done.wait()
            assert len(aborts) == (0 if ending == "normal" else 1)
            if ending != "normal":
                await cancelled.wait()
            assert host_close is not None
    finally:
        if host_close is not None:
            await asyncio.gather(host_close, return_exceptions=True)
        if not bridge.done():
            bridge.cancel()
            await asyncio.gather(bridge, return_exceptions=True)


# HS-50
async def test_pipe_closed_waits_for_stream_transport(
    monkeypatch: pytest.MonkeyPatch,
    bridge_timeouts: dict[asyncio.Future[None], asyncio.Queue[asyncio.Timeout]],
) -> None:
    import socket

    from zmux import _streams

    local, remote = socket.socketpair()
    reader, writer = await asyncio.open_connection(sock=local)
    peer, peer_writer = await asyncio.open_connection(sock=remote)
    arrived = asyncio.Event()
    release = asyncio.Event()
    original_close = writer.close
    original_wait_closed = writer.wait_closed

    async def wait_for_transport() -> None:
        # Hold the transport open at the bridge's close barrier.
        arrived.set()
        await release.wait()
        original_close()
        await original_wait_closed()

    monkeypatch.setattr(writer, "can_write_eof", lambda: False)
    monkeypatch.setattr(writer, "close", lambda: None)
    monkeypatch.setattr(writer, "wait_closed", wait_for_transport)
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=3)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    try:
        async with (
            asyncio.timeout(8),
            zmux.Listener(config=config) as listener,
            asyncio.TaskGroup() as tasks,
        ):
            handler = tasks.create_task(
                listener.handle_pipe(zmux.pipe_from_streams(peer, peer_writer))
            )
            before = set(_streams._bridges)
            io = zmux.pipe_from_streams(reader, writer)
            (bridge,) = _streams._bridges - before
            async with (
                await zmux.Session.connect(io, config=config) as client,
                await listener.accept(),
            ):
                await handler
                pipe = client.pipes()[0]

                async def wait_for_pipe() -> None:
                    with pytest.raises(zmux.PipeAbortedError):
                        await pipe.wait_closed()

                waiting = tasks.create_task(wait_for_pipe())
                pipe.abort()
                await arrived.wait()
                assert not waiting.done()
                assert not bridge.done()
                assert local.fileno() >= 0
                release.set()
                await waiting
                assert bridge.done() and bridge not in _streams._bridges
                assert local.fileno() == -1
    finally:
        release.set()
        original_close()
        peer_writer.close()
        await asyncio.gather(
            original_wait_closed(), peer_writer.wait_closed(), return_exceptions=True
        )


async def test_unsent_count_is_reported_by_the_carrier() -> None:

    count = zmux.adapter.UnsentCount()
    assert count.value is None
    count.set(1234)
    assert count.value == 1234
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=2)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    async with zmux.Listener(config=config) as listener:
        server = asyncio.create_task(echo(listener))
        addr = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(*addr)
        pipe, end = zmux.adapter.pipe_pair(unsent=count)

        async def inbound() -> None:
            while data := await reader.read(65536):
                await end.write(data)
            await end.write(b"")

        async def outbound() -> None:
            while data := await end.read():
                writer.write(data)
                await writer.drain()

        bridges = [asyncio.ensure_future(inbound()), asyncio.ensure_future(outbound())]
        async with await zmux.Session.connect(pipe, config=config) as session:
            await round_trip(session)
            await until(session, lambda: session.pipe_stats()[0].queued_bytes == 1234)
            count.set(None)
        for b in bridges:
            b.cancel()
        server.cancel()
        await asyncio.gather(*bridges, server, return_exceptions=True)
        writer.close()
        await writer.wait_closed()


def test_threads() -> None:
    """Sessions on several threads' event loops at once (free-threaded builds run them in parallel)."""
    import threading

    async def one() -> None:
        async with zmux.Listener() as listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            server = asyncio.ensure_future(echo(listener))
            async with await zmux.connect_tcp(*addr) as session:
                for _ in range(20):
                    await round_trip(session, b"t" * 10_000)
            server.cancel()

    errors: list[BaseException] = []

    def run() -> None:
        try:
            asyncio.run(one())
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors


async def test_typed_surface() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            assert (
                client.role == zmux.Role.CLIENT
                and client.state == zmux.SessionState.ACTIVE
            )
            send, recv = await client.open_bi()
            async with send:
                send.priority = zmux.Priority(1, True)
                assert send.priority == zmux.Priority(1, True)
                await send.write(b"ab")
            s2, r2 = await server.accept_bi()
            assert b"".join([c async for c in r2]) == b"ab"
            with pytest.raises(ValueError):
                async with s2:
                    await s2.write(b"x")
                    raise ValueError
            with pytest.raises(zmux.StreamResetError):
                await recv.read_to_end()
            _, _r3 = await client.open_bi()
            _s3, w = await server.open_stream_pair()
            w.writelines([b"1", b"2"])
            await w.drain()
            assert w.can_write_eof() and not w.is_closing()
            await w.wait_closed()
            _, r4 = await client.accept_bi()
            assert await r4.read_to_end() == b"12"
            s5 = await client.open_uni()
            await s5.write(b"y" * 10)
            await s5.finish()
            with pytest.raises(zmux.LimitExceededError):
                await (await server.accept_uni()).read_to_end(limit=4)
        listener.close()
        with pytest.raises(zmux.ListenerClosedError):
            await listener.accept()


def test_config() -> None:
    c = zmux.Config(max_idle_timeout=5, protocols=["a"])  # type: ignore[arg-type]  # a list, to check its conversion
    assert c.replace(carrier_early_data=True).carrier_early_data and c.protocols == (
        "a",
    )
    assert "max_idle_timeout" in repr(c)


async def test_no_leaks_on_cancel() -> None:
    """Cancelled reads, writes and accepts release their streams; fds stay flat."""
    import gc
    import os

    def fds() -> int:
        return len(os.listdir("/dev/fd")) if os.path.isdir("/dev/fd") else 0

    async def cancel_at_spawn(start: Callable[[], Awaitable[object]]) -> None:
        async def run() -> object:
            task = asyncio.current_task()
            assert task is not None

            def cancel() -> None:
                task.cancel()

            return await native_call(start, on_create=cancel)

        with pytest.raises(asyncio.CancelledError):
            await asyncio.create_task(run())

    async with asyncio.timeout(WATCHDOG), zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.connect_tcp(*addr) as client,
            await listener.accept() as server,
        ):
            base = fds()
            for _ in range(200):
                send, recv = await client.open_bi()
                await cancel_at_spawn(recv.read)
                await cancel_at_spawn(partial(send.write, b"z" * 1_000_000))
                await cancel_at_spawn(server.accept_uni)
                send.reset(0)
                recv.stop(0)
                del send, recv
            gc.collect()
            await until(client, lambda: client.stats().streams_active == 0)
            assert fds() <= base + 2
            assert await client.ping() >= 0


async def test_shaper() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.connect_tcp(*addr) as client,
            await listener.accept() as server,
        ):
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(definition="not json")
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(definition=PAD_1000, by_kind={})
            client.shaper = zmux.shaping.Shaper(
                definition=PAD_1000,
                budget=zmux.shaping.ShapingBudget(
                    profile=zmux.shaping.ShapingProfileLimits(floor_bytes=1000)
                ),
            )
            send, _recv = await client.open_bi()
            await send.write(b"x" * 10)
            await send.finish()
            _s_send, s_recv = await server.accept_bi()
            assert await s_recv.read_to_end() == b"x" * 10
            st = client.shaping_stats()
            assert st["ledger"]["measured_bytes"] >= 900, st
            assert st["wire_spent"] == st["faults"] == 0, st
            client.shaper = None
            assert set(st) == {
                "wire_spent",
                "stall_spent",
                "injection_accepted_bytes",
                "injection_sent_bytes",
                "injection_accepted_requests",
                "injection_rejected",
                "injection_rejected_by_reason",
                "runtime_reasons",
                "generation",
                "ledger",
                "handshake_measured_bytes",
                "handshake_reserved_bytes",
                "handshake_unresolved_bytes",
                "max_added_delay",
                "clamped",
                "handshake_unplanned",
                "faults",
            }


PAD_1000 = '{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'
PAD_RANGE = (
    '{"machines":[{"start":0,"states":[{"record":{"pad_to":{"t":[[1,500,3000]]}}}]}]}'
)


async def shaped_padding(
    config: zmux.Config | None = None, **shaper: Any
) -> zmux.shaping.ShapingStats:
    """The padding a client shaped by `shaper` adds to one short stream."""
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr, config=config) as client:
            server = await listener.accept()
            client.shaper = zmux.shaping.Shaper(**shaper)
            send, _recv = await client.open_bi()
            await send.write(b"x" * 10)
            await send.finish()
            _, s_recv = await server.accept_bi()
            assert await s_recv.read_to_end() == b"x" * 10
            return client.shaping_stats()


async def test_shaping_limits_and_seed() -> None:
    profile = zmux.shaping.ShapingProfileLimits(floor_bytes=2048)
    limits = zmux.shaping.ShapingLimits(
        wire=zmux.shaping.ShapingAccount(ceiling=1, initial=1),
        profile=profile,
    )
    st = await shaped_padding(zmux.Config(shaping_limits=limits), definition=PAD_1000)
    assert st["ledger"]["measured_bytes"] > st["ledger"]["baseline_bytes"]
    local = st["ledger"]["local"]
    assert local is not None and local["profile"] == profile
    assert st["wire_spent"] == 0  # padding on a record is not cover spending
    bad: dict[str, Any]
    for bad in (
        {"window_seconds": 0},
        {"extra_bytes_ppm": 1_000_001},
        {"floor_bytes": -1},
        {"max_added_delay": float("nan")},
        {"max_added_delay": float("inf")},
        {"max_added_delay": True},
    ):
        with pytest.raises(ValueError):
            zmux.shaping.ShapingProfileLimits(**bad)
    for bad in ({"initial": -1}, {"per_mb": 1.5}, {"per_sec": (1 << 43) + 1}):
        with pytest.raises(ValueError):
            zmux.shaping.ShapingAccount(**bad)
    assert zmux.shaping.ShapingSizeLimits(max_slots=0).max_slots == 0  # no slot
    assert zmux.shaping.ShapingSizeLimits().max_slots == zmux.shaping.DEFAULT_MAX_SLOTS
    assert zmux.shaping.ShapingSizeLimits(max_slots=None).max_slots is None
    st = await shaped_padding(
        zmux.Config(shaping_limits=zmux.shaping.ShapingLimits(no_padding=True)),
        definition=PAD_1000,
    )
    assert st["wire_spent"] == 0, st
    for bad in ({"max_bytes": -1}, {"max_states": 1.5}):
        with pytest.raises(ValueError):
            zmux.shaping.ShapingSizeLimits(**bad)
    assert zmux.DEFAULT_STANDBY_PROBE == 1
    assert (
        zmux.DEFAULT_KEEP_ALIVE_PERIOD,
        zmux.DEFAULT_MAX_IDLE_TIMEOUT,
        zmux.DEFAULT_PROBE_JITTER,
    ) == (15, 30, 0.25)
    assert (
        zmux.DEFAULT_MAX_RECORD_SIZE,
        zmux.shaping.MIN_MAX_LEN,
    ) == (
        16382,
        64,
    )
    assert (zmux.DEFAULT_MIN_BACKOFF, zmux.DEFAULT_MAX_BACKOFF) == (1, 60)
    assert zmux.DEFAULT_JOIN_TIMEOUT == 10
    assert zmux.DEFAULT_FIRST_RECORD_TIMEOUT == 2
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(
                    definition=PAD_1000,
                    limits=zmux.shaping.ShapingSizeLimits(max_bytes=4),
                )
            client.shaper = zmux.shaping.Shaper(
                definition=PAD_1000,
                limits=zmux.shaping.ShapingSizeLimits(max_bytes=len(PAD_1000)),
            )
    runs = [
        (await shaped_padding(definition=PAD_RANGE, seed=b"seed"))["ledger"][
            "measured_bytes"
        ]
        for _ in range(2)
    ]
    # The same draw both times; the records it pads differ by a few control bytes.
    assert runs[0] > 0 and abs(runs[0] - runs[1]) < 64, runs


# HS-40
async def test_split_bootstrap_and_one_endpoint() -> None:
    async with zmux.Listener() as listener, asyncio.TaskGroup() as tasks:
        addr = await listener.serve_http(LOOPBACK, 0, websocket=True)
        server = tasks.create_task(echo(listener))
        try:
            async with asyncio.timeout(30):
                async with await zmux.connect_split(*addr) as session:
                    await round_trip(session)
                async with await zmux.connect_streaming(*addr) as session:
                    await round_trip(session)
                async with await zmux.connect_websocket(
                    f"ws://{addr[0]}:{addr[1]}/zmux"
                ) as session:
                    await round_trip(session)
                conn = await zmux.Http2Connection.dial(*addr)
                async with await zmux.Session.connect(
                    await conn.open_split()
                ) as session:
                    await round_trip(session)
        finally:
            server.cancel()


@pytest.mark.parametrize("carrier", ["quic", "http3", "webtransport"])
async def test_direct_candidates(carrier: str, tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        if carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
            candidate = zmux.Candidate.quic(
                *addr, tls=client_tls, server_name="localhost"
            )
        elif carrier == "http3":
            addr = await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            candidate = zmux.Candidate.http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
        else:
            addr = await listener.serve_webtransport("localhost", 0, tls=server_tls)
            port = addr[1]
            candidate = zmux.Candidate.webtransport(
                f"https://localhost:{port}/zmux", tls=client_tls
            )
        assert candidate.kind is zmux.CarrierKind(carrier)
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            controller = zmux.SessionController(
                carrier,
                candidates=[candidate.with_identity(carrier, cache_key=carrier)],
            )
            try:
                session, _ = await controller.open(zmux.SessionTarget())
                async with session:
                    await round_trip(session)
                    assert session.stats().carrier == zmux.CarrierKind(carrier)
            finally:
                controller.close()
                await controller.done()
        server.cancel()


async def test_auto_choice_falls_back_to_quic(tls: Tls) -> None:
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
        port = addr[1]
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            # The QUIC listener offers no HTTP/3: that candidate fails.
            h3 = zmux.Candidate.http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
            quic = zmux.Candidate.quic(*addr, tls=client_tls, server_name="localhost")
            controller = zmux.SessionController(
                "fallback",
                candidates=[
                    h3.with_identity("h3", cache_key="h3"),
                    quic.with_identity("quic", cache_key="quic"),
                ],
            )
            try:
                session, _ = await controller.open(zmux.SessionTarget())
                async with session:
                    await round_trip(session)
                    assert session.stats().carrier is zmux.CarrierKind.QUIC
            finally:
                controller.close()
                await controller.done()
        server.cancel()


async def test_trusted_source_and_early_data() -> None:
    seen: list[tuple[str, int] | None] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append(info.source)
        return zmux.AdmissionVerdict.accept(0)

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            trusted_proxies=["127.0.0.0/8"],
            forwarded_header="X-Forwarded-For",
            admission=zmux.Admission(decide, peek=0),
        )
    ) as listener:
        addr = await listener.serve_http("127.0.0.1", 0)
        host, port = addr
        head = (
            "GET /zmux HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.7\r\n"
            "Zmux-Pipe-Pair: AAECAwQFBgcICQoLDA0ODw\r\n{}\r\n"
        )
        for extra, status in [("", b"200"), ("Early-Data: 1\r\n", b"425")]:
            r, w = await asyncio.open_connection(host, int(port))
            w.write(head.format(extra).encode())
            await w.drain()
            line = await asyncio.wait_for(r.readline(), 5)
            assert line.split()[1] == status, line
            w.close()
        assert seen and seen[0] is not None and seen[0][0] == "198.51.100.7"


async def test_proxy_protocol_sources(tls: Tls) -> None:
    import ssl

    server_tls, _ = tls
    seen: asyncio.Queue[str] = asyncio.Queue()
    client_ready = asyncio.Event()

    async def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        assert info.source is not None
        # The server can finish TLS while the client is still upgrading its transport.
        await client_ready.wait()
        seen.put_nowait(info.source[0])
        return zmux.AdmissionVerdict.CLOSE

    admission = zmux.Admission(decide, peek=0, peek_timeout=WATCHDOG)

    def insecure(alpn: list[str]) -> ssl.SSLContext:
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.set_alpn_protocols(alpn)
        return client_context

    upgrade = (
        b"GET /zmux HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Protocol: qmux-02\r\n\r\n"
    )
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            trusted_proxies=["127.0.0.0/8"], proxy_protocol=True, admission=admission
        )
    ) as listener:
        servers = [
            (await listener.serve_tcp("127.0.0.1", 0), None, b""),
            (
                await listener.serve_tls("127.0.0.1", 0, tls=server_tls),
                insecure(["qmux-02"]),
                b"",
            ),
            (await listener.serve_websocket("127.0.0.1", 0), None, upgrade),
            (
                await listener.serve_websocket("127.0.0.1", 0, tls=server_tls),
                insecure(["http/1.1"]),
                upgrade,
            ),
        ]
        async with asyncio.timeout(WATCHDOG):
            for addr, ctx, request in servers:
                client_ready.clear()
                host, port = addr
                _r, w = await asyncio.open_connection(host, int(port))
                try:
                    w.write(b"PROXY TCP4 198.51.100.7 10.0.0.1 4000 443\r\n")
                    await w.drain()
                    if ctx is not None:
                        await w.start_tls(ctx, server_hostname="localhost")
                    w.write(request)
                    await w.drain()
                    client_ready.set()
                    assert await seen.get() == "198.51.100.7", addr
                finally:
                    w.close()
                    with contextlib.suppress(ConnectionResetError):
                        await w.wait_closed()


@pytest.mark.parametrize("carrier", ["quic", "h3", "webtransport", "tcp"])
async def test_datagram_channels(carrier: str, tls: Tls) -> None:
    """QUIC, HTTP/3 and WebTransport carriers send datagrams on their own
    datagram channel when the session enables datagrams; others in records."""
    server_tls, client_tls = tls
    config = zmux.Config(enable_datagrams=True)
    async with zmux.Listener(config=config) as listener:
        if carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
            dial = zmux.dial_quic(*addr, tls=client_tls, server_name="localhost")
        elif carrier == "h3":
            addr = await listener.serve_http3("127.0.0.1", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_http3(
                f"https://localhost:{port}/zmux", tls=client_tls, addr=addr
            )
        elif carrier == "webtransport":
            addr = await listener.serve_webtransport("localhost", 0, tls=server_tls)
            port = addr[1]
            dial = zmux.dial_webtransport(
                f"https://localhost:{port}/zmux", tls=client_tls
            )
        else:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            dial = zmux.dial_tcp(*addr)
        async with await zmux.Session.connect(await dial, config=config) as client:
            server = await asyncio.wait_for(listener.accept(), 10)
            for i in range(10):
                client.send_datagram(bytes([i]) * 100)
                assert (
                    await asyncio.wait_for(server.read_datagram(), 10)
                    == bytes([i]) * 100
                )
                server.send_datagram(bytes([i]) * 50)
                assert (
                    await asyncio.wait_for(client.read_datagram(), 10)
                    == bytes([i]) * 50
                )
            c, s = client.stats(), server.stats()
            assert c.datagrams_received_channel <= c.datagrams_received == 10
            if carrier == "tcp":
                assert (c.datagrams_sent_channel, s.datagrams_sent_channel) == (0, 0)
            else:
                # HTTP/3: the client's first ones may precede the server's SETTINGS.
                assert c.datagrams_sent_channel >= 8 and s.datagrams_sent_channel == 10
                assert s.datagrams_received_channel == c.datagrams_sent_channel
            server.close()


async def test_split_join_as_further_pipes() -> None:
    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=8)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    async with zmux.Listener(
        config=config,
        listener_config=zmux.ListenerConfig(
            instance_id=b"instance", limits=zmux.ListenerLimits(max_suspended=16)
        ),
    ) as listener:
        addr = await listener.serve_http("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with asyncio.timeout(30):
            async with await zmux.connect_streaming(*addr, config=config) as session:
                # A split bootstrap's carrier makes pipe pair 0 only.
                with pytest.raises(zmux.InvalidArgumentError) as refused:
                    await session.add_pipe(await zmux.dial_split(*addr))
                assert refused.value.kind == zmux.ErrorKind.INVALID_ARGUMENT
                options = zmux.PipeOptions(label="split")
                pipes = await zmux.join_split(session, *addr, options=options)
                assert len(pipes) == 1, "one Join across the pair, one attachment"
                assert pipes[0].options is not None
                assert pipes[0].options.label == "split"
                await round_trip(session)
                assert len(session.pipe_stats()) == 2
        server.cancel()


async def test_admission_stats_and_async_decide() -> None:
    seen: list[tuple[tuple[str, int] | None, tuple[str, int] | None]] = []
    deciding = asyncio.Event()
    release = asyncio.Event()

    async def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append((info.source, info.peer))
        if prefix != b"z":
            return zmux.AdmissionVerdict.CLOSE
        deciding.set()
        await release.wait()
        return zmux.AdmissionVerdict.accept(1)

    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(
                admission=zmux.Admission(decide, peek=1, peek_timeout=2 * WATCHDOG),
                handshake_timeout=2 * WATCHDOG,
            )
        ) as listener,
        asyncio.TaskGroup() as tasks,
    ):
        addr = await listener.serve_tcp("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(*addr)
        try:
            writer.write(b"x")
            await writer.drain()
            assert await reader.read() == b""
        finally:
            writer.close()
            await writer.wait_closed()

        async def connect() -> None:
            pipe = await zmux.dial_tcp(*addr, carrier_credential=_Fixed(b"z"))
            async with await zmux.Session.connect(
                pipe, config=zmux.Config(handshake_timeout=None)
            ) as session:
                await round_trip(session)

        server = tasks.create_task(echo(listener))
        client = tasks.create_task(connect())
        try:
            await deciding.wait()
            assert listener.stats().sessions == 0
            release.set()
            await client
        finally:
            release.set()
            server.cancel()
        st = listener.stats()
        assert isinstance(st.admission, zmux.AdmissionStats)
        assert (st.admission.accepted, st.admission.closed, st.rejected) == (1, 1, 0)
        assert (
            seen[0][0] == seen[0][1]
            and seen[0][0] is not None
            and seen[0][0][0] == "127.0.0.1"
        )


class _Fixed:
    """A credential of fixed bytes."""

    def __init__(self, prefix: bytes) -> None:
        self._prefix = prefix

    def prefix(self, info: zmux.CarrierInfo) -> bytes:
        return self._prefix

    def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
        return "x-token", self._prefix.decode()


# HS-55
@pytest.mark.skipif(not TEST_HOOKS, reason="requires the test-hooks build")
async def test_a_late_async_decide_is_a_peek_timeout() -> None:
    clock = manual_clock()
    peek_timeout = 7
    entered: asyncio.Queue[None] = asyncio.Queue()
    cancelling: asyncio.Queue[None] = asyncio.Queue()
    deciders: list[asyncio.Task[Any]] = []
    release = asyncio.Event()
    calls = 0

    async def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        nonlocal calls
        calls += 1
        if calls > 2:
            return zmux.AdmissionVerdict.CLOSE
        decision_task = asyncio.current_task()
        assert decision_task is not None
        deciders.append(decision_task)
        never: asyncio.Future[Never] = asyncio.Future()
        try:
            entered.put_nowait(None)
            return await never
        except asyncio.CancelledError:
            cancelling.put_nowait(None)
            await release.wait()
            raise

    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            config=zmux.Config(clock_domain=clock.domain),
            listener_config=zmux.ListenerConfig(
                limits=zmux.ListenerLimits(max_pending_per_source=2),
                admission=zmux.Admission(decide, peek_timeout=peek_timeout),
            ),
        ) as listener,
    ):
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        connections: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        try:
            for _ in range(2):
                connections.append(await asyncio.open_connection(host, port))
                await entered.get()
            await clock.wait_for_timer(peek_timeout, count=2)
            clock.advance(peek_timeout)
            await cancelling.get()
            await cancelling.get()
            for reader, _ in connections:
                assert await reader.read() == b""
            refused = await asyncio.open_connection(host, port)
            connections.append(refused)
            assert await refused[0].read() == b""
            assert calls == 2
            assert listener.stats().admission.peek_timed_out == 2
            assert listener.stats().refused == 1
        except BaseException:
            for task in deciders:
                task.cancel()
            raise
        finally:
            release.set()
            for _, writer in connections:
                writer.close()
            await asyncio.gather(
                *(writer.wait_closed() for _, writer in connections),
                *deciders,
                return_exceptions=True,
            )
        r, w = await asyncio.open_connection(host, port)
        try:
            assert await r.read() == b""
        finally:
            w.close()
            await w.wait_closed()
        assert calls == 3


async def test_handle_pipe_is_admitted_with_its_source() -> None:
    seen: list[tuple[tuple[str, int] | None, tuple[str, int] | None]] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        seen.append((info.source, info.peer))
        return zmux.AdmissionVerdict.CLOSE

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=zmux.Admission(decide))
    ) as listener:
        io, _end = zmux.adapter.pipe_pair()
        with pytest.raises(zmux.ZmuxError):
            await listener.handle_pipe(
                io, peer=("127.0.0.1", 9), source=("198.51.100.7", 4000)
            )
        assert seen == [(("198.51.100.7", 4000), ("127.0.0.1", 9))]
        assert listener.stats().admission.closed == 1


# HS-34, HS-35
async def test_shutdown_refuses_new_sessions() -> None:
    async with asyncio.timeout(8), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        handling = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near) as client:
            server = await listener.accept()
            await handling
            send, _recv = await client.open_bi()
            await send.write(b"hold shutdown")
            held = await server.accept_bi()
            shutdown = asyncio.ensure_future(listener.shutdown(17, b"bye"))
            with pytest.raises(zmux.ListenerClosedError):
                await listener.accept()
            listener.undrain()
            near, far = await _connected_carriers()
            handling = asyncio.ensure_future(listener.handle_pipe(far))
            refused: zmux.SessionClosedError
            try:
                second = await zmux.Session.connect(near)
            except zmux.ConnectionRefusedError as e:
                refused = e
            else:
                refused = await second.wait_closed()
            assert isinstance(refused, zmux.ConnectionRefusedError)
            assert refused.remote and refused.reason == b"bye"
            with pytest.raises(zmux.ConnectError):
                await handling
            assert listener.stats().refused == 1
            del send, held, _recv
            client.close()
            await shutdown


async def test_preamble_too_large() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(*addr) as session:
            with pytest.raises(zmux.PreambleTooLargeError) as e:
                await session.open_bi(info=b"x" * 5000)
            assert isinstance(e.value, ValueError)
            assert 0 < e.value.max <= 4096
            await round_trip(session)
        server.cancel()


async def dial_then_connect(
    addr: tuple[str, int], client_tls: zmux.TlsConfig
) -> zmux.Session:
    pipe = await zmux.dial_quic(*addr, tls=client_tls, server_name="localhost")
    return await zmux.Session.connect(pipe)


async def test_a_coded_close_over_quic_closes_the_connection_after_the_zmux_close(
    tls: Tls,
) -> None:
    server_tls, client_tls = tls
    data = b"before the close" * 4096
    async with zmux.Listener() as listener:
        addr = await listener.serve_quic("127.0.0.1", 0, tls=server_tls)
        client = zmux.QuicClient(client_tls)
        for via_client in (True, False):
            if via_client:
                session = await client.connect(*addr, server_name="localhost")
            else:
                session = await dial_then_connect(addr, client_tls)
            server = await asyncio.wait_for(listener.accept(), 5)
            send, _ = await session.open_bi()
            await send.write(b"x")
            _, recv = await asyncio.wait_for(server.accept_bi(), 5)
            await asyncio.wait_for(recv.read_exact(1), 5)
            await send.write(data)
            session.close(0x2A, b"bye")
            got = bytearray()
            with pytest.raises(zmux.ApplicationClosedError) as err:
                while True:
                    chunk = await asyncio.wait_for(recv.read(65536), 5)
                    assert chunk
                    got += chunk
            assert bytes(got) == data and err.value.code == 0x2A
            # Both ends end; the QUIC close came after the zmux close.
            info = await asyncio.wait_for(server.wait_closed(), 5)
            assert (info.code, info.reason, info.remote) == (0x2A, b"bye", True)
            local = await asyncio.wait_for(session.wait_closed(), 5)
            assert (local.code, local.remote) == (0x2A, False)


@pytest.mark.parametrize("invalid", ["duplicate", "keyword", "positional", "reenter"])
async def test_handle_pipe_claim_precedes_argument_dispatch(invalid: str) -> None:
    async with zmux.Listener() as listener:
        pipe, peer = zmux.adapter.pipe_pair()

        # Exercise runtime argument rejection beyond the typed signature.
        handle_pipe: Callable[..., Coroutine[Any, Any, None]] = listener.handle_pipe

        class Port:
            def __index__(self) -> Never:
                with pytest.raises(zmux.PipeUsedError):
                    handle_pipe(pipe).close()
                raise ValueError("after reentry")

        with pytest.raises(ValueError if invalid == "reenter" else TypeError):
            if invalid == "duplicate":
                handle_pipe(pipe, pipe=pipe).close()
            elif invalid == "keyword":
                handle_pipe(pipe=pipe, extra=True).close()
            elif invalid == "positional":
                handle_pipe(pipe, 0).close()
            else:
                handle_pipe(pipe, peer=("!", Port())).close()
        with pytest.raises(zmux.PipeUsedError):
            listener.handle_pipe(pipe).close()
        assert await asyncio.wait_for(peer.read(), 2) == b""


# HS-01
async def test_handle_pipe_withdraw_before_start_and_during_transform() -> None:
    import socket

    entered, resume = asyncio.Event(), asyncio.Event()

    async def transform(
        input_pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint
    ) -> zmux.PipeIo:
        entered.set()
        await resume.wait()
        return input_pipe

    async with (
        asyncio.timeout(5),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(inbound_transform=transform)
        ) as listener,
    ):
        pipe, peer = zmux.adapter.pipe_pair()
        unstarted = asyncio.ensure_future(listener.handle_pipe(pipe))
        unstarted.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unstarted
        with pytest.raises(zmux.PipeUsedError):
            listener.handle_pipe(pipe).close()
        assert await peer.read() == b""

        left, right = socket.socketpair()
        server = zmux.pipe_from_streams(*await asyncio.open_connection(sock=left))
        client = zmux.pipe_from_streams(*await asyncio.open_connection(sock=right))
        handling = asyncio.ensure_future(listener.handle_pipe(server))
        connecting = asyncio.ensure_future(zmux.Session.connect(client))
        await entered.wait()
        resume.set()
        handling.cancel()
        with pytest.raises(asyncio.CancelledError):
            await handling
        with pytest.raises(zmux.ZmuxError):
            await connecting
        assert listener.stats().sessions == 0


@pytest.mark.parametrize("ending", ["graceful", "timeout", "error"])
# HS-05, HS-51
async def test_layer_wait_closed_includes_retained_writer(
    ending: str,
    bridge_timeouts: dict[asyncio.Future[None], asyncio.Queue[asyncio.Timeout]],
) -> None:
    from zmux import _streams

    closing, resume = asyncio.Event(), asyncio.Event()
    retained = []

    class Writer:
        def __init__(self, writer: asyncio.StreamWriter) -> None:
            self.inner = writer

        def write(self, data: bytes) -> None:
            self.inner.write(data)

        async def drain(self) -> None:
            await self.inner.drain()

        def close(self) -> None:
            self.inner.close()

        async def wait_closed(self) -> None:
            closing.set()
            await resume.wait()
            if ending == "error":
                raise OSError("layer shutdown")
            await self.inner.wait_closed()

    async def layer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, Writer]:
        layer_writer = Writer(writer)
        retained.append(layer_writer)
        return reader, layer_writer

    import socket

    config = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=3)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
    )
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(config=config) as listener,
        asyncio.TaskGroup() as tasks,
    ):
        near, far = socket.socketpair()
        remote = zmux.pipe_from_streams(*await asyncio.open_connection(sock=far))
        handling = tasks.create_task(listener.handle_pipe(remote))
        native = zmux.pipe_from_streams(*await asyncio.open_connection(sock=near))
        before = set(_streams._bridges)
        wrapped = await native.wrap(layer)
        (bridge,) = _streams._bridges - before
        async with await zmux.Session.connect(wrapped, config=config) as session:
            server = await listener.accept()
            await handling
            (pipe,) = session.pipes()

            async def wait_closed() -> None:
                with pytest.raises(zmux.PipeAbortedError):
                    await pipe.wait_closed()

            waiting = tasks.create_task(wait_closed())
            pipe.abort()
            try:
                await closing.wait()
                assert not waiting.done() and not bridge.done()
                if ending == "timeout":
                    deadlines = bridge_timeouts[bridge]
                    await deadlines.get()  # The outbound flush has already finished.
                    deadline = await deadlines.get()
                    deadline.reschedule(asyncio.get_running_loop().time())
                else:
                    resume.set()
                await waiting
            finally:
                resume.set()
            assert bridge.done() and retained[0].inner.is_closing()
            assert near.fileno() == -1
            server.close()


async def serve_test_http(listener: zmux.Listener) -> tuple[str, int]:
    from ipaddress import IPv4Address
    from socket import INADDR_LOOPBACK

    return await listener.serve_http(str(IPv4Address(INADDR_LOOPBACK)), 0)


async def _connected_carriers() -> tuple[zmux.PipeIo, zmux.PipeIo]:
    import socket

    left, right = socket.socketpair()
    return (
        zmux.pipe_from_streams(*await asyncio.open_connection(sock=left)),
        zmux.pipe_from_streams(*await asyncio.open_connection(sock=right)),
    )


# HS-30, HS-32
async def test_listener_drain_can_be_reversed_and_replaced() -> None:
    async with asyncio.timeout(8), zmux.Listener() as listener:
        for reason in (b"first", None, b"second"):
            if reason is None:
                listener.undrain()
            else:
                listener.drain(b"obsolete")
                listener.drain(reason)
            near, far = await _connected_carriers()
            handling = asyncio.ensure_future(listener.handle_pipe(far))
            if reason is None:
                async with await zmux.Session.connect(near) as client:
                    server = await listener.accept()
                    await handling
                    assert client.id != server.id
                    server.close()
            else:
                error: zmux.SessionClosedError
                try:
                    session = await zmux.Session.connect(near)
                except zmux.ConnectionRefusedError as refused:
                    error = refused
                else:
                    error = await session.wait_closed()
                assert isinstance(error, zmux.ConnectionRefusedError)
                assert error.kind == zmux.ErrorKind.CONNECTION_REFUSED
                assert error.reason == reason and error.remote
                with pytest.raises(zmux.ZmuxError):
                    await handling
        assert listener.stats().refused == 2
        assert listener.stats().sessions == 1


# HS-20, HS-27
# HS-24
# HS-25
# HS-24
def test_quality_band_checks_subnanoseconds_before_rounding() -> None:
    with pytest.raises(ValueError):
        zmux.QualityBand(rtt=0.75e-9)
    with pytest.raises(ValueError):
        zmux.QualityBand(min_interval=0.75e-9)


@pytest.mark.parametrize("outcome", ["queued", "fallback", "fallback_error"])
async def test_committed_setup_survives_cancellation_during_delivery(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    failure = ValueError("host result")
    unraisable: list[BaseException | None] = []
    monkeypatch.setattr(
        "sys.unraisablehook", lambda event: unraisable.append(event.exc_value)
    )

    def fallback(_takeover: zmux.Takeover) -> None:
        if outcome == "fallback_error":
            raise failure

    cfg = (
        zmux.ListenerConfig()
        if outcome == "queued"
        else zmux.ListenerConfig(
            admission=zmux.Admission(
                lambda *_: zmux.AdmissionVerdict.fallback(), peek=0
            ),
            fallback=fallback,
        )
    )
    async with asyncio.timeout(8), zmux.Listener(listener_config=cfg) as listener:
        near, far = await _connected_carriers()
        arrival = listener.handle_pipe(far)
        frame = cast("CoroutineType[Any, Any, None]", arrival).cr_frame
        assert frame is not None
        future_type = frame.f_globals["SetupFuture"]
        method = "set_exception" if outcome == "fallback_error" else "set_result"
        original = getattr(future_type, method)
        attempts: list[bool] = []

        def deliver(future: asyncio.Future[None], result: object) -> None:
            attempts.append(setup.cancel("after commit"))
            original(future, result)

        monkeypatch.setattr(future_type, method, deliver)
        setup = asyncio.create_task(arrival)
        if outcome == "queued":
            async with await zmux.Session.connect(near) as client:
                await setup
                async with await listener.accept():
                    assert await client.ping() >= 0
        else:
            try:
                if outcome == "fallback_error":
                    with pytest.raises(zmux.ConnectError) as raised:
                        await setup
                    assert raised.value.__cause__ is failure
                    assert unraisable == [failure]
                else:
                    await setup
                    assert not unraisable
            finally:
                await near.into_stream().shutdown()
        assert attempts == [True]


# HS-04, HS-22
# HS-28
# HS-26. A hook runs outside the work whose exit wait_closed observes.
# HS-26
# HS-03. The decider stops its own listener before delivering its final verdict.
@pytest.mark.parametrize(
    "verdict", [zmux.AdmissionVerdict.accept(), zmux.AdmissionVerdict.fallback()]
)
# HS-03
async def test_admission_stop_precedes_the_handoff(
    verdict: zmux.AdmissionVerdict,
) -> None:
    called = []

    def decide(*_: object) -> zmux.AdmissionVerdict:
        listener.close()
        return verdict

    conf = zmux.ListenerConfig(
        admission=zmux.Admission(decide), fallback=lambda _: called.append(True)
    )
    async with asyncio.timeout(6), zmux.Listener(listener_config=conf) as listener:
        carrier, peer = zmux.adapter.pipe_pair()
        with pytest.raises(zmux.ConnectError):
            await listener.handle_pipe(carrier)
        assert not called
        assert listener.stats().sessions == 0
        assert await peer.read() == b""


@pytest.mark.parametrize("stage", ["exporter", "handshake"])
# HS-01
async def test_cancel_during_exporter_or_handshake(stage: str) -> None:
    entered, stopped = asyncio.Event(), asyncio.Event()

    async def pending(*_: object) -> Never:
        entered.set()
        try:
            never: asyncio.Future[Never] = asyncio.Future()
            await never
        finally:
            stopped.set()

    conf = zmux.ListenerConfig(session_config=pending if stage == "handshake" else None)
    async with asyncio.timeout(6), zmux.Listener(listener_config=conf) as listener:
        if stage == "exporter":
            carrier, peer = zmux.adapter.pipe_pair(exporter=pending)
        else:
            near, carrier = await _connected_carriers()
            dial = asyncio.ensure_future(zmux.Session.connect(near))
        setup = asyncio.ensure_future(listener.handle_pipe(carrier))
        await entered.wait()
        setup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await setup
        if stage == "exporter":
            assert await peer.read() == b""
        else:
            with pytest.raises(zmux.ZmuxError):
                await dial
            await stopped.wait()
        assert listener.stats().sessions == 0


# HS-06
async def test_finished_bridge_receipt_is_idempotent() -> None:
    pipe, end = zmux.adapter.pipe_pair()
    end._track_bridge(pipe)
    end._bridge_done()
    end._bridge_done()
    del pipe
    async with asyncio.timeout(5):
        await end._released()
        fresh, peer = zmux.adapter.pipe_pair()
        end._track_bridge(fresh)
        del fresh
        await peer._released()
        await end._released()


# HS-54
async def test_cancelled_pipe_waiters_can_be_registered_again() -> None:
    async with asyncio.timeout(6), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near) as client:
            server = await listener.accept()
            await setup
            pipe = client.pipes()[0]
            for _ in range(32):
                task = asyncio.Task(
                    pipe.wait_closed(),
                    eager_start=True,
                    loop=asyncio.get_running_loop(),
                )
                assert not task.done()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert await client.ping() >= 0
            server.close()
            with contextlib.suppress(zmux.SessionClosedError, zmux.PipeError):
                await pipe.wait_closed()


# HS-30
async def test_drained_split_reports_protocol_reason() -> None:
    async with asyncio.timeout(10), zmux.Listener() as listener:
        addr = await serve_test_http(listener)
        listener.drain(b"split drain")
        refused: zmux.SessionClosedError
        try:
            session = await zmux.connect_split(*addr)
        except zmux.ConnectionRefusedError as e:
            refused = e
        else:
            refused = await session.wait_closed()
        assert isinstance(refused, zmux.ConnectionRefusedError)
        assert refused.remote and refused.reason == b"split drain"


@pytest.mark.parametrize("refuse", [True, False])
# HS-33
async def test_bootstrap_keeps_its_decision_across_drain(refuse: bool) -> None:
    entered, proceed = asyncio.Event(), asyncio.Event()

    async def configure(_: zmux.SessionCarrier) -> None:
        entered.set()
        await proceed.wait()

    async with (
        asyncio.timeout(8),
        zmux.Listener(
            listener_config=zmux.ListenerConfig(session_config=configure)
        ) as listener,
    ):
        if refuse:
            listener.drain(b"captured")
        a, b = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(b))
        dial = asyncio.ensure_future(zmux.Session.connect(a))
        await entered.wait()
        if refuse:
            listener.undrain()
        else:
            listener.drain(b"subsequent")
        proceed.set()
        if refuse:
            with pytest.raises(zmux.ConnectError):
                await setup
            try:
                client = await dial
            except zmux.ConnectionRefusedError as e:
                reason = e.reason
            else:
                reason = (await client.wait_closed()).reason
            assert reason == b"captured"
            assert listener.stats().sessions == 0
        else:
            async with await dial as client:
                await setup
                accepted = await listener.accept()
                assert await client.ping() >= 0
                accepted.close()


# HS-21
# HS-31
async def test_draining_listener_accepts_a_resumption() -> None:
    cfg = zmux.Config(
        session_policy=zmux.SessionPolicy(
            limits=zmux.CapacityLimits(steady_attachments=4)
        ),
        pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end(),
        resume_timeout=30,
    )
    async with (
        asyncio.timeout(8),
        zmux.Listener(
            config=cfg, listener_config=zmux.ListenerConfig(instance_id=b"drain")
        ) as listener,
    ):
        near, far = await _connected_carriers()
        setup = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near, config=cfg) as client:
            server = await listener.accept()
            await setup
            listener.drain(b"emptying")
            client.pipes()[0].abort()
            for side in (client, server):
                async for event in side.events():
                    if event.kind == zmux.EventKind.SESSION_SUSPENDED:
                        break
            near, far = await _connected_carriers()
            await asyncio.gather(client.add_pipe(near), listener.handle_pipe(far))
            assert await client.ping() >= 0
            server.close()


class SplitHalf:
    """A raw socket for an HTTP split request, with no transport-owned reads."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.loop = asyncio.get_running_loop()
        self.buffer = bytearray()

    async def send(self, data: bytes) -> None:
        await self.loop.sock_sendall(self.sock, data)

    async def _receive(self) -> bool:
        data = await self.loop.sock_recv(self.sock, 65536)
        self.buffer.extend(data)
        return bool(data)

    def _take(self, size: int) -> bytes:
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    async def read_until(self, delimiter: bytes) -> bytes:
        while (end := self.buffer.find(delimiter)) < 0:
            if not await self._receive():
                return self._take(len(self.buffer))
        return self._take(end + len(delimiter))

    async def read_exactly(self, size: int) -> bytes:
        while len(self.buffer) < size:
            if not await self._receive():
                raise asyncio.IncompleteReadError(self._take(len(self.buffer)), size)
        return self._take(size)

    async def wait_eof(self) -> None:
        while await self.loop.sock_recv(self.sock, 65536):
            pass

    def close(self) -> None:
        self.sock.close()

    def reset(self) -> None:
        # Winsock uses two unsigned shorts for linger. Closing the socket
        # without shutdown sends a reset on both platforms.
        linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        self.close()


async def _split_half(
    addr: tuple[str, int],
    *,
    sockets: contextlib.AsyncExitStack,
    token: bytes,
    method: str,
    initial: int = 0,
) -> SplitHalf:
    sock = sockets.enter_context(socket.socket())
    sock.setblocking(False)
    half = SplitHalf(sock)
    await half.loop.sock_connect(sock, addr)
    hdr = b"Transfer-Encoding: chunked\r\n" if method == "POST" else b""
    await half.send(
        method.encode()
        + b" /zmux HTTP/1.1\r\nHost: "
        + addr[0].encode()
        + b"\r\nZmux-Pipe-Pair: "
        + token
        + b"\r\n"
        + hdr
        + b"\r\n"
    )
    if initial and method == "POST":
        await half.send(f"{initial:x}\r\n".encode() + b"a" * initial + b"\r\n")
    head = await half.read_until(b"\r\n\r\n")
    assert head.endswith(b"\r\n\r\n")
    assert b" 200 " in head
    return half


@pytest.mark.parametrize("first", ["GET", "POST"])
@pytest.mark.parametrize("initial_bytes", [3, 128 * 1024])
# HS-05, HS-42, HS-43, HS-44
async def test_split_request_withdrawal(first: str, initial_bytes: int) -> None:
    import base64
    from secrets import token_bytes

    entered: asyncio.Queue[None] = asyncio.Queue()
    stopped: asyncio.Queue[None] = asyncio.Queue()
    held = []

    async def transform(pipe: zmux.PipeIo, _: zmux.adapter.PipeHint) -> Never:
        unused, worker = zmux.adapter.pipe_pair()
        del unused
        worker._track_bridge(pipe)
        held.append(worker)
        entered.put_nowait(None)
        try:
            never: asyncio.Future[Never] = asyncio.Future()
            await never
        finally:
            stopped.put_nowait(None)

    conf = zmux.ListenerConfig(
        admission=zmux.Admission(lambda *_: zmux.AdmissionVerdict.accept()),
        inbound_transform=transform,
    )
    token = base64.urlsafe_b64encode(token_bytes(16)).rstrip(b"=")
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(listener_config=conf) as listener,
        contextlib.AsyncExitStack() as cleanup,
    ):

        def release_workers() -> None:
            while held:
                held.pop()._bridge_done()

        cleanup.callback(release_workers)
        addr = await serve_test_http(listener)

        async def half(method: str) -> SplitHalf:
            # The large POST exceeds the Rust setup probe's replay budget.
            # Withdrawal then depends on observing the TCP reset independently.
            return await _split_half(
                addr, sockets=cleanup, token=token, method=method, initial=initial_bytes
            )

        other = "POST" if first == "GET" else "GET"
        a = await half(first)
        b = await half(other)
        await entered.get()
        a.reset()
        # The active token outlives even both requests if the joined carrier
        # has a separately owned worker. A duplicate POST's empty body ends.
        duplicate = await half("POST")
        assert await duplicate.read_until(b"\n") in (b"0\r\n", b"")
        duplicate.close()
        assert stopped.empty()
        b.reset()
        await stopped.get()
        assert listener.stats().sessions == 0
        duplicate = await half("POST")
        assert await duplicate.read_until(b"\n") in (b"0\r\n", b"")
        duplicate.close()
        held.pop()._bridge_done()
        a = await half(other)
        b = await half(first)
        await entered.get()
        a.reset()
        b.reset()
        await stopped.get()
        held.pop()._bridge_done()


@pytest.mark.parametrize("first", ["GET", "POST"])
# HS-40, HS-41
@pytest.mark.skipif(not TEST_HOOKS, reason="requires the test-hooks build")
async def test_expired_split_half_cannot_join_its_replacement(first: str) -> None:
    from secrets import token_urlsafe

    token = token_urlsafe(16).encode()
    clock = manual_clock()
    handshake_timeout = 2 * WATCHDOG
    cfg = zmux.ListenerConfig(
        handshake_timeout=handshake_timeout,
        admission=zmux.Admission(lambda *_: zmux.AdmissionVerdict.accept()),
    )
    async with (
        asyncio.timeout(WATCHDOG),
        zmux.Listener(
            config=zmux.Config(clock_domain=clock.domain), listener_config=cfg
        ) as listener,
        contextlib.AsyncExitStack() as sockets,
    ):
        addr = await serve_test_http(listener)
        expired = await _split_half(addr, sockets=sockets, token=token, method=first)
        await clock.wait_for_timer(handshake_timeout)
        clock.advance(handshake_timeout)
        with contextlib.suppress(ConnectionResetError):
            await expired.wait_eof()
        expired.close()
        assert listener.stats().sessions == 0
        # Establish a real session over this same token, in the opposite order.
        directions = ["POST", "GET"] if first == "GET" else ["GET", "POST"]
        halves = {
            method: await _split_half(addr, sockets=sockets, token=token, method=method)
            for method in directions
        }
        up = halves["POST"]
        down = halves["GET"]
        near, end = zmux.adapter.pipe_pair()

        async def upload() -> None:
            while data := await end.read():
                await up.send(f"{len(data):x}\r\n".encode() + data + b"\r\n")

        async def download() -> None:
            while size := await down.read_until(b"\n"):
                n = int(size.strip(), 16)
                if n == 0:
                    break
                await end.write(await down.read_exactly(n))
                assert await down.read_exactly(2) == b"\r\n"

        pumps = [asyncio.create_task(upload()), asyncio.create_task(download())]
        try:
            async with (
                await zmux.Session.connect(near) as client,
                await listener.accept(),
            ):
                assert await client.ping() >= 0
            assert listener.stats().sessions == 1
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)


# HS-02
async def test_session_close_reaches_peer_after_handler_cancel() -> None:
    async with asyncio.timeout(6), zmux.Listener() as listener:
        near, far = await _connected_carriers()
        handling = asyncio.ensure_future(listener.handle_pipe(far))
        async with await zmux.Session.connect(near) as client:
            server = await listener.accept()
            await handling
            assert not handling.cancel()
            assert await client.ping() >= 0
            server.close(23, b"handed off")
            reason = await client.wait_closed()
            assert isinstance(reason, zmux.ApplicationClosedError)
            assert (
                reason.remote and reason.code == 23 and reason.reason == b"handed off"
            )


# HS-20, HS-24. Reading the Reply proves the acceptor authorized this join.
