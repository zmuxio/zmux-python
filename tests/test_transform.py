"""Inbound transforms and carrier layers, admission values, unknown joins,
write overhead, mode pools and the runtime at interpreter exit."""

import asyncio
import os
import subprocess
import sys
import textwrap
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
import zmux


async def echo(listener: zmux.Listener) -> None:
    async for session in listener:
        async for send, recv in session:
            await send.write(await recv.read_to_end())
            await send.finish()


async def round_trip(session: zmux.Session, data: bytes = b"hello") -> None:
    send, recv = await session.open_bi()
    await send.write(data)
    await send.finish()
    assert await recv.read_to_end() == data


class _XorWriter:
    def __init__(
        self, writer: asyncio.StreamWriter, key: int, task: asyncio.Future[None]
    ) -> None:
        self._writer, self._key, self._task = writer, key, task

    def write(self, data: bytes) -> None:
        self._writer.write(bytes(b ^ self._key for b in data))

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self) -> None:
        self._task.cancel()
        self._writer.close()


def xor_layer(
    key: int,
) -> Callable[
    [asyncio.StreamReader, asyncio.StreamWriter],
    Awaitable[tuple[asyncio.StreamReader, _XorWriter]],
]:
    """A layer that XORs every byte both ways, one write below per write."""

    async def layer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, _XorWriter]:
        r2 = asyncio.StreamReader()

        async def pump() -> None:
            while data := await reader.read(65536):
                r2.feed_data(bytes(b ^ key for b in data))
            r2.feed_eof()

        task = asyncio.ensure_future(pump())

        return r2, _XorWriter(writer, key, task)

    return layer


async def test_inbound_transform_wraps_and_sees_the_admitted_value() -> None:
    hints: list[zmux.PipeHint] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.Verdict:
        return zmux.Verdict.accept(1, value={"user": prefix.decode()})

    async def transform(pipe: zmux.PipeIo, hint: zmux.PipeHint) -> zmux.PipeIo:
        hints.append(hint)
        return (await pipe.wrap(xor_layer(0x5A), server_side=True)).with_write_overhead(
            0
        )

    admission = zmux.Admission(decide, peek=1, peek_timeout=5)
    async with zmux.Listener(
        admission=admission, inbound_transform=transform
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")

        class Cred:
            def prefix(self, info: zmux.CarrierInfo) -> bytes:
                return b"u"

            def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
                return ("x", "u")

        pipe = await zmux.dial_tcp(addr, credential=Cred())
        pipe = await pipe.wrap(xor_layer(0x5A))
        async with asyncio.timeout(10):
            client_task = asyncio.ensure_future(zmux.Session.connect(pipe))
            server = await listener.accept()
            client = await client_task
            assert server.admitted == {"user": "u"} and client.admitted is None
            assert server.pipes()[0].admitted == {"user": "u"}
            (hint,) = hints
            assert hint.admitted == {"user": "u"} and not hint.split
            assert hint.peer is not None and hint.source == hint.peer
            serve = asyncio.ensure_future(echo_one(server))
            await round_trip(client, b"x" * 200_000)
            await serve
            client.close()


async def echo_one(session: zmux.Session) -> None:
    send, recv = await session.accept_bi()
    await send.write(await recv.read_to_end())
    await send.finish()


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_a_failing_transform_is_a_setup_failure() -> None:
    async def transform(pipe: zmux.PipeIo, hint: zmux.PipeHint) -> zmux.PipeIo:
        raise RuntimeError("no")

    async with zmux.Listener(
        inbound_transform=transform, handshake_timeout=2
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        with pytest.raises(zmux.ZmuxError):
            async with asyncio.timeout(10):
                await zmux.connect_tcp(addr)
        # Counted once the listener's handling returned, which may follow
        # the client's view of the close.
        async with asyncio.timeout(5):
            while listener.stats().setup_failures < 1:
                await asyncio.sleep(0.01)


def test_a_transform_needs_a_running_loop() -> None:
    with pytest.raises(RuntimeError):
        zmux.Listener(inbound_transform=lambda pipe, hint: pipe)


async def test_open_carrier_writes_once_per_write() -> None:
    pipe, end = zmux.pipe_pair()
    reader, writer = await zmux.open_carrier(pipe)
    # The in-memory pipe is a byte stream, which joins writes it holds
    # together: read each write before the next one.
    for chunk in (b"a", b"bc", b"def"):
        writer.write(chunk)
        await writer.drain()
        assert await end.read() == chunk
    await end.write(b"back")
    assert await reader.read(10) == b"back"
    writer.close()


def test_verdict_values() -> None:
    a = zmux.Verdict.accept(2, value=[1])
    assert a == zmux.Verdict.accept(2, value=[1]) != zmux.Verdict.accept(2)
    assert a.skip == 2 and a.value == [1] and zmux.Verdict.CLOSE.skip is None
    assert repr(a) == "Verdict.accept(2, value=[1])"


def test_write_overhead_bounds() -> None:
    for bad in (-1, 65536):
        pipe, _ = zmux.pipe_pair()
        with pytest.raises(ValueError):
            pipe.with_write_overhead(bad)
    pipe, _ = zmux.pipe_pair()
    assert pipe.with_write_overhead(65535).carrier is None


async def test_an_unknown_join_is_answered() -> None:
    config = zmux.Config(max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32))
    async with (
        zmux.Listener(config, instance_id=b"i") as home,
        zmux.Listener(config, instance_id=b"i", answer_unknown_joins=True) as other,
    ):
        addr = await home.serve_tcp("127.0.0.1:0")
        other_addr = await other.serve_tcp("127.0.0.1:0")
        server = asyncio.ensure_future(echo(home))
        async with (
            asyncio.timeout(10),
            await zmux.connect_tcp(addr, config=config) as session,
        ):
            pipe = session.add_pipe(await zmux.dial_tcp(other_addr))
            with pytest.raises(zmux.ZmuxError):
                await pipe.joined()
            # Only the join failed.
            await round_trip(session)
            assert other.stats().rejected >= 1
        server.cancel()
    assert int(zmux.TransportErrorCode.RESUME_FAILED) == 0x0F05F74E


async def test_pipe_loss_statistics() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        server = asyncio.ensure_future(echo(listener))
        async with await zmux.connect_tcp(addr) as session:
            await round_trip(session)
            (st,) = session.pipe_stats()
            assert st.bytes_lost in (0, None) and st.records_lost in (0, None)
            assert st.bytes_retransmitted is None or st.bytes_retransmitted >= 0
            assert st.loss_rate is None or st.loss_rate >= 0
        server.cancel()


async def test_mode_pool() -> None:
    config = zmux.Config(max_pipes=4, pipe_auth=zmux.PipeAuth.psk(b"k" * 32))
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_http("127.0.0.1:0")
        server = asyncio.ensure_future(echo(listener))
        cache = zmux.CarrierCache()
        mode = zmux.Mode.auto([zmux.Candidate.streaming(addr)])
        with pytest.raises(ValueError):
            zmux.PipePool.mode(mode, timer_factor=-1)
        with pytest.raises(ValueError):
            zmux.PipePool.mode(mode, settle=-1)
        pool = zmux.PipePool.mode(mode, count=2, cache=cache, key="k")
        assert pool.count == 2
        async with (
            asyncio.timeout(20),
            await zmux.connect_http(addr, config=config) as session,
        ):
            handle = session.maintain_pipes(pool)
            while len(session.pipes()) < 3:
                await asyncio.sleep(0.05)
            await round_trip(session)
            handle.stop()
        assert cache.is_usable("k", "streaming")
        server.cancel()


EXIT_SCRIPT = textwrap.dedent(
    """
    import asyncio, sys, zmux

    async def decide(info, prefix):
        await asyncio.sleep(0)
        return zmux.Verdict.accept(0)

    async def transform(pipe, hint):
        await asyncio.sleep(0)
        return pipe

    async def main():
        listener = zmux.Listener(admission=zmux.Admission(decide, peek=0), inbound_transform=transform)
        addr = await listener.serve_tcp("127.0.0.1:0")
        sessions = []

        async def churn():
            while True:
                try:
                    sessions.append(await zmux.connect_tcp(addr))
                except zmux.ZmuxError:
                    pass

        for _ in range(8):
            asyncio.ensure_future(churn())
        await asyncio.sleep(0.3)
        print("OK", flush=True)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
    """
)


def test_exit_while_the_runtime_calls_python() -> None:
    # Leaves carriers in their async decide and transform at exit, with
    # the loop neither stopped nor closed.
    for _ in range(3):
        r = subprocess.run(
            [sys.executable, "-c", EXIT_SCRIPT],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PYTHONFAULTHANDLER": "1"},
        )
        assert (r.returncode, r.stdout.strip()) == (0, "OK"), r.stderr[-2000:]


async def test_a_tls_layer(tmp_path: Path) -> None:
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    client_ctx = ssl.create_default_context(cafile=tmp_path / "c.pem")

    async def server_tls(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        await writer.start_tls(server_ctx)
        return reader, writer

    async def client_tls(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        await writer.start_tls(client_ctx, server_hostname="localhost")
        return reader, writer

    async def transform(pipe: zmux.PipeIo, hint: zmux.PipeHint) -> zmux.PipeIo:
        return (await pipe.wrap(server_tls, server_side=True)).with_write_overhead(22)

    async with zmux.Listener(inbound_transform=transform) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        server = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(10):
            pipe = await (await zmux.dial_tcp(addr)).wrap(client_tls)
            async with await zmux.Session.connect(pipe) as session:
                await round_trip(session, b"t" * 300_000)
        server.cancel()
