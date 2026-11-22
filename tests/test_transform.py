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
    hints: list[zmux.adapter.PipeHint] = []

    def decide(info: zmux.CarrierInfo, prefix: bytes) -> zmux.AdmissionVerdict:
        return zmux.AdmissionVerdict.accept(1, value={"user": prefix.decode()})

    async def transform(pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint) -> zmux.PipeIo:
        hints.append(hint)
        wrapped = await pipe.wrap(xor_layer(0x5A), server_side=True)
        wrapped.write_overhead = 0
        return wrapped

    admission = zmux.Admission(decide, peek=1, peek_timeout=5)
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            admission=admission, inbound_transform=transform
        )
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)

        class Cred:
            def prefix(self, info: zmux.CarrierInfo) -> bytes:
                return b"u"

            def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
                return ("x", "u")

        pipe = await zmux.dial_tcp(*addr, carrier_credential=Cred())
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
            client.abort(0)


async def echo_one(session: zmux.Session) -> None:
    send, recv = await session.accept_bi()
    await send.write(await recv.read_to_end())
    await send.finish()


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
async def test_a_failing_transform_is_a_setup_failure() -> None:
    async def transform(pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint) -> zmux.PipeIo:
        raise RuntimeError("no")

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(
            inbound_transform=transform, handshake_timeout=2
        )
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        with pytest.raises(zmux.ZmuxError):
            async with asyncio.timeout(10):
                await zmux.connect_tcp(*addr)
        # Counted once the listener's handling returned, which may follow
        # the client's view of the close.
        async with asyncio.timeout(5):
            while listener.stats().setup_failures < 1:
                await asyncio.sleep(0.01)


def test_a_listener_made_without_a_loop_binds_its_hooks_at_first_use() -> None:
    seen: list[zmux.adapter.PipeHint] = []

    def transform(pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint) -> zmux.PipeIo:
        seen.append(hint)
        return pipe

    listener = zmux.Listener(
        listener_config=zmux.ListenerConfig(inbound_transform=transform)
    )

    async def main() -> None:
        async with listener:
            addr = await listener.serve_tcp("127.0.0.1", 0)
            async with await zmux.connect_tcp(*addr):
                async with asyncio.timeout(5):
                    async with await listener.accept():
                        pass

    asyncio.run(main())
    assert seen


async def test_open_carrier_writes_once_per_write() -> None:
    pipe, end = zmux.adapter.pipe_pair()
    reader, writer = await zmux.adapter.open_carrier(pipe)
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
    a = zmux.AdmissionVerdict.accept(2, value=[1])
    assert (
        a
        == zmux.AdmissionVerdict.accept(2, value=[1])
        != zmux.AdmissionVerdict.accept(2)
    )
    assert a.skip == 2 and a.value == [1] and zmux.AdmissionVerdict.CLOSE.skip is None
    assert repr(a) == "AdmissionVerdict.accept(2, value=[1])"


def test_write_overhead_bounds() -> None:
    for bad in (-1, 65536):
        pipe, _ = zmux.adapter.pipe_pair()
        with pytest.raises(ValueError):
            pipe.write_overhead = bad
    pipe, _ = zmux.adapter.pipe_pair()
    pipe.write_overhead = 65535
    assert pipe.write_overhead == 65535
    assert pipe.carrier_kind is None


async def test_an_unknown_join_goes_to_on_reject() -> None:
    config = zmux.Config(
        max_pipes=8, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    asked: list[zmux.RejectInfo] = []

    def on_reject(info: zmux.RejectInfo) -> zmux.RejectAction:
        asked.append(info)
        return zmux.RejectAction.CLOSE

    async with (
        zmux.Listener(
            config=config, listener_config=zmux.ListenerConfig(instance_id=b"i")
        ) as home,
        zmux.Listener(
            config=config,
            listener_config=zmux.ListenerConfig(instance_id=b"i", on_reject=on_reject),
        ) as other,
    ):
        addr = await home.serve_tcp("127.0.0.1", 0)
        other_addr = await other.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(home))
        async with (
            asyncio.timeout(10),
            await zmux.connect_tcp(*addr, config=config) as session,
        ):
            with pytest.raises(zmux.ZmuxError):
                await session.add_pipe(await zmux.dial_tcp(*other_addr))
            # Only the join failed.
            await round_trip(session)
            assert other.stats().rejected >= 1
        server.cancel()
    assert [i.reason for i in asked] == ["unknown_locator"]
    assert asked[0].profile == 2


async def test_pipe_loss_statistics() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        async with await zmux.connect_tcp(*addr) as session:
            await round_trip(session)
            (st,) = session.pipe_stats()
            assert st.bytes_lost in (0, None) and st.records_lost in (0, None)
            sample = st.carrier_sample
            assert sample is not None
            assert sample.generation == 0
            assert sample.direction is zmux.Direction.OUT
            assert isinstance(sample.sampled_at, int)
            if sample.source in (
                zmux.CarrierSource.UNKNOWN,
                zmux.CarrierSource.WINDOWS_SIO_TCP_INFO,
            ):
                assert sample.counts is None
            elif sample.source is zmux.CarrierSource.LINUX_TCP_INFO:
                assert isinstance(sample.counts, zmux.TcpSegmentCounters)
                assert sample.counts.data_segs_out >= 0
            assert session.pipe_stats()[0].carrier_sample == sample
        server.cancel()


async def test_choice_pool() -> None:
    config = zmux.Config(
        max_pipes=4, pipe_auth=zmux.PipeAuth.psk(b"k" * 32).with_end_to_end()
    )
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_http("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        cache = zmux.CarrierCache()
        choice = zmux.CarrierChoice.auto([zmux.Candidate.streaming(*addr)])
        with pytest.raises(ValueError):
            zmux.helpers.PipePool(
                2,
                choice=choice,
                choice_policy=zmux.CarrierChoicePolicy(timer_factor=-1),
            )
        with pytest.raises(ValueError):
            zmux.helpers.PipePool(
                2, choice=choice, choice_policy=zmux.CarrierChoicePolicy(settle=-1)
            )
        pool = zmux.helpers.PipePool(
            2,
            choice=choice,
            choice_policy=zmux.CarrierChoicePolicy(cache=cache, key="k"),
        )
        assert pool.count == 2
        async with (
            asyncio.timeout(20),
            await zmux.connect_streaming(*addr, config=config) as session,
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
        return zmux.AdmissionVerdict.accept(0)

    async def transform(pipe, hint):
        await asyncio.sleep(0)
        return pipe

    async def main():
        listener = zmux.Listener(listener_config=zmux.ListenerConfig(admission=zmux.Admission(decide, peek=0), inbound_transform=transform))
        addr = await listener.serve_tcp("127.0.0.1", 0)
        sessions = []

        async def churn():
            while True:
                try:
                    sessions.append(await zmux.connect_tcp(*addr))
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
    import ssl

    pytest.importorskip("cryptography")  # no 32-bit Windows wheels
    from certs import self_signed

    cert_pem, key_pem = self_signed()
    (tmp_path / "c.pem").write_bytes(cert_pem)
    (tmp_path / "k.pem").write_bytes(key_pem)
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

    async def transform(pipe: zmux.PipeIo, hint: zmux.adapter.PipeHint) -> zmux.PipeIo:
        wrapped = await pipe.wrap(server_tls, server_side=True)
        wrapped.write_overhead = 22
        return wrapped

    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(inbound_transform=transform)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        server = asyncio.ensure_future(echo(listener))
        async with asyncio.timeout(10):
            pipe = await (await zmux.dial_tcp(*addr)).wrap(client_tls)
            async with await zmux.Session.connect(pipe) as session:
                await round_trip(session, b"t" * 300_000)
        server.cancel()


async def test_a_layer_transport_force_closes_like_asyncio_transports() -> None:
    # asyncio's TLS protocol ends its transport with `_force_close(exc)` on a
    # fatal error, such as data after close_notify.
    from zmux._layer import _CarrierTransport

    class Idle:
        async def read(self) -> bytes:
            await asyncio.Event().wait()
            return b""

        async def write(self, data: bytes) -> None:
            await asyncio.Event().wait()

        async def shutdown(self) -> None:
            pass

    lost: asyncio.Future[BaseException | None] = asyncio.Future()

    class Proto(asyncio.Protocol):
        def connection_lost(self, exc: BaseException | None) -> None:
            lost.set_result(exc)

    transport = _CarrierTransport(Idle(), Proto())  # type: ignore[arg-type]  # a stand-in carrier stream
    transport.write(b"queued")
    err = OSError("fatal")
    transport._force_close(err)
    assert transport.is_closing() and transport.get_write_buffer_size() == 0
    assert await asyncio.wait_for(lost, 5) is err


def test_carrier_counter_conversion_distinguishes_absence_from_zero() -> None:
    from zmux._types import _carrier_sample

    zero = _carrier_sample(7, 0, zmux.Direction.OUT, "quinn", 123, ("quic", 0, 0))
    absent = _carrier_sample(7, 0, zmux.Direction.OUT, "quinn", 123, None)
    windows = _carrier_sample(
        8, 0, zmux.Direction.OUT, "windows_sio_tcp_info", 123, None
    )
    assert isinstance(zero.carrier_id, zmux.CarrierId)
    assert len({zero.carrier_id, absent.carrier_id, windows.carrier_id}) == 2
    assert zero.counts == zmux.QuicCounters(0, 0)
    darwin = _carrier_sample(
        9,
        0,
        zmux.Direction.OUT,
        "darwin_tcp_connection_info",
        123,
        ("tcp_packets", 4, 2),
    )
    assert isinstance(darwin.counts, zmux.TcpPacketCounters)
    assert (darwin.counts.packets_sent, darwin.counts.packets_retransmitted) == (4, 2)
    assert absent.counts is None and absent.source is zmux.CarrierSource.QUINN
    assert windows.counts is None
    assert windows.source is zmux.CarrierSource.WINDOWS_SIO_TCP_INFO
