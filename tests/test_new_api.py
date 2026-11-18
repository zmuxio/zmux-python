"""Fallback on a late prefix, `join_prefix`, the HTTP pair field, WebSocket
without a subprotocol and a stream's requested priority."""

import asyncio
import contextlib
from collections.abc import AsyncIterator

import pytest
import zmux


@contextlib.asynccontextmanager
async def serving_http(
    **kwargs: object,
) -> AsyncIterator[tuple[zmux.Listener, tuple[str, int]]]:
    async with zmux.Listener() as listener:
        yield listener, await listener.serve_http("127.0.0.1", 0, **kwargs)  # type: ignore[arg-type]  # forwarded options


async def test_preamble_priority() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr)) as c,
            await listener.accept() as s,
        ):
            send, recv = await c.open_bi(peer_priority=zmux.Priority(2, True))
            await send.write(b"x")
            _, remote = await asyncio.wait_for(s.accept_bi(), 5)
            assert remote.preamble_priority == zmux.Priority(2, True)
            assert recv.preamble_priority is None
            plain, _ = await c.open_bi()
            await plain.write(b"x")
            _, remote = await asyncio.wait_for(s.accept_bi(), 5)
            assert remote.preamble_priority is None


async def test_join_prefix_needs_a_hello() -> None:
    async with zmux.Listener() as listener:
        assert (
            zmux.adapter.join_prefix(listener, b"\x01abc")[0]
            == zmux.adapter.JoinPrefix.NOT_JOIN
        )
        kind, need = zmux.adapter.join_prefix(listener, b"\x02")
        assert kind == zmux.adapter.JoinPrefix.NEED_MORE and need > 1


async def test_fallback_on_peek_timeout() -> None:
    admission = zmux.Admission(
        lambda info, prefix: zmux.AdmissionVerdict.accept(0),
        peek=8,
        peek_timeout=0.3,
        fallback_on_peek_timeout=True,
    )
    assert admission.fallback_on_peek_timeout
    assert not zmux.Admission(
        lambda i, p: zmux.AdmissionVerdict.CLOSE
    ).fallback_on_peek_timeout
    async with zmux.Listener(
        listener_config=zmux.ListenerConfig(admission=admission)
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        host, port = addr
        _, writer = await asyncio.open_connection(host, int(port))
        writer.write(b"ab")
        await writer.drain()
        async with asyncio.timeout(5):
            while not listener.stats().admission.fallback:
                await asyncio.sleep(0.01)
        stats = listener.stats().admission
        assert (stats.peek_timed_out, stats.fallback) == (1, 1)
        writer.close()


async def test_http_split_pair_field() -> None:
    async with serving_http(pair_field="X-Pair") as (listener, addr):
        pipe = await zmux.dial_split(*addr, pair_field="X-Pair")
        async with (
            asyncio.timeout(5),
            await zmux.Session.connect(pipe) as c,
            await listener.accept() as s,
        ):
            assert c.is_established and s.is_established
    with pytest.raises(ValueError):
        await zmux.dial_split("127.0.0.1", 1, pair_field="bad name")


async def test_websocket_without_subprotocol() -> None:
    async with serving_http(websocket=True, websocket_no_subprotocol=True) as (
        listener,
        addr,
    ):
        pipe = await zmux.dial_websocket(
            f"ws://{addr[0]}:{addr[1]}/zmux", no_subprotocol=True
        )
        async with (
            asyncio.timeout(5),
            await zmux.Session.connect(pipe) as c,
            await listener.accept() as s,
        ):
            assert c.is_established and s.is_established


async def test_stream_pair_reader_and_writer() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr)) as c,
            await listener.accept() as s,
        ):
            reader, writer = await c.open_stream_pair(info=b"pair")
            assert isinstance(reader, zmux.StreamPairReader)
            assert isinstance(writer, zmux.StreamPairWriter)
            assert isinstance(reader.stream, zmux.RecvStream)
            writer.write(b"line one\nline two\n12345tail")
            await writer.drain()
            send, recv = await asyncio.wait_for(s.accept_bi(), 5)
            assert recv.preamble.info == b"pair"
            peer_reader = zmux.StreamPairReader(recv)
            assert await peer_reader.readline() == b"line one\n"
            assert await peer_reader.readuntil(b"\n") == b"line two\n"
            assert await peer_reader.readexactly(5) == b"12345"
            assert not peer_reader.at_eof()
            writer.write_eof()
            await writer.wait_closed()
            assert await peer_reader.read() == b"tail"
            assert peer_reader.at_eof()
            with pytest.raises(asyncio.IncompleteReadError) as e:
                await peer_reader.readexactly(3)
            assert e.value.partial == b""
            await send.finish()
            assert await reader.read() == b""
            assert reader.at_eof()


async def test_stream_pair_writer_raises_the_first_send_error() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr)) as c,
            await listener.accept() as s,
        ):
            _reader, writer = await c.open_stream_pair()
            writer.write(b"x")
            await writer.drain()
            _send, recv = await asyncio.wait_for(s.accept_bi(), 5)
            recv.stop(9)
            with pytest.raises(zmux.StreamStoppedError):
                async with asyncio.timeout(5):
                    while True:
                        writer.write(b"y" * 1000)
                        await writer.drain()
                        await asyncio.sleep(0.01)
            # Kept: every later call raises it again.
            with pytest.raises(zmux.StreamStoppedError):
                writer.write(b"z")
            with pytest.raises(zmux.StreamStoppedError):
                await writer.drain()
            writer.abort(1)


async def test_stream_pair_writer_abort() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with (
            await zmux.Session.connect(await zmux.dial_tcp(*addr)) as c,
            await listener.accept(),
        ):
            # Aborted before any write: closing, and wait_closed returns.
            _reader, writer = await c.open_stream_pair()
            writer.abort(3)
            assert writer.is_closing()
            await asyncio.wait_for(writer.wait_closed(), 5)
            # Aborted after close: the pending finish ends quietly.
            _reader, writer = await c.open_stream_pair()
            writer.write(b"x")
            writer.close()
            writer.abort(4)
            assert writer.is_closing()
            await asyncio.wait_for(writer.wait_closed(), 5)


def test_exception_hierarchy() -> None:
    # A session's end is never a timeout of the operation that saw it.
    assert issubclass(zmux.IdleTimeoutError, zmux.SessionClosedError)
    for ended in (
        zmux.IdleTimeoutError,
        zmux.HandshakeTimeoutError,
        zmux.ResumeTimeoutError,
    ):
        assert not issubclass(ended, TimeoutError)
    assert issubclass(zmux.DeadlineExceededError, (zmux.ZmuxError, TimeoutError))
    assert issubclass(zmux.InvalidArgumentError, (zmux.ZmuxError, ValueError))
    assert not issubclass(zmux.NotNegotiatedError, zmux.PipeError)
    assert not issubclass(zmux.NotEstablishedError, zmux.PipeError)
    assert issubclass(zmux.StreamResetError, ConnectionError)
    assert issubclass(zmux.StreamStoppedError, ConnectionError)
    assert issubclass(zmux.IncompleteReadError, asyncio.IncompleteReadError)
    assert not issubclass(zmux.LimitExceededError, ValueError)
    assert issubclass(zmux.LimitExceededError, zmux.StreamError)
    assert issubclass(zmux.PreambleTooLargeError, zmux.ZmuxError)
    assert issubclass(zmux.PreambleTooLargeError, ValueError)
    for name in (
        "SessionClosedError",
        "ApplicationClosedError",
        "TransportClosedError",
        "CarrierChoiceError",
        "VerifyRejectedError",
        "NoExporterError",
    ):
        cls = getattr(zmux, name)
        assert issubclass(cls, zmux.ZmuxError) and cls.__module__ == "zmux", name
    assert zmux.Session.__module__ == zmux.SendStream.__module__ == "zmux"
    for old in ("SessionClosed", "ModeError", "Verdict", "Group", "dial_mode"):
        assert not hasattr(zmux, old), old


class _Refusing:
    """A carrier credential whose prefix fails."""

    def prefix(self, info: zmux.CarrierInfo) -> bytes:
        raise LookupError("no credential for this carrier")

    def header(self, info: zmux.CarrierInfo) -> tuple[str, str]:
        raise LookupError("no credential for this carrier")


async def test_carrier_credential_error_surfaces_as_itself() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        with pytest.raises(LookupError, match="no credential"):
            await zmux.dial_tcp(*addr, carrier_credential=_Refusing())


async def test_listener_closed_while_serving_stops_the_server() -> None:
    listener = zmux.Listener()
    serving = asyncio.ensure_future(listener.serve_tcp("127.0.0.1", 0))
    await asyncio.sleep(0)
    listener.close()
    addr = await asyncio.wait_for(serving, 5)
    host, port = addr
    async with asyncio.timeout(5):
        while True:
            try:
                _r, w = await asyncio.open_connection(host, int(port))
            except OSError:
                break
            w.close()
            await w.wait_closed()
            await asyncio.sleep(0.05)
