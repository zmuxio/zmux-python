"""zmux_aioquic against aioquic-shaped backend objects, without aioquic.

The fakes below expose only the surface aioquic 1.x really has: the protocol
hands out real ``asyncio.StreamReader``/``asyncio.StreamWriter`` pairs over a
``QuicStreamAdapter``-like transport, incoming streams arrive only through the
``stream_handler(reader, writer)`` callback (unidirectional ones included),
stream resets and stops exist only on the private, non-transmitting
``_quic`` connection, local stream IDs are allocated lazily, and terminal
events are dispatched through ``quic_event_received``.
"""

import asyncio
import sys
import time
import unittest
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import zmux

_AIOQUIC_SRC = Path(__file__).resolve().parents[1] / "packages" / "zmuxio-aioquic" / "src"
if str(_AIOQUIC_SRC) not in sys.path:
    sys.path.insert(0, str(_AIOQUIC_SRC))

import zmux_aioquic

PROTOCOL = int(zmux.ErrorCode.PROTOCOL)
CANCELLED = int(zmux.ErrorCode.CANCELLED)


# Event classes named like aioquic.quic.events; the adapter dispatches by name.
@dataclass
class StreamDataReceived(object):
    data: bytes
    end_stream: bool
    stream_id: int


@dataclass
class StreamReset(object):
    error_code: int
    stream_id: int


@dataclass
class StopSendingReceived(object):
    error_code: int
    stream_id: int


@dataclass
class ConnectionTerminated(object):
    error_code: int
    frame_type: Optional[int]
    reason_phrase: str


class FakeQuicConnection(object):
    """The QuicConnection calls the adapter may make, with aioquic's checks."""

    def __init__(self, is_client=True):
        self.is_client = is_client
        self._streams = {}
        self._next_bidi = 0 if is_client else 1
        self._next_uni = 2 if is_client else 3
        self.calls = []

    def _local(self, stream_id):
        return (stream_id & 1) == (0 if self.is_client else 1)

    def get_next_available_stream_id(self, is_unidirectional=False):
        return self._next_uni if is_unidirectional else self._next_bidi

    def _state_for_send(self, stream_id):
        if not self._local(stream_id) and stream_id & 2:
            raise ValueError("Cannot send data on peer-initiated unidirectional stream")
        state = self._streams.get(stream_id)
        if state is None:
            state = self._streams[stream_id] = {"fin": False, "reset": None}
            if stream_id & 2:
                self._next_uni = stream_id + 4
            else:
                self._next_bidi = stream_id + 4
        return state

    def send_stream_data(self, stream_id, data, end_stream=False):
        state = self._state_for_send(stream_id)
        if state["reset"] is not None:
            raise AssertionError("cannot call write() after reset()")
        if state["fin"]:
            raise AssertionError("cannot call write() after FIN")
        self.calls.append(("send", stream_id, bytes(data), end_stream))
        if end_stream:
            state["fin"] = True

    def stop_stream(self, stream_id, error_code):
        if self._local(stream_id) and stream_id & 2:
            raise ValueError("Cannot stop receiving on a local-initiated unidirectional stream")
        if stream_id not in self._streams:
            raise ValueError("Cannot stop receiving on an unknown stream")
        self.calls.append(("stop", stream_id, error_code))

    def reset_stream(self, stream_id, error_code):
        state = self._state_for_send(stream_id)
        if state["reset"] is None:
            state["reset"] = error_code
            self.calls.append(("reset", stream_id, error_code))

    def peer_reset_sender(self, stream_id):
        # What aioquic does to the send half when STOP_SENDING arrives.
        self._streams[stream_id]["reset"] = 0

    def sends(self, stream_id):
        return [call for call in self.calls if call[0] == "send" and call[1] == stream_id]


class FakeQuicStreamAdapter(asyncio.Transport):
    """Mirror of aioquic.asyncio.protocol.QuicStreamAdapter."""

    def __init__(self, protocol, stream_id):
        super().__init__()
        self.protocol = protocol
        self.stream_id = stream_id
        self._closing = False

    def can_write_eof(self):
        return True

    def get_extra_info(self, name, default=None):
        if name == "stream_id":
            return self.stream_id
        return default

    def write(self, data):
        self.protocol._quic.send_stream_data(self.stream_id, data)
        self.protocol._transmit_soon()

    def write_eof(self):
        if self._closing:
            return
        self._closing = True
        self.protocol._quic.send_stream_data(self.stream_id, b"", end_stream=True)
        self.protocol._transmit_soon()

    def close(self):
        self.write_eof()

    def is_closing(self):
        return self._closing


class FakeAioquicProtocol(object):
    """Mirror of aioquic.asyncio.protocol.QuicConnectionProtocol, minus I/O."""

    def __init__(self, is_client=True):
        self._quic = FakeQuicConnection(is_client)
        self._loop = asyncio.get_running_loop()
        self._closed = asyncio.Event()
        self._stream_readers = {}
        self._stream_handler = lambda reader, writer: None
        self.transmit_calls = 0
        self.close_args = None

    async def create_stream(self, is_unidirectional=False):
        stream_id = self._quic.get_next_available_stream_id(
            is_unidirectional=is_unidirectional
        )
        return self._create_stream(stream_id)

    def _create_stream(self, stream_id):
        adapter = FakeQuicStreamAdapter(self, stream_id)
        reader = asyncio.StreamReader()
        protocol = asyncio.streams.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(adapter, protocol, reader, self._loop)
        self._stream_readers[stream_id] = reader
        return reader, writer

    def transmit(self):
        self.transmit_calls += 1

    def _transmit_soon(self):
        return None

    def close(self, error_code=0, reason_phrase=""):
        self.close_args = (error_code, reason_phrase)
        self.transmit()
        self._loop.call_soon(
            self._process_events,
            ConnectionTerminated(error_code, None, reason_phrase),
        )

    async def wait_closed(self):
        await self._closed.wait()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for reader in self._stream_readers.values():
                reader.feed_eof()
        elif isinstance(event, StreamDataReceived):
            reader = self._stream_readers.get(event.stream_id, None)
            if reader is None:
                reader, writer = self._create_stream(event.stream_id)
                self._stream_handler(reader, writer)
            reader.feed_data(event.data)
            if event.end_stream:
                reader.feed_eof()

    def _process_events(self, *events):
        for event in events:
            if isinstance(event, ConnectionTerminated):
                self._closed.set()
            self.quic_event_received(event)

    def peer_data(self, stream_id, data=b"", end_stream=False):
        self._quic._streams.setdefault(stream_id, {"fin": False, "reset": None})
        self._process_events(StreamDataReceived(data, end_stream, stream_id))


def wrap(protocol, options=None):
    session = zmux_aioquic.wrap_session(protocol, options)
    tasks = []

    def stream_handler(reader, writer):
        tasks.append(session.queue_incoming_stream(reader, writer))

    protocol._stream_handler = stream_handler
    return session, tasks


class AioquicBackendShapeTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        # Abandoned test streams are finalized by asyncio.StreamWriter.__del__.
        warnings.filterwarnings(
            "ignore", message=r"unclosed <StreamWriter", category=ResourceWarning
        )

    async def test_queued_peer_uni_stream_uses_quic_id_and_direction(self):
        conn = FakeAioquicProtocol(is_client=True)
        session, tasks = wrap(conn)
        conn.peer_data(3, zmux_aioquic.build_stream_prelude() + b"uni")
        await tasks[0]

        stream = await session.accept_uni_stream(0.1)

        self.assertIsInstance(stream, zmux_aioquic.AioquicRecvStream)
        self.assertEqual(stream.stream_id, 3)
        self.assertFalse(stream.bidirectional)
        self.assertEqual(await stream.read(3), b"uni")
        with self.assertRaises(zmux.AcceptTimeout):
            await session.accept_stream(0.01)
        transmits = conn.transmit_calls

        await stream.close_read()

        self.assertEqual(conn._quic.calls, [("stop", 3, CANCELLED)])
        self.assertGreater(conn.transmit_calls, transmits)
        # aioquic's writer for a receive-only stream must never try to FIN.
        await session.close()
        self.assertEqual(conn._quic.sends(3), [])

    async def test_queued_peer_bidi_stream_uses_quic_id_for_controls(self):
        conn = FakeAioquicProtocol(is_client=True)
        session, tasks = wrap(conn)
        conn.peer_data(5, zmux_aioquic.build_stream_prelude(zmux.OpenOptions(open_info=b"m")))
        await tasks[0]

        stream = await session.accept_stream(0.1)

        self.assertEqual(stream.stream_id, 5)
        self.assertTrue(stream.bidirectional)
        self.assertEqual(stream.open_info, b"m")
        await stream.cancel_write(300)
        await stream.close_read()
        self.assertEqual(conn._quic.calls, [("reset", 5, 300), ("stop", 5, CANCELLED)])

    async def test_explicit_direction_must_match_quic_stream_id(self):
        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)
        reader, writer = conn._create_stream(3)

        with self.assertRaises(zmux.AdapterUnsupported):
            await session.add_incoming_stream(reader, writer, 3, True)
        with self.assertRaises(zmux.AdapterUnsupported):
            await session.add_incoming_stream(reader, writer, 5, False)

    async def test_half_close_returns_once_fin_is_queued(self):
        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)

        stream = await session.open_stream()
        self.assertEqual(await asyncio.wait_for(stream.write_final(b"x"), 1.0), 1)
        self.assertTrue(stream.write_closed)
        self.assertEqual(
            conn._quic.sends(0),
            [
                ("send", 0, b"", False),
                ("send", 0, zmux_aioquic.build_stream_prelude(), False),
                ("send", 0, b"x", False),
                ("send", 0, b"", True),
            ],
        )

        timed = await session.open_stream()
        await asyncio.wait_for(timed.close_write(timeout=0.2), 1.0)
        self.assertTrue(timed.write_closed)
        with self.assertRaises(zmux.WriteClosed):
            await timed.write(b"late")

        closing = await session.open_stream()
        await asyncio.wait_for(closing.close(), 1.0)
        self.assertTrue(closing.read_closed)
        self.assertTrue(closing.write_closed)
        self.assertIn(("stop", closing.stream_id, CANCELLED), conn._quic.calls)

        uni = await asyncio.wait_for(session.open_uni_and_send(b"u"), 1.0)
        self.assertTrue(uni.write_closed)
        self.assertEqual(conn._quic.sends(uni.stream_id)[-1], ("send", uni.stream_id, b"", True))
        self.assertEqual(session.stats.active_streams.total, 2)
        await stream.close_read()
        await timed.close_read()
        self.assertEqual(session.stats.active_streams.total, 0)

    async def test_stream_controls_flush_queued_quic_frames(self):
        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)
        cases = (
            (lambda stream: stream.cancel_write(300), [("reset", 0, 300)]),
            (lambda stream: stream.close_read(), [("stop", 4, CANCELLED)]),
            (lambda stream: stream.cancel_read(302), [("stop", 8, 302)]),
            (
                lambda stream: stream.close_with_error(301, "abort"),
                [("stop", 12, 301), ("reset", 12, 301)],
            ),
        )
        for action, expected in cases:
            stream = await session.open_stream()
            await stream.write(b"x")
            conn._quic.calls.clear()
            transmits = conn.transmit_calls

            await action(stream)

            controls = [call for call in conn._quic.calls if call[0] != "send"]
            self.assertEqual(controls, expected)
            self.assertGreater(conn.transmit_calls, transmits)

    async def test_rejected_accepted_preludes_are_reset_with_protocol_code(self):
        conn = FakeAioquicProtocol()
        session, tasks = wrap(
            conn, zmux_aioquic.SessionOptions(accepted_prelude_read_timeout=0.05)
        )
        conn.peer_data(1, b"\x7f\xff")
        conn.peer_data(3, b"\x7f\xff")
        conn.peer_data(5, b"\x05\x01", end_stream=True)
        conn.peer_data(9)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        self.assertIsInstance(results[0], zmux.OpenMetadataTooLarge)
        self.assertIsInstance(results[1], zmux.OpenMetadataTooLarge)
        self.assertIsInstance(results[2], zmux.ProtocolError)
        self.assertIsInstance(results[3], zmux.ReadTimeout)
        self.assertEqual(
            sorted(call for call in conn._quic.calls if call[0] != "send"),
            sorted(
                [
                    ("stop", 1, PROTOCOL),
                    ("reset", 1, PROTOCOL),
                    ("stop", 3, PROTOCOL),
                    ("stop", 5, PROTOCOL),
                    ("reset", 5, PROTOCOL),
                    ("stop", 9, PROTOCOL),
                    ("reset", 9, PROTOCOL),
                ]
            ),
        )
        self.assertEqual([call for call in conn._quic.calls if call[0] == "send"], [])
        self.assertGreater(conn.transmit_calls, 0)
        with self.assertRaises(zmux.AcceptTimeout):
            await session.accept_stream(0.01)

    async def test_open_metadata_is_validated_before_a_quic_stream_exists(self):
        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)
        too_large = zmux.OpenOptions(open_info=b"x" * 20000)

        with self.assertRaises(zmux.OpenMetadataTooLarge):
            await session.open_stream(too_large)
        with self.assertRaises(zmux.OpenMetadataTooLarge):
            await session.open_uni_stream(too_large)

        self.assertEqual(conn._quic.calls, [])
        self.assertEqual(conn._stream_readers, {})
        stream = await session.open_stream(zmux.OpenOptions(open_info=b"ok"))
        self.assertEqual(stream.stream_id, 0)
        self.assertEqual(
            conn._quic.sends(0)[-1],
            ("send", 0, zmux_aioquic.build_stream_prelude(zmux.OpenOptions(open_info=b"ok")), False),
        )

    async def test_opens_without_writes_never_share_a_quic_stream(self):
        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)

        first = await session.open_stream()
        second = await session.open_stream()
        uni_first = await session.open_uni_stream()
        uni_second = await session.open_uni_stream()
        concurrent = await asyncio.gather(
            *(session.open_stream(timeout=1.0) for _ in range(4))
        )

        ids = [first.stream_id, second.stream_id, uni_first.stream_id, uni_second.stream_id]
        self.assertEqual(ids, [0, 4, 2, 6])
        self.assertEqual(sorted(stream.stream_id for stream in concurrent), [8, 12, 16, 20])
        self.assertEqual(len(conn._stream_readers), 8)
        # Reserving an ID queues no data and no FIN.
        self.assertTrue(all(call == ("send", call[1], b"", False) for call in conn._quic.calls))
        await second.write(b"two")
        await first.write(b"one")
        self.assertEqual(conn._quic.sends(4)[-1], ("send", 4, b"two", False))
        self.assertEqual(conn._quic.sends(0)[-1], ("send", 0, b"one", False))

    async def test_peer_reset_fails_reads_with_code_but_not_writes(self):
        conn = FakeAioquicProtocol()
        session, tasks = wrap(conn)
        conn.peer_data(1, zmux_aioquic.build_stream_prelude() + b"ab")
        await tasks[0]
        stream = await session.accept_stream(0.1)
        self.assertEqual(await stream.read(2), b"ab")
        blocked = asyncio.create_task(stream.read(1))
        await asyncio.sleep(0)

        conn._process_events(StreamReset(300, 1))

        with self.assertRaises(zmux.ApplicationError) as caught:
            await asyncio.wait_for(blocked, 1.0)
        self.assertEqual(caught.exception.code, 300)
        self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(caught.exception.direction, zmux.ErrorDirection.READ)
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.RESET)
        self.assertTrue(stream.read_closed)
        self.assertEqual(await stream.write(b"reply"), 5)
        await stream.close_write()
        self.assertEqual(conn._quic.sends(1)[-1], ("send", 1, b"", True))
        self.assertEqual(session.stats.active_streams.total, 0)

    async def test_peer_stop_sending_fails_writes_with_code(self):
        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream()
        await stream.write(b"x")

        conn._quic.peer_reset_sender(0)
        conn._process_events(StopSendingReceived(301, 0))

        with self.assertRaises(zmux.ApplicationError) as caught:
            await stream.write(b"y")
        self.assertEqual(caught.exception.code, 301)
        self.assertEqual(caught.exception.direction, zmux.ErrorDirection.WRITE)
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.STOPPED)
        self.assertTrue(stream.write_closed)
        self.assertFalse(session.closed)
        self.assertTrue(stream._writer.transport.is_closing())
        await stream.close()
        self.assertFalse(any(call[3] for call in conn._quic.sends(0)))

        # A stop the adapter did not observe still is not a session failure.
        error = zmux_aioquic.translate_write_error(
            AssertionError("cannot call write() after reset()")
        )
        self.assertIsInstance(error, zmux.WriteClosed)
        self.assertEqual(error.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(error.termination_kind, zmux.TerminationKind.STOPPED)
        self.assertIsInstance(
            zmux_aioquic.translate_write_error(asyncio.TimeoutError()), zmux.WriteTimeout
        )

    async def test_peer_application_close_fails_unfinished_streams(self):
        conn = FakeAioquicProtocol()
        session, tasks = wrap(conn)
        prelude = zmux_aioquic.build_stream_prelude()
        conn.peer_data(1, prelude + b"done", end_stream=True)
        conn.peer_data(5, prelude + b"part")
        await asyncio.gather(*tasks)
        finished = await session.accept_stream(0.1)
        truncated = await session.accept_stream(0.1)
        self.assertEqual(await truncated.read(4), b"part")
        blocked_read = asyncio.create_task(truncated.read(1))
        blocked_accept = asyncio.create_task(session.accept_stream())
        await asyncio.sleep(0)

        conn._process_events(ConnectionTerminated(77, None, "bye"))

        with self.assertRaises(zmux.ApplicationError) as caught:
            await asyncio.wait_for(blocked_read, 1.0)
        self.assertEqual((caught.exception.code, caught.exception.reason), (77, "bye"))
        with self.assertRaises(zmux.SessionClosed):
            await asyncio.wait_for(blocked_accept, 1.0)
        self.assertTrue(session.closed)
        self.assertEqual(session.state, zmux.SessionState.FAILED)
        self.assertEqual(session.peer_close_error.code, 77)
        self.assertEqual(session.peer_close_error.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(await finished.read(), b"done")
        self.assertEqual(await finished.read(), b"")
        with self.assertRaises(zmux.ApplicationError):
            await finished.write(b"x")
        with self.assertRaises(zmux.SessionClosed):
            await session.open_stream()
        with self.assertRaises(zmux.ApplicationError) as caught:
            await session.wait(1.0)
        self.assertEqual(caught.exception.code, 77)
        # Ordinary close of a stream on a dead session only releases local state.
        await truncated.close()
        await finished.close()
        self.assertEqual(session.stats.active_streams.total, 0)
        self.assertEqual(conn._quic.calls, [])

    async def test_peer_graceful_close_and_transport_failure(self):
        conn = FakeAioquicProtocol()
        session, tasks = wrap(conn)
        conn.peer_data(1, zmux_aioquic.build_stream_prelude())
        await tasks[0]
        stream = await session.accept_stream(0.1)

        conn._process_events(ConnectionTerminated(0, None, ""))

        with self.assertRaises(zmux.SessionClosed) as caught:
            await stream.read(1, timeout=1.0)
        self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        self.assertIsNone(await session.wait(1.0))
        self.assertEqual(session.state, zmux.SessionState.CLOSED)
        self.assertIsNone(session.close_error)
        self.assertIsNone(session.peer_close_error)

        conn = FakeAioquicProtocol()
        session = zmux_aioquic.wrap_session(conn)
        conn._process_events(ConnectionTerminated(1, 0, "Idle timeout"))
        self.assertEqual(session.state, zmux.SessionState.FAILED)
        self.assertIsNone(session.peer_close_error)
        with self.assertRaises(zmux.SessionClosed) as caught:
            await session.wait(1.0)
        self.assertEqual(caught.exception.source, zmux.ErrorSource.TRANSPORT)

    async def test_local_close_fails_blocked_reads_and_wait_reports_code(self):
        conn = FakeAioquicProtocol()
        session, tasks = wrap(conn)
        conn.peer_data(1, zmux_aioquic.build_stream_prelude())
        await tasks[0]
        stream = await session.accept_stream(0.1)
        blocked = asyncio.create_task(stream.read(1))
        await asyncio.sleep(0)
        started = time.monotonic()

        await session.close_with_error(42, "local")

        with self.assertRaises(zmux.ApplicationError) as caught:
            await asyncio.wait_for(blocked, 1.0)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(caught.exception.code, 42)
        self.assertEqual(conn.close_args, (42, "local"))
        with self.assertRaises(zmux.ApplicationError) as caught:
            await session.wait(1.0)
        self.assertEqual(caught.exception.code, 42)
        self.assertIsNone(session.peer_close_error)


if __name__ == "__main__":
    unittest.main()
