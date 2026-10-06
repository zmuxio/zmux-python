"""zmux_aioquic over a real in-process aioquic client/server pair.

These tests exercise the adapter against aioquic's own QuicConnectionProtocol,
asyncio.StreamReader/StreamWriter and QuicStreamAdapter objects, wired the way
the package README documents. They are skipped when aioquic (and the
cryptography package it depends on) is not installed.
"""

import asyncio
import datetime
import importlib.util
import sys
import time
import unittest
import warnings
from pathlib import Path

import zmux

_AIOQUIC_SRC = Path(__file__).resolve().parents[1] / "packages" / "zmuxio-aioquic" / "src"
if str(_AIOQUIC_SRC) not in sys.path:
    sys.path.insert(0, str(_AIOQUIC_SRC))

import zmux_aioquic

HAVE_AIOQUIC = (
    importlib.util.find_spec("aioquic") is not None
    and importlib.util.find_spec("cryptography") is not None
)

if HAVE_AIOQUIC:
    from aioquic.asyncio import connect, serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic import events
    from aioquic.quic.configuration import QuicConfiguration
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    class ZmuxTestProtocol(QuicConnectionProtocol):
        """README integration pattern plus raw QUIC event recording."""

        def __init__(self, quic, stream_handler=None):
            super().__init__(quic, stream_handler=self._handle_stream)
            self.session = zmux_aioquic.wrap_session(self)
            self.incoming_tasks = []
            self.quic_events = []

        def _handle_stream(self, reader, writer):
            self.incoming_tasks.append(self.session.queue_incoming_stream(reader, writer))

        def quic_event_received(self, event):
            if isinstance(
                    event,
                    (
                        events.StreamDataReceived,
                        events.StreamReset,
                        events.StopSendingReceived,
                        events.ConnectionTerminated,
                    ),
            ):
                self.quic_events.append(event)
            super().quic_event_received(event)

else:  # pragma: no cover - exercised only without aioquic
    ZmuxTestProtocol = None


ALPN = "zmux-aioquic-loopback-test"
STEP = 2.0
PROMPT = 1.0


def _self_signed_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


async def _wait_until(predicate, timeout=PROMPT, message="condition"):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("timed out waiting for %s" % message)
        await asyncio.sleep(0.005)


async def _read_to_end(stream, timeout=STEP):
    chunks = []
    while True:
        chunk = await stream.read(65536, timeout=timeout)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _has_event(protocol, kind, stream_id, **fields):
    for event in protocol.quic_events:
        if not isinstance(event, kind) or event.stream_id != stream_id:
            continue
        if all(getattr(event, key) == value for key, value in fields.items()):
            return True
    return False


@unittest.skipUnless(HAVE_AIOQUIC, "aioquic is not installed")
class AioquicLoopbackTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        # Streams a test abandons are finalized by asyncio.StreamWriter.__del__.
        warnings.filterwarnings(
            "ignore", message=r"unclosed <StreamWriter", category=ResourceWarning
        )

    async def asyncSetUp(self):
        certificate, key = _self_signed_certificate()
        server_config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN])
        server_config.certificate = certificate
        server_config.private_key = key
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=[ALPN], server_name="localhost"
        )
        client_config.load_verify_locations(
            cadata=certificate.public_bytes(serialization.Encoding.PEM)
        )

        self.server_protocols = []

        def create_server_protocol(*args, **kwargs):
            protocol = ZmuxTestProtocol(*args, **kwargs)
            self.server_protocols.append(protocol)
            return protocol

        self.server = await serve(
            "127.0.0.1",
            0,
            configuration=server_config,
            create_protocol=create_server_protocol,
        )
        port = self.server._transport.get_extra_info("sockname")[1]
        self.client_context = connect(
            "127.0.0.1",
            port,
            configuration=client_config,
            create_protocol=ZmuxTestProtocol,
        )
        self.client = await asyncio.wait_for(self.client_context.__aenter__(), STEP)
        await _wait_until(lambda: self.server_protocols, STEP, "server protocol")
        self.server_conn = self.server_protocols[0]

    async def asyncTearDown(self):
        try:
            await asyncio.wait_for(self.client_session.close(), STEP)
            await asyncio.wait_for(self.server_session.close(), STEP)
            await asyncio.wait_for(
                self.client_context.__aexit__(None, None, None), STEP
            )
        finally:
            self.server.close()

    @property
    def client_session(self):
        return self.client.session

    @property
    def server_session(self):
        return self.server_conn.session

    async def test_graceful_send_completion_returns_once_fin_is_queued(self):
        stream = await self.client_session.open_stream(zmux.OpenOptions(open_info=b"hi"))

        written = await asyncio.wait_for(stream.write_final(b"payload"), STEP)

        self.assertEqual(written, len(b"payload"))
        self.assertTrue(stream.write_closed)
        accepted = await self.server_session.accept_stream(STEP)
        self.assertEqual(accepted.stream_id, stream.stream_id)
        self.assertEqual(accepted.open_info, b"hi")
        self.assertEqual(await _read_to_end(accepted), b"payload")

        await asyncio.wait_for(accepted.write(b"pong"), STEP)
        await asyncio.wait_for(accepted.close_write(), STEP)
        self.assertEqual(await _read_to_end(stream), b"pong")
        await asyncio.wait_for(accepted.close(), STEP)
        await asyncio.wait_for(stream.close(), STEP)

        send_stream = await asyncio.wait_for(
            self.client_session.open_uni_and_send(b"event"), STEP
        )
        self.assertTrue(send_stream.write_closed)
        recv_stream = await self.server_session.accept_uni_stream(STEP)
        self.assertEqual(await _read_to_end(recv_stream), b"event")

        open_stream = await self.client_session.open_stream()
        await open_stream.write(b"x")
        await asyncio.wait_for(open_stream.close(), STEP)
        self.assertTrue(open_stream.read_closed)
        self.assertTrue(open_stream.write_closed)
        self.assertEqual(self.client_session.stats.active_streams.total, 0)
        self.assertEqual(self.server_session.stats.active_streams.total, 0)

    async def test_incoming_streams_keep_quic_stream_id_and_direction(self):
        first = await self.client_session.open_stream()
        second = await self.client_session.open_stream()
        uni = await self.client_session.open_uni_stream()

        self.assertEqual((first.stream_id, second.stream_id, uni.stream_id), (0, 4, 2))
        await second.write(b"second")
        await first.write(b"first")
        await uni.write(b"uni")

        accepted = {}
        for _ in range(2):
            stream = await self.server_session.accept_stream(STEP)
            accepted[stream.stream_id] = stream
        self.assertEqual(sorted(accepted), [0, 4])
        self.assertEqual(await accepted[0].read(5, timeout=STEP), b"first")
        self.assertEqual(await accepted[4].read(6, timeout=STEP), b"second")
        recv = await self.server_session.accept_uni_stream(STEP)
        self.assertIsInstance(recv, zmux_aioquic.AioquicRecvStream)
        self.assertEqual(recv.stream_id, 2)
        self.assertFalse(recv.bidirectional)
        self.assertEqual(await recv.read(3, timeout=STEP), b"uni")
        with self.assertRaises(zmux.AcceptTimeout):
            await self.server_session.accept_stream(0.1)

        await recv.close_read()

        await _wait_until(
            lambda: _has_event(
                self.client,
                events.StopSendingReceived,
                2,
                error_code=int(zmux.ErrorCode.CANCELLED),
            ),
            message="STOP_SENDING on the unidirectional stream",
        )
        self.assertFalse(_has_event(self.client, events.StopSendingReceived, 0))
        with self.assertRaises(zmux.ApplicationError) as caught:
            await uni.write(b"late")
        self.assertEqual(caught.exception.code, int(zmux.ErrorCode.CANCELLED))
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.STOPPED)
        await first.write(b"!")
        self.assertEqual(await accepted[0].read(1, timeout=STEP), b"!")

    async def test_stream_reset_and_stop_codes_reach_the_peer_promptly(self):
        reset_stream = await self.client_session.open_stream()
        await reset_stream.write(b"x")
        reset_peer = await self.server_session.accept_stream(STEP)
        self.assertEqual(await reset_peer.read(1, timeout=STEP), b"x")

        started = time.monotonic()
        await reset_stream.cancel_write(77)
        with self.assertRaises(zmux.ApplicationError) as caught:
            await reset_peer.read(1, timeout=STEP)
        self.assertLess(time.monotonic() - started, PROMPT)
        self.assertEqual(caught.exception.code, 77)
        self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.RESET)
        # The peer's receive-side reset does not fail its own send half.
        await reset_peer.write_final(b"still-writable")
        self.assertEqual(await _read_to_end(reset_stream), b"still-writable")

        stopped_stream = await self.client_session.open_stream()
        await stopped_stream.write(b"y")
        stopped_peer = await self.server_session.accept_stream(STEP)
        await stopped_peer.cancel_read(302)
        await _wait_until(
            lambda: _has_event(
                self.client, events.StopSendingReceived, stopped_stream.stream_id,
                error_code=302,
            ),
            message="STOP_SENDING(302)",
        )
        with self.assertRaises(zmux.ApplicationError) as caught:
            await stopped_stream.write(b"more")
        self.assertEqual(caught.exception.code, 302)
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.STOPPED)
        self.assertFalse(self.client_session.closed)

        aborted_stream = await self.client_session.open_stream()
        await aborted_stream.write(b"z")
        aborted_peer = await self.server_session.accept_stream(STEP)
        self.assertEqual(await aborted_peer.read(1, timeout=STEP), b"z")
        await aborted_stream.close_with_error(301, "abort")
        await _wait_until(
            lambda: _has_event(
                self.server_conn, events.StreamReset, aborted_stream.stream_id,
                error_code=301,
            )
            and _has_event(
                self.server_conn, events.StopSendingReceived, aborted_stream.stream_id,
                error_code=301,
            ),
            message="RESET_STREAM(301) and STOP_SENDING(301)",
        )
        with self.assertRaises(zmux.ApplicationError) as caught:
            await aborted_peer.read(1, timeout=STEP)
        self.assertEqual(caught.exception.code, 301)
        with self.assertRaises(zmux.ApplicationError) as caught:
            await aborted_peer.write(b"x")
        self.assertEqual(caught.exception.code, 301)

        fresh = await self.client_session.open_and_send(b"ok")
        fresh_peer = await self.server_session.accept_stream(STEP)
        self.assertEqual(fresh_peer.stream_id, fresh.stream_id)
        self.assertEqual(await fresh_peer.read(2, timeout=STEP), b"ok")

    async def test_rejected_preludes_are_reset_with_protocol_code(self):
        quic = self.client._quic
        bidi_id = quic.get_next_available_stream_id()
        quic.send_stream_data(bidi_id, b"\x7f\xff")
        uni_id = quic.get_next_available_stream_id(is_unidirectional=True)
        quic.send_stream_data(uni_id, b"\x7f\xff")
        self.client.transmit()
        protocol_code = int(zmux.ErrorCode.PROTOCOL)

        await _wait_until(
            lambda: _has_event(
                self.client, events.StopSendingReceived, bidi_id, error_code=protocol_code
            )
            and _has_event(self.client, events.StreamReset, bidi_id, error_code=protocol_code)
            and _has_event(
                self.client, events.StopSendingReceived, uni_id, error_code=protocol_code
            ),
            message="PROTOCOL rejection of malformed preludes",
        )
        self.assertFalse(
            any(
                isinstance(event, events.StreamDataReceived) and event.end_stream
                for event in self.client.quic_events
            )
        )
        for task in self.server_conn.incoming_tasks:
            with self.assertRaises(zmux.OpenMetadataTooLarge):
                await task
        with self.assertRaises(zmux.AcceptTimeout):
            await self.server_session.accept_stream(0.1)
        with self.assertRaises(zmux.AcceptTimeout):
            await self.server_session.accept_uni_stream(0.1)
        self.assertFalse(self.server_session.closed)

    async def test_oversized_open_metadata_never_creates_a_quic_stream(self):
        too_large = zmux.OpenOptions(open_info=b"x" * 20000)

        with self.assertRaises(zmux.OpenMetadataTooLarge):
            await self.client_session.open_stream(too_large)
        with self.assertRaises(zmux.OpenMetadataTooLarge):
            await self.client_session.open_uni_stream(too_large)

        stream = await self.client_session.open_stream()
        uni = await self.client_session.open_uni_stream()
        self.assertEqual((stream.stream_id, uni.stream_id), (0, 2))
        with self.assertRaises(zmux.AcceptTimeout):
            await self.server_session.accept_stream(0.2)
        self.assertEqual(self.server_conn.quic_events, [])

    async def test_peer_application_close_fails_blocked_operations_with_its_code(self):
        finished = await self.server_session.open_stream()
        await finished.write_final(b"complete")
        truncated = await self.server_session.open_stream()
        await truncated.write(b"partial")
        accepted = {}
        for _ in range(2):
            stream = await self.client_session.accept_stream(STEP)
            accepted[stream.stream_id] = stream
        finished_peer = accepted[finished.stream_id]
        truncated_peer = accepted[truncated.stream_id]
        self.assertEqual(await truncated_peer.read(7, timeout=STEP), b"partial")
        await _wait_until(
            lambda: _has_event(
                self.client, events.StreamDataReceived, finished.stream_id, end_stream=True
            ),
            message="FIN of the finished stream",
        )

        blocked_read = asyncio.create_task(truncated_peer.read(1))
        blocked_accept = asyncio.create_task(self.client_session.accept_stream())
        await asyncio.sleep(0.01)
        await self.server_session.close_with_error(77, "bye")

        with self.assertRaises(zmux.ApplicationError) as caught:
            await asyncio.wait_for(blocked_read, STEP)
        self.assertEqual(caught.exception.code, 77)
        with self.assertRaises(zmux.SessionClosed):
            await asyncio.wait_for(blocked_accept, PROMPT)
        self.assertTrue(self.client_session.closed)
        self.assertEqual(self.client_session.state, zmux.SessionState.FAILED)
        self.assertEqual(self.client_session.peer_close_error.code, 77)
        self.assertEqual(self.client_session.peer_close_error.reason, "bye")
        with self.assertRaises(zmux.ApplicationError) as caught:
            await self.client_session.wait(STEP)
        self.assertEqual((caught.exception.code, caught.exception.reason), (77, "bye"))
        with self.assertRaises(zmux.SessionClosed):
            await self.client_session.open_stream()
        # A receive half that already saw the peer FIN still drains to EOF.
        self.assertEqual(await _read_to_end(finished_peer), b"complete")
        with self.assertRaises(zmux.ApplicationError):
            await accepted[finished.stream_id].write(b"x")

    async def test_peer_graceful_close_reports_session_closed_not_eof(self):
        server_stream = await self.server_session.open_stream()
        await server_stream.write(b"partial")
        accepted = await self.client_session.accept_stream(STEP)
        self.assertEqual(await accepted.read(7, timeout=STEP), b"partial")
        blocked_read = asyncio.create_task(accepted.read(1))
        await asyncio.sleep(0.01)

        await self.server_session.close()

        with self.assertRaises(zmux.SessionClosed) as caught:
            await asyncio.wait_for(blocked_read, STEP)
        self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        self.assertIsNone(await self.client_session.wait(STEP))
        self.assertEqual(self.client_session.state, zmux.SessionState.CLOSED)
        self.assertIsNone(self.client_session.close_error)
        self.assertIsNone(self.client_session.peer_close_error)
        with self.assertRaises(zmux.SessionClosed):
            await self.client_session.accept_stream(0.1)

    async def test_local_close_wakes_blocked_reads(self):
        server_stream = await self.server_session.open_stream()
        await server_stream.write(b"x")
        accepted = await self.client_session.accept_stream(STEP)
        self.assertEqual(await accepted.read(1, timeout=STEP), b"x")
        blocked_read = asyncio.create_task(accepted.read(1))
        await asyncio.sleep(0.01)

        await self.client_session.close_with_error(55, "local")

        with self.assertRaises(zmux.ApplicationError) as caught:
            await asyncio.wait_for(blocked_read, PROMPT)
        self.assertEqual(caught.exception.code, 55)
        with self.assertRaises(zmux.ApplicationError):
            await accepted.write(b"x")
        with self.assertRaises(zmux.ApplicationError) as caught:
            await self.client_session.wait(STEP)
        self.assertEqual(caught.exception.code, 55)


if __name__ == "__main__":
    unittest.main()
