"""Writer-thread, bounded close, keepalive and fatal-CLOSE regressions.

The native session used to write every frame synchronously under one lock,
including from the reader thread, so two Python peers deadlocked in
full-duplex transfer and every timeout/close path could hang on a peer that
stopped reading.  These tests drive real sessions over ``socket.socketpair``
with small socket buffers, using a raw zmux peer where a stalled or
misbehaving remote is needed.
"""

import hashlib
import socket
import sys
import threading
import time
import unittest
from unittest import mock

import zmux
from zmux import native as native_module
from zmux._runtime import session as runtime_session_module

BIG_WINDOW = 1 << 40
SMALL_BUFFER = 8192


def _small_buffers(*socks):
    for sock in socks:
        for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, SMALL_BUFFER)
            except OSError:
                pass


def _big_window_settings():
    return zmux.Settings(
        initial_max_data=BIG_WINDOW,
        initial_max_stream_data_bidi_locally_opened=BIG_WINDOW,
        initial_max_stream_data_bidi_peer_opened=BIG_WINDOW,
        initial_max_stream_data_uni=BIG_WINDOW,
    )


class RawPeer(object):
    """Minimal hand-driven zmux endpoint on one socket."""

    def __init__(self, sock):
        self.socket = sock

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def send_preface(self, role, settings=None):
        config = zmux.Config(
            role=role,
            settings=settings or zmux.Settings(),
            preface_padding=False,
            ping_padding=False,
        )
        self.socket.sendall(config.local_preface_payload())

    def read_preface(self):
        return zmux.read_preface(self)

    def send_frame(self, frame):
        self.socket.sendall(frame.marshal())

    def frames_until_eof(self, timeout=5.0):
        """Read frames until the session closes the transport."""

        self.socket.settimeout(timeout)
        frames = []
        while True:
            try:
                frames.append(zmux.read_frame(self))
            except (zmux.TransportError, zmux.ProtocolError, OSError):
                return frames

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass


class _GatedTransport(object):
    """Socket transport whose writes block while ``gate`` is cleared."""

    def __init__(self, sock):
        self.socket = sock
        self.gate = threading.Event()
        self.gate.set()
        self.blocked = threading.Event()

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def write_all(self, data):
        if not self.gate.is_set():
            self.blocked.set()
            self.gate.wait()
        self.socket.sendall(data)

    def close(self):
        self.gate.set()
        try:
            self.socket.close()
        except OSError:
            pass


def _python_client_with_raw_server(config=None, settings=None):
    """Python initiator against a raw responder that never reads after setup."""

    left, right = socket.socketpair()
    _small_buffers(left, right)
    peer = RawPeer(right)
    peer.send_preface(zmux.Role.RESPONDER, settings or _big_window_settings())
    session = zmux.client(left, config or zmux.Config(keepalive_interval=None))
    peer.read_preface()
    return session, peer


def _python_server_with_raw_client(config=None):
    left, right = socket.socketpair()
    peer = RawPeer(left)
    peer.send_preface(zmux.Role.INITIATOR)
    session = zmux.server(right, config or zmux.Config(keepalive_interval=None))
    peer.read_preface()
    return session, peer


def _close_frames(frames):
    return [frame for frame in frames if frame.frame_type == zmux.FrameType.CLOSE]


def _run(target, *args, **kwargs):
    result = {}

    def runner():
        try:
            result["value"] = target(*args, **kwargs)
        except BaseException as exc:
            result["error"] = exc
        finally:
            result["finished_at"] = time.monotonic()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, result


def _start_stalled_write(session, size=8 << 20):
    stream = session.open_stream(timeout=1.0)
    thread, result = _run(stream.write_all, b"x" * size)
    # Let the writer fill the socket buffers and block in the transport.
    deadline = time.monotonic() + 2.0
    while not session._inflight_writes and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.05)
    return stream, thread, result


def _tcp_pair(buffer_size):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            client.setsockopt(socket.SOL_SOCKET, option, buffer_size)
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            server.setsockopt(socket.SOL_SOCKET, option, buffer_size)
        return client, server
    finally:
        listener.close()


class FullDuplexTest(unittest.TestCase):
    # Before the writer thread both readers blocked sending MAX_DATA while both
    # application writers sat in sendall: a distributed deadlock whenever the
    # in-flight window exceeded the transport buffering.

    def test_python_peers_full_duplex_bulk_transfer_over_socketpair(self):
        left, right = socket.socketpair()
        _small_buffers(left, right)
        self._assert_full_duplex(left, right, zmux.Config(), 4 << 20)

    def test_python_peers_full_duplex_bulk_transfer_over_tcp_with_large_windows(self):
        left, right = _tcp_pair(64 * 1024)
        config = zmux.Config(
            settings=zmux.Settings(
                initial_max_data=4 << 20,
                initial_max_stream_data_bidi_locally_opened=1 << 20,
                initial_max_stream_data_bidi_peer_opened=1 << 20,
            )
        )
        self._assert_full_duplex(left, right, config, 8 << 20)

    def _assert_full_duplex(self, left, right, config, size):
        server_thread, established = _run(zmux.server, right, config)
        client = zmux.client(left, config)
        server_thread.join(2.0)
        server = established["value"]
        client_data = bytes(range(256)) * (size // 256)
        server_data = bytes(reversed(range(256))) * (size // 256)
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"h", timeout=1.0)
            inbound = server.accept_stream(timeout=2.0)
            self.assertEqual(inbound.read_exact(1, timeout=2.0), b"h")

            results = {}

            def pump(name, stream, payload):
                try:
                    stream.write_final(payload, timeout=20.0)
                    results[name + "_wrote"] = True
                except BaseException as exc:
                    results[name + "_write_error"] = exc

            def drain(name, stream):
                try:
                    digest = hashlib.sha256()
                    total = 0
                    while True:
                        chunk = stream.read(65536, timeout=20.0)
                        if not chunk:
                            break
                        digest.update(chunk)
                        total += len(chunk)
                    results[name + "_read"] = (total, digest.hexdigest())
                except BaseException as exc:
                    results[name + "_read_error"] = exc

            threads = [
                threading.Thread(target=pump, args=("client", outbound, client_data)),
                threading.Thread(target=pump, args=("server", inbound, server_data)),
                threading.Thread(target=drain, args=("client", outbound)),
                threading.Thread(target=drain, args=("server", inbound)),
            ]
            started = time.monotonic()
            for thread in threads:
                thread.daemon = True
                thread.start()
            for thread in threads:
                thread.join(max(0.0, 20.0 - (time.monotonic() - started)))
            self.assertFalse(
                any(thread.is_alive() for thread in threads),
                "full-duplex transfer stalled: %r" % sorted(results),
            )
            for key in ("client_write_error", "server_write_error"):
                self.assertNotIn(key, results)
            self.assertEqual(
                results.get("server_read"),
                (size, hashlib.sha256(client_data).hexdigest()),
            )
            self.assertEqual(
                results.get("client_read"),
                (size, hashlib.sha256(server_data).hexdigest()),
            )
        finally:
            client.close()
            server.close()


class StalledTransportTest(unittest.TestCase):
    def test_write_timeout_is_honoured_while_transport_is_stalled(self):
        session, peer = _python_client_with_raw_server()
        try:
            stream = session.open_stream(timeout=1.0)
            started = time.monotonic()
            with self.assertRaises(zmux.WriteTimeout):
                stream.write_all(b"x" * (64 << 20), timeout=0.5)
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual(session.state, zmux.SessionState.READY)
        finally:
            session.close_with_error(int(zmux.ErrorCode.CANCELLED))
            peer.close()

    def test_ping_timeout_is_honoured_while_writer_is_stalled(self):
        session, peer = _python_client_with_raw_server()
        try:
            _start_stalled_write(session)
            started = time.monotonic()
            with self.assertRaises(zmux.PingTimeout):
                session.ping(timeout=0.3)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertFalse(session.stats.ping_outstanding)
        finally:
            session.close_with_error(int(zmux.ErrorCode.CANCELLED))
            peer.close()

    def test_close_with_error_is_bounded_and_wakes_blocked_operations(self):
        session, peer = _python_client_with_raw_server()
        try:
            stream, writer, write_result = _start_stalled_write(session)
            accept_thread, accept_result = _run(session.accept_stream)
            read_thread, read_result = _run(stream.read, 1)
            time.sleep(0.05)

            started = time.monotonic()
            session.close_with_error(5, "abort")
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertTrue(session.closed)
            self.assertEqual(session.state, zmux.SessionState.FAILED)

            for thread, result in (
                (writer, write_result),
                (accept_thread, accept_result),
                (read_thread, read_result),
            ):
                thread.join(1.0)
                self.assertFalse(thread.is_alive())
                self.assertIsInstance(result.get("error"), zmux.ZmuxError)
            with self.assertRaises(zmux.ApplicationError) as caught:
                session.wait(1.0)
            self.assertEqual(caught.exception.code, 5)
        finally:
            peer.close()

    def test_close_waits_for_concurrent_close_with_error_to_finish(self):
        session, peer = _python_client_with_raw_server()
        try:
            _start_stalled_write(session)
            # Stretch the bounded CLOSE wait so close() overlaps it.
            session._last_ping_rtt = 0.1
            closer, _ = _run(session.close_with_error, 5, "abort")
            deadline = time.monotonic() + 1.0
            while session.state is not zmux.SessionState.FAILED and time.monotonic() < deadline:
                time.sleep(0.001)
            started = time.monotonic()
            session.close()
            self.assertTrue(session.closed)
            self.assertLess(time.monotonic() - started, 3.0)
            closer.join(2.0)
            self.assertFalse(closer.is_alive())
        finally:
            peer.close()

    def test_graceful_close_is_bounded_on_stalled_transport(self):
        session, peer = _python_client_with_raw_server()
        try:
            _start_stalled_write(session)
            started = time.monotonic()
            try:
                session.close()
            except zmux.GracefulCloseTimeout:
                pass
            self.assertLess(time.monotonic() - started, 5.0)
            self.assertTrue(session.closed)
        finally:
            peer.close()

    def test_keepalive_timeout_fires_while_write_is_stalled(self):
        config = zmux.Config(keepalive_interval=0.5, keepalive_timeout=0.5)
        session, peer = _python_client_with_raw_server(config)
        try:
            _start_stalled_write(session)
            started = time.monotonic()
            with self.assertRaises(zmux.KeepaliveTimeout):
                session.wait(5.0)
            self.assertLess(time.monotonic() - started, 5.0)
            self.assertEqual(session.state, zmux.SessionState.FAILED)
        finally:
            peer.close()

    def test_reader_keeps_processing_frames_while_writer_is_stalled(self):
        session, peer = _python_client_with_raw_server()
        try:
            _start_stalled_write(session)
            # Each PING needs a PONG the stalled writer cannot send; the reader
            # must still go on to process the CLOSE.
            for nonce in range(3):
                peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, nonce.to_bytes(8, "big")))
            peer.send_frame(
                zmux.Frame(
                    zmux.FrameType.CLOSE,
                    0,
                    0,
                    zmux.build_error_payload(7, "bye"),
                )
            )
            with self.assertRaises(zmux.ApplicationError) as caught:
                session.wait(2.0)
            self.assertEqual(caught.exception.code, 7)
            self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        finally:
            peer.close()

    def test_stream_control_stays_behind_queued_data_of_same_stream(self):
        session, peer = _python_client_with_raw_server()
        try:
            _start_stalled_write(session)
            second = session.open_stream(timeout=1.0)
            # The opener of the second stream queues behind the stalled frame.
            with self.assertRaises(zmux.WriteTimeout):
                second.write_all(b"y" * 1024, timeout=0.2)
            second.cancel_write(int(zmux.ErrorCode.CANCELLED))
            with session._write_cond:
                data_lane = [
                    (request.frame.frame_type, request.frame.stream_id)
                    for request in session._data_writes
                    if request.frame.stream_id == second.stream_id
                ]
            self.assertEqual(
                data_lane,
                [
                    (zmux.FrameType.DATA, second.stream_id),
                    (zmux.FrameType.RESET, second.stream_id),
                ],
            )
        finally:
            session.close_with_error(int(zmux.ErrorCode.CANCELLED))
            peer.close()

    def test_reader_max_data_updates_coalesce_while_writer_is_stalled(self):
        session, peer = _python_client_with_raw_server()
        try:
            _start_stalled_write(session)
            for value in (1000, 3000, 2000):
                session._queue_frame(
                    zmux.Frame(zmux.FrameType.MAX_DATA, 0, 0, zmux.encode_varint(value)),
                    from_reader=True,
                )
            with session._write_cond:
                pending = [
                    request.frame
                    for request in session._urgent_writes
                    if request.frame.frame_type == zmux.FrameType.MAX_DATA
                ]
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].payload, zmux.encode_varint(3000))
        finally:
            session.close_with_error(int(zmux.ErrorCode.CANCELLED))
            peer.close()


class GatedWriterTest(unittest.TestCase):
    def test_ping_times_out_behind_blocked_transport_write_then_recovers(self):
        left, right = socket.socketpair()
        transport = _GatedTransport(left)
        server_thread, established = _run(zmux.server, right)
        client = zmux.client(transport, zmux.Config(keepalive_interval=None))
        server_thread.join(2.0)
        server = established["value"]
        try:
            transport.gate.clear()
            started = time.monotonic()
            with self.assertRaises(zmux.PingTimeout):
                client.ping(timeout=0.3)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(client.state, zmux.SessionState.READY)
            transport.gate.set()
            self.assertGreaterEqual(client.ping(timeout=2.0), 0.0)
        finally:
            transport.gate.set()
            client.close()
            server.close()


class SingleCloseTest(unittest.TestCase):
    def setUp(self):
        # A tiny GIL switch interval widens the race between the two closers.
        self._switch_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)

    def tearDown(self):
        sys.setswitchinterval(self._switch_interval)

    def _collect(self, peer, result):
        result["frames"] = peer.frames_until_eof()

    def _concurrent_close_pair(self, first, second):
        session, peer = _python_client_with_raw_server(settings=zmux.Settings())
        collected = {}
        reader = threading.Thread(target=self._collect, args=(peer, collected), daemon=True)
        reader.start()
        barrier = threading.Barrier(2)

        def call(action):
            barrier.wait()
            try:
                action(session)
            except zmux.ZmuxError:
                pass

        threads = [
            threading.Thread(target=call, args=(first,), daemon=True),
            threading.Thread(target=call, args=(second,), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5.0)
        reader.join(5.0)
        peer.close()
        return session, _close_frames(collected.get("frames", []))

    def test_second_close_while_first_close_frame_is_in_flight_emits_nothing(self):
        left, right = socket.socketpair()
        transport = _GatedTransport(left)
        peer = RawPeer(right)
        peer.send_preface(zmux.Role.RESPONDER)
        session = zmux.client(transport, zmux.Config(keepalive_interval=None))
        peer.read_preface()
        collected = {}
        reader = threading.Thread(target=self._collect, args=(peer, collected), daemon=True)
        reader.start()
        try:
            # Stretch the bounded CLOSE wait so the gate below decides the race.
            session._last_ping_rtt = 1.0
            transport.gate.clear()
            first, _ = _run(session.close_with_error, 5, "five")
            deadline = time.monotonic() + 2.0
            while not transport.blocked.is_set() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue(transport.blocked.is_set())
            second, _ = _run(session.close_with_error, 7, "seven")
            time.sleep(0.1)
            transport.gate.set()
            first.join(5.0)
            second.join(5.0)
            reader.join(5.0)
            closes = _close_frames(collected.get("frames", []))
            self.assertEqual(len(closes), 1)
            self.assertEqual(zmux.parse_error_payload(closes[0].payload)[0], 5)
            self.assertEqual(session.close_error.code, 5)
        finally:
            transport.gate.set()
            peer.close()

    def test_concurrent_close_with_error_emits_single_close_frame(self):
        for _ in range(20):
            session, closes = self._concurrent_close_pair(
                lambda conn: conn.close_with_error(5, "five"),
                lambda conn: conn.close_with_error(7, "seven"),
            )
            self.assertEqual(len(closes), 1)
            code, _ = zmux.parse_error_payload(closes[0].payload)
            self.assertEqual(code, session.close_error.code)

    def test_close_racing_close_with_error_emits_single_close_frame(self):
        for _ in range(10):
            session, closes = self._concurrent_close_pair(
                lambda conn: conn.close(),
                lambda conn: conn.close_with_error(5, "five"),
            )
            self.assertEqual(len(closes), 1)
            self.assertTrue(session.closed)


class FatalCloseTest(unittest.TestCase):
    """Locally detected fatal errors are signalled with CLOSE(code)."""

    def _assert_close_code(self, peer, expected_code):
        frames = peer.frames_until_eof()
        closes = _close_frames(frames)
        self.assertEqual(len(closes), 1, frames)
        self.assertEqual(closes[0].stream_id, 0)
        code, _ = zmux.parse_error_payload(closes[0].payload)
        self.assertEqual(code, int(expected_code))
        return closes[0]

    def test_invalid_frame_type_sends_close_protocol(self):
        session, peer = _python_server_with_raw_client()
        try:
            peer.socket.sendall(bytes((2, 0x0C, 0)))
            self._assert_close_code(peer, zmux.ErrorCode.PROTOCOL)
            with self.assertRaises(zmux.ProtocolError):
                session.wait(2.0)
        finally:
            peer.close()

    def test_peer_stream_id_gap_sends_close_protocol(self):
        session, peer = _python_server_with_raw_client()
        try:
            peer.send_frame(zmux.Frame(zmux.FrameType.DATA, 8, 0, b"gap"))
            self._assert_close_code(peer, zmux.ErrorCode.PROTOCOL)
            with self.assertRaises(zmux.ProtocolError) as raised:
                session.wait(2.0)
            # The local error carries the code its CLOSE reported.
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.PROTOCOL))
            self.assertEqual(zmux.error_code(session.close_error), int(zmux.ErrorCode.PROTOCOL))
        finally:
            peer.close()

    def test_uncoded_peer_violations_report_close_code_locally(self):
        # Violations detected by state checks used to leave close_error (and
        # wait()) without a code although the CLOSE said PROTOCOL.
        cases = (
            zmux.Frame(zmux.FrameType.MAX_DATA, 4, 0, zmux.encode_varint(1)),
            zmux.Frame(zmux.FrameType.DATA, 3, 0, b"x"),
        )
        for frame in cases:
            with self.subTest(frame_type=frame.frame_type.name, stream_id=frame.stream_id):
                session, peer = _python_server_with_raw_client()
                try:
                    peer.send_frame(frame)
                    self._assert_close_code(peer, zmux.ErrorCode.PROTOCOL)
                    with self.assertRaises(zmux.ProtocolError) as raised:
                        session.wait(2.0)
                    self.assertIs(raised.exception, session.close_error)
                    self.assertEqual(raised.exception.code, int(zmux.ErrorCode.PROTOCOL))
                finally:
                    peer.close()

    def test_peer_stream_violations_carry_protocol_code_without_fallback(self):
        # Each violation raises with its own wire code, so the CLOSE does not
        # depend on the class-based fallback for uncoded protocol errors.
        cancelled = zmux.build_error_payload(int(zmux.ErrorCode.CANCELLED), "")
        metadata = zmux.build_open_metadata_prefix(zmux.DEFAULT_CAPABILITIES, group=5)
        cases = (
            (
                "ABORT on a locally-owned stream id",
                (zmux.Frame(zmux.FrameType.ABORT, 1, 0, cancelled),),
            ),
            (
                "ABORT skipping the expected peer stream id",
                (zmux.Frame(zmux.FrameType.ABORT, 8, 0, cancelled),),
            ),
            (
                "DATA skipping the expected peer stream id",
                (zmux.Frame(zmux.FrameType.DATA, 8, 0, b"gap"),),
            ),
            (
                "STOP_SENDING on an unknown stream",
                (zmux.Frame(zmux.FrameType.STOP_SENDING, 4, 0, cancelled),),
            ),
            (
                "BLOCKED on an unknown stream",
                (zmux.Frame(zmux.FrameType.BLOCKED, 4, 0, zmux.encode_varint(0)),),
            ),
            (
                "OPEN_METADATA on an already-open stream",
                (
                    zmux.Frame(
                        zmux.FrameType.DATA,
                        4,
                        zmux.FRAME_FLAG_OPEN_METADATA,
                        metadata + b"a",
                    ),
                    zmux.Frame(
                        zmux.FrameType.DATA,
                        4,
                        zmux.FRAME_FLAG_OPEN_METADATA,
                        metadata + b"b",
                    ),
                ),
            ),
        )
        internal = int(zmux.ErrorCode.INTERNAL)
        for name, frames in cases:
            with self.subTest(name), mock.patch.object(
                native_module, "_uncoded_close_code", return_value=internal
            ), mock.patch.object(
                runtime_session_module, "_uncoded_close_code", return_value=internal
            ):
                session, peer = _python_server_with_raw_client()
                try:
                    for frame in frames:
                        peer.send_frame(frame)
                    self._assert_close_code(peer, zmux.ErrorCode.PROTOCOL)
                    with self.assertRaises(zmux.ProtocolError) as raised:
                        session.wait(2.0)
                    self.assertIs(raised.exception, session.close_error)
                    self.assertEqual(raised.exception.code, int(zmux.ErrorCode.PROTOCOL))
                finally:
                    peer.close()

    def test_short_ping_sends_close_frame_size(self):
        session, peer = _python_server_with_raw_client()
        try:
            peer.socket.sendall(bytes((4, int(zmux.FrameType.PING), 0)) + b"abc")
            self._assert_close_code(peer, zmux.ErrorCode.FRAME_SIZE)
            with self.assertRaises(zmux.FrameSizeError) as raised:
                session.wait(2.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.FRAME_SIZE))
        finally:
            peer.close()

    def test_session_flow_control_overrun_sends_close_flow_control(self):
        config = zmux.Config(
            keepalive_interval=None,
            settings=zmux.Settings(
                initial_max_data=100,
                initial_max_stream_data_bidi_peer_opened=1000,
            ),
        )
        session, peer = _python_server_with_raw_client(config)
        try:
            peer.send_frame(zmux.Frame(zmux.FrameType.DATA, 4, 0, b"z" * 200))
            self._assert_close_code(peer, zmux.ErrorCode.FLOW_CONTROL)
            with self.assertRaises(zmux.FlowControlError) as raised:
                session.wait(2.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.FLOW_CONTROL))
        finally:
            peer.close()

    def test_keepalive_timeout_sends_close_idle_timeout(self):
        config = zmux.Config(keepalive_interval=0.2, keepalive_timeout=0.5)
        session, peer = _python_server_with_raw_client(config)
        try:
            close = self._assert_close_code(peer, zmux.ErrorCode.IDLE_TIMEOUT)
            _, reason = zmux.parse_error_payload(close.payload)
            self.assertIn("keepalive timeout", reason)
            with self.assertRaises(zmux.KeepaliveTimeout):
                session.wait(2.0)
        finally:
            peer.close()

    def test_peer_close_is_not_echoed(self):
        session, peer = _python_server_with_raw_client()
        try:
            peer.send_frame(
                zmux.Frame(zmux.FrameType.CLOSE, 0, 0, zmux.build_error_payload(0, ""))
            )
            self.assertEqual(_close_frames(peer.frames_until_eof()), [])
            session.wait(2.0)
        finally:
            peer.close()

    def test_transport_eof_does_not_send_close(self):
        session, peer = _python_server_with_raw_client()
        try:
            peer.socket.shutdown(socket.SHUT_WR)
            self.assertEqual(_close_frames(peer.frames_until_eof()), [])
            with self.assertRaises(zmux.TransportError):
                session.wait(2.0)
        finally:
            peer.close()


if __name__ == "__main__":
    unittest.main()
