"""Receive-credit, BLOCKED and flow-control-violation regressions.

The native session used to grant MAX_DATA as soon as DATA arrived and then
parked its single reader thread on a per-stream high-water mark, so one unread
stream stalled every other stream and all control frames.  It also counted
every inbound BLOCKED (and every limit-raising MAX_DATA) as abusive control
traffic, sent a stream BLOCKED before a zero-credit stream's opener, never
granted credit to a zero initial window, and failed the whole session for a
stream-only window overrun.  These tests drive real sessions over
``socket.socketpair``, using a raw zmux peer where exact frames matter.
"""

import socket
import threading
import time
import unittest
from unittest import mock

import zmux
from zmux.native import Conn


class RawPeer(object):
    """Hand-driven zmux endpoint that records every frame it receives."""

    def __init__(self, sock):
        self.socket = sock
        self.frames = []
        self._cond = threading.Condition()
        self._reader = None

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

    def start_collecting(self):
        self._reader = threading.Thread(target=self._collect, daemon=True)
        self._reader.start()

    def _collect(self):
        while True:
            try:
                frame = zmux.read_frame(self)
            except (zmux.ZmuxError, OSError, ValueError):
                return
            with self._cond:
                self.frames.append(frame)
                self._cond.notify_all()

    def wait_for(self, predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for frame in self.frames:
                    if predicate(frame):
                        return frame
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def snapshot(self):
        with self._cond:
            return list(self.frames)

    def send_frame(self, frame):
        self.socket.sendall(frame.marshal())

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass


def _server_with_raw_client(settings=None, **config):
    left, right = socket.socketpair()
    peer = RawPeer(left)
    peer.send_preface(zmux.Role.INITIATOR)
    config.setdefault("keepalive_interval", None)
    session = zmux.server(right, zmux.Config(settings=settings or zmux.Settings(), **config))
    peer.read_preface()
    peer.start_collecting()
    return session, peer


def _client_with_raw_server(settings=None):
    left, right = socket.socketpair()
    peer = RawPeer(right)
    peer.send_preface(zmux.Role.RESPONDER, settings)
    session = zmux.client(left, zmux.Config(keepalive_interval=None))
    peer.read_preface()
    peer.start_collecting()
    return session, peer


def _session_pair(server_config=None, client_config=None):
    left, right = socket.socketpair()
    result = {}

    def run_server():
        try:
            result["server"] = zmux.server(right, server_config)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    client = zmux.client(left, client_config)
    thread.join(2.0)
    if "server" not in result:
        client.close_with_error(int(zmux.ErrorCode.INTERNAL))
        raise result.get("error") or AssertionError("server establishment timed out")
    return client, result["server"]


def _close(*sessions):
    for session in sessions:
        try:
            session.close_with_error(int(zmux.ErrorCode.NO_ERROR))
        except zmux.ZmuxError:
            pass


def _run(target, *args, **kwargs):
    result = {}

    def runner():
        try:
            result["value"] = target(*args, **kwargs)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, result


def _wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def _wait_stable(read_value, quiet=0.3, timeout=5.0):
    """Wait until ``read_value()`` stops changing for ``quiet`` seconds."""

    deadline = time.monotonic() + timeout
    last = read_value()
    changed_at = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(0.02)
        current = read_value()
        if current != last:
            last = current
            changed_at = time.monotonic()
        elif time.monotonic() - changed_at >= quiet:
            return current
    return last


def _data(stream_id, payload, flags=0):
    return zmux.Frame(zmux.FrameType.DATA, stream_id, flags, payload)


def _max_data(stream_id, value):
    return zmux.Frame(zmux.FrameType.MAX_DATA, stream_id, 0, zmux.encode_varint(value))


def _blocked(stream_id, value):
    return zmux.Frame(zmux.FrameType.BLOCKED, stream_id, 0, zmux.encode_varint(value))


def _varint(frame):
    value, _ = zmux.parse_varint(frame.payload)
    return value


def _is_max_data(stream_id, minimum=0):
    return lambda frame: (
        frame.frame_type == zmux.FrameType.MAX_DATA
        and frame.stream_id == stream_id
        and _varint(frame) >= minimum
    )


def _error_code(frame):
    code, _ = zmux.parse_error_payload(frame.payload)
    return code


def _drain(stream, size, timeout=10.0):
    total = 0
    while total < size:
        chunk = stream.read(65536, timeout=timeout)
        if not chunk:
            break
        total += len(chunk)
    return total


class ReceiveCreditTest(unittest.TestCase):
    def test_stream_credit_is_granted_on_read_not_on_arrival(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(initial_max_stream_data_bidi_peer_opened=4096)
        )
        try:
            peer.send_frame(_data(4, b"x" * 4000))
            inbound = session.accept_stream(timeout=1.0)
            time.sleep(0.2)
            self.assertIsNone(
                peer.wait_for(lambda f: f.frame_type == zmux.FrameType.MAX_DATA, timeout=0)
            )
            self.assertEqual(inbound._recv_advertised, 4096)
            self.assertEqual(session.stats.pressure.receive_backlog_bytes, 4000)

            self.assertEqual(inbound.read_exact(4000, timeout=1.0), b"x" * 4000)
            grant = peer.wait_for(_is_max_data(inbound.stream_id))
            self.assertIsNotNone(grant)
            self.assertGreaterEqual(_varint(grant), 4000 + 4096)
            self.assertEqual(session.stats.pressure.receive_backlog_bytes, 0)
        finally:
            _close(session)
            peer.close()

    def test_reader_keeps_processing_frames_while_a_stream_is_unread(self):
        # 512 KiB unread on one stream is within its window; the old reader
        # parked at a 256 KiB high-water mark and stopped answering PINGs.
        session, peer = _server_with_raw_client(
            zmux.Settings(
                initial_max_data=4 << 20,
                initial_max_stream_data_bidi_peer_opened=2 << 20,
            )
        )
        try:
            chunk = b"y" * 16384
            frames = [_data(4, chunk) for _ in range(32)]
            frames.append(zmux.Frame(zmux.FrameType.PING, 0, 0, b"12345678"))
            # Sent from a helper: a stalled reader would block these writes.
            _run(lambda: [peer.send_frame(frame) for frame in frames])
            self.assertIsNotNone(
                peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PONG)
            )
            peer.send_frame(_data(8, b"hello"))
            first = session.accept_stream(timeout=1.0)
            second = session.accept_stream(timeout=1.0)
            self.assertEqual(second.read_exact(5, timeout=1.0), b"hello")
            self.assertEqual(first._read_buffered, 32 * len(chunk))
            self.assertIsNone(peer.wait_for(_is_max_data(first.stream_id), timeout=0))
        finally:
            _close(session)
            peer.close()

    def test_unread_stream_does_not_stall_other_streams_or_pings(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            payload = b"a" * (4 << 20)
            writer, written = _run(outbound.write_all, payload, timeout=10.0)
            inbound = server.accept_stream(timeout=1.0)
            buffered = _wait_stable(lambda: inbound._read_buffered)
            self.assertTrue(writer.is_alive(), "writer should be blocked on stream credit")
            # Unread bytes stay within what the receiver advertised: the
            # initial window plus at most one standing-target grant.
            self.assertLessEqual(buffered, inbound._recv_advertised)
            self.assertLessEqual(buffered, (64 << 10) + (512 << 10))

            other = client.open_stream(timeout=1.0)
            other.write_all(b"hello", timeout=1.0)
            accepted = server.accept_stream(timeout=1.0)
            self.assertEqual(accepted.read_exact(5, timeout=1.0), b"hello")
            server.ping(timeout=1.0)
            client.ping(timeout=1.0)

            self.assertEqual(_drain(inbound, len(payload)), len(payload))
            writer.join(5.0)
            self.assertNotIn("error", written)
        finally:
            _close(client, server)

    def test_unread_streams_are_bounded_by_advertised_windows(self):
        server_config = zmux.Config(
            settings=zmux.Settings(
                initial_max_data=64 << 10,
                initial_max_stream_data_bidi_peer_opened=16 << 10,
            ),
            per_stream_queued_data_hwm=32 << 10,
            session_queued_data_hwm=128 << 10,
        )
        client, server = _session_pair(server_config)
        try:
            size = 200 << 10
            writers = []
            for _ in range(8):
                stream = client.open_stream(timeout=1.0)
                writers.append(_run(stream.write_all, b"b" * size, timeout=10.0))
            inbound = [server.accept_stream(timeout=1.0) for _ in range(8)]
            total = _wait_stable(lambda: sum(stream._read_buffered for stream in inbound))
            self.assertTrue(all(thread.is_alive() for thread, _ in writers))
            self.assertLessEqual(total, server._recv_session_advertised)
            for stream in inbound:
                self.assertLessEqual(stream._read_buffered, stream._recv_advertised)
                # Growth stops once a stream holds its high-water mark unread.
                self.assertLessEqual(stream._read_buffered, (16 << 10) + (64 << 10))
            self.assertEqual(server.stats.pressure.receive_backlog_bytes, total)
            server.ping(timeout=1.0)

            for stream in inbound:
                self.assertEqual(_drain(stream, size), size)
            for thread, result in writers:
                thread.join(5.0)
                self.assertNotIn("error", result)
            self.assertEqual(server.stats.pressure.receive_backlog_bytes, 0)
        finally:
            _close(client, server)

    def test_peer_reset_discards_unread_bytes_and_returns_session_credit(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(
                initial_max_data=8192,
                initial_max_stream_data_bidi_peer_opened=8192,
            )
        )
        try:
            peer.send_frame(_data(4, b"r" * 4000))
            inbound = session.accept_stream(timeout=1.0)
            peer.send_frame(
                zmux.Frame(zmux.FrameType.RESET, 4, 0, zmux.build_error_payload(7, ""))
            )
            self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
            with self.assertRaises(zmux.ApplicationError) as raised:
                inbound.read(1, timeout=1.0)
            self.assertEqual(raised.exception.code, 7)
            self.assertIsNotNone(peer.wait_for(_is_max_data(0, 8192 + 4000)))
            self.assertEqual(session.stats.pressure.receive_backlog_bytes, 0)
        finally:
            _close(session)
            peer.close()

    def test_close_read_discards_unread_bytes_and_returns_session_credit(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(
                initial_max_data=8192,
                initial_max_stream_data_bidi_peer_opened=8192,
            )
        )
        try:
            peer.send_frame(_data(4, b"s" * 3000))
            inbound = session.accept_stream(timeout=1.0)
            self.assertTrue(_wait_until(lambda: inbound._read_buffered == 3000))
            inbound.close_read()
            self.assertIsNotNone(peer.wait_for(_is_max_data(0, 8192 + 3000)))
            self.assertIsNone(peer.wait_for(_is_max_data(4), timeout=0))
            self.assertEqual(session.stats.pressure.receive_backlog_bytes, 0)
        finally:
            _close(session)
            peer.close()


    def test_close_after_peer_fin_drops_unread_bytes_and_returns_session_credit(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(
                initial_max_data=8192,
                initial_max_stream_data_bidi_peer_opened=8192,
            )
        )
        try:
            peer.send_frame(_data(4, b"f" * 2000, zmux.FRAME_FLAG_FIN))
            inbound = session.accept_stream(timeout=1.0)
            self.assertTrue(_wait_until(lambda: inbound._read_finished))
            inbound.close()
            self.assertIsNotNone(peer.wait_for(_is_max_data(0, 8192 + 2000)))
            self.assertEqual(session.stats.pressure.receive_backlog_bytes, 0)
        finally:
            _close(session)
            peer.close()


class BlockedAndControlBudgetTest(unittest.TestCase):
    def test_default_config_bulk_transfer_completes(self):
        # Limit-raising MAX_DATA from the receiver's own replenishment exceeds
        # the 2048-per-window control budget here; it must not count.
        client, server = _session_pair()
        size = 64 << 20
        try:
            outbound = client.open_stream(timeout=1.0)
            writer, written = _run(self._write_chunks, outbound, size)
            inbound = server.accept_stream(timeout=2.0)
            self.assertEqual(_drain(inbound, size, timeout=20.0), size)
            writer.join(20.0)
            self.assertNotIn("error", written)
            self.assertIsNone(client.close_error)
            self.assertIsNone(server.close_error)
            self.assertGreater(server.stats.sent_frames, 2048)
            self.assertEqual(client.stats.abuse.inbound_control_frames, 0)
        finally:
            _close(client, server)

    def test_bulk_transfer_with_frequent_blocked_completes(self):
        # Small receive windows and a slow reader make the sender stall (and
        # send BLOCKED at a new limit) every few KiB.  Every BLOCKED used to be
        # a no-op, so the receiver failed after 128 of them.
        server_config = zmux.Config(
            settings=zmux.Settings(
                initial_max_data=64 << 10,
                initial_max_stream_data_bidi_peer_opened=16 << 10,
            ),
            per_stream_queued_data_hwm=8 << 10,
            session_queued_data_hwm=16 << 10,
        )
        client, server = _session_pair(server_config)
        size = 16 << 20
        try:
            with mock.patch.object(
                Conn,
                "_handle_blocked",
                autospec=True,
                side_effect=Conn._handle_blocked,
            ) as handled:
                outbound = client.open_stream(timeout=1.0)
                writer, written = _run(self._write_chunks, outbound, size)
                inbound = server.accept_stream(timeout=2.0)
                total = 0
                reads = 0
                buffer = bytearray(4096)
                while total < size:
                    count = inbound.readinto(buffer, timeout=10.0)
                    if not count:
                        break
                    total += count
                    reads += 1
                    if reads % 2 == 0:
                        time.sleep(0.0002)
                writer.join(20.0)
            self.assertEqual(total, size)
            self.assertNotIn("error", written)
            self.assertIsNone(server.close_error)
            self.assertIsNone(client.close_error)
            self.assertGreater(handled.call_count, 2 * server.stats.abuse.no_op_blocked_budget)
            self.assertLess(server.stats.abuse.no_op_blocked, server.stats.abuse.no_op_blocked_budget)
        finally:
            _close(client, server)

    def test_blocked_at_each_new_limit_is_progress_but_repeats_are_charged(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(
                initial_max_data=1 << 20,
                initial_max_stream_data_bidi_peer_opened=1024,
            ),
            per_stream_queued_data_hwm=1024,
        )
        try:
            session._dispatch_frame(_data(4, b"x" * 1024))
            inbound = session.accept_stream(timeout=1.0)
            for _ in range(300):
                limit = inbound._recv_advertised
                fill = limit - inbound._recv_received
                if fill:
                    session._dispatch_frame(_data(4, b"x" * fill))
                session._dispatch_frame(_blocked(4, limit))
                inbound.read_exact(inbound._read_buffered, timeout=1.0)
            self.assertEqual(session.stats.abuse.no_op_blocked, 0)
            self.assertEqual(session.stats.abuse.inbound_control_frames, 0)

            limit = inbound._recv_advertised
            with self.assertRaisesRegex(zmux.ProtocolError, "budget exceeded"):
                for _ in range(300):
                    session._dispatch_frame(_blocked(4, limit))
        finally:
            _close(session)
            peer.close()

    def test_blocked_for_a_limit_never_advertised_is_a_no_op(self):
        session, peer = _server_with_raw_client(no_op_blocked_budget=2)
        try:
            limit = session._recv_session_advertised
            session._dispatch_frame(_blocked(0, limit + 1))
            session._dispatch_frame(_blocked(0, limit + 2))
            with self.assertRaisesRegex(zmux.ProtocolError, "no-op BLOCKED budget exceeded"):
                session._dispatch_frame(_blocked(0, limit + 3))
        finally:
            _close(session)
            peer.close()

    def test_increasing_max_data_is_not_charged_but_repeats_are(self):
        session, peer = _client_with_raw_server()
        try:
            stream = session.open_stream(timeout=1.0)
            stream.write_all(b"open", timeout=1.0)
            base = session._send_session_max
            for step in range(1, 4097):
                session._dispatch_frame(_max_data(0, base + step))
            for step in range(1, 1025):
                session._dispatch_frame(_max_data(stream.stream_id, stream._send_max + 1))
            self.assertEqual(session.stats.abuse.inbound_control_frames, 0)
            self.assertEqual(session.stats.abuse.no_op_max_data, 0)

            with self.assertRaisesRegex(zmux.ProtocolError, "budget exceeded"):
                for _ in range(300):
                    session._dispatch_frame(_max_data(0, base + 4096))
            self.assertGreater(session.stats.abuse.inbound_control_frames, 0)
        finally:
            _close(session)
            peer.close()

    def _assert_close_code(self, peer, code):
        close = peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE)
        self.assertIsNotNone(close)
        self.assertEqual(_error_code(close), int(code))

    def test_stream_blocked_on_unopened_stream_closes_session_with_protocol(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_blocked(4, 0))
            self._assert_close_code(peer, zmux.ErrorCode.PROTOCOL)
            with self.assertRaises(zmux.ProtocolError):
                session.wait(2.0)
        finally:
            peer.close()

    def test_stream_max_data_on_unopened_local_stream_closes_session_with_protocol(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_max_data(1, 100))
            self._assert_close_code(peer, zmux.ErrorCode.PROTOCOL)
            with self.assertRaises(zmux.ProtocolError):
                session.wait(2.0)
        finally:
            peer.close()

    def test_flow_control_frames_on_finished_stream_are_ignored(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"done", zmux.FRAME_FLAG_FIN))
            inbound = session.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(4, timeout=1.0), b"done")
            inbound.close_write(timeout=1.0)
            self.assertTrue(_wait_until(lambda: 4 not in session._streams))
            peer.send_frame(_blocked(4, 4))
            peer.send_frame(_max_data(4, 100))
            peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"87654321"))
            self.assertIsNotNone(
                peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PONG)
            )
            self.assertFalse(session.closed)
        finally:
            _close(session)
            peer.close()

    @staticmethod
    def _write_chunks(stream, size):
        chunk = b"z" * (1 << 20)
        for _ in range(size // len(chunk)):
            stream.write_all(chunk, timeout=20.0)
        stream.close_write(timeout=20.0)


class ZeroWindowTest(unittest.TestCase):
    def test_zero_stream_credit_write_sends_empty_opener_before_blocked(self):
        settings = zmux.Settings(
            initial_max_stream_data_bidi_peer_opened=0,
            initial_max_stream_data_uni=0,
        )
        for bidirectional in (True, False):
            with self.subTest(bidirectional=bidirectional):
                session, peer = _client_with_raw_server(settings)
                try:
                    stream = (
                        session.open_stream(timeout=1.0)
                        if bidirectional
                        else session.open_uni_stream(timeout=1.0)
                    )
                    writer, written = _run(stream.write, b"hello", timeout=2.0)
                    sid = stream.stream_id
                    blocked = peer.wait_for(
                        lambda f, sid=sid: (
                            f.frame_type == zmux.FrameType.BLOCKED and f.stream_id == sid
                        )
                    )
                    self.assertIsNotNone(blocked)
                    stream_frames = [f for f in peer.snapshot() if f.stream_id == sid]
                    opener = stream_frames[0]
                    self.assertEqual(opener.frame_type, zmux.FrameType.DATA)
                    self.assertEqual((opener.flags, opener.payload), (0, b""))
                    self.assertEqual(_varint(blocked), 0)

                    peer.send_frame(_max_data(sid, 5))
                    writer.join(2.0)
                    self.assertEqual(written.get("value"), 5, written)
                    data = peer.wait_for(
                        lambda f: f.frame_type == zmux.FrameType.DATA and f.payload == b"hello"
                    )
                    self.assertIsNotNone(data)
                    self.assertEqual(data.stream_id, sid)
                finally:
                    _close(session)
                    peer.close()

    def test_sender_reports_each_blocked_limit_once(self):
        session, peer = _client_with_raw_server(
            zmux.Settings(initial_max_stream_data_bidi_peer_opened=0)
        )
        try:
            stream = session.open_stream(timeout=1.0)
            for _ in range(3):
                with self.assertRaises(zmux.WriteTimeout):
                    stream.write(b"xy", timeout=0.05)
            peer.send_frame(_max_data(stream.stream_id, 1))
            with self.assertRaises(zmux.WriteTimeout):
                stream.write(b"xy", timeout=0.2)
            self.assertIsNotNone(
                peer.wait_for(
                    lambda f: f.frame_type == zmux.FrameType.BLOCKED and _varint(f) == 1
                )
            )
            limits = [
                _varint(f)
                for f in peer.snapshot()
                if f.frame_type == zmux.FrameType.BLOCKED and f.stream_id == stream.stream_id
            ]
            self.assertEqual(limits, [0, 1])
        finally:
            _close(session)
            peer.close()

    def test_python_peers_exchange_data_under_zero_initial_windows(self):
        cases = {
            "bidi": (zmux.Settings(initial_max_stream_data_bidi_peer_opened=0), True),
            "uni": (zmux.Settings(initial_max_stream_data_uni=0), False),
            "session": (zmux.Settings(initial_max_data=0), True),
        }
        for name, (settings, bidirectional) in cases.items():
            with self.subTest(case=name):
                client, server = _session_pair(zmux.Config(settings=settings))
                try:
                    stream = (
                        client.open_stream(timeout=1.0)
                        if bidirectional
                        else client.open_uni_stream(timeout=1.0)
                    )
                    writer, written = _run(stream.write_final, b"0123456789", timeout=2.0)
                    inbound = (
                        server.accept_stream(timeout=2.0)
                        if bidirectional
                        else server.accept_uni_stream(timeout=2.0)
                    )
                    self.assertEqual(inbound.read_exact(10, timeout=2.0), b"0123456789")
                    writer.join(2.0)
                    self.assertEqual(written.get("value"), 10, written)
                    self.assertFalse(client.closed)
                    self.assertFalse(server.closed)
                finally:
                    _close(client, server)

    def test_zero_window_receiver_grants_on_peer_blocked(self):
        cases = {
            "bidi": (zmux.Settings(initial_max_stream_data_bidi_peer_opened=0), 4, 4),
            "uni": (zmux.Settings(initial_max_stream_data_uni=0), 2, 2),
            "session": (zmux.Settings(initial_max_data=0), 4, 0),
        }
        for name, (settings, stream_id, scope) in cases.items():
            with self.subTest(case=name):
                session, peer = _server_with_raw_client(settings)
                try:
                    peer.send_frame(_data(stream_id, b""))
                    peer.send_frame(_blocked(scope, 0))
                    grant = peer.wait_for(_is_max_data(scope, 1))
                    self.assertIsNotNone(grant)
                    self.assertEqual(session.stats.abuse.no_op_blocked, 0)
                finally:
                    _close(session)
                    peer.close()

    def test_zero_window_receiver_grants_on_accept_and_read_unless_memory_is_tight(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(initial_max_stream_data_bidi_peer_opened=0)
        )
        try:
            peer.send_frame(_data(4, b""))
            with mock.patch.object(Conn, "_memory_pressure_high_locked", return_value=True):
                inbound = session.accept_stream(timeout=1.0)
                with self.assertRaises(zmux.ReadTimeout):
                    inbound.read(1, timeout=0.05)
            self.assertIsNone(peer.wait_for(_is_max_data(4), timeout=0.1))

            with self.assertRaises(zmux.ReadTimeout):
                inbound.read(1, timeout=0.05)
            self.assertIsNotNone(peer.wait_for(_is_max_data(4, 1)))
        finally:
            _close(session)
            peer.close()


class FlowControlViolationTest(unittest.TestCase):
    def test_stream_window_overrun_aborts_only_that_stream(self):
        session, peer = _server_with_raw_client(
            zmux.Settings(
                initial_max_data=1 << 20,
                initial_max_stream_data_bidi_peer_opened=4,
            )
        )
        try:
            peer.send_frame(_data(4, b"ab"))
            peer.send_frame(_data(8, b"cd"))
            first = session.accept_stream(timeout=1.0)
            second = session.accept_stream(timeout=1.0)
            peer.send_frame(_data(4, b"12345"))

            abort = peer.wait_for(
                lambda f: f.frame_type == zmux.FrameType.ABORT and f.stream_id == 4
            )
            self.assertIsNotNone(abort)
            self.assertEqual(_error_code(abort), int(zmux.ErrorCode.FLOW_CONTROL))
            # The rejected (and the discarded unread) bytes still return
            # session credit.
            self.assertIsNotNone(peer.wait_for(_is_max_data(0, (1 << 20) + 5)))
            with self.assertRaises(zmux.ApplicationError) as raised:
                first.write(b"x", timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.FLOW_CONTROL))

            self.assertFalse(session.closed)
            self.assertEqual(second.read_exact(2, timeout=1.0), b"cd")
            peer.send_frame(_data(8, b"ef"))
            self.assertEqual(second.read_exact(2, timeout=1.0), b"ef")
            second.write_all(b"ok", timeout=1.0)
            self.assertIsNotNone(
                peer.wait_for(
                    lambda f: f.frame_type == zmux.FrameType.DATA
                    and f.stream_id == 8
                    and f.payload == b"ok"
                )
            )
            self.assertIsNone(
                peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE, timeout=0)
            )
        finally:
            _close(session)
            peer.close()

    def test_reset_on_unseen_stream_sends_close_protocol(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(
                zmux.Frame(zmux.FrameType.RESET, 4, 0, zmux.build_error_payload(0, ""))
            )
            close = peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE)
            self.assertIsNotNone(close)
            self.assertEqual(_error_code(close), int(zmux.ErrorCode.PROTOCOL))
            with self.assertRaises(zmux.ProtocolError):
                session.wait(2.0)
        finally:
            peer.close()


if __name__ == "__main__":
    unittest.main()
