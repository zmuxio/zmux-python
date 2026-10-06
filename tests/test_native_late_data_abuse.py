"""Late-data, used-stream bookkeeping, abuse budget and EXT codec regressions.

The native session used to fail the whole session with PROTOCOL as soon as a
stopped or aborted stream received more than 8 KiB of DATA the peer had
legitimately put in flight, counted every late byte against a session-lifetime
aggregate, kept one used-stream range per closed stream once stream classes
interleaved (growing without bound), rebuilt its tombstone queue on every
stream close, never enforced the hidden/visible open-then-abort churn budgets,
dropped a duplicate-then-truncated PRIORITY_UPDATE instead of rejecting it,
closed with FRAME_SIZE for an EXT payload too short for its ext_type, and
judged PRIORITY_UPDATE payloads even when the capability was not negotiated.
These tests drive real sessions over ``socket.socketpair``, using a raw zmux
peer where exact frames matter.
"""

import socket
import threading
import time
import unittest

import zmux
from zmux.native import Conn


class RawPeer(object):
    """Hand-driven zmux endpoint that records every frame it receives."""

    def __init__(self, sock):
        self.socket = sock
        self.frames = []
        self._cond = threading.Condition()
        self._pings = 0

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def send_preface(self, role, settings=None, **config):
        preface = zmux.Config(
            role=role,
            settings=settings or zmux.Settings(),
            preface_padding=False,
            ping_padding=False,
            **config,
        )
        self.socket.sendall(preface.local_preface_payload())

    def start_collecting(self):
        zmux.read_preface(self)
        threading.Thread(target=self._collect, daemon=True).start()

    def _collect(self):
        while True:
            try:
                frame = zmux.read_frame(self)
            except (zmux.ZmuxError, OSError, ValueError):
                return
            with self._cond:
                self.frames.append(frame)
                self._cond.notify_all()

    def wait_for(self, predicate, timeout=3.0):
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

    def barrier(self):
        """Return once the session processed every frame sent before."""

        self._pings += 1
        # Unique per call: a reused token would match an earlier PONG.
        token = b"barrier:" + self._pings.to_bytes(8, "big")
        self.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, token))
        pong = self.wait_for(
            lambda f: f.frame_type == zmux.FrameType.PONG and f.payload.startswith(token)
        )
        if pong is None:
            raise AssertionError("session did not answer the barrier PING")

    def send_frame(self, frame):
        self.socket.sendall(frame.marshal())

    def send_raw(self, frame_type, stream_id, payload):
        """Send a frame the outbound codec would refuse to encode."""

        body = bytes((int(frame_type),)) + zmux.encode_varint(stream_id) + bytes(payload)
        self.socket.sendall(zmux.encode_varint(len(body)) + body)

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass


def _server_with_raw_client(settings=None, peer_config=None, **config):
    left, right = socket.socketpair()
    peer = RawPeer(left)
    peer.send_preface(zmux.Role.INITIATOR, **(peer_config or {}))
    config.setdefault("keepalive_interval", None)
    session = zmux.server(right, zmux.Config(settings=settings or zmux.Settings(), **config))
    peer.start_collecting()
    return session, peer


def _session_pair(server_config=None, client_config=None, buffer_size=None):
    left, right = socket.socketpair()
    if buffer_size is not None:
        for sock in (left, right):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
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


def _wait_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def _data(stream_id, payload, flags=0):
    return zmux.Frame(zmux.FrameType.DATA, stream_id, flags, payload)


def _error_frame(frame_type, stream_id, code):
    return zmux.Frame(frame_type, stream_id, 0, zmux.build_error_payload(code, ""))


def _error_code(frame):
    code, _ = zmux.parse_error_payload(frame.payload)
    return code


def _priority_update(stream_id, priority):
    payload = zmux.build_priority_update_payload(
        zmux.DEFAULT_CAPABILITIES,
        zmux.MetadataUpdate(priority=priority),
    )
    return zmux.Frame(zmux.FrameType.EXT, stream_id, 0, payload)


def _is_frame(frame_type, stream_id, code=None):
    return lambda frame: (
        frame.frame_type == frame_type
        and frame.stream_id == stream_id
        and (code is None or _error_code(frame) == int(code))
    )


def _is_close(frame):
    return frame.frame_type == zmux.FrameType.CLOSE


def _max_data_values(peer, stream_id):
    return [
        zmux.parse_varint(frame.payload)[0]
        for frame in peer.snapshot()
        if frame.frame_type == zmux.FrameType.MAX_DATA and frame.stream_id == stream_id
    ]


def _send_late_tail(peer, stream_id, total, chunk=16384):
    sent = 0
    while sent < total:
        size = min(chunk, total - sent)
        peer.send_frame(_data(stream_id, b"t" * size))
        sent += size


class _SessionAssertions(unittest.TestCase):
    def assert_closed_with(self, session, peer, code):
        close = peer.wait_for(_is_close)
        self.assertIsNotNone(close, "no CLOSE frame")
        self.assertEqual(_error_code(close), int(code))
        self.assertTrue(_wait_until(lambda: session.closed))
        self.assertEqual(session.close_error.code, int(code))

    def assert_open(self, session, peer):
        peer.barrier()
        self.assertIsNone(peer.wait_for(_is_close, timeout=0.05))
        self.assertFalse(session.closed)
        self.assertEqual(session.state, zmux.SessionState.READY)


class LateDataAllowanceTest(_SessionAssertions):
    """SPEC 9.3/9.5, DESIGN D2: in-credit late DATA never fails the session (finding 40)."""

    def _accept_one_byte_stream(self, session, peer, stream_id=4):
        peer.send_frame(_data(stream_id, b"a"))
        inbound = session.accept_stream(timeout=1.0)
        self.assertEqual(inbound.read_exact(1, timeout=1.0), b"a")
        return inbound

    def test_full_stream_window_in_flight_after_close_read_is_tolerated(self):
        session, peer = _server_with_raw_client()
        try:
            inbound = self._accept_one_byte_stream(session, peer)
            inbound.close_read()
            self.assertIsNotNone(peer.wait_for(_is_frame(zmux.FrameType.STOP_SENDING, 4)))
            stream_grants = len(_max_data_values(peer, 4))

            # Everything the stream credit still allowed: 65536 - 1 bytes,
            # several max-size frames, far above the 8 KiB repository cap.
            _send_late_tail(peer, 4, 65535)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.diagnostics.late_data_after_close_read, 65535)
            self.assertEqual(len(_max_data_values(peer, 4)), stream_grants)
            self.assertGreaterEqual(max(_max_data_values(peer, 0)), 262144 + 65535)
            inbound.write_all(b"still writable", timeout=1.0)

            # One byte beyond the advertised stream credit is a stream
            # FLOW_CONTROL violation, not a session error (SPEC section 8).
            peer.send_frame(_data(4, b"z"))
            abort = peer.wait_for(_is_frame(zmux.FrameType.ABORT, 4))
            self.assertIsNotNone(abort)
            self.assertEqual(_error_code(abort), int(zmux.ErrorCode.FLOW_CONTROL))
            self.assert_open(session, peer)
            self.assertGreaterEqual(max(_max_data_values(peer, 0)), 262144 + 65536)
            with self.assertRaises(zmux.ApplicationError) as raised:
                inbound.write(b"x", timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.FLOW_CONTROL))
            self.assertEqual(session.stats.diagnostics.late_data_after_close_read, 65535)
        finally:
            _close(session)
            peer.close()

    def test_full_stream_window_in_flight_after_local_abort_is_tolerated(self):
        session, peer = _server_with_raw_client()
        try:
            inbound = self._accept_one_byte_stream(session, peer)
            inbound.close_with_error(int(zmux.ErrorCode.CANCELLED))
            self.assertIsNotNone(peer.wait_for(_is_frame(zmux.FrameType.ABORT, 4)))

            _send_late_tail(peer, 4, 65535)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.diagnostics.late_data_after_abort, 65535)
            self.assertGreaterEqual(max(_max_data_values(peer, 0)), 262144 + 65535)

            # Beyond the credit outstanding at the abort only a
            # non-compliant peer can go; that keeps the session escalation.
            peer.send_frame(_data(4, b"z"))
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_late_data_allowance_and_count_carry_into_the_tombstone(self):
        session, peer = _server_with_raw_client()
        try:
            inbound = self._accept_one_byte_stream(session, peer)
            inbound.close_read()
            self.assertIsNotNone(peer.wait_for(_is_frame(zmux.FrameType.STOP_SENDING, 4)))
            _send_late_tail(peer, 4, 40000)
            peer.barrier()
            self.assertIn(4, session._streams)
            self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 40000)

            inbound.close_write(timeout=1.0)
            self.assertTrue(_wait_until(lambda: 4 not in session._streams))
            record = session._terminal_state.tombstones[4]
            self.assertEqual(record.late_data_received, 40000)
            self.assertEqual(record.late_data_cap, 65535)
            self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 40000)

            _send_late_tail(peer, 4, 25535)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 65535)
            peer.send_frame(_data(4, b"z"))
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_refused_peer_open_tolerates_its_whole_stream_window_in_flight(self):
        # The peer may put its whole initial stream window in flight before
        # it sees ABORT(REFUSED_STREAM), whichever limit refused the open.
        refusals = {
            "incoming stream limit": (zmux.Settings(max_incoming_streams_bidi=1), {}),
            "accept backlog": (None, {"accept_backlog_limit": 1}),
        }
        for name, (settings, config) in refusals.items():
            with self.subTest(refused_by=name):
                session, peer = _server_with_raw_client(settings, **config)
                try:
                    peer.send_frame(_data(4, b"a"))
                    peer.send_frame(_data(8, b"o" * 16384))
                    refused = peer.wait_for(_is_frame(zmux.FrameType.ABORT, 8))
                    self.assertIsNotNone(refused)
                    self.assertEqual(_error_code(refused), int(zmux.ErrorCode.REFUSED_STREAM))

                    _send_late_tail(peer, 8, 65536 - 16384)
                    self.assert_open(session, peer)
                    self.assertEqual(
                        session.stats.diagnostics.late_data_after_abort,
                        65536 - 16384,
                    )
                    self.assertGreaterEqual(max(_max_data_values(peer, 0)), 262144 + 65536)
                    accepted = session.accept_stream(timeout=1.0)
                    self.assertEqual(accepted.stream_id, 4)
                    self.assertEqual(accepted.read_exact(1, timeout=1.0), b"a")
                finally:
                    _close(session)
                    peer.close()

    def test_data_after_peer_reset_keeps_the_repository_allowance(self):
        # On an ordered transport a peer cannot legitimately send DATA after
        # its own RESET, so that direction only gets the repository cap
        # (8 KiB for the default 64 KiB window), and exceeding it is still
        # escalated (DESIGN D2).
        session, peer = _server_with_raw_client()
        try:
            inbound = self._accept_one_byte_stream(session, peer)
            peer.send_frame(_error_frame(zmux.FrameType.RESET, 4, int(zmux.ErrorCode.CANCELLED)))
            peer.barrier()
            self.assertIn(4, session._streams)
            _send_late_tail(peer, 4, 8192, chunk=4096)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.diagnostics.late_data_after_reset, 8192)
            inbound.write_all(b"send half still open", timeout=1.0)

            peer.send_frame(_data(4, b"z"))
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_python_pair_survives_stop_or_abort_during_in_flight_write(self):
        for stop in ("close_read", "close_with_error"):
            with self.subTest(stop=stop):
                self._stop_during_in_flight_write(stop)

    def _stop_during_in_flight_write(self, stop):
        client, server = _session_pair(
            zmux.Config(keepalive_interval=None),
            zmux.Config(keepalive_interval=None),
            buffer_size=512 * 1024,
        )
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"a", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"a")
            written = {}

            def write_window():
                try:
                    outbound.write_all(b"w" * 65535, timeout=5.0)
                    written["ok"] = True
                except zmux.ZmuxError as exc:
                    written["error"] = exc

            def stop_reading():
                if stop == "close_read":
                    inbound.close_read()
                else:
                    inbound.close_with_error(int(zmux.ErrorCode.CANCELLED))

            # Holding the server's writer keeps STOP_SENDING / ABORT off the
            # wire, so the client puts its whole stream window in flight
            # after the local stop committed.
            with server._write_cond:
                stopper = threading.Thread(target=stop_reading, daemon=True)
                stopper.start()
                self.assertTrue(
                    _wait_until(
                        lambda: inbound._read_stopped or inbound._read_error is not None
                    )
                )
                writer = threading.Thread(target=write_window, daemon=True)
                writer.start()
                writer.join(5.0)
            writer.join(5.0)
            stopper.join(5.0)
            self.assertTrue(written.get("ok"), written)

            def late_bytes():
                diagnostics = server.stats.diagnostics
                return diagnostics.late_data_after_close_read + diagnostics.late_data_after_abort

            _wait_until(lambda: late_bytes() >= 65535, timeout=5.0)
            self.assertEqual(late_bytes(), 65535)
            self.assertFalse(server.closed, server.close_error)
            self.assertFalse(client.closed, client.close_error)

            again = client.open_stream(timeout=1.0)
            again.write_final(b"ping", timeout=1.0)
            echoed = server.accept_stream(timeout=1.0)
            self.assertEqual(echoed.read(timeout=1.0), b"ping")
            echoed.write_final(b"pong", timeout=1.0)
            self.assertEqual(again.read(timeout=1.0), b"pong")
        finally:
            _close(client, server)


class AggregateLateDataTest(_SessionAssertions):
    """DESIGN D2: the aggregate tracks retained accounting, never fails (finding 42)."""

    def _stopped_stream_with_tail(self, session, peer, stream_id, tail):
        peer.send_frame(_data(stream_id, b"x"))
        inbound = session.accept_stream(timeout=1.0)
        self.assertEqual(inbound.read_exact(1, timeout=1.0), b"x")
        inbound.close_read()
        self.assertIsNotNone(peer.wait_for(_is_frame(zmux.FrameType.STOP_SENDING, stream_id)))
        peer.send_frame(_data(stream_id, b"t" * tail))
        peer.send_frame(
            _error_frame(zmux.FrameType.RESET, stream_id, int(zmux.ErrorCode.CANCELLED))
        )
        peer.barrier()
        inbound.close()
        self.assertTrue(_wait_until(lambda: stream_id not in session._streams))

    def test_repeated_close_read_late_tails_do_not_exhaust_the_session(self):
        session, peer = _server_with_raw_client()
        try:
            for index in range(32):
                self._stopped_stream_with_tail(session, peer, 4 + 4 * index, 6000)
            self.assert_open(session, peer)
            pressure = session.stats.pressure
            # Still retained by the tombstones: above the 64 KiB aggregate
            # cap, which only reports pressure.
            self.assertEqual(pressure.aggregate_late_data_bytes, 32 * 6000)
            self.assertTrue(pressure.aggregate_late_data_at_cap)
            peer.send_frame(_data(4 + 4 * 32, b"next", zmux.FRAME_FLAG_FIN))
            stream = session.accept_stream(timeout=1.0)
            self.assertEqual(stream.read(timeout=1.0), b"next")
        finally:
            _close(session)
            peer.close()

    def test_aggregate_drops_late_bytes_of_reaped_tombstones(self):
        session, peer = _server_with_raw_client(tombstone_limit=2)
        try:
            for index in range(10):
                self._stopped_stream_with_tail(session, peer, 4 + 4 * index, 6000)
                self.assertLessEqual(session.stats.pressure.aggregate_late_data_bytes, 2 * 6000)
            self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 2 * 6000)
            # Late DATA on a reaped (marker-only) ID retains nothing.
            peer.send_frame(_data(4, b"t" * 500))
            self.assert_open(session, peer)
            self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 2 * 6000)
            self.assertEqual(session._live_late_data_retained, 0)
        finally:
            _close(session)
            peer.close()


class SessionStateBoundTest(unittest.TestCase):
    """No per-stream session state outlives a compacted stream (finding 45)."""

    def test_session_containers_stay_bounded_after_many_streams(self):
        config = zmux.Config(keepalive_interval=None, tombstone_limit=8, used_marker_limit=16)
        client, server = _session_pair(config, config)
        try:
            payload = b"u" * (40 * 1024)
            for index in range(120):
                outbound = client.open_stream(timeout=2.0)
                if index % 3 == 2:
                    # Late DATA after the server stops reading.
                    outbound.write_all(b"head", timeout=2.0)
                    inbound = server.accept_stream(timeout=2.0)
                    inbound.read_exact(4, timeout=2.0)
                    inbound.close_read()
                    try:
                        outbound.write_all(b"tail" * 64, timeout=2.0)
                    except zmux.ApplicationError:
                        pass
                    inbound.close_write(timeout=2.0)
                    outbound.close_with_error(int(zmux.ErrorCode.CANCELLED))
                    continue
                outbound.write_final(payload, timeout=2.0)
                inbound = server.accept_stream(timeout=2.0)
                self.assertEqual(len(inbound.read(timeout=2.0)), len(payload))
                inbound.write_final(b"ok", timeout=2.0)
                self.assertEqual(outbound.read(timeout=2.0), b"ok")
            for session in (client, server):
                self.assertTrue(_wait_until(lambda session=session: not session._streams))
            for session in (client, server):
                for name in Conn.__slots__:
                    value = getattr(session, name, None)
                    if isinstance(value, (dict, set, list)) or type(value).__name__ == "deque":
                        with self.subTest(name=name):
                            self.assertLessEqual(len(value), 16)
                terminal = session._terminal_state
                self.assertLessEqual(len(terminal.tombstones), 8)
                self.assertLessEqual(terminal.marker_only_retained(), 16)
                self.assertEqual(session._live_late_data_retained, 0)
            self.assertFalse(client.closed)
            self.assertFalse(server.closed)
        finally:
            _close(client, server)


class LateDataStateBoundTest(_SessionAssertions):
    """Per-stream late-data counts leave with their stream (finding 45)."""

    def test_late_data_counts_are_not_kept_per_stream_id(self):
        session, peer = _server_with_raw_client(
            tombstone_limit=8,
            used_marker_limit=16,
            inbound_ping_budget=10_000,
        )
        try:
            for index in range(120):
                stream_id = 4 + 4 * index
                peer.send_frame(_data(stream_id, b"head"))
                inbound = session.accept_stream(timeout=1.0)
                self.assertEqual(inbound.read_exact(4, timeout=1.0), b"head")
                inbound.close_read()
                self.assertIsNotNone(
                    peer.wait_for(_is_frame(zmux.FrameType.STOP_SENDING, stream_id))
                )
                peer.send_frame(_data(stream_id, b"t" * 256))
                peer.send_frame(
                    _error_frame(zmux.FrameType.RESET, stream_id, int(zmux.ErrorCode.CANCELLED))
                )
                peer.barrier()
                inbound.close()
                self.assertTrue(
                    _wait_until(lambda sid=stream_id: sid not in session._streams)
                )
            self.assert_open(session, peer)
            self.assertEqual(session.stats.diagnostics.late_data_after_close_read, 120 * 256)
            for name in Conn.__slots__:
                value = getattr(session, name, None)
                if isinstance(value, (dict, set, list)) or type(value).__name__ == "deque":
                    with self.subTest(name=name):
                        self.assertLessEqual(len(value), 16)
            self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 8 * 256)
        finally:
            _close(session)
            peer.close()


class UsedStreamMarkerTest(_SessionAssertions):
    """DESIGN D4: interleaved classes and mixed closes stay bounded (finding 43)."""

    def test_interleaved_classes_and_mixed_closes_keep_markers_bounded(self):
        session, peer = _server_with_raw_client(
            tombstone_limit=2,
            used_marker_limit=4,
            inbound_ping_budget=10_000,
        )
        try:
            for index in range(150):
                peer_id = 4 + 4 * index
                peer.send_frame(_data(peer_id, b"x", zmux.FRAME_FLAG_FIN))
                inbound = session.accept_stream(timeout=1.0)
                self.assertEqual(inbound.read(timeout=1.0), b"x")
                if index % 2:
                    inbound.close_with_error(8)
                else:
                    inbound.write_final(b"y", timeout=1.0)
                local = session.open_stream(timeout=1.0)
                local.write_final(b"z", timeout=1.0)
                local_id = local.stream_id
                self.assertIsNotNone(peer.wait_for(_is_frame(zmux.FrameType.DATA, local_id)))
                if index % 3:
                    peer.send_frame(_data(local_id, b"", zmux.FRAME_FLAG_FIN))
                else:
                    peer.send_frame(
                        _error_frame(zmux.FrameType.RESET, local_id, int(zmux.ErrorCode.CANCELLED))
                    )
                peer.barrier()
                self.assertTrue(
                    _wait_until(
                        lambda ids=(peer_id, local_id): not any(i in session._streams for i in ids)
                    )
                )
                terminal = session._terminal_state
                self.assertLessEqual(len(terminal.used_stream_ranges), 4)
            self.assert_open(session, peer)

            # Long-reaped IDs of both classes are still known as used: late
            # frames on them are ignored, never "unknown stream" errors.
            grants = len(_max_data_values(peer, 0))
            for stream_id in (4, 8, 1, 5):
                self.assertTrue(session._terminal_state.has_terminal_marker(stream_id))
                peer.send_frame(_data(stream_id, b"late"))
                peer.send_frame(
                    _error_frame(zmux.FrameType.STOP_SENDING, stream_id, int(zmux.ErrorCode.CANCELLED))
                )
                peer.send_frame(zmux.Frame(zmux.FrameType.MAX_DATA, stream_id, 0, zmux.encode_varint(1 << 20)))
            self.assert_open(session, peer)
            self.assertGreater(len(_max_data_values(peer, 0)), grants)
        finally:
            _close(session)
            peer.close()

    def test_live_stream_below_a_coarsened_floor_still_gets_its_data(self):
        session, peer = _server_with_raw_client(
            tombstone_limit=2,
            used_marker_limit=4,
            inbound_ping_budget=10_000,
        )
        try:
            peer.send_frame(_data(4, b"a"))
            survivor = session.accept_stream(timeout=1.0)
            self.assertEqual(survivor.read_exact(1, timeout=1.0), b"a")
            for index in range(1, 40):
                stream_id = 4 + 4 * index
                peer.send_frame(_data(stream_id, b"x", zmux.FRAME_FLAG_FIN))
                inbound = session.accept_stream(timeout=1.0)
                self.assertEqual(inbound.read(timeout=1.0), b"x")
                if index % 2:
                    inbound.close_with_error(8)
                else:
                    inbound.write_final(b"y", timeout=1.0)
                self.assertTrue(
                    _wait_until(lambda sid=stream_id: sid not in session._streams)
                )
            # The class floor now covers the still-open stream 4, but a live
            # stream always wins over used-ID bookkeeping.
            self.assertGreater(session._terminal_state.used_stream_floors[0] or 0, 4)
            self.assertIn(4, session._streams)
            peer.send_frame(_data(4, b"bc", zmux.FRAME_FLAG_FIN))
            self.assertEqual(survivor.read_exact(2, timeout=1.0), b"bc")
            survivor.write_final(b"done", timeout=1.0)
            self.assertIsNotNone(
                peer.wait_for(
                    lambda f: f.frame_type == zmux.FrameType.DATA
                    and f.stream_id == 4
                    and f.payload == b"done"
                )
            )
            self.assert_open(session, peer)
        finally:
            _close(session)
            peer.close()


class ChurnBudgetTest(_SessionAssertions):
    """IMPLEMENTATION 7, SPEC 13: open-then-abort churn budgets (finding 46)."""

    def _abort(self, peer, stream_id):
        peer.send_frame(_error_frame(zmux.FrameType.ABORT, stream_id, int(zmux.ErrorCode.CANCELLED)))

    def test_hidden_abort_churn_closes_session_with_protocol(self):
        session, peer = _server_with_raw_client()
        try:
            for index in range(128):
                self._abort(peer, 4 + 4 * index)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.hidden_abort_churn, 128)
            self._abort(peer, 4 + 4 * 128)
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_hidden_abort_churn_threshold_and_window_overrides(self):
        session, peer = _server_with_raw_client(
            hidden_abort_churn_threshold=4,
            hidden_abort_churn_window=0.2,
        )
        try:
            for index in range(4):
                self._abort(peer, 4 + 4 * index)
            self.assert_open(session, peer)
            time.sleep(0.3)
            for index in range(4, 8):
                self._abort(peer, 4 + 4 * index)
            self.assert_open(session, peer)
            # A repeated ABORT on a hidden tombstone is not new churn.
            self._abort(peer, 4)
            self.assert_open(session, peer)
            self._abort(peer, 4 + 4 * 8)
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_visible_open_then_abort_churn_closes_session_with_protocol(self):
        session, peer = _server_with_raw_client(visible_terminal_churn_threshold=4)
        try:
            for index in range(4):
                stream_id = 4 + 4 * index
                peer.send_frame(_data(stream_id, b"x"))
                self._abort(peer, stream_id)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.visible_terminal_churn, 4)
            peer.send_frame(_data(20, b"x"))
            self._abort(peer, 20)
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_visible_churn_counts_only_unaccepted_fully_terminal_streams(self):
        session, peer = _server_with_raw_client(visible_terminal_churn_threshold=2)
        try:
            # Accepted streams are not churn.
            for index in range(6):
                stream_id = 4 + 4 * index
                peer.send_frame(_data(stream_id, b"x"))
                session.accept_stream(timeout=1.0)
                self._abort(peer, stream_id)
            # A bidi RESET alone leaves the send half open: not terminal.
            for index in range(6, 12):
                stream_id = 4 + 4 * index
                peer.send_frame(_data(stream_id, b"x"))
                peer.send_frame(
                    _error_frame(zmux.FrameType.RESET, stream_id, int(zmux.ErrorCode.CANCELLED))
                )
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.visible_terminal_churn, 0)
            # A RESET makes an unaccepted peer uni stream fully terminal.
            for stream_id in (2, 6, 10):
                peer.send_frame(_data(stream_id, b"x"))
                peer.send_frame(
                    _error_frame(zmux.FrameType.RESET, stream_id, int(zmux.ErrorCode.CANCELLED))
                )
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_terminal_control_on_a_closed_unaccepted_stream_is_ignored_control(self):
        # The aborted stream stays live (in the accept queue) until it is
        # accepted; RESET, STOP_SENDING and ABORT on it change nothing.
        for frame_type in (
                zmux.FrameType.RESET,
                zmux.FrameType.STOP_SENDING,
                zmux.FrameType.ABORT,
        ):
            with self.subTest(frame_type=frame_type):
                session, peer = _server_with_raw_client(ignored_control_budget=3)
                try:
                    peer.send_frame(_data(4, b"x"))
                    self._abort(peer, 4)
                    for _ in range(3):
                        peer.send_frame(_error_frame(frame_type, 4, int(zmux.ErrorCode.CANCELLED)))
                    self.assert_open(session, peer)
                    self.assertIn(4, session._streams)
                    self.assertEqual(session.stats.abuse.ignored_control, 3)
                    peer.send_frame(_error_frame(frame_type, 4, int(zmux.ErrorCode.CANCELLED)))
                    self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
                finally:
                    _close(session)
                    peer.close()

    def test_effective_abort_clears_ignored_control_budget(self):
        session, peer = _server_with_raw_client(ignored_control_budget=3)
        try:
            peer.send_frame(_data(4, b"x"))
            for _ in range(4):
                peer.send_frame(
                    _error_frame(zmux.FrameType.RESET, 4, int(zmux.ErrorCode.CANCELLED))
                )
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.ignored_control, 3)
            peer.send_frame(_data(8, b"x"))
            self._abort(peer, 8)
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.ignored_control, 0)
            for _ in range(4):
                peer.send_frame(
                    _error_frame(zmux.FrameType.RESET, 4, int(zmux.ErrorCode.CANCELLED))
                )
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()


class ExtFrameCodecTest(_SessionAssertions):
    """SPEC 6.11, 7.2, 7.6 (findings 11, 12, 53)."""

    def test_ext_payload_too_short_for_ext_type_closes_with_protocol(self):
        for payload in (b"", b"\x40", b"\x40\x01"):
            with self.subTest(payload=payload):
                session, peer = _server_with_raw_client()
                try:
                    peer.send_raw(zmux.FrameType.EXT, 0, payload)
                    self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
                    self.assertNotIsInstance(session.close_error, zmux.FrameSizeError)
                finally:
                    _close(session)
                    peer.close()

    def test_duplicate_then_truncated_priority_update_closes_with_frame_size(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"x"))
            peer.send_raw(zmux.FrameType.EXT, 4, bytes((1, 1, 1, 2, 1, 1, 3, 1)))
            self.assert_closed_with(session, peer, zmux.ErrorCode.FRAME_SIZE)
            self.assertEqual(session.stats.abuse.dropped_priority_update, 0)
        finally:
            _close(session)
            peer.close()

    def test_duplicate_singleton_priority_update_is_dropped_and_counted(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"x"))
            peer.send_raw(zmux.FrameType.EXT, 4, bytes((1, 1, 1, 2, 1, 1, 3)))
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.dropped_priority_update, 1)
            stream = session.accept_stream(timeout=1.0)
            self.assertIsNone(stream.metadata.priority)
        finally:
            _close(session)
            peer.close()

    def test_effective_priority_update_clears_the_no_op_budget(self):
        session, peer = _server_with_raw_client(no_op_priority_update_budget=4)
        try:
            peer.send_frame(_data(4, b"x"))
            accepted = session.accept_stream(timeout=1.0)
            for _ in range(5):
                peer.send_frame(_priority_update(4, 9))
            self.assert_open(session, peer)
            self.assertEqual(session.stats.abuse.no_op_priority_update, 4)

            # An update that changes the priority starts the count again.
            for _ in range(5):
                peer.send_frame(_priority_update(4, 10))
            self.assert_open(session, peer)
            self.assertEqual(accepted.metadata.priority, 10)
            self.assertEqual(session.stats.abuse.no_op_priority_update, 4)
            peer.send_frame(_priority_update(4, 10))
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_unnegotiated_priority_update_is_ignored_without_parsing(self):
        session, peer = _server_with_raw_client(peer_config={"disable_capabilities": True})
        try:
            self.assertEqual(session.negotiated().capabilities, 0)
            peer.send_frame(_data(4, b"x"))
            peer.send_raw(zmux.FrameType.EXT, 4, bytes((1, 1, 1)))
            peer.send_raw(zmux.FrameType.EXT, 4, bytes((1, 1, 1, 2, 1, 1, 3, 1)))
            peer.send_raw(zmux.FrameType.EXT, 0, bytes((1, 1, 1, 2)))
            self.assert_open(session, peer)
            stream = session.accept_stream(timeout=1.0)
            self.assertEqual(stream.read_exact(1, timeout=1.0), b"x")
            self.assertEqual(session.stats.abuse.dropped_priority_update, 0)
        finally:
            _close(session)
            peer.close()

    def test_negotiated_priority_update_on_stream_zero_closes_with_protocol(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_raw(zmux.FrameType.EXT, 0, bytes((1, 1, 1, 2)))
            self.assert_closed_with(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            _close(session)
            peer.close()

    def test_negotiated_truncated_priority_update_closes_with_frame_size(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"x"))
            peer.send_raw(zmux.FrameType.EXT, 4, bytes((1, 1, 1)))
            self.assert_closed_with(session, peer, zmux.ErrorCode.FRAME_SIZE)
        finally:
            _close(session)
            peer.close()


if __name__ == "__main__":
    unittest.main()
