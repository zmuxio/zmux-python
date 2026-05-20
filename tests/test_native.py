import socket
import threading
import time
import unittest

import zmux
from zmux._runtime.keepalive import (
    build_ping_payload,
    has_ping_padding_tag,
    ping_padding_tag,
    pong_payload_for_ping,
)
from zmux._runtime.read_loop import InboundBudgetTracker
from zmux._state.tombstone import TerminalBookkeepingState
from zmux.native import Conn, _PendingPing


def session_pair():
    left, right = socket.socketpair()
    result = {}

    def run_server():
        try:
            result["server"] = zmux.server(right)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    client = zmux.client(left)
    thread.join(2.0)
    if "error" in result:
        client.close()
        raise result["error"]
    if "server" not in result:
        client.close()
        raise AssertionError("server session establishment timed out")
    return client, result["server"]


def close_pair(client, server):
    errors = []
    for session in (client, server):
        try:
            session.close()
        except BaseException as exc:
            errors.append(exc)
    if errors and all(session.closed for session in (client, server)):
        return
    if errors:
        raise errors[0]


class RecordingNativeSession(object):
    def __init__(self):
        self.config = zmux.Config()
        self.peer_limits = zmux.Limits(
            max_frame_payload=3,
            max_control_payload_bytes=4096,
            max_extension_payload_bytes=4096,
        )
        self.closed = False
        self.frames = []
        self.opened = []
        self._negotiated = zmux.Negotiated(
            proto=zmux.PROTO_VERSION,
            capabilities=zmux.DEFAULT_CAPABILITIES,
            local_role=zmux.Role.INITIATOR,
            peer_role=zmux.Role.RESPONDER,
            peer_settings=zmux.default_settings(),
        )

    def negotiated(self):
        return self._negotiated

    def send_frame(self, frame):
        self.frames.append(frame)

    def emit_stream_opened(self, stream):
        self.opened.append(stream)


class NativeSessionTest(unittest.TestCase):
    def test_native_session_is_primary_sync_session(self):
        client, server = session_pair()
        try:
            self.assertIsInstance(client, zmux.Conn)
            self.assertIsInstance(client, zmux.Session)
            self.assertIsInstance(client.stats, zmux.SessionStats)
            self.assertEqual(client.state, zmux.SessionState.READY)
            self.assertEqual(server.state, zmux.SessionState.READY)
            self.assertEqual(client.local_preface().role, zmux.Role.INITIATOR)
            self.assertEqual(server.local_preface().role, zmux.Role.RESPONDER)
            self.assertEqual(client.negotiated().local_role, zmux.Role.INITIATOR)
            self.assertEqual(server.negotiated().local_role, zmux.Role.RESPONDER)
        finally:
            close_pair(client, server)

    def test_wait_timeout_and_wait_surface_failed_close_error(self):
        client, server = session_pair()
        try:
            self.assertFalse(client.wait_timeout(0.001))
            client.close_with_error(7, "boom")
            with self.assertRaises(zmux.ApplicationError) as caught:
                client.wait()
            self.assertEqual(caught.exception.code, 7)
            with self.assertRaises(zmux.ApplicationError):
                client.wait_timeout(0)
            self.assertTrue(zmux.closed_session().wait_timeout(0))
        finally:
            server.close()

    def test_bidirectional_stream_roundtrip_with_metadata(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream(zmux.OpenOptions(open_info=b"rpc"))
            outbound.write_final(b"hello")

            inbound = server.accept_stream(timeout=1.0)
            self.assertIsInstance(inbound, zmux.NativeStream)
            self.assertIsInstance(inbound, zmux.Stream)
            self.assertIsInstance(inbound.metadata, zmux.StreamMetadata)
            self.assertEqual(inbound.stream_id, 4)
            self.assertFalse(inbound.opened_locally)
            self.assertTrue(inbound.bidirectional)
            self.assertEqual(inbound.open_info, b"rpc")
            self.assertEqual(inbound.open_info_len, 3)
            self.assertTrue(inbound.has_open_info)
            first = bytearray(2)
            second = bytearray(3)
            self.assertEqual(inbound.read_vectored((first, second)), 5)
            self.assertEqual(first, bytearray(b"he"))
            self.assertEqual(second, bytearray(b"llo"))
            self.assertEqual(inbound.read(), b"")

            inbound.write_final(b"world")
            self.assertEqual(outbound.read_exact(5), b"world")
            self.assertEqual(outbound.read(), b"")
        finally:
            close_pair(client, server)

    def test_unidirectional_stream_roundtrip(self):
        client, server = session_pair()
        try:
            send = client.open_uni_and_send(b"event", zmux.OpenOptions(open_info=b"uni"))
            recv = server.accept_uni_stream(timeout=1.0)
            self.assertIsInstance(send, zmux.SendStream)
            self.assertIsInstance(recv, zmux.RecvStream)
            self.assertTrue(send.write_closed)
            self.assertFalse(recv.bidirectional)
            self.assertEqual(recv.open_info, b"uni")
            self.assertEqual(recv.open_info_len, 3)
            self.assertTrue(recv.has_open_info)
            self.assertEqual(recv.read(), b"event")
            with self.assertRaises(zmux.StreamNotWritable):
                recv.write(b"nope")
        finally:
            close_pair(client, server)

    def test_peer_opened_bidirectional_stream_can_send_metadata_update(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream()
            outbound.write(b"start")
            inbound = server.accept_stream(timeout=1.0)

            inbound.update_metadata(zmux.MetadataUpdate(priority=12))

            deadline = time.monotonic() + 1.0
            while outbound.metadata.priority != 12:
                if time.monotonic() >= deadline:
                    raise AssertionError("metadata update was not received")
                time.sleep(0.01)
        finally:
            close_pair(client, server)

    def test_native_unopened_metadata_update_requires_open_capability(self):
        config = zmux.Config(disable_capabilities=True)
        client, server = session_pair_with_config(config)
        try:
            outbound = client.open_stream(timeout=1.0)
            with self.assertRaises(zmux.PriorityUpdateUnavailable):
                outbound.update_metadata(zmux.MetadataUpdate(priority=3))
        finally:
            close_pair(client, server)

    def test_write_vectored_final_marks_last_payload_frame_final(self):
        session = RecordingNativeSession()
        stream = zmux.NativeStream(
            session,
            4,
            opened_locally=True,
            bidirectional=True,
            local_send=True,
            local_receive=True,
            metadata=zmux.StreamMetadata(),
            opened_sent=True,
        )

        written = stream.write_vectored_final((b"ab", b"cd"))

        self.assertEqual(written, 4)
        self.assertTrue(stream.write_closed)
        self.assertEqual([frame.payload for frame in session.frames], [b"ab", b"cd"])
        self.assertEqual(session.frames[0].flags & zmux.FRAME_FLAG_FIN, 0)
        self.assertNotEqual(session.frames[1].flags & zmux.FRAME_FLAG_FIN, 0)
        with self.assertRaises(zmux.WriteClosed):
            stream.write(b"late")
        self.assertEqual(stream.write(b""), 0)
        self.assertEqual(stream.write_vectored(()), 0)

        session = RecordingNativeSession()
        stream = zmux.NativeStream(
            session,
            8,
            opened_locally=True,
            bidirectional=True,
            local_send=True,
            local_receive=True,
            metadata=zmux.StreamMetadata(),
            opened_sent=True,
        )

        stream.write_vectored_final((b"", b"xy"))

        self.assertEqual([frame.payload for frame in session.frames], [b"xy"])
        self.assertNotEqual(session.frames[0].flags & zmux.FRAME_FLAG_FIN, 0)

    def test_native_write_uses_priority_fragment_policy(self):
        session = RecordingNativeSession()
        session.peer_limits = zmux.Limits(
            max_frame_payload=16,
            max_control_payload_bytes=4096,
            max_extension_payload_bytes=4096,
        )
        stream = zmux.NativeStream(
            session,
            4,
            opened_locally=True,
            bidirectional=True,
            local_send=True,
            local_receive=True,
            metadata=zmux.StreamMetadata(priority=20),
            opened_sent=True,
        )

        self.assertEqual(stream.write(b"abcdefghijklmnop"), 16)

        self.assertEqual([len(frame.payload) for frame in session.frames], [4, 4, 4, 4])
        self.assertEqual(b"".join(frame.payload for frame in session.frames), b"abcdefghijklmnop")

    def test_native_stream_receive_buffer_tightens_large_tail(self):
        session = RecordingNativeSession()
        session.config = zmux.Config(per_stream_queued_data_hwm=1 << 20)
        stream = zmux.NativeStream(
            session,
            4,
            opened_locally=False,
            bidirectional=True,
            local_send=False,
            local_receive=True,
            metadata=zmux.StreamMetadata(),
            opened_sent=True,
        )
        source = b"x" * (512 << 10)

        stream.receive_data(memoryview(source))
        out = bytearray(len(source) - 1)
        self.assertEqual(stream.readinto(out), len(out))

        self.assertEqual(stream._read_buffered, 1)
        self.assertLessEqual(stream._read_buf.retained_bytes, 1)
        rest = bytearray(1)
        self.assertEqual(stream.readinto(rest), 1)
        self.assertEqual(rest, bytearray(b"x"))
        self.assertEqual(stream._read_buffered, 0)

    def test_native_cancel_read_reports_terminal_read_side(self):
        session = RecordingNativeSession()
        stream = zmux.NativeStream(
            session,
            4,
            opened_locally=False,
            bidirectional=True,
            local_send=True,
            local_receive=True,
            metadata=zmux.StreamMetadata(),
            opened_sent=True,
        )

        stream.cancel_read(int(zmux.ErrorCode.CANCELLED))
        self.assertEqual(len(session.frames), 1)
        with self.assertRaises(zmux.ReadClosed) as local_closed:
            stream.cancel_read(int(zmux.ErrorCode.CANCELLED))
        self.assertEqual(local_closed.exception.source, zmux.ErrorSource.LOCAL)
        self.assertEqual(
            local_closed.exception.termination_kind,
            zmux.TerminationKind.STOPPED,
        )
        self.assertEqual(len(session.frames), 1)

        finished = zmux.NativeStream(
            session,
            8,
            opened_locally=False,
            bidirectional=True,
            local_send=True,
            local_receive=True,
            metadata=zmux.StreamMetadata(),
            opened_sent=True,
        )
        finished.receive_fin()
        with self.assertRaises(zmux.ReadClosed) as remote_closed:
            finished.cancel_read(int(zmux.ErrorCode.CANCELLED))
        self.assertEqual(remote_closed.exception.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(
            remote_closed.exception.termination_kind,
            zmux.TerminationKind.GRACEFUL,
        )
        self.assertEqual(len(session.frames), 1)

    def test_native_cancel_write_preserves_reset_error(self):
        session = RecordingNativeSession()
        stream = zmux.NativeStream(
            session,
            4,
            opened_locally=True,
            bidirectional=True,
            local_send=True,
            local_receive=True,
            metadata=zmux.StreamMetadata(),
            opened_sent=True,
        )

        stream.cancel_write(41)
        self.assertEqual(len(session.frames), 1)
        self.assertEqual(session.frames[0].frame_type, zmux.FrameType.RESET)
        with self.assertRaises(zmux.ApplicationError) as write_error:
            stream.write(b"late")
        self.assertEqual(write_error.exception.code, 41)
        self.assertEqual(write_error.exception.source, zmux.ErrorSource.LOCAL)
        self.assertEqual(write_error.exception.direction, zmux.ErrorDirection.WRITE)
        self.assertEqual(
            write_error.exception.termination_kind,
            zmux.TerminationKind.RESET,
        )
        with self.assertRaises(zmux.ApplicationError):
            stream.update_metadata(zmux.MetadataUpdate(priority=2))

    def test_native_write_waits_for_peer_max_data_credit(self):
        settings = zmux.Settings(
            initial_max_stream_data_bidi_locally_opened=0,
            initial_max_stream_data_bidi_peer_opened=0,
            initial_max_stream_data_uni=0,
            initial_max_data=0,
            max_frame_payload=16384,
            max_control_payload_bytes=4096,
            max_extension_payload_bytes=4096,
        )
        client, server = session_pair_with_config(zmux.Config(settings=settings))
        try:
            outbound = client.open_stream(zmux.OpenOptions(open_info=b"flow"))
            result = {}

            def write_data():
                try:
                    result["written"] = outbound.write(b"abc", timeout=1.0)
                except BaseException as exc:
                    result["error"] = exc

            thread = threading.Thread(target=write_data, daemon=True)
            thread.start()
            inbound = server.accept_stream(timeout=1.0)
            time.sleep(0.05)
            self.assertNotIn("written", result)
            self.assertNotIn("error", result)

            server._send_frame(zmux.Frame(zmux.FrameType.MAX_DATA, 0, 0, zmux.encode_varint(3)))
            server._send_frame(
                zmux.Frame(zmux.FrameType.MAX_DATA, inbound.stream_id, 0, zmux.encode_varint(3))
            )
            thread.join(1.0)
            if "error" in result:
                raise result["error"]
            self.assertEqual(result.get("written"), 3)
            self.assertEqual(inbound.read_exact(3, timeout=1.0), b"abc")
        finally:
            close_pair(client, server)

    def test_native_stop_sending_closes_writer(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream()
            outbound.write_all(b"open", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(4, timeout=1.0), b"open")
            payload = zmux.build_error_payload(
                int(zmux.ErrorCode.CANCELLED),
                "",
                server.peer_limits.max_control_payload_bytes,
            )
            server._send_frame(
                zmux.Frame(zmux.FrameType.STOP_SENDING, outbound.stream_id, 0, payload)
            )
            deadline = time.monotonic() + 1.0
            while not outbound.write_closed and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(outbound.write_closed)
            with self.assertRaises(zmux.ApplicationError) as closed:
                outbound.write(b"again", timeout=1.0)
            self.assertEqual(closed.exception.source, zmux.ErrorSource.REMOTE)
            self.assertEqual(
                closed.exception.termination_kind,
                zmux.TerminationKind.STOPPED,
            )
            self.assertEqual(closed.exception.code, int(zmux.ErrorCode.CANCELLED))
        finally:
            close_pair(client, server)

    def test_native_local_open_commits_stream_ids_fifo(self):
        client, server = session_pair()
        try:
            first = client.open_stream(timeout=1.0)
            second = client.open_stream(timeout=1.0)
            self.assertEqual(first.stream_id, 0)
            self.assertEqual(second.stream_id, 0)
            result = {}

            def write_second():
                try:
                    second.write_all(b"second", timeout=1.0)
                    result["done"] = True
                except BaseException as exc:
                    result["error"] = exc

            thread = threading.Thread(target=write_second, daemon=True)
            thread.start()
            time.sleep(0.05)
            self.assertNotIn("done", result)
            self.assertEqual(second.stream_id, 0)

            first.write_all(b"first", timeout=1.0)
            thread.join(1.0)
            if "error" in result:
                raise result["error"]
            self.assertTrue(result.get("done"))
            self.assertEqual(first.stream_id, 4)
            self.assertEqual(second.stream_id, 8)

            accepted_first = server.accept_stream(timeout=1.0)
            accepted_second = server.accept_stream(timeout=1.0)
            self.assertEqual(accepted_first.stream_id, 4)
            self.assertEqual(accepted_second.stream_id, 8)
            self.assertEqual(accepted_first.read_exact(5, timeout=1.0), b"first")
            self.assertEqual(accepted_second.read_exact(6, timeout=1.0), b"second")
        finally:
            close_pair(client, server)

    def test_native_cancel_uncommitted_local_open_stays_hidden(self):
        client, server = session_pair()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.cancel_write(int(zmux.ErrorCode.CANCELLED))
            self.assertEqual(stream.stream_id, 0)
            self.assertTrue(stream.closed)
            self.assertEqual(client.stats.provisionals.bidi, 0)
            with self.assertRaises(zmux.AcceptTimeout):
                server.accept_stream(timeout=0.05)
        finally:
            close_pair(client, server)

    def test_native_abort_uncommitted_local_open_stays_hidden(self):
        client, server = session_pair()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.close_with_error(int(zmux.ErrorCode.CANCELLED), "unused")
            self.assertEqual(stream.stream_id, 0)
            self.assertTrue(stream.closed)
            self.assertEqual(client.stats.provisionals.bidi, 0)
            with self.assertRaises(zmux.AcceptTimeout):
                server.accept_stream(timeout=0.05)
        finally:
            close_pair(client, server)

    def test_native_set_read_deadline_wakes_blocked_read(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"x", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"x")
            result = {}

            def read_more():
                try:
                    inbound.read(1)
                    result["done"] = True
                except BaseException as exc:
                    result["error"] = exc

            thread = threading.Thread(target=read_more, daemon=True)
            thread.start()
            time.sleep(0.05)
            inbound.set_read_timeout(0.01)
            thread.join(1.0)
            self.assertIsInstance(result.get("error"), zmux.ReadTimeout)
            self.assertNotIn("done", result)
        finally:
            close_pair(client, server)

    def test_native_set_write_deadline_wakes_blocked_write(self):
        settings = zmux.Settings(
            initial_max_stream_data_bidi_locally_opened=0,
            initial_max_stream_data_bidi_peer_opened=0,
            initial_max_stream_data_uni=0,
            initial_max_data=0,
        )
        client, server = session_pair_with_config(zmux.Config(settings=settings))
        try:
            outbound = client.open_stream(timeout=1.0)
            result = {}

            def write_data():
                try:
                    outbound.write_all(b"x")
                    result["done"] = True
                except BaseException as exc:
                    result["error"] = exc

            thread = threading.Thread(target=write_data, daemon=True)
            thread.start()
            time.sleep(0.05)
            outbound.set_write_timeout(0.01)
            thread.join(1.0)
            self.assertIsInstance(result.get("error"), zmux.WriteTimeout)
            self.assertNotIn("done", result)
        finally:
            close_pair(client, server)

    def test_ping_uses_native_session_not_adapter(self):
        client, server = session_pair()
        try:
            rtt = client.ping(b"echo", timeout=1.0)
            self.assertGreaterEqual(rtt, 0.0)
            self.assertGreaterEqual(client.stats.sent_frames, 1)
            self.assertGreaterEqual(server.stats.received_frames, 1)
        finally:
            close_pair(client, server)

    def test_native_ping_uses_negotiated_padding(self):
        config = zmux.Config(
            ping_padding=True,
            ping_padding_min_bytes=8,
            ping_padding_max_bytes=8,
        )
        client, server = session_pair_with_config(config)
        try:
            self.assertNotEqual(client.local_preface().settings.ping_padding_key, 0)
            self.assertNotEqual(server.local_preface().settings.ping_padding_key, 0)
            self.assertGreaterEqual(client.ping(b"echo", timeout=1.0), 0.0)
        finally:
            close_pair(client, server)

    def test_native_pong_for_padded_ping_may_add_padding(self):
        conn = _DispatchConn()
        key = 0xABC
        local = zmux.Settings(max_control_payload_bytes=64, ping_padding_key=key)
        peer = zmux.Settings(max_control_payload_bytes=64, ping_padding_key=key)
        conn._local_preface = _preface(zmux.Role.INITIATOR, local)
        conn._peer_preface = _preface(zmux.Role.RESPONDER, peer)
        conn._ping_state = _Holder()

        tag = ping_padding_tag(key, 7)
        ping = build_ping_payload(tag.to_bytes(8, "big") + b"hi", 7)
        self.assertTrue(has_ping_padding_tag(ping, key))

        conn._dispatch_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, ping))

        self.assertEqual(len(conn.sent), 1)
        pong = conn.sent[0].payload
        self.assertEqual(pong[: len(ping)], ping)
        self.assertGreaterEqual(len(pong), len(ping))

    def test_native_dispatch_uses_read_loop_validation(self):
        conn = _DispatchConn()
        with self.assertRaises(zmux.FrameSizeError):
            conn._dispatch_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"short"))

        metadata = zmux.build_open_metadata_prefix(
            zmux.DEFAULT_CAPABILITIES,
            open_info=b"x",
        )
        conn._negotiated = zmux.Negotiated(
            proto=zmux.PROTO_VERSION,
            capabilities=0,
            local_role=zmux.Role.INITIATOR,
            peer_role=zmux.Role.RESPONDER,
            peer_settings=zmux.default_settings(),
        )
        with self.assertRaises(zmux.ProtocolError):
            conn._dispatch_frame(
                zmux.Frame(
                    zmux.FrameType.DATA,
                    4,
                    zmux.FRAME_FLAG_OPEN_METADATA,
                    metadata,
                )
            )

    def test_native_dispatch_applies_inbound_flood_budgets(self):
        conn = _DispatchConn()
        conn._config = zmux.Config(inbound_ping_budget=1)
        conn._inbound_budget = InboundBudgetTracker.from_config(conn._config)
        conn._dispatch_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"12345678"))

        with self.assertRaises(zmux.ProtocolError):
            conn._dispatch_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"abcdefgh"))

    def test_native_dispatch_tracks_no_op_control_and_zero_data(self):
        conn = _DispatchConn()
        conn._config = zmux.Config(
            ignored_control_budget=1,
            no_op_zero_data_budget=1,
        )
        conn._inbound_budget = InboundBudgetTracker.from_config(conn._config)

        conn._handle_pong(b"12345678")
        with self.assertRaises(zmux.ProtocolError):
            conn._handle_blocked()

        client, server = session_pair_with_config(zmux.Config(no_op_zero_data_budget=1))
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"x", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"x")

            frame = zmux.Frame(zmux.FrameType.DATA, inbound.stream_id, 0, b"")
            server._dispatch_frame(frame)
            self.assertEqual(server.stats.abuse.no_op_zero_data, 1)
            self.assertEqual(server.stats.abuse.no_op_zero_data_budget, 1)
            with self.assertRaises(zmux.ProtocolError):
                server._dispatch_frame(frame)
        finally:
            close_pair(client, server)

    def test_native_pong_matching_accepts_peer_padding_when_negotiated(self):
        conn = _DispatchConn()
        done = threading.Event()
        holder = [0.0]
        ping = build_ping_payload(b"payload", 9)
        conn._pings = {
            ping: _PendingPing(done, 1.0, holder, True),
        }
        conn._handle_pong(pong_payload_for_ping(_Holder(), zmux.Settings(), zmux.Settings(), ping))

        self.assertTrue(done.is_set())
        self.assertNotIn(ping, conn._pings)

    def test_native_peer_errors_are_returned_as_snapshots(self):
        conn = _DispatchConn()
        close_error = zmux.ApplicationError(7, "close")
        goaway_error = zmux.ApplicationError(8, "goaway")
        conn._peer_close_error = close_error
        conn._peer_go_away_error = goaway_error

        self.assertIsNot(conn.peer_close_error, close_error)
        self.assertEqual(conn.peer_close_error.reason, "close")
        self.assertIsNot(conn.peer_go_away_error, goaway_error)
        self.assertEqual(conn.peer_go_away_error.reason, "goaway")

    def test_native_keepalive_sends_idle_ping(self):
        config = zmux.Config(
            keepalive_interval=0.02,
            keepalive_max_ping_interval=0.02,
            keepalive_timeout=0.5,
        )
        client, server = session_pair_with_config(config)
        try:
            deadline = time.monotonic() + 1.0
            while (
                client.stats.last_pong_at is None
                and server.stats.last_pong_at is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertTrue(
                client.stats.last_pong_at is not None
                or server.stats.last_pong_at is not None
            )
            self.assertFalse(client.stats.ping_outstanding)
            self.assertFalse(server.stats.ping_outstanding)
        finally:
            close_pair(client, server)

    def test_native_goaway_refuses_later_local_opens(self):
        client, server = session_pair()
        try:
            server.go_away(0, 0)
            deadline = time.monotonic() + 1.0
            while client.state is not zmux.SessionState.DRAINING and time.monotonic() < deadline:
                time.sleep(0.01)
            with self.assertRaises(zmux.ApplicationError) as raised:
                client.open_stream(timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.REFUSED_STREAM))
        finally:
            close_pair(client, server)

    def test_native_goaway_reclaims_unopened_local_stream(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            server.go_away(0, 0)
            deadline = time.monotonic() + 1.0
            while not outbound.closed and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(outbound.closed)
            self.assertNotIn(outbound.stream_id, client._streams)
            with self.assertRaises(zmux.ApplicationError) as raised:
                outbound.write_all(b"late", timeout=0.05)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.REFUSED_STREAM))
        finally:
            close_pair(client, server)

    def test_native_open_stream_obeys_provisional_limit(self):
        config = zmux.Config(max_provisional_streams_bidi=1)
        client, server = session_pair_with_config(config)
        try:
            first = client.open_stream(timeout=1.0)
            with self.assertRaises(zmux.OpenLimited):
                client.open_stream(timeout=1.0)
            first.write_all(b"opened", timeout=1.0)
            second = client.open_stream(timeout=1.0)
            second.write_final(b"ok", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(6, timeout=1.0), b"opened")
        finally:
            close_pair(client, server)

    def test_native_receiver_replenishes_flow_control_credit(self):
        config = zmux.Config(
            settings=zmux.Settings(
                initial_max_stream_data_bidi_peer_opened=32,
                initial_max_data=64,
            )
        )
        client, server = session_pair_with_config(config)
        try:
            payload = b"x" * 40
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(payload, timeout=1.0)

            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(len(payload), timeout=1.0), payload)

            deadline = time.monotonic() + 1.0
            while server.stats.sent_frames < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertGreaterEqual(server.stats.sent_frames, 2)
        finally:
            close_pair(client, server)

    def test_native_receiver_rejects_data_beyond_advertised_credit(self):
        config = zmux.Config(
            settings=zmux.Settings(
                initial_max_stream_data_bidi_peer_opened=4,
                initial_max_data=4,
            )
        )
        client, server = session_pair_with_config(config)
        try:
            with self.assertRaisesRegex(zmux.ProtocolError, "max_data exceeded"):
                server._dispatch_frame(zmux.Frame(zmux.FrameType.DATA, 4, 0, b"12345"))
        finally:
            close_pair(client, server)

    def test_native_accept_backlog_refuses_newest_stream_over_limit(self):
        config = zmux.Config(accept_backlog_limit=1)
        client, server = session_pair_with_config(config)
        try:
            first = client.open_stream(timeout=1.0)
            first.write_all(b"first", timeout=1.0)
            deadline = time.monotonic() + 1.0
            while server.stats.accept_backlog.count < 1 and time.monotonic() < deadline:
                time.sleep(0.01)

            second = client.open_stream(timeout=1.0)
            second.write_all(b"second", timeout=1.0)
            deadline = time.monotonic() + 1.0
            while server.stats.accept_backlog.refused < 1 and time.monotonic() < deadline:
                time.sleep(0.01)

            self.assertEqual(server.stats.accept_backlog.refused, 1)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(5, timeout=1.0), b"first")
            with self.assertRaises(zmux.AcceptTimeout):
                server.accept_stream(timeout=0.05)
        finally:
            close_pair(client, server)

    def test_native_stream_is_released_after_both_halves_finish(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"hello", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(5, timeout=1.0), b"hello")
            self.assertEqual(inbound.read(timeout=1.0), b"")
            inbound.write_final(b"world", timeout=1.0)
            self.assertEqual(outbound.read_exact(5, timeout=1.0), b"world")
            self.assertEqual(outbound.read(timeout=1.0), b"")

            deadline = time.monotonic() + 1.0
            while (
                (outbound.stream_id in client._streams or inbound.stream_id in server._streams)
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertNotIn(outbound.stream_id, client._streams)
            self.assertNotIn(inbound.stream_id, server._streams)

            server._dispatch_frame(zmux.Frame(zmux.FrameType.DATA, inbound.stream_id, 0, b"late"))
            self.assertNotIn(inbound.stream_id, server._streams)
            with self.assertRaises(zmux.AcceptTimeout):
                server.accept_stream(timeout=0.01)
        finally:
            close_pair(client, server)

    def test_native_late_data_on_terminal_stream_is_capped(self):
        config = zmux.Config(aggregate_late_data_cap=3)
        client, server = session_pair_with_config(config)
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"hello", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(5, timeout=1.0), b"hello")
            self.assertEqual(inbound.read(timeout=1.0), b"")
            inbound.write_final(b"world", timeout=1.0)
            self.assertEqual(outbound.read_exact(5, timeout=1.0), b"world")
            self.assertEqual(outbound.read(timeout=1.0), b"")

            deadline = time.monotonic() + 1.0
            while inbound.stream_id in server._streams and time.monotonic() < deadline:
                time.sleep(0.01)

            with self.assertRaises(zmux.ProtocolError):
                server._dispatch_frame(
                    zmux.Frame(zmux.FrameType.DATA, inbound.stream_id, 0, b"late")
                )
            self.assertEqual(server.stats.pressure.aggregate_late_data_bytes, 4)
        finally:
            close_pair(client, server)

    def test_native_rejects_open_metadata_after_opening_data(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"hello", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            prefix = zmux.build_open_metadata_prefix(
                server.negotiated().capabilities,
                open_info=b"late",
            )
            with self.assertRaises(zmux.ProtocolError):
                server._dispatch_frame(
                    zmux.Frame(
                        zmux.FrameType.DATA,
                        inbound.stream_id,
                        zmux.FRAME_FLAG_OPEN_METADATA,
                        prefix,
                    )
                )
        finally:
            close_pair(client, server)

    def test_native_rejects_peer_stream_id_gap(self):
        client, server = session_pair()
        try:
            with self.assertRaises(zmux.ProtocolError):
                server._dispatch_frame(zmux.Frame(zmux.FrameType.DATA, 8, 0, b"gap"))
        finally:
            close_pair(client, server)

    def test_native_refuses_peer_open_over_stream_limit(self):
        config = zmux.Config(
            settings=zmux.Settings(max_incoming_streams_bidi=1)
        )
        client, server = session_pair_with_config(config)
        try:
            first = client.open_stream(timeout=1.0)
            first.write_all(b"first", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(5, timeout=1.0), b"first")

            server._dispatch_frame(zmux.Frame(zmux.FrameType.DATA, 8, 0, b"second"))
            self.assertFalse(server._accept_bidi)
            self.assertTrue(server._terminal_state.has_terminal_marker(8))
            self.assertIn(8, server._terminal_streams)
        finally:
            close_pair(client, server)

    def test_native_local_open_obeys_peer_zero_stream_limit(self):
        config = zmux.Config(
            settings=zmux.Settings(max_incoming_streams_bidi=0)
        )
        client, server = session_pair_with_config(config)
        try:
            with self.assertRaises(zmux.ApplicationError) as raised:
                client.open_stream(timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.REFUSED_STREAM))
        finally:
            close_pair(client, server)

    def test_native_peer_open_obeys_zero_stream_limit(self):
        config = zmux.Config(
            settings=zmux.Settings(max_incoming_streams_bidi=0)
        )
        client, server = session_pair_with_config(config)
        try:
            server._dispatch_frame(zmux.Frame(zmux.FrameType.DATA, 4, 0, b"blocked"))
            self.assertFalse(server._accept_bidi)
            self.assertTrue(server._terminal_state.has_terminal_marker(4))
            self.assertIn(4, server._terminal_streams)
        finally:
            close_pair(client, server)

    def test_open_and_send_aborts_stream_after_write_failure(self):
        client, server = session_pair()
        original_write = zmux.NativeStream.write_all
        original_close = zmux.NativeStream.close_with_error
        seen = []
        closed = []

        def fail_write(stream, data, *, timeout=None):
            seen.append(stream)
            raise zmux.WriteTimeout()

        def fake_close(stream, code, reason=""):
            closed.append((stream, code, reason))
            with stream._cond:
                stream._read_finished = True
                stream._read_closed = True
                stream._write_closed = True
                stream._closed = True
                stream._cond.notify_all()
            stream._session.forget_stream(stream)

        zmux.NativeStream.write_all = fail_write
        zmux.NativeStream.close_with_error = fake_close
        try:
            with self.assertRaises(zmux.WriteTimeout):
                client.open_and_send(b"payload", timeout=1.0)
            self.assertEqual(len(seen), 1)
            self.assertEqual(len(closed), 1)
            self.assertEqual(closed[0][1], int(zmux.ErrorCode.CANCELLED))
            self.assertEqual(closed[0][2], "open_and_send failed")
            self.assertTrue(seen[0].closed)
            self.assertNotIn(seen[0].stream_id, client._streams)
        finally:
            zmux.NativeStream.write_all = original_write
            zmux.NativeStream.close_with_error = original_close
            close_pair(client, server)

    def test_open_uni_and_send_aborts_stream_after_write_failure(self):
        client, server = session_pair()
        original_write = zmux.NativeStream.write_final
        original_close = zmux.NativeStream.close_with_error
        seen = []
        closed = []

        def fail_write(stream, data, *, timeout=None):
            seen.append(stream)
            raise zmux.WriteTimeout()

        def fake_close(stream, code, reason=""):
            closed.append((stream, code, reason))
            with stream._cond:
                stream._read_finished = True
                stream._read_closed = True
                stream._write_closed = True
                stream._closed = True
                stream._cond.notify_all()
            stream._session.forget_stream(stream)

        zmux.NativeStream.write_final = fail_write
        zmux.NativeStream.close_with_error = fake_close
        try:
            with self.assertRaises(zmux.WriteTimeout):
                client.open_uni_and_send(b"payload", timeout=1.0)
            self.assertEqual(len(seen), 1)
            self.assertEqual(len(closed), 1)
            self.assertEqual(closed[0][1], int(zmux.ErrorCode.CANCELLED))
            self.assertEqual(closed[0][2], "open_uni_and_send failed")
            self.assertTrue(seen[0].closed)
            self.assertNotIn(seen[0].stream_id, client._streams)
        finally:
            zmux.NativeStream.write_final = original_write
            zmux.NativeStream.close_with_error = original_close
            close_pair(client, server)


def session_pair_with_config(config):
    left, right = socket.socketpair()
    result = {}

    def run_server():
        try:
            result["server"] = zmux.server(right, config)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    client = zmux.client(left, config)
    thread.join(2.0)
    if "error" in result:
        client.close()
        raise result["error"]
    if "server" not in result:
        client.close()
        raise AssertionError("server session establishment timed out")
    return client, result["server"]


class _Holder(object):
    ping_padding = True
    ping_padding_min = 8
    ping_padding_max = 8
    last_ping_padding_len = 0
    ping_nonce_state = 1
    keepalive_jitter_state = 1


def _preface(role, settings):
    return zmux.Preface(
        preface_version=zmux.PREFACE_VERSION,
        role=role,
        tie_breaker_nonce=1,
        min_proto=zmux.PROTO_VERSION,
        max_proto=zmux.PROTO_VERSION,
        capabilities=zmux.DEFAULT_CAPABILITIES,
        settings=settings,
    )


class _DispatchConn(Conn):
    def __init__(self):
        self.sent = []
        self._config = zmux.Config(keepalive_interval=None)
        self._inbound_budget = InboundBudgetTracker.from_config(self._config)
        self._terminal_state = TerminalBookkeepingState()
        self._lock = threading.Condition(threading.RLock())
        self._pings = {}
        self._local_preface = _preface(zmux.Role.INITIATOR, zmux.Settings())
        self._peer_preface = _preface(zmux.Role.RESPONDER, zmux.Settings())
        self._negotiated = zmux.Negotiated(
            proto=zmux.PROTO_VERSION,
            capabilities=zmux.DEFAULT_CAPABILITIES,
            local_role=zmux.Role.INITIATOR,
            peer_role=zmux.Role.RESPONDER,
            peer_settings=zmux.default_settings(),
        )
        self._local_role = zmux.Role.INITIATOR
        self._peer_go_away_bidi = None
        self._peer_go_away_uni = None
        self._ping_state = _Holder()
        self._last_ping_rtt = 0.0
        self._last_pong_at = None
        self._read_idle_ping_due_at = None
        self._write_idle_ping_due_at = None
        self._max_ping_due_at = None

    def _send_frame(self, frame):
        self.sent.append(frame)


if __name__ == "__main__":
    unittest.main()
