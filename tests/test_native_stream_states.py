"""Stream half-state regressions for the native session.

The native session used to accept stream-scoped frames for the wrong side of
a unidirectional stream, ignore DATA after the peer's FIN on live streams,
let a late RESET or STOP_SENDING overwrite a half that had already finished,
re-send ABORT for an aborted stream, keep handing out buffered bytes (and a
generic local "read closed" error) after RESET, ABORT or session close, turn
a benign session close into EOF on unfinished streams, raise from close()
after a normal request/response exchange, leave a timed-out close half-open,
report success from close_write() on a finished or failed half, could put
DATA on the wire after the stream's own RESET or ABORT, and applied
PRIORITY_UPDATE to terminal streams.  These tests drive real sessions over
``socket.socketpair``, using a raw zmux peer where exact frames matter.
"""

import socket
import threading
import time
import unittest
from unittest import mock

import zmux
from zmux._state.tombstone import LateDataAction, LateDataCause
from zmux.native import Conn, NativeStream


class RawPeer(object):
    """Hand-driven zmux endpoint that records every frame it receives."""

    def __init__(self, sock):
        self.socket = sock
        self.frames = []
        self._cond = threading.Condition()
        self._pings = 0

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
    peer.start_collecting()
    return session, peer


def _client_with_raw_server(settings=None):
    left, right = socket.socketpair()
    peer = RawPeer(right)
    peer.send_preface(zmux.Role.RESPONDER, settings)
    session = zmux.client(left, zmux.Config(keepalive_interval=None))
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


def _wait_until(predicate, timeout=2.0):
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


def _varint_frame(frame_type, stream_id, value):
    return zmux.Frame(frame_type, stream_id, 0, zmux.encode_varint(value))


def _priority_update(stream_id, priority):
    payload = zmux.build_priority_update_payload(
        zmux.DEFAULT_CAPABILITIES,
        zmux.MetadataUpdate(priority=priority),
    )
    return zmux.Frame(zmux.FrameType.EXT, stream_id, 0, payload)


def _error_code(frame):
    code, _ = zmux.parse_error_payload(frame.payload)
    return code


def _is_abort(stream_id, code=None):
    return lambda frame: (
        frame.frame_type == zmux.FrameType.ABORT
        and frame.stream_id == stream_id
        and (code is None or _error_code(frame) == int(code))
    )


def _frames_of(peer, frame_type, stream_id):
    return [
        frame
        for frame in peer.snapshot()
        if frame.frame_type == frame_type and frame.stream_id == stream_id
    ]


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


class PeerStreamControlValidationTest(unittest.TestCase):
    """SPEC sections 6.2, 6.6, 9.1 and 9.6 (finding 22)."""

    def _assert_close_code(self, session, peer, code):
        close = peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE)
        self.assertIsNotNone(close)
        self.assertEqual(_error_code(close), int(code))
        with self.assertRaises(zmux.ProtocolError):
            session.wait(2.0)

    def test_max_data_on_unused_peer_stream_closes_session_with_protocol(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_varint_frame(zmux.FrameType.MAX_DATA, 4, 100))
            self._assert_close_code(session, peer, zmux.ErrorCode.PROTOCOL)
        finally:
            peer.close()

    def test_wrong_side_frames_on_local_send_only_stream_abort_stream_state(self):
        session, peer = _server_with_raw_client()
        try:
            for frame_for in (
                lambda sid: _data(sid, b"bad"),
                lambda sid: _varint_frame(zmux.FrameType.BLOCKED, sid, 0),
                lambda sid: _error_frame(zmux.FrameType.RESET, sid, 9),
            ):
                stream = session.open_uni_stream(timeout=1.0)
                stream.write(b"x", timeout=1.0)
                sid = stream.stream_id
                self.assertIsNotNone(
                    peer.wait_for(lambda f, sid=sid: f.frame_type == zmux.FrameType.DATA and f.stream_id == sid)
                )
                peer.send_frame(frame_for(sid))
                abort = peer.wait_for(_is_abort(sid))
                self.assertIsNotNone(abort, f"no ABORT for stream {sid}")
                self.assertEqual(_error_code(abort), int(zmux.ErrorCode.STREAM_STATE))
                with self.assertRaises(zmux.ApplicationError) as raised:
                    stream.write(b"y", timeout=1.0)
                self.assertEqual(raised.exception.code, int(zmux.ErrorCode.STREAM_STATE))
                self.assertEqual(raised.exception.source, zmux.ErrorSource.LOCAL)
                self.assertNotIn(sid, session._streams)
            # Wrong-direction DATA is not late data, but it still returned
            # session credit.
            self.assertEqual(session.stats.diagnostics.late_data_after_close_read, 0)
            self.assertIsNotNone(
                peer.wait_for(lambda f: f.frame_type == zmux.FrameType.MAX_DATA and f.stream_id == 0)
            )
            self.assertFalse(session.closed)
        finally:
            _close(session)
            peer.close()

    def test_wrong_side_frames_on_peer_receive_only_stream_abort_stream_state(self):
        session, peer = _server_with_raw_client()
        try:
            cases = (
                (2, _varint_frame(zmux.FrameType.MAX_DATA, 2, 100)),
                (6, _error_frame(zmux.FrameType.STOP_SENDING, 6, 8)),
            )
            for sid, frame in cases:
                peer.send_frame(_data(sid, b"hi"))
                stream = session.accept_uni_stream(timeout=1.0)
                self.assertEqual(stream.stream_id, sid)
                peer.send_frame(frame)
                abort = peer.wait_for(_is_abort(sid))
                self.assertIsNotNone(abort, f"no ABORT for stream {sid}")
                self.assertEqual(_error_code(abort), int(zmux.ErrorCode.STREAM_STATE))
                with self.assertRaises(zmux.ApplicationError) as raised:
                    stream.read(10, timeout=1.0)
                self.assertEqual(raised.exception.code, int(zmux.ErrorCode.STREAM_STATE))
            self.assertFalse(session.closed)
        finally:
            _close(session)
            peer.close()


class DataAfterFinTest(unittest.TestCase):
    """SPEC sections 9.2 and 9.6, STATE_MACHINE 5.1/8.1 (findings 27, 35)."""

    def _open_finished_stream(self, session, peer, payload=b"abc"):
        peer.send_frame(_data(4, payload, zmux.FRAME_FLAG_FIN))
        inbound = session.accept_stream(timeout=1.0)
        self.assertEqual(inbound.read_exact(len(payload), timeout=1.0), payload)
        self.assertEqual(inbound.read(timeout=1.0), b"")
        return inbound

    def test_data_after_peer_fin_on_live_stream_aborts_stream_closed(self):
        for late in (
            _data(4, b"LATE"),
            _data(4, b""),
            _data(4, b"", zmux.FRAME_FLAG_FIN),
        ):
            with self.subTest(payload=late.payload, flags=late.flags):
                session, peer = _server_with_raw_client()
                try:
                    inbound = self._open_finished_stream(session, peer)
                    # The send half is still open, so the stream is live.
                    self.assertIn(4, session._streams)
                    peer.send_frame(late)
                    abort = peer.wait_for(_is_abort(4))
                    self.assertIsNotNone(abort)
                    self.assertEqual(_error_code(abort), int(zmux.ErrorCode.STREAM_CLOSED))
                    with self.assertRaises(zmux.ApplicationError) as raised:
                        inbound.write(b"reply", timeout=1.0)
                    self.assertEqual(raised.exception.code, int(zmux.ErrorCode.STREAM_CLOSED))
                    self.assertNotIn(4, session._streams)
                    diagnostics = session.stats.diagnostics
                    self.assertEqual(diagnostics.late_data_after_close_read, 0)
                    self.assertEqual(session.stats.pressure.aggregate_late_data_bytes, 0)
                    peer.barrier()
                    self.assertFalse(session.closed)
                    # The stream is now aborted: in-flight DATA behind the
                    # violation is ignored like any late data after ABORT.
                    peer.send_frame(_data(4, b"again"))
                    peer.barrier()
                    self.assertEqual(len(_frames_of(peer, zmux.FrameType.ABORT, 4)), 1)
                finally:
                    _close(session)
                    peer.close()

    def test_rejected_data_after_fin_returns_session_credit(self):
        session, peer = _server_with_raw_client(zmux.Settings(initial_max_data=64))
        try:
            self._open_finished_stream(session, peer, b"x" * 8)
            peer.send_frame(_data(4, b"y" * 32))
            self.assertIsNotNone(peer.wait_for(_is_abort(4, zmux.ErrorCode.STREAM_CLOSED)))
            grant = peer.wait_for(
                lambda f: f.frame_type == zmux.FrameType.MAX_DATA
                and f.stream_id == 0
                and zmux.parse_varint(f.payload)[0] >= 64 + 32
            )
            self.assertIsNotNone(grant)
        finally:
            _close(session)
            peer.close()

    def test_data_after_fin_on_read_stopped_live_stream_aborts_stream_closed(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"a"))
            inbound = session.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"a")
            inbound.close_read()
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.STOP_SENDING))
            # The in-flight tail with FIN is ignored ...
            peer.send_frame(_data(4, b"x", zmux.FRAME_FLAG_FIN))
            peer.barrier()
            self.assertEqual(_frames_of(peer, zmux.FrameType.ABORT, 4), [])
            self.assertIn(4, session._streams)
            # ... but DATA after that FIN is a violation.
            peer.send_frame(_data(4, b"late"))
            abort = peer.wait_for(_is_abort(4))
            self.assertIsNotNone(abort)
            self.assertEqual(_error_code(abort), int(zmux.ErrorCode.STREAM_CLOSED))
            with self.assertRaises(zmux.ApplicationError):
                inbound.write(b"z", timeout=1.0)
        finally:
            _close(session)
            peer.close()

    def test_data_after_fin_on_read_stopped_compacted_stream_aborts_stream_closed(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"a"))
            inbound = session.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"a")
            inbound.close_write(timeout=1.0)
            inbound.close_read()
            # Both halves are concluded locally, so the stream is compacted
            # before the peer's FIN arrives.
            self.assertTrue(_wait_until(lambda: 4 not in session._streams))
            peer.send_frame(_data(4, b"x", zmux.FRAME_FLAG_FIN))
            peer.barrier()
            self.assertEqual(_frames_of(peer, zmux.FrameType.ABORT, 4), [])
            peer.send_frame(_data(4, b"late"))
            abort = peer.wait_for(_is_abort(4))
            self.assertIsNotNone(abort)
            self.assertEqual(_error_code(abort), int(zmux.ErrorCode.STREAM_CLOSED))
            self.assertFalse(session.closed)
        finally:
            _close(session)
            peer.close()

    def test_data_after_fin_on_read_stopped_stream_compacted_later_aborts_stream_closed(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"a"))
            inbound = session.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"a")
            inbound.close_read()
            peer.send_frame(_data(4, b"x", zmux.FRAME_FLAG_FIN))
            peer.barrier()
            self.assertIn(4, session._streams)
            # Concluding the send half compacts the stream after the peer's
            # FIN, so its tombstone must still reject DATA after that FIN.
            inbound.close_write(timeout=1.0)
            self.assertTrue(_wait_until(lambda: 4 not in session._streams))
            disposition = session._terminal_state.terminal_data_disposition_for(4).disposition
            self.assertIs(disposition.action, LateDataAction.ABORT_CLOSED)
            peer.send_frame(_data(4, b"late"))
            abort = peer.wait_for(_is_abort(4))
            self.assertIsNotNone(abort)
            self.assertEqual(_error_code(abort), int(zmux.ErrorCode.STREAM_CLOSED))
            self.assertFalse(session.closed)
        finally:
            _close(session)
            peer.close()

    def test_late_data_after_local_read_stop_without_fin_is_ignored(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"a"))
            inbound = session.accept_stream(timeout=1.0)
            inbound.close_read()
            peer.send_frame(_data(4, b"in-flight"))
            peer.barrier()
            self.assertEqual(_frames_of(peer, zmux.FrameType.ABORT, 4), [])
            self.assertEqual(session.stats.diagnostics.late_data_after_close_read, 9)
            inbound.write_all(b"still writable", timeout=1.0)
        finally:
            _close(session)
            peer.close()

    def test_python_peer_sees_stream_closed_after_sending_data_after_fin(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"abc", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(3, timeout=1.0), b"abc")
            self.assertEqual(inbound.read(timeout=1.0), b"")
            client._send_frame(_data(outbound.stream_id, b"LATE"))
            with self.assertRaises(zmux.ApplicationError) as raised:
                outbound.read(1, timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.STREAM_CLOSED))
            self.assertEqual(raised.exception.source, zmux.ErrorSource.REMOTE)
            self.assertEqual(server.stats.diagnostics.late_data_after_close_read, 0)
            self.assertFalse(server.closed)
        finally:
            _close(client, server)


class TerminalReadErrorTest(unittest.TestCase):
    """API_SEMANTICS sections 3 and 7, SPEC 6.8/6.10 (findings 28, 75, 76)."""

    def _buffered_pair(self, payload=b"hello", uni=False):
        client, server = _session_pair()
        outbound = client.open_uni_stream(timeout=1.0) if uni else client.open_stream(timeout=1.0)
        outbound.write_all(payload, timeout=1.0)
        inbound = (
            server.accept_uni_stream(timeout=1.0) if uni else server.accept_stream(timeout=1.0)
        )
        self.assertTrue(_wait_until(lambda: inbound._read_buffered == len(payload)))
        return client, server, outbound, inbound

    def _assert_app_error(self, call, code, source, kind):
        with self.assertRaises(zmux.ApplicationError) as raised:
            call()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(raised.exception.source, source)
        self.assertEqual(raised.exception.termination_kind, kind)

    def test_peer_reset_discards_buffered_bytes(self):
        client, server, outbound, inbound = self._buffered_pair()
        try:
            outbound.cancel_write(300)
            self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
            self.assertEqual(inbound._read_buffered, 0)
            for _ in range(2):
                self._assert_app_error(
                    lambda: inbound.read(100, timeout=1.0),
                    300,
                    zmux.ErrorSource.REMOTE,
                    zmux.TerminationKind.RESET,
                )
        finally:
            _close(client, server)

    def test_peer_abort_discards_buffered_bytes_and_reports_code(self):
        client, server, outbound, inbound = self._buffered_pair()
        try:
            outbound.close_with_error(301, "boom")
            self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
            self.assertEqual(inbound._read_buffered, 0)
            for read in (
                lambda: inbound.read(100, timeout=1.0),
                lambda: inbound.read(100, timeout=1.0),
                lambda: inbound.read_vectored([bytearray(4)], timeout=1.0),
                lambda: inbound.write(b"x", timeout=1.0),
            ):
                self._assert_app_error(
                    read, 301, zmux.ErrorSource.REMOTE, zmux.TerminationKind.ABORT
                )
        finally:
            _close(client, server)

    def test_peer_abort_code_is_visible_on_receive_only_stream(self):
        client, server, outbound, inbound = self._buffered_pair(b"x", uni=True)
        try:
            self.assertEqual(inbound.read(1, timeout=1.0), b"x")
            outbound.close_with_error(777)
            self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
            self._assert_app_error(
                lambda: inbound.read(1, timeout=1.0),
                777,
                zmux.ErrorSource.REMOTE,
                zmux.TerminationKind.ABORT,
            )
        finally:
            _close(client, server)

    def test_local_abort_reports_local_abort_on_read(self):
        client, server, _outbound, inbound = self._buffered_pair()
        try:
            inbound.close_with_error(302, "local")
            for read in (
                lambda: inbound.read(100, timeout=1.0),
                lambda: inbound.read(100, timeout=1.0),
            ):
                self._assert_app_error(
                    read, 302, zmux.ErrorSource.LOCAL, zmux.TerminationKind.ABORT
                )
            other = client.open_stream(timeout=1.0)
            other.write_all(b"x", timeout=1.0)
            other.close_with_error(55, "x")
            self._assert_app_error(
                lambda: other.read(1, timeout=1.0),
                55,
                zmux.ErrorSource.LOCAL,
                zmux.TerminationKind.ABORT,
            )
        finally:
            _close(client, server)

    def test_bytes_discarded_by_peer_reset_or_abort_return_session_credit(self):
        for frame_type in (zmux.FrameType.RESET, zmux.FrameType.ABORT):
            with self.subTest(frame=frame_type):
                session, peer = _server_with_raw_client(zmux.Settings(initial_max_data=64))
                try:
                    peer.send_frame(_data(4, b"y" * 32))
                    inbound = session.accept_stream(timeout=1.0)
                    self.assertTrue(
                        _wait_until(lambda inbound=inbound: inbound._read_buffered == 32)
                    )

                    def returned(frame):
                        return (
                            frame.frame_type == zmux.FrameType.MAX_DATA
                            and frame.stream_id == 0
                            and zmux.parse_varint(frame.payload)[0] >= 64 + 32
                        )

                    peer.barrier()
                    self.assertFalse(any(returned(frame) for frame in peer.snapshot()))
                    peer.send_frame(_error_frame(frame_type, 4, 300))
                    # The unread bytes are dropped, not left to the
                    # application, and their session credit comes back.
                    self.assertIsNotNone(peer.wait_for(returned))
                    self.assertEqual(inbound._read_buffered, 0)
                    with self.assertRaises(zmux.ApplicationError) as raised:
                        inbound.read(100, timeout=1.0)
                    self.assertEqual(raised.exception.code, 300)
                finally:
                    _close(session)
                    peer.close()

    def test_local_read_stop_takes_precedence_over_later_peer_abort(self):
        client, server, outbound, inbound = self._buffered_pair()
        try:
            inbound.cancel_read(8)
            outbound_error = _wait_until(lambda: outbound.write_closed)
            self.assertTrue(outbound_error)
            outbound.close_with_error(300)
            self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
            with self.assertRaises(zmux.ReadClosed) as raised:
                inbound.read(1, timeout=1.0)
            self.assertEqual(raised.exception.source, zmux.ErrorSource.LOCAL)
            self.assertEqual(raised.exception.termination_kind, zmux.TerminationKind.STOPPED)
        finally:
            _close(client, server)

    def test_peer_session_close_with_error_discards_buffered_bytes(self):
        client, server, _outbound, inbound = self._buffered_pair()
        try:
            client.close_with_error(77, "bye")
            self.assertTrue(_wait_until(lambda: server.closed))
            self.assertEqual(inbound._read_buffered, 0)
            for call in (
                lambda: inbound.read(100, timeout=1.0),
                lambda: inbound.read(100, timeout=1.0),
                lambda: inbound.write(b"x", timeout=1.0),
            ):
                self._assert_app_error(
                    call,
                    77,
                    zmux.ErrorSource.REMOTE,
                    zmux.TerminationKind.SESSION_TERMINATION,
                )
        finally:
            _close(client, server)

    def test_benign_session_close_fails_unfinished_streams(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"partial", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(7, timeout=1.0), b"partial")
            blocked, result = _run(inbound.read, 64, timeout=2.0)
            time.sleep(0.05)
            client.close_with_error(0)
            blocked.join(2.0)
            self.assertIsInstance(result.get("error"), zmux.SessionClosed)
            self.assertTrue(_wait_until(lambda: server.closed))
            with self.assertRaises(zmux.SessionClosed):
                inbound.read(64, timeout=1.0)
            with self.assertRaises(zmux.SessionClosed):
                inbound.read(timeout=1.0)
            with self.assertRaises(zmux.SessionClosed):
                inbound.write(b"x", timeout=1.0)
            with self.assertRaises(zmux.SessionClosed):
                outbound.read(1, timeout=1.0)
        finally:
            _close(client, server)

    def test_benign_session_close_discards_unfinished_buffered_bytes(self):
        client, server, _outbound, inbound = self._buffered_pair(b"partial")
        try:
            client.close_with_error(0)
            self.assertTrue(_wait_until(lambda: server.closed))
            self.assertEqual(inbound._read_buffered, 0)
            with self.assertRaises(zmux.SessionClosed):
                inbound.read(timeout=1.0)
        finally:
            _close(client, server)

    def test_session_close_keeps_finished_direction_readable_to_eof(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"done", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertTrue(_wait_until(lambda: inbound._peer_fin_seen))
            client.close_with_error(0)
            self.assertTrue(_wait_until(lambda: server.closed))
            self.assertEqual(inbound.read(timeout=1.0), b"done")
            self.assertEqual(inbound.read(timeout=1.0), b"")
        finally:
            _close(client, server)


class StreamCloseTest(unittest.TestCase):
    """API_SEMANTICS section 6.5, STATE_MACHINE 4.1 (findings 29, 77, 80)."""

    def test_close_after_reading_peer_fin_does_not_raise(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"hi", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read(timeout=1.0), b"hi")
            self.assertIsNone(inbound.close())
            self.assertEqual(outbound.read(timeout=1.0), b"")
            # Full FIN/FIN exchange: the opener's close does not raise either.
            self.assertIsNone(outbound.close())
            self.assertNotIn(outbound.stream_id, client._streams)
        finally:
            _close(client, server)

    def test_with_block_exit_after_peer_fin_keeps_application_exception(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"req", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            with inbound:
                self.assertEqual(inbound.read(timeout=1.0), b"req")
                inbound.write_all(b"resp", timeout=1.0)
            self.assertEqual(outbound.read(timeout=1.0), b"resp")

            second = client.open_stream(timeout=1.0)
            second.write_final(b"req", timeout=1.0)
            accepted = server.accept_stream(timeout=1.0)
            with self.assertRaises(ValueError), accepted:
                accepted.read(timeout=1.0)
                raise ValueError("application failure")
        finally:
            _close(client, server)

    def test_close_after_peer_reset_does_not_raise(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"x", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            outbound.cancel_write(9)
            self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
            self.assertIsNone(inbound.close())
        finally:
            _close(client, server)

    def test_close_racing_peer_reset_or_abort_does_not_raise(self):
        # A peer RESET or ABORT applied by the reader between close()'s
        # snapshot and its close_read()/close_write() call is as benign as one
        # that arrived before close() (verdict of finding 29).
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"x", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            original_close_read = NativeStream.close_read

            def close_read_after_peer_reset(stream):
                if stream is inbound:
                    outbound.cancel_write(77)
                    self.assertTrue(_wait_until(lambda: inbound._read_error is not None))
                return original_close_read(stream)

            with mock.patch.object(NativeStream, "close_read", close_read_after_peer_reset):
                self.assertIsNone(inbound.close())
            self.assertTrue(inbound.closed)
            with self.assertRaises(zmux.ApplicationError) as raised:
                inbound.read(timeout=1.0)
            self.assertEqual(raised.exception.code, 77)

            aborted_out = client.open_stream(timeout=1.0)
            aborted_out.write_all(b"y", timeout=1.0)
            aborted_in = server.accept_stream(timeout=1.0)
            original_close_write = NativeStream.close_write

            def close_write_after_peer_abort(stream, *, timeout=None):
                if stream is aborted_in:
                    aborted_out.close_with_error(78)
                    self.assertTrue(_wait_until(lambda: aborted_in._write_error is not None))
                return original_close_write(stream, timeout=timeout)

            with mock.patch.object(NativeStream, "close_write", close_write_after_peer_abort):
                self.assertIsNone(aborted_in.close())
            self.assertTrue(aborted_in.closed)
            self.assertTrue(_wait_until(lambda: aborted_in.stream_id not in server._streams))

            # A local failure in the same step is still reported.
            failing_out = client.open_stream(timeout=1.0)
            failing_out.write_all(b"z", timeout=1.0)
            failing_in = server.accept_stream(timeout=1.0)

            def failing_close_read(stream):
                raise RuntimeError("stop could not be queued")

            with (
                mock.patch.object(NativeStream, "close_read", failing_close_read),
                self.assertRaises(RuntimeError),
            ):
                failing_in.close()
        finally:
            _close(client, server)

    def test_close_after_fin_with_unread_data_drops_it_and_fails_reads(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_final(b"unread", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertTrue(_wait_until(lambda: inbound._peer_fin_seen))
            self.assertIsNone(inbound.close())
            with self.assertRaises(zmux.ReadClosed) as raised:
                inbound.read(timeout=1.0)
            self.assertEqual(raised.exception.source, zmux.ErrorSource.LOCAL)
        finally:
            _close(client, server)

    def test_close_with_open_read_half_still_stops_sending(self):
        client, server = _session_pair()
        try:
            outbound = client.open_stream(timeout=1.0)
            outbound.write_all(b"x", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            inbound.close()
            self.assertTrue(_wait_until(lambda: outbound.write_closed))
            with self.assertRaises(zmux.ApplicationError) as raised:
                outbound.write(b"more", timeout=1.0)
            self.assertEqual(raised.exception.termination_kind, zmux.TerminationKind.STOPPED)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.CANCELLED))
        finally:
            _close(client, server)

    def test_close_falls_back_to_reset_when_fin_times_out(self):
        settings = zmux.Settings(max_incoming_streams_bidi=1)
        client, server = _session_pair(server_config=zmux.Config(settings=settings))
        try:
            stream = client.open_stream(timeout=1.0)
            stream.write(b"hello", timeout=1.0)
            peer = server.accept_stream(timeout=1.0)
            # Read before the RESET can arrive: RESET discards unread bytes.
            self.assertEqual(peer.read_exact(5, timeout=1.0), b"hello")
            stream.set_write_deadline(time.monotonic() - 1)
            with self.assertRaises(zmux.WriteTimeout):
                stream.close()
            with self.assertRaises(zmux.ApplicationError) as raised:
                peer.read(timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.CANCELLED))
            self.assertEqual(raised.exception.termination_kind, zmux.TerminationKind.RESET)
            self.assertTrue(_wait_until(lambda: peer.stream_id not in server._streams))
            self.assertNotIn(stream.stream_id, client._streams)

            # The peer's only incoming slot is free again, and the local
            # accounting agrees.
            second = client.open_stream(timeout=1.0)
            second.write_all(b"world", timeout=1.0)
            accepted = server.accept_stream(timeout=1.0)
            self.assertEqual(accepted.read_exact(5, timeout=1.0), b"world")
        finally:
            _close(client, server)

    def test_close_keeps_stream_tracked_while_send_half_is_still_open(self):
        client, server = _session_pair()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.write_all(b"hello", timeout=1.0)
            peer = server.accept_stream(timeout=1.0)
            self.assertEqual(peer.read_exact(5, timeout=1.0), b"hello")
            original = NativeStream.close_write

            def failing_close_write(self, *, timeout=None):
                if self is stream:
                    raise RuntimeError("FIN could not be queued")
                return original(self, timeout=timeout)

            with (
                mock.patch.object(NativeStream, "close_write", failing_close_write),
                self.assertRaises(RuntimeError),
            ):
                stream.close()
            # Neither FIN nor RESET went out, so the stream still occupies the
            # peer's slot: it stays tracked (and counted) and the application
            # can still conclude it.
            self.assertFalse(stream.closed)
            self.assertIn(stream.stream_id, client._streams)
            stream.cancel_write(int(zmux.ErrorCode.CANCELLED))
            with self.assertRaises(zmux.ApplicationError) as raised:
                peer.read(timeout=1.0)
            self.assertEqual(raised.exception.code, int(zmux.ErrorCode.CANCELLED))
            self.assertTrue(_wait_until(lambda: stream.stream_id not in client._streams))
        finally:
            _close(client, server)

    def test_close_write_on_finished_or_failed_half_reports_an_error(self):
        client, server = _session_pair()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.write_all(b"x", timeout=1.0)
            stream.close_write(timeout=1.0)
            with self.assertRaises(zmux.WriteClosed):
                stream.close_write(timeout=1.0)
            self.assertIsNone(stream.close())

            reset = client.open_stream(timeout=1.0)
            reset.write_all(b"x", timeout=1.0)
            reset.cancel_write(7)
            with self.assertRaises(zmux.ApplicationError) as raised:
                reset.close_write(timeout=1.0)
            self.assertEqual(raised.exception.code, 7)

            aborted = client.open_stream(timeout=1.0)
            aborted.write_all(b"x", timeout=1.0)
            aborted.close_with_error(9)
            with self.assertRaises(zmux.ApplicationError) as raised:
                aborted.close_write(timeout=1.0)
            self.assertEqual(raised.exception.code, 9)

            stopped = client.open_stream(timeout=1.0)
            stopped.write_all(b"x", timeout=1.0)
            for _ in range(4):
                accepted = server.accept_stream(timeout=1.0)
                if accepted.stream_id == stopped.stream_id:
                    break
            accepted.close_read()
            self.assertTrue(_wait_until(lambda: stopped.write_closed))
            # Concluded by peer STOP_SENDING (and our RESET): a no-op.
            self.assertIsNone(stopped.close_write(timeout=1.0))

            uni_out = server.open_uni_stream(timeout=1.0)
            uni_out.write_all(b"u", timeout=1.0)
            uni_in = client.accept_uni_stream(timeout=1.0)
            with self.assertRaises(zmux.StreamNotWritable):
                uni_in.close_write(timeout=1.0)

            pending = client.open_stream(timeout=1.0)
            pending.write_all(b"x", timeout=1.0)
            server.close_with_error(0)
            self.assertTrue(_wait_until(lambda: client.closed))
            with self.assertRaises(zmux.SessionClosed):
                pending.close_write(timeout=1.0)
        finally:
            _close(client, server)


class LateTerminalControlTest(unittest.TestCase):
    """STATE_MACHINE sections 4.1, 5.1 and 5.2 (findings 31, 32)."""

    def test_reset_after_fin_keeps_eof(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"hello", zmux.FRAME_FLAG_FIN))
            peer.send_frame(_error_frame(zmux.FrameType.RESET, 4, 9))
            inbound = session.accept_stream(timeout=1.0)
            peer.barrier()
            self.assertEqual(inbound.read(timeout=1.0), b"hello")
            self.assertEqual(inbound.read(timeout=1.0), b"")
            peer.send_frame(_error_frame(zmux.FrameType.RESET, 4, 10))
            peer.barrier()
            self.assertEqual(inbound.read(timeout=1.0), b"")
            self.assertEqual(session.stats.reasons.reset, {})
            self.assertEqual(session.stats.abuse.ignored_control, 2)
            # The terminal record still rejects DATA after that FIN.
            inbound.close_write(timeout=1.0)
            self.assertTrue(_wait_until(lambda: 4 not in session._streams))
            disposition = session._terminal_state.terminal_data_disposition_for(4).disposition
            self.assertIs(disposition.action, LateDataAction.ABORT_CLOSED)
        finally:
            _close(session)
            peer.close()

    def test_duplicate_reset_keeps_first_code(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"x"))
            inbound = session.accept_stream(timeout=1.0)
            peer.send_frame(_error_frame(zmux.FrameType.RESET, 4, 9))
            peer.send_frame(_error_frame(zmux.FrameType.RESET, 4, 10))
            peer.barrier()
            with self.assertRaises(zmux.ApplicationError) as raised:
                inbound.read(1, timeout=1.0)
            self.assertEqual(raised.exception.code, 9)
            self.assertEqual(session.stats.reasons.reset, {9: 1})
        finally:
            _close(session)
            peer.close()

    def test_reset_after_local_read_stop_is_applied(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"x"))
            inbound = session.accept_stream(timeout=1.0)
            inbound.close_read()
            peer.send_frame(_error_frame(zmux.FrameType.RESET, 4, 9))
            peer.barrier()
            self.assertEqual(session.stats.reasons.reset, {9: 1})
            with self.assertRaises(zmux.ReadClosed) as raised:
                inbound.read(1, timeout=1.0)
            self.assertEqual(raised.exception.source, zmux.ErrorSource.LOCAL)
            inbound.close_write(timeout=1.0)
            self.assertTrue(_wait_until(lambda: 4 not in session._streams))
            disposition = session._terminal_state.terminal_data_disposition_for(4).disposition
            self.assertIs(disposition.cause, LateDataCause.RESET)
        finally:
            _close(session)
            peer.close()

    def test_stop_sending_after_local_fin_or_reset_keeps_outcome(self):
        client, peer = _client_with_raw_server()
        try:
            finished = client.open_stream(timeout=1.0)
            finished.write_final(b"x", timeout=1.0)
            reset = client.open_stream(timeout=1.0)
            reset.write_all(b"x", timeout=1.0)
            reset.cancel_write(77)
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.RESET))
            # A local RESET after a committed FIN is a local error, never a frame.
            with self.assertRaises(zmux.WriteClosed):
                finished.cancel_write(5)
            ignored_before = client.stats.abuse.ignored_control
            peer.send_frame(_error_frame(zmux.FrameType.STOP_SENDING, finished.stream_id, 8))
            peer.send_frame(_error_frame(zmux.FrameType.STOP_SENDING, reset.stream_id, 8))
            peer.barrier()
            self.assertEqual(_frames_of(peer, zmux.FrameType.RESET, finished.stream_id), [])
            self.assertEqual(len(_frames_of(peer, zmux.FrameType.RESET, reset.stream_id)), 1)
            self.assertEqual(client.stats.abuse.ignored_control, ignored_before + 2)
            with self.assertRaises(zmux.WriteClosed):
                finished.write(b"y", timeout=1.0)
            with self.assertRaises(zmux.ApplicationError) as raised:
                reset.write(b"y", timeout=1.0)
            self.assertEqual(raised.exception.code, 77)
            self.assertEqual(raised.exception.source, zmux.ErrorSource.LOCAL)
            self.assertEqual(raised.exception.termination_kind, zmux.TerminationKind.RESET)
        finally:
            _close(client)
            peer.close()

    def test_repeated_local_abort_sends_one_abort(self):
        client, peer = _client_with_raw_server()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.write_all(b"x", timeout=1.0)
            stream.close_with_error(9)
            stream.close_with_error(9)
            stream.close_with_error(10, "different")
            peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"flushed!"))
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PONG))
            aborts = _frames_of(peer, zmux.FrameType.ABORT, stream.stream_id)
            self.assertEqual([_error_code(frame) for frame in aborts], [9])
            with self.assertRaises(zmux.ApplicationError) as raised:
                stream.write(b"y", timeout=1.0)
            self.assertEqual(raised.exception.code, 9)
        finally:
            _close(client)
            peer.close()

    def test_local_abort_after_peer_abort_is_a_no_op(self):
        client, peer = _client_with_raw_server()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.write_all(b"x", timeout=1.0)
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.DATA))
            peer.send_frame(_error_frame(zmux.FrameType.ABORT, stream.stream_id, 42))
            self.assertTrue(_wait_until(lambda: stream._write_error is not None))
            stream.close_with_error(9)
            peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"flushed!"))
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PONG))
            self.assertEqual(_frames_of(peer, zmux.FrameType.ABORT, stream.stream_id), [])
            with self.assertRaises(zmux.ApplicationError) as raised:
                stream.write(b"y", timeout=1.0)
            self.assertEqual(raised.exception.code, 42)
            self.assertEqual(raised.exception.source, zmux.ErrorSource.REMOTE)
        finally:
            _close(client)
            peer.close()

    def test_repeated_abort_of_uncommitted_stream_is_a_no_op(self):
        client, peer = _client_with_raw_server()
        try:
            stream = client.open_stream(timeout=1.0)
            stream.close_with_error(9)
            self.assertIsNone(stream.close_with_error(9))
            with self.assertRaises(zmux.ApplicationError):
                stream.write(b"x", timeout=1.0)
        finally:
            _close(client)
            peer.close()


class _PausedReservation(object):
    """Pause one named writer thread right after it reserved send credit."""

    def __init__(self, thread_name):
        self.thread_name = thread_name
        self.reserved = threading.Event()
        self.release = threading.Event()
        self._original = Conn._reserve_send_credit
        paused = self

        def reserve(conn, stream, byte_count, timeout_deadline):
            taken = paused._original(conn, stream, byte_count, timeout_deadline)
            if threading.current_thread().name == paused.thread_name and not paused.reserved.is_set():
                paused.reserved.set()
                paused.release.wait(5.0)
            return taken

        self.patch = mock.patch.object(Conn, "_reserve_send_credit", reserve)

    def __enter__(self):
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.release.set()
        self.patch.stop()


class TerminalFrameOrderingTest(unittest.TestCase):
    """SPEC sections 6.3, 6.7 and 6.8 (finding 33)."""

    def _start_paused_write(self, client, peer, final=False):
        stream = client.open_stream(timeout=1.0)
        stream.write_all(b"o", timeout=1.0)
        self.assertIsNotNone(
            peer.wait_for(lambda f: f.frame_type == zmux.FrameType.DATA and f.stream_id == stream.stream_id)
        )
        payload = b"y" * 4096
        target = stream.write_final if final else stream.write_all
        result = {}

        def run():
            try:
                target(payload, timeout=5.0)
            except BaseException as exc:
                result["error"] = exc

        thread = threading.Thread(target=run, name="paused-writer", daemon=True)
        return stream, thread, result

    def _assert_no_data_after(self, client, peer, stream, terminal_type):
        # The terminal frame queues behind this stream's earlier DATA; once it
        # arrived, a PING round trip flushes anything queued after it.
        self.assertIsNotNone(
            peer.wait_for(
                lambda f: f.frame_type == terminal_type and f.stream_id == stream.stream_id,
                timeout=5.0,
            )
        )
        peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"ordered!"))
        self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PONG))
        frames = [
            frame for frame in peer.snapshot() if frame.stream_id == stream.stream_id
        ]
        kinds = [frame.frame_type for frame in frames]
        self.assertIn(terminal_type, kinds)
        after = kinds[kinds.index(terminal_type):]
        self.assertNotIn(zmux.FrameType.DATA, after)
        # Credit reserved for the dropped bytes was returned.
        sent = sum(
            len(frame.payload) for frame in frames if frame.frame_type == zmux.FrameType.DATA
        )
        self.assertEqual(client._send_session_used, sent)
        self.assertEqual(stream._send_sent, sent)

    def test_cancel_write_during_reserved_write_suppresses_later_data(self):
        for final in (False, True):
            with self.subTest(final=final):
                client, peer = _client_with_raw_server()
                try:
                    with _PausedReservation("paused-writer") as paused:
                        stream, thread, result = self._start_paused_write(client, peer, final)
                        thread.start()
                        self.assertTrue(paused.reserved.wait(2.0))
                        stream.cancel_write(77)
                        paused.release.set()
                        thread.join(2.0)
                    self.assertIsInstance(result.get("error"), zmux.ApplicationError)
                    self.assertEqual(result["error"].code, 77)
                    self._assert_no_data_after(client, peer, stream, zmux.FrameType.RESET)
                finally:
                    _close(client)
                    peer.close()

    def test_close_with_error_during_reserved_write_suppresses_later_data(self):
        client, peer = _client_with_raw_server()
        try:
            with _PausedReservation("paused-writer") as paused:
                stream, thread, result = self._start_paused_write(client, peer)
                thread.start()
                self.assertTrue(paused.reserved.wait(2.0))
                stream.close_with_error(88)
                paused.release.set()
                thread.join(2.0)
            self.assertIsInstance(result.get("error"), zmux.ApplicationError)
            self.assertEqual(result["error"].code, 88)
            self._assert_no_data_after(client, peer, stream, zmux.FrameType.ABORT)
        finally:
            _close(client)
            peer.close()

    def test_peer_stop_sending_during_reserved_write_suppresses_later_data(self):
        client, peer = _client_with_raw_server()
        try:
            with _PausedReservation("paused-writer") as paused:
                stream, thread, result = self._start_paused_write(client, peer)
                thread.start()
                self.assertTrue(paused.reserved.wait(2.0))
                peer.send_frame(_error_frame(zmux.FrameType.STOP_SENDING, stream.stream_id, 99))
                self.assertTrue(_wait_until(lambda: stream.write_closed))
                paused.release.set()
                thread.join(2.0)
            self.assertIsInstance(result.get("error"), zmux.ApplicationError)
            self.assertEqual(result["error"].code, 99)
            self.assertEqual(result["error"].termination_kind, zmux.TerminationKind.STOPPED)
            self._assert_no_data_after(client, peer, stream, zmux.FrameType.RESET)
        finally:
            _close(client)
            peer.close()

    @staticmethod
    def _write_chunks(stream, count):
        for _ in range(count):
            stream.write_all(b"z" * 8192, timeout=2.0)

    def test_concurrent_writer_and_cancel_never_put_data_after_reset(self):
        for _ in range(20):
            client, peer = _client_with_raw_server()
            try:
                stream = client.open_stream(timeout=1.0)
                stream.write_all(b"o", timeout=1.0)
                thread, _ = _run(self._write_chunks, stream, 64)
                time.sleep(0.002)
                stream.cancel_write(5)
                thread.join(3.0)
                self._assert_no_data_after(client, peer, stream, zmux.FrameType.RESET)
            finally:
                _close(client)
                peer.close()


class PriorityUpdateTest(unittest.TestCase):
    """SPEC section 7.6, IMPLEMENTATION section 7 (finding 52)."""

    def test_update_for_aborted_stream_in_accept_queue_is_ignored(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(4, b"x"))
            peer.send_frame(_error_frame(zmux.FrameType.ABORT, 4, 8))
            peer.send_frame(_priority_update(4, 9))
            peer.barrier()
            accepted = session.accept_stream(timeout=1.0)
            self.assertIsNone(accepted.metadata.priority)
            self.assertEqual(session.stats.abuse.no_op_priority_update, 1)
        finally:
            _close(session)
            peer.close()

    def test_update_for_finished_uni_stream_in_accept_queue_is_ignored(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(2, b"", zmux.FRAME_FLAG_FIN))
            peer.send_frame(_priority_update(2, 9))
            peer.barrier()
            accepted = session.accept_uni_stream(timeout=1.0)
            self.assertIsNone(accepted.metadata.priority)
        finally:
            _close(session)
            peer.close()

    def test_update_for_live_stream_applies_and_repeats_are_no_ops(self):
        session, peer = _server_with_raw_client(no_op_priority_update_budget=4)
        try:
            peer.send_frame(_data(4, b"x"))
            accepted = session.accept_stream(timeout=1.0)
            peer.send_frame(_priority_update(4, 9))
            peer.barrier()
            self.assertEqual(accepted.metadata.priority, 9)
            self.assertEqual(session.stats.abuse.no_op_priority_update, 0)
            for _ in range(4):
                peer.send_frame(_priority_update(4, 9))
            peer.barrier()
            self.assertEqual(session.stats.abuse.no_op_priority_update, 4)
            self.assertFalse(session.closed)
            peer.send_frame(_priority_update(4, 9))
            close = peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE)
            self.assertIsNotNone(close)
            self.assertEqual(_error_code(close), int(zmux.ErrorCode.PROTOCOL))
        finally:
            _close(session)
            peer.close()

    def test_terminal_stream_update_flood_closes_session(self):
        session, peer = _server_with_raw_client(no_op_priority_update_budget=4)
        try:
            peer.send_frame(_data(4, b"x"))
            peer.send_frame(_error_frame(zmux.FrameType.ABORT, 4, 8))
            for _ in range(5):
                peer.send_frame(_priority_update(4, 9))
            close = peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE)
            self.assertIsNotNone(close)
            self.assertEqual(_error_code(close), int(zmux.ErrorCode.PROTOCOL))
        finally:
            _close(session)
            peer.close()


if __name__ == "__main__":
    unittest.main()
