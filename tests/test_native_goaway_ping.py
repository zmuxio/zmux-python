"""GOAWAY ordering/API, PING limits/serialization, PRNG seeding and partial writes.

The native session used to commit a local GOAWAY watermark under the session
lock but queue the frame after releasing it, so concurrent ``go_away`` calls
(or ``go_away`` racing a graceful ``close``) could put increasing watermarks
on the wire and the peer failed the session.  A peer GOAWAY that raced
session termination still changed watermarks and state, ``go_away`` reported
the caller's own bad arguments as remote read errors and refused a request an
earlier GOAWAY already covered, and a NO_ERROR GOAWAY cause was hidden.
``ping`` only bounded its payload by the peer limit, let any number of PINGs
be outstanding at once, and every process drew the same jitter/PING PRNG
sequence.  A write that failed after queueing part of its bytes reported no
progress.  These tests drive real sessions over ``socket.socketpair``, using a
raw zmux peer where exact frames matter.
"""

import itertools
import os
import random
import socket
import subprocess
import sys
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
        self._pings = 0

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def send_preface(self, role, settings=None):
        preface = zmux.Config(
            role=role,
            settings=settings or zmux.Settings(),
            preface_padding=False,
            ping_padding=False,
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


def _server_with_raw_client(**config):
    left, right = socket.socketpair()
    peer = RawPeer(left)
    peer.send_preface(zmux.Role.INITIATOR)
    config.setdefault("keepalive_interval", None)
    session = zmux.server(right, zmux.Config(**config))
    peer.start_collecting()
    return session, peer


def _client_with_raw_server(settings=None, **config):
    left, right = socket.socketpair()
    peer = RawPeer(right)
    peer.send_preface(zmux.Role.RESPONDER, settings)
    config.setdefault("keepalive_interval", None)
    session = zmux.client(left, zmux.Config(**config))
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


def _run(target, *args, name=None, **kwargs):
    result = {}

    def runner():
        try:
            result["value"] = target(*args, **kwargs)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=runner, name=name, daemon=True)
    thread.start()
    return thread, result


def _go_away_frame(bidi, uni, code=0, reason=""):
    return zmux.Frame(
        zmux.FrameType.GOAWAY,
        0,
        0,
        zmux.build_go_away_payload(bidi, uni, code, reason),
    )


def _go_aways(peer):
    watermarks = []
    for frame in peer.snapshot():
        if frame.frame_type == zmux.FrameType.GOAWAY:
            parsed = zmux.parse_go_away_payload(frame.payload)
            watermarks.append((parsed.last_accepted_bidi, parsed.last_accepted_uni))
    return watermarks


def _assert_non_increasing(test, watermarks):
    for earlier, later in itertools.pairwise(watermarks):
        test.assertLessEqual(later[0], earlier[0], watermarks)
        test.assertLessEqual(later[1], earlier[1], watermarks)


class _DelayedGoAwayQueue(object):
    """Delay queueing of GOAWAY frames issued by one named thread.

    ``Conn`` uses ``__slots__``, so the hook patches the class and only
    affects ``session``.
    """

    def __init__(self, session, thread_name, delay=0.2):
        self.session = session
        self.thread_name = thread_name
        self.delay = delay
        self.entered = threading.Event()
        self._original = Conn._queue_frame

    def __enter__(self):
        hook = self
        original = self._original

        def queue_frame(conn, frame, *args, **kwargs):
            if (
                conn is hook.session
                and frame.frame_type == zmux.FrameType.GOAWAY
                and threading.current_thread().name == hook.thread_name
                and not hook.entered.is_set()
            ):
                hook.entered.set()
                time.sleep(hook.delay)
            return original(conn, frame, *args, **kwargs)

        self._patch = mock.patch.object(Conn, "_queue_frame", queue_frame)
        self._patch.start()
        return self

    def __exit__(self, *exc_info):
        self._patch.stop()
        return False


class GoAwayWireOrderTest(unittest.TestCase):
    """Finding 60: commit and queue of a local GOAWAY are one atomic step."""

    def test_concurrent_go_away_calls_reach_the_wire_in_commit_order(self):
        session, peer = _server_with_raw_client()
        try:
            with _DelayedGoAwayQueue(session, "goaway-a") as hook:
                first, first_result = _run(session.go_away, 400, 402, name="goaway-a")
                self.assertTrue(hook.entered.wait(2.0))
                # The permissive GOAWAY is already committed; the stricter one
                # must not overtake it on the wire.
                session.go_away(4, 2)
                first.join(2.0)
            self.assertNotIn("error", first_result)
            peer.barrier()
            self.assertEqual(_go_aways(peer), [(400, 402), (4, 2)])
            self.assertIs(session.state, zmux.SessionState.DRAINING)
        finally:
            _close(session)
            peer.close()

    def test_go_away_racing_graceful_close_keeps_watermarks_non_increasing(self):
        session, peer = _server_with_raw_client()
        try:
            # A never-written local stream makes close() take the graceful
            # path (initial GOAWAY, drain interval, refined GOAWAY).
            session.open_stream()
            with _DelayedGoAwayQueue(session, "closer") as hook:
                closer, close_result = _run(session.close, name="closer")
                self.assertTrue(hook.entered.wait(2.0))
                session.go_away(4, 2)
                closer.join(3.0)
            self.assertFalse(closer.is_alive())
            self.assertNotIn("error", close_result)
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE))
            watermarks = _go_aways(peer)
            self.assertIn((4, 2), watermarks)
            self.assertEqual(watermarks[-1], (0, 0))
            _assert_non_increasing(self, watermarks)
        finally:
            _close(session)
            peer.close()

    def test_natural_go_away_race_never_fails_the_peer(self):
        previous = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            for iteration in range(30):
                self._race_go_away_once(iteration)
        finally:
            sys.setswitchinterval(previous)

    def _race_go_away_once(self, iteration):
        client, server = _session_pair()
        try:
            barrier = threading.Barrier(2)

            def call(bidi, uni):
                barrier.wait(2.0)
                server.go_away(bidi, uni)

            threads = [
                threading.Thread(target=call, args=(800, 802), daemon=True),
                threading.Thread(target=call, args=(4, 2), daemon=True),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2.0)
            self.assertTrue(
                _wait_until(
                    lambda: client._peer_go_away_bidi == 4
                    or client.state is zmux.SessionState.FAILED
                ),
                iteration,
            )
            self.assertIsNot(client.state, zmux.SessionState.FAILED, iteration)
            self.assertEqual((client._peer_go_away_bidi, client._peer_go_away_uni), (4, 2))
        finally:
            _close(client, server)


class GoAwayWhileClosingTest(unittest.TestCase):
    """Finding 62: no GOAWAY processing once the session is closing."""

    def test_peer_go_away_while_closing_is_ignored_without_side_effects(self):
        session, peer = _client_with_raw_server()
        try:
            unsent = session.open_stream()
            peer.send_frame(_go_away_frame(8, 6, 0, "first"))
            peer.barrier()
            self.assertIs(session.state, zmux.SessionState.DRAINING)
            budget = session._inbound_budget
            before = (
                budget.control.frames,
                budget.mixed.frames,
                budget.ignored_control.count,
            )
            received = session._received_frames
            with session._lock:
                session._state = zmux.SessionState.CLOSING
            try:
                # Stricter (would reclaim the unsent stream), increasing
                # (would be a PROTOCOL error) and a PING (would be answered).
                peer.send_frame(_go_away_frame(0, 0, 7, "second"))
                peer.send_frame(_go_away_frame(12, 10))
                peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"closing!"))
                peer.send_frame(zmux.Frame(zmux.FrameType.PING, 0, 0, b"closing?"))
                self.assertTrue(_wait_until(lambda: session._received_frames >= received + 4))
                self.assertIs(session.state, zmux.SessionState.CLOSING)
                self.assertEqual((session._peer_go_away_bidi, session._peer_go_away_uni), (8, 6))
                self.assertEqual(session.peer_go_away_error.reason, "first")
                self.assertFalse(unsent.closed)
                self.assertEqual(
                    (
                        budget.control.frames,
                        budget.mixed.frames,
                        budget.ignored_control.count,
                    ),
                    before,
                )
            finally:
                with session._lock:
                    session._state = zmux.SessionState.DRAINING
            peer.barrier()
            self.assertEqual(
                [f for f in peer.snapshot() if f.frame_type == zmux.FrameType.PONG
                 and f.payload.startswith(b"closing")],
                [],
            )
            self.assertIs(session.state, zmux.SessionState.DRAINING)
        finally:
            _close(session)
            peer.close()

    def test_local_go_away_while_closing_is_refused(self):
        session, peer = _client_with_raw_server()
        try:
            with session._lock:
                session._state = zmux.SessionState.CLOSING
            try:
                with self.assertRaises(zmux.SessionClosed):
                    session.go_away(0, 0)
                self.assertIs(session.state, zmux.SessionState.CLOSING)
                self.assertEqual(
                    (session._local_go_away_bidi, session._local_go_away_uni),
                    (zmux.MAX_VARINT62, zmux.MAX_VARINT62),
                )
            finally:
                with session._lock:
                    session._state = zmux.SessionState.READY
            peer.barrier()
            self.assertEqual(_go_aways(peer), [])
        finally:
            _close(session)
            peer.close()

    def test_go_away_racing_termination_changes_nothing(self):
        client, server = _session_pair()
        _close(client)
        self.assertTrue(_wait_until(lambda: client.closed))
        frame = _go_away_frame(0, 0, 9, "late")
        # The reader may already hold a frame read before the terminal commit.
        client._dispatch_frame(frame)
        parsed = zmux.parse_go_away_payload(frame.payload)
        client._handle_go_away(parsed)
        self.assertIs(client.state, zmux.SessionState.CLOSED)
        self.assertIsNone(client._peer_go_away_bidi)
        self.assertIsNone(client.peer_go_away_error)
        _close(server)


class GoAwayApiTest(unittest.TestCase):
    """Finding 63: GOAWAY API matches Go, Rust and Java."""

    def test_no_error_go_away_cause_is_reported_with_its_reason(self):
        client, server = _session_pair()
        try:
            server.go_away(0, 0, 0, "maintenance")
            self.assertTrue(_wait_until(lambda: client.state is zmux.SessionState.DRAINING))
            error = client.peer_go_away_error
            self.assertIsInstance(error, zmux.ApplicationError)
            self.assertEqual(error.code, int(zmux.ErrorCode.NO_ERROR))
            self.assertEqual(error.reason, "maintenance")
            self.assertIs(error.source, zmux.ErrorSource.REMOTE)
        finally:
            _close(client, server)

    def test_invalid_local_watermarks_are_local_close_errors(self):
        client, server = _session_pair()
        try:
            # 1 and 3 are server-created IDs; 6 is a unidirectional ID.
            for bidi, uni in ((1, 2), (4, 3), (6, 2), (4, 4)):
                with self.subTest(bidi=bidi, uni=uni):
                    with self.assertRaises(zmux.ProtocolError) as raised:
                        server.go_away(bidi, uni)
                    error = raised.exception
                    self.assertEqual(error.code, int(zmux.ErrorCode.PROTOCOL))
                    self.assertIs(error.source, zmux.ErrorSource.LOCAL)
                    self.assertIs(error.operation, zmux.ErrorOperation.CLOSE)
                    self.assertIs(error.scope, zmux.ErrorScope.SESSION)
            self.assertIs(server.state, zmux.SessionState.READY)
        finally:
            _close(client, server)

    def test_request_covered_by_an_earlier_go_away_is_a_no_op(self):
        session, peer = _server_with_raw_client()
        try:
            session.go_away(8, 6)
            self.assertIsNone(session.go_away(12, 10))
            self.assertIsNone(session.go_away(8, 6))
            peer.barrier()
            self.assertEqual(_go_aways(peer), [(8, 6)])
            self.assertEqual((session._local_go_away_bidi, session._local_go_away_uni), (8, 6))
        finally:
            _close(session)
            peer.close()

    def test_partially_increasing_request_still_raises_a_local_error(self):
        session, peer = _server_with_raw_client()
        try:
            session.go_away(8, 6)
            for bidi, uni in ((4, 10), (12, 2)):
                with self.subTest(bidi=bidi, uni=uni):
                    with self.assertRaises(zmux.ProtocolError) as raised:
                        session.go_away(bidi, uni)
                    self.assertIs(raised.exception.source, zmux.ErrorSource.LOCAL)
                    self.assertIs(raised.exception.operation, zmux.ErrorOperation.CLOSE)
                    self.assertEqual(raised.exception.code, int(zmux.ErrorCode.PROTOCOL))
            session.go_away(4, 2)
            peer.barrier()
            self.assertEqual(_go_aways(peer), [(8, 6), (4, 2)])
        finally:
            _close(session)
            peer.close()

    def test_peer_go_away_reclaims_provisionals_once(self):
        # Provisionals the peer's watermark leaves no ID for fail locally with
        # REFUSED_STREAM, each recorded once as an abort reason; nothing goes
        # on the wire for them.
        session, peer = _client_with_raw_server()
        try:
            kept = session.open_stream()
            reclaimed = (session.open_stream(), session.open_stream())
            peer.send_frame(_go_away_frame(4, 2))
            peer.barrier()
            self.assertIs(session.state, zmux.SessionState.DRAINING)
            for stream in reclaimed:
                self.assertTrue(stream.closed)
                with self.assertRaises(zmux.ApplicationError) as raised:
                    stream.write(b"late", timeout=1.0)
                self.assertEqual(raised.exception.code, int(zmux.ErrorCode.REFUSED_STREAM))
                self.assertIs(raised.exception.source, zmux.ErrorSource.REMOTE)
                self.assertEqual(stream.stream_id, 0)
            stats = session.stats
            self.assertEqual(stats.provisionals.bidi, 1)
            self.assertEqual(dict(stats.reasons.abort), {int(zmux.ErrorCode.REFUSED_STREAM): 2})
            kept.write_final(b"kept", timeout=1.0)
            self.assertIsNotNone(peer.wait_for(lambda f: f.stream_id == 4))
            peer.barrier()
            self.assertEqual(
                [f for f in peer.snapshot() if f.frame_type == zmux.FrameType.ABORT],
                [],
            )
            self.assertEqual(
                {f.stream_id for f in peer.snapshot() if f.stream_id != 0},
                {4},
            )
        finally:
            _close(session)
            peer.close()


class PingPayloadLimitTest(unittest.TestCase):
    """Finding 66: PING length is bounded by min(local, peer) limits."""

    def test_echo_over_the_local_limit_is_rejected_before_sending(self):
        client, server = _session_pair(
            server_config=zmux.Config(settings=zmux.Settings(max_control_payload_bytes=16384)),
        )
        try:
            nonce_state = client._ping_state.ping_nonce_state
            with self.assertRaises(zmux.FrameSizeError) as raised:
                client.ping(b"x" * (4096 - 8 + 1), timeout=1.0)
            error = raised.exception
            self.assertEqual(error.code, int(zmux.ErrorCode.FRAME_SIZE))
            self.assertIs(error.operation, zmux.ErrorOperation.PING)
            self.assertIs(error.source, zmux.ErrorSource.LOCAL)
            self.assertEqual(client._ping_state.ping_nonce_state, nonce_state)
            self.assertEqual(client._pings, {})
            self.assertGreaterEqual(client.ping(b"x" * (4096 - 8), timeout=2.0), 0.0)
            self.assertEqual(server._inbound_budget.inbound_ping.count, 1)
            self.assertIs(client.state, zmux.SessionState.READY)
            self.assertIs(server.state, zmux.SessionState.READY)
        finally:
            _close(client, server)

    def test_echo_over_the_peer_limit_raises_frame_size_not_value_error(self):
        client, server = _session_pair(
            client_config=zmux.Config(settings=zmux.Settings(max_control_payload_bytes=16384)),
        )
        try:
            with self.assertRaises(zmux.FrameSizeError):
                client.ping(b"x" * 5000, timeout=1.0)
            self.assertGreaterEqual(client.ping(b"x" * (4096 - 8), timeout=2.0), 0.0)
            self.assertIs(server.state, zmux.SessionState.READY)
        finally:
            _close(client, server)


def _pings(peer):
    return [f for f in peer.snapshot() if f.frame_type == zmux.FrameType.PING]


class SinglePingSlotTest(unittest.TestCase):
    """Finding 68: at most one locally originated PING is outstanding."""

    def test_concurrent_pings_never_overlap_on_a_silent_peer(self):
        session, peer = _client_with_raw_server()
        try:
            first, first_result = _run(session.ping, timeout=1.0)
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PING))
            observed = []
            stop = threading.Event()

            def monitor():
                while not stop.is_set():
                    observed.append(len(session._pings))
                    time.sleep(0.001)

            watcher = threading.Thread(target=monitor, daemon=True)
            watcher.start()
            others = [_run(session.ping, timeout=0.3) for _ in range(4)]
            started = time.monotonic()
            for thread, _ in others:
                thread.join(2.0)
            elapsed = time.monotonic() - started
            first.join(2.0)
            stop.set()
            watcher.join(1.0)
            for _, result in others + [(first, first_result)]:
                self.assertIsInstance(result.get("error"), zmux.PingTimeout)
            self.assertLess(elapsed, 1.0)
            self.assertLessEqual(max(observed), 1)
            self.assertEqual(len(_pings(peer)), 1)
            self.assertIs(session.state, zmux.SessionState.READY)
        finally:
            _close(session)
            peer.close()

    def test_user_ping_waits_for_an_outstanding_keepalive_ping(self):
        session, peer = _client_with_raw_server(keepalive_interval=0.05)
        try:
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PING))
            with self.assertRaises(zmux.PingTimeout):
                session.ping(timeout=0.2)
            self.assertEqual(len(_pings(peer)), 1)
            self.assertLessEqual(len(session._pings), 1)
        finally:
            _close(session)
            peer.close()

    def test_waiting_ping_proceeds_once_the_slot_frees(self):
        session, peer = _client_with_raw_server(ping_padding=False)
        try:
            first, first_result = _run(session.ping, b"one", timeout=3.0)
            ping_one = peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PING)
            self.assertIsNotNone(ping_one)
            second, second_result = _run(session.ping, b"two", timeout=3.0)
            time.sleep(0.1)
            self.assertEqual(len(_pings(peer)), 1)
            peer.send_frame(zmux.Frame(zmux.FrameType.PONG, 0, 0, ping_one.payload))
            first.join(2.0)
            self.assertNotIn("error", first_result)
            ping_two = peer.wait_for(
                lambda f: f.frame_type == zmux.FrameType.PING and f.payload[8:] == b"two"
            )
            self.assertIsNotNone(ping_two)
            peer.send_frame(zmux.Frame(zmux.FrameType.PONG, 0, 0, ping_two.payload))
            second.join(2.0)
            self.assertNotIn("error", second_result)
            self.assertGreaterEqual(second_result["value"], 0.0)
            self.assertEqual(len(_pings(peer)), 2)
        finally:
            _close(session)
            peer.close()

    def test_waiting_ping_fails_with_the_session_error(self):
        session, peer = _client_with_raw_server()
        try:
            first, _ = _run(session.ping, timeout=3.0)
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.PING))
            second, second_result = _run(session.ping, timeout=3.0)
            time.sleep(0.05)
            session.close_with_error(42, "bye")
            second.join(2.0)
            first.join(2.0)
            self.assertFalse(second.is_alive())
            self.assertIsInstance(second_result.get("error"), zmux.ApplicationError)
            self.assertEqual(second_result["error"].code, 42)
            self.assertEqual(len(_pings(peer)), 1)
        finally:
            _close(session)
            peer.close()


_SEED_PROBE = r"""
import socket, threading, zmux
from zmux._runtime.keepalive import init_keepalive_jitter_state
left, right = socket.socketpair()
result = {}
thread = threading.Thread(target=lambda: result.setdefault("server", zmux.server(right)))
thread.start()
client = zmux.client(left)
thread.join()
server = result["server"]
print(
    client._ping_state.ping_nonce_state,
    client._ping_state.keepalive_jitter_state,
    server._ping_state.ping_nonce_state,
    server._ping_state.keepalive_jitter_state,
    init_keepalive_jitter_state(0),
)
client.close_with_error(0)
server.close_with_error(0)
"""


class _SeededSource(object):
    def __init__(self, seed):
        self.seed = seed

    def __call__(self, n):
        return bytes(range(1, n + 1))


class _DeterministicSource(object):
    def __init__(self, seed):
        self._random = random.Random(seed)

    def __call__(self, n):
        return bytes(self._random.getrandbits(8) for _ in range(n))


class LivenessSeedTest(unittest.TestCase):
    """Finding 70 / DESIGN D11: per-session PRNG seeds."""

    def _probe(self):
        env = dict(os.environ)
        src = os.path.dirname(os.path.dirname(os.path.abspath(zmux.__file__)))
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        output = subprocess.run(
            [sys.executable, "-c", _SEED_PROBE],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.split()
        return [int(value) for value in output]

    def test_fresh_processes_draw_independent_seeds(self):
        first = self._probe()
        second = self._probe()
        self.assertEqual(len(first), 5)
        # Session N of every process used to draw the same counter values.
        for index, (a, b) in enumerate(zip(first, second)):
            self.assertNotEqual(a, b, index)
        self.assertEqual(len(set(first[:4])), 4)

    def test_nonce_source_drives_the_seeds(self):
        states = []
        for _ in range(2):
            client, server = _session_pair(
                client_config=zmux.Config(nonce_source=_DeterministicSource(7)),
            )
            try:
                states.append(
                    (
                        client._ping_state.ping_nonce_state,
                        client._ping_state.keepalive_jitter_state,
                    )
                )
            finally:
                _close(client, server)
        self.assertEqual(states[0], states[1])
        self.assertNotEqual(states[0][0], states[0][1])

    def test_explicit_seed_hook_is_preserved(self):
        jitter_states = []
        for _ in range(2):
            client, server = _session_pair(
                client_config=zmux.Config(nonce_source=_SeededSource(0x1234)),
            )
            try:
                self.assertEqual(client._ping_state.ping_nonce_state, 0x1234)
                # Already advanced by the initial keepalive schedule draws.
                jitter_states.append(client._ping_state.keepalive_jitter_state)
            finally:
                _close(client, server)
        self.assertEqual(jitter_states[0], jitter_states[1])

    def test_failing_nonce_source_falls_back_to_the_csprng(self):
        from zmux._runtime.keepalive import session_liveness_seed

        def broken(n):
            raise OSError("no entropy")

        seeds = {session_liveness_seed(broken) for _ in range(8)}
        self.assertEqual(len(seeds), 8)
        self.assertNotIn(0, seeds)


class PartialWriteProgressTest(unittest.TestCase):
    """Finding 79: a failed write reports the bytes it already queued."""

    def _client(self):
        return _client_with_raw_server(
            zmux.Settings(initial_max_stream_data_bidi_peer_opened=4),
        )

    def _payload(self, peer, stream_id):
        return b"".join(
            f.payload
            for f in peer.snapshot()
            if f.frame_type == zmux.FrameType.DATA and f.stream_id == stream_id
        )

    def test_write_timeout_after_partial_progress_carries_the_count(self):
        session, peer = self._client()
        try:
            for name, call in (
                ("write", lambda s: s.write(b"abcdefgh", timeout=0.3)),
                ("write_vectored", lambda s: s.write_vectored([b"ABC", b"DEFGH"], timeout=0.3)),
                ("write_final", lambda s: s.write_final(b"01234567", timeout=0.3)),
            ):
                with self.subTest(call=name):
                    stream = session.open_stream()
                    with self.assertRaises(zmux.WriteTimeout) as raised:
                        call(stream)
                    self.assertEqual(raised.exception.characters_written, 4)
                    peer.barrier()
                    self.assertEqual(len(self._payload(peer, stream.stream_id)), 4)
                    # Nothing more can be queued: no count on the next failure.
                    with self.assertRaises(zmux.WriteTimeout) as again:
                        stream.write(b"x", timeout=0.05)
                    self.assertFalse(hasattr(again.exception, "characters_written"))
        finally:
            _close(session)
            peer.close()

    def test_retry_after_partial_write_does_not_duplicate_bytes(self):
        session, peer = self._client()
        try:
            stream = session.open_stream()
            data = b"abcdefgh"
            try:
                stream.write(data, timeout=0.3)
            except zmux.WriteTimeout as exc:
                data = data[exc.characters_written:]
            peer.barrier()
            peer.send_frame(
                zmux.Frame(zmux.FrameType.MAX_DATA, stream.stream_id, 0, zmux.encode_varint(1000))
            )
            stream.write(data, timeout=2.0)
            peer.barrier()
            self.assertEqual(self._payload(peer, stream.stream_id), b"abcdefgh")
        finally:
            _close(session)
            peer.close()

    def test_stored_stream_error_is_not_mutated(self):
        session, peer = self._client()
        try:
            stream = session.open_stream()
            writer, result = _run(stream.write, b"abcdefgh", timeout=3.0)
            self.assertIsNotNone(
                peer.wait_for(
                    lambda f: f.frame_type == zmux.FrameType.DATA
                    and f.stream_id == stream.stream_id
                    and f.payload
                )
            )
            peer.send_frame(
                zmux.Frame(
                    zmux.FrameType.STOP_SENDING,
                    stream.stream_id,
                    0,
                    zmux.build_error_payload(9, ""),
                )
            )
            writer.join(2.0)
            error = result.get("error")
            self.assertIsInstance(error, zmux.ZmuxError)
            self.assertEqual(error.characters_written, 4)
            with self.assertRaises(zmux.ZmuxError) as again:
                stream.write(b"x", timeout=0.5)
            self.assertIs(type(again.exception), type(error))
            self.assertFalse(hasattr(again.exception, "characters_written"))
        finally:
            _close(session)
            peer.close()


if __name__ == "__main__":
    unittest.main()
