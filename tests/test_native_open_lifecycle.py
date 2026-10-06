"""Local open, peer open admission and graceful-close lifecycle regressions.

The native session used to commit a local stream ID before checking that the
opener could carry its metadata and before the opener was queued, so a
rejected ``open_info`` or a concurrent first write on another stream put a
later stream ID on the wire first and the peer failed the session.  It also
let ``update_metadata`` race the opener and only change the local snapshot,
reported a cleared stream group as ``0``, kept admitting local opens during
its own graceful close, kept that close waiting for unaccepted, unread or
never-written streams, counted fully terminal queued peer streams against
``max_incoming_streams``, rejected (or consumed) peer opens above its own
GOAWAY watermark with the wrong outcome, and never started a GOAWAY when a
local stream-ID class ran out.  These tests drive real sessions over
``socket.socketpair``, using a raw zmux peer where exact frames matter.
"""

import socket
import sys
import threading
import time
import unittest
from unittest import mock

import zmux
from zmux import native

_LAST_CLIENT_BIDI_ID = (1 << 62) - 4


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


def _data(stream_id, payload, flags=0):
    return zmux.Frame(zmux.FrameType.DATA, stream_id, flags, payload)


def _error_frame(frame_type, stream_id, code):
    return zmux.Frame(frame_type, stream_id, 0, zmux.build_error_payload(code, ""))


def _varint_frame(frame_type, stream_id, value):
    return zmux.Frame(frame_type, stream_id, 0, zmux.encode_varint(value))


def _error_code(frame):
    code, _ = zmux.parse_error_payload(frame.payload)
    return code


def _frames_of(peer, frame_type, stream_id=None):
    return [
        frame
        for frame in peer.snapshot()
        if frame.frame_type == frame_type
        and (stream_id is None or frame.stream_id == stream_id)
    ]


def _is_close(code):
    return lambda frame: (
        frame.frame_type == zmux.FrameType.CLOSE and _error_code(frame) == int(code)
    )


class _PrefixGate(object):
    """Park one named writer thread inside the opener's prefix build."""

    def __init__(self, thread_name):
        self.thread_name = thread_name
        self.entered = threading.Event()
        self.release = threading.Event()
        self._build = native.build_open_metadata_prefix

    def __call__(self, *args, **kwargs):
        if threading.current_thread().name == self.thread_name and not self.entered.is_set():
            self.entered.set()
            self.release.wait(5.0)
        return self._build(*args, **kwargs)

    def install(self):
        return mock.patch.object(native, "build_open_metadata_prefix", self)


def _named_thread(name, target, *args, **kwargs):
    result = {}

    def runner():
        try:
            result["value"] = target(*args, **kwargs)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=runner, name=name, daemon=True)
    thread.start()
    return thread, result


class OpenMetadataValidationTest(unittest.TestCase):
    """Finding 50: a rejected opener never consumes a stream ID."""

    def _assert_next_streams_are_first_ids(self, client, server):
        bidi = client.open_stream()
        bidi.write(b"y", timeout=1.0)
        uni = client.open_uni_stream()
        uni.write_final(b"u", timeout=1.0)
        self.assertEqual((bidi.stream_id, uni.stream_id), (4, 2))
        accepted = server.accept_stream(timeout=1.0)
        self.assertEqual(accepted.stream_id, 4)
        self.assertEqual(accepted.read_exact(1, timeout=1.0), b"y")
        accepted_uni = server.accept_uni_stream(timeout=1.0)
        self.assertEqual(accepted_uni.stream_id, 2)
        self.assertEqual(accepted_uni.read(timeout=1.0), b"u")
        self.assertEqual(server.state, zmux.SessionState.READY)
        self.assertEqual(client.state, zmux.SessionState.READY)

    def test_open_info_without_negotiated_open_metadata_fails_at_open(self):
        client, server = _session_pair(server_config=zmux.Config(disable_capabilities=True))
        try:
            attempts = (
                lambda: client.open_stream(zmux.OpenOptions(open_info=b"z")),
                lambda: client.open_uni_stream(zmux.OpenOptions(open_info=b"z")),
                lambda: client.open_and_send(b"x", zmux.OpenOptions(open_info=b"z")),
                lambda: client.open_uni_and_send(b"x", zmux.OpenOptions(open_info=b"z")),
            )
            for attempt in attempts:
                with self.assertRaises(zmux.OpenInfoUnavailable) as raised:
                    attempt()
                self.assertTrue(zmux.open_info_unavailable(raised.exception))
                self.assertEqual(raised.exception.operation, zmux.ErrorOperation.OPEN)
            self.assertEqual(client.stats.provisionals.bidi, 0)
            self.assertEqual(client.stats.provisionals.uni, 0)
            self._assert_next_streams_are_first_ids(client, server)
        finally:
            _close(client, server)

    def test_oversized_open_metadata_fails_at_open(self):
        client, server = _session_pair()
        try:
            options = zmux.OpenOptions(open_info=b"z" * 20000)
            attempts = (
                lambda: client.open_stream(options),
                lambda: client.open_uni_stream(options),
                lambda: client.open_and_send(b"x", options),
                lambda: client.open_uni_and_send(b"x", options),
            )
            for attempt in attempts:
                with self.assertRaises(zmux.OpenMetadataTooLarge) as raised:
                    attempt()
                self.assertTrue(zmux.open_metadata_too_large(raised.exception))
            self.assertEqual((client._next_bidi, client._next_uni), (4, 2))
            self._assert_next_streams_are_first_ids(client, server)
        finally:
            _close(client, server)

    def test_unsendable_metadata_found_at_first_write_drops_the_provisional_stream(self):
        client, server = _session_pair()
        try:
            stream = client.open_stream()
            # Bypass open-time validation: the write must still fail before
            # the stream ID is committed.
            stream._metadata = zmux.StreamMetadata(open_info=b"z" * 20000)
            with self.assertRaises(zmux.OpenMetadataTooLarge):
                stream.write(b"x", timeout=1.0)
            self.assertEqual(stream.stream_id, 0)
            self.assertEqual(client.stats.provisionals.bidi, 0)
            uni = client.open_uni_stream()
            uni.write_final(b"u", timeout=1.0)
            bidi = client.open_stream()
            bidi.write(b"y", timeout=1.0)
            self.assertEqual(bidi.stream_id, 4)
            self.assertEqual(server.accept_stream(timeout=1.0).stream_id, 4)
            self.assertEqual(server.state, zmux.SessionState.READY)
        finally:
            _close(client, server)

    def test_pre_open_metadata_update_is_validated_against_the_opener(self):
        client, server = _session_pair()
        try:
            # 16365 prefix bytes fit the default 16384-byte frame; maximal
            # priority and group TLVs would not.
            open_info = b"z" * 16360
            stream = client.open_stream(zmux.OpenOptions(open_info=open_info))
            with self.assertRaises(zmux.OpenMetadataTooLarge):
                stream.update_metadata(
                    zmux.MetadataUpdate(priority=(1 << 62) - 1, group=(1 << 62) - 1)
                )
            self.assertIsNone(stream.metadata.priority)
            stream.write(b"y", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual((inbound.stream_id, inbound.open_info), (4, open_info))
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"y")
        finally:
            _close(client, server)


class OpenerOrderingTest(unittest.TestCase):
    """Finding 71: openers of one class reach the wire in stream-ID order."""

    def setUp(self):
        # A tiny GIL switch interval widens any window between assigning a
        # stream ID and queueing that stream's opener.
        self._switch_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)

    def tearDown(self):
        sys.setswitchinterval(self._switch_interval)

    def _concurrent_opens(self, threads, payload_len, server_config=None, priorities=False):
        client, server = _session_pair(server_config=server_config, client_config=server_config)
        accepted = []
        received = {}
        errors = []

        def serve():
            readers = []
            try:
                for _ in range(threads):
                    stream = server.accept_stream(timeout=5.0)
                    accepted.append(stream.stream_id)
                    reader = threading.Thread(target=drain, args=(stream,), daemon=True)
                    reader.start()
                    readers.append(reader)
            except BaseException as exc:
                errors.append(exc)
            for reader in readers:
                reader.join(5.0)

        def drain(stream):
            try:
                received[stream.stream_id] = len(stream.read_exact(payload_len, timeout=5.0))
            except BaseException as exc:
                errors.append(exc)

        start = threading.Barrier(threads)

        def open_and_write(index):
            options = zmux.OpenOptions(initial_priority=index % 16) if priorities else None
            stream = client.open_stream(options)
            start.wait(5.0)
            stream.write(b"x" * payload_len, timeout=5.0)

        server_thread = threading.Thread(target=serve, daemon=True)
        server_thread.start()
        writers = [_run(open_and_write, index) for index in range(threads)]
        try:
            for thread, result in writers:
                thread.join(10.0)
                if "error" in result:
                    errors.append(result["error"])
            server_thread.join(10.0)
            self.assertEqual(errors, [])
            self.assertEqual(server.state, zmux.SessionState.READY)
            self.assertEqual(client.state, zmux.SessionState.READY)
            self.assertEqual(accepted, sorted(accepted))
            self.assertEqual(len(set(accepted)), threads)
            self.assertEqual(set(received.values()), {payload_len})
        finally:
            _close(client, server)

    def test_many_concurrent_first_writes_keep_stream_ids_in_order(self):
        for _ in range(4):
            self._concurrent_opens(60, 100)

    def test_few_concurrent_first_writes_keep_stream_ids_in_order(self):
        for _ in range(20):
            self._concurrent_opens(8, 100)

    def test_concurrent_first_writes_with_mixed_priorities_keep_stream_ids_in_order(self):
        for _ in range(4):
            self._concurrent_opens(32, 100, priorities=True)

    def test_concurrent_first_writes_larger_than_the_windows_keep_stream_ids_in_order(self):
        config = zmux.Config(
            settings=zmux.Settings(
                initial_max_data=16384,
                initial_max_stream_data_bidi_peer_opened=4096,
            )
        )
        for _ in range(3):
            self._concurrent_opens(16, 40000, server_config=config)

    def test_nothing_between_id_commit_and_opener_can_delay_the_opener(self):
        # The first stream's writer is parked while it prepares its opener;
        # the second stream must not get a stream ID (or reach the wire)
        # ahead of it.
        client, server = _session_pair()
        gate = _PrefixGate("writer-a")
        try:
            first = client.open_stream()
            second = client.open_stream()
            with gate.install():
                writer_a, result_a = _named_thread("writer-a", first.write, b"a" * 10, timeout=5.0)
                self.assertTrue(gate.entered.wait(2.0))
                writer_b, result_b = _named_thread("writer-b", second.write, b"b" * 10, timeout=5.0)
                time.sleep(0.1)
                self.assertTrue(writer_b.is_alive())
                gate.release.set()
                writer_a.join(2.0)
                writer_b.join(2.0)
            self.assertNotIn("error", result_a)
            self.assertNotIn("error", result_b)
            self.assertEqual((first.stream_id, second.stream_id), (4, 8))
            inbound_a = server.accept_stream(timeout=1.0)
            inbound_b = server.accept_stream(timeout=1.0)
            self.assertEqual((inbound_a.stream_id, inbound_b.stream_id), (4, 8))
            self.assertEqual(inbound_a.read_exact(10, timeout=1.0), b"a" * 10)
            self.assertEqual(inbound_b.read_exact(10, timeout=1.0), b"b" * 10)
            self.assertEqual(server.state, zmux.SessionState.READY)
        finally:
            gate.release.set()
            _close(client, server)

    def test_terminal_operation_on_a_fresh_stream_sends_the_opener_first(self):
        session, peer = _client_with_raw_server()
        try:
            aborted = session.open_stream()
            stopped = session.open_stream()
            written = session.open_stream()
            # A provisional stream is dropped locally and never reaches the
            # wire; a stream committed by a terminal operation gets its
            # opener first, in ID order.
            aborted.close_with_error(int(zmux.ErrorCode.CANCELLED))
            stopped.cancel_read(int(zmux.ErrorCode.CANCELLED))
            written.write(b"w", timeout=1.0)
            peer.barrier()
            self.assertEqual(aborted.stream_id, 0)
            self.assertEqual((stopped.stream_id, written.stream_id), (4, 8))
            self.assertEqual(
                [
                    (frame.frame_type, frame.stream_id)
                    for frame in peer.snapshot()
                    if frame.stream_id != 0
                ],
                [
                    (zmux.FrameType.DATA, 4),
                    (zmux.FrameType.STOP_SENDING, 4),
                    (zmux.FrameType.DATA, 8),
                ],
            )
        finally:
            _close(session)
            peer.close()


class ProvisionalWaitAgeTest(unittest.TestCase):
    def test_waiter_does_not_age_behind_an_abandoned_head(self):
        # Two streams opened at the same instant; the first is abandoned and
        # about to expire.  The second waits behind it to commit: that wait is
        # not idle provisional time, so it opens once the head expires instead
        # of expiring with it.
        client, server = _session_pair()
        try:
            abandoned = client.open_stream()
            writer = client.open_stream()
            with client._lock:
                created = (
                    time.monotonic()
                    - native.provisional_open_max_age(client._last_ping_rtt)
                    + 0.2
                )
                abandoned._provisional_created_at = created
                writer._provisional_created_at = created

            writer.write(b"w", timeout=5.0)
            with self.assertRaises(zmux.OpenExpired):
                abandoned.write(b"late")

            accepted = server.accept_stream(timeout=2.0)
            self.assertEqual(accepted.stream_id, writer.stream_id)
            self.assertEqual(accepted.read_exact(1, timeout=2.0), b"w")
        finally:
            _close(client, server)


class ProvisionalStatsTest(unittest.TestCase):
    """The provisional limited/expired counters (zmux-go session stats)."""

    def test_provisional_cap_refusals_count_as_limited(self):
        client, server = _session_pair(
            client_config=zmux.Config(max_provisional_streams_bidi=1)
        )
        try:
            client.open_stream()
            for expected in (1, 2):
                with self.assertRaises(zmux.OpenLimited):
                    client.open_stream()
                self.assertEqual(client.stats.provisionals.limited, expected)
            self.assertEqual(client.stats.provisionals.expired, 0)
        finally:
            _close(client, server)

    def test_expired_provisional_is_counted_once(self):
        client, server = _session_pair()
        try:
            abandoned = client.open_stream()
            with client._lock:
                abandoned._provisional_created_at = (
                    time.monotonic()
                    - native.provisional_open_max_age(client._last_ping_rtt)
                    - 1.0
                )
            # The next open reaps the expired head.
            fresh = client.open_stream()
            self.assertEqual(client.stats.provisionals.expired, 1)
            with self.assertRaises(zmux.OpenExpired):
                abandoned.write(b"late")
            fresh.write(b"ok", timeout=1.0)
            accepted = server.accept_stream(timeout=1.0)
            self.assertEqual(accepted.read_exact(2, timeout=1.0), b"ok")
            stats = client.stats.provisionals
            self.assertEqual((stats.expired, stats.limited, stats.bidi), (1, 0, 0))
        finally:
            _close(client, server)

    def test_stream_id_exhaustion_is_not_counted_as_limited(self):
        # As in zmux-go, only provisional-capacity refusals count.
        session, peer = _client_with_raw_server()
        try:
            with session._lock:
                session._next_bidi = _LAST_CLIENT_BIDI_ID + 4
            with self.assertRaises(zmux.OpenLimited):
                session.open_stream()
            self.assertEqual(session.stats.provisionals.limited, 0)
        finally:
            _close(session)
            peer.close()


class MetadataUpdateRaceTest(unittest.TestCase):
    """Findings 56 and 54: metadata updates reach the peer and normalize group 0."""

    def test_update_during_first_write_reaches_the_peer(self):
        client, server = _session_pair()
        gate = _PrefixGate("writer")
        try:
            stream = client.open_stream()
            with gate.install():
                writer, written = _named_thread("writer", stream.write, b"x", timeout=5.0)
                self.assertTrue(gate.entered.wait(2.0))
                updater, updated = _run(stream.update_metadata, zmux.MetadataUpdate(priority=9))
                time.sleep(0.05)
                # Serialized with the in-progress write, like Go's permit.
                self.assertTrue(updater.is_alive())
                gate.release.set()
                writer.join(2.0)
                updater.join(2.0)
            self.assertNotIn("error", written)
            self.assertNotIn("error", updated)
            self.assertEqual(stream.metadata.priority, 9)
            inbound = server.accept_stream(timeout=1.0)
            self.assertTrue(_wait_until(lambda: inbound.metadata.priority == 9, 1.0))
        finally:
            gate.release.set()
            _close(client, server)

    def test_update_waiting_behind_a_write_honours_the_write_deadline(self):
        client, server = _session_pair()
        gate = _PrefixGate("writer")
        try:
            stream = client.open_stream()
            with gate.install():
                writer, written = _named_thread("writer", stream.write, b"x")
                self.assertTrue(gate.entered.wait(2.0))
                stream.set_write_timeout(0.05)
                started = time.monotonic()
                with self.assertRaises(zmux.WriteTimeout):
                    stream.update_metadata(zmux.MetadataUpdate(priority=3))
                self.assertLess(time.monotonic() - started, 1.0)
                stream.set_write_deadline(None)
                gate.release.set()
                writer.join(2.0)
            self.assertNotIn("error", written)
            self.assertIsNone(stream.metadata.priority)
        finally:
            gate.release.set()
            _close(client, server)

    def test_group_zero_clears_the_group_on_both_sides(self):
        client, server = _session_pair()
        try:
            stream = client.open_stream(zmux.OpenOptions(initial_group=5, initial_priority=1))
            stream.write(b"hi", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.metadata.group, 5)

            # A priority-only update leaves the group alone.
            stream.update_metadata(zmux.MetadataUpdate(priority=7))
            self.assertTrue(_wait_until(lambda: inbound.metadata.priority == 7, 1.0))
            self.assertEqual(inbound.metadata.group, 5)

            stream.update_metadata(zmux.MetadataUpdate(group=0))
            self.assertIsNone(stream.metadata.group)
            self.assertTrue(_wait_until(lambda: inbound.metadata.group != 5, 1.0))
            self.assertIsNone(inbound.metadata.group)
            self.assertEqual(inbound.metadata.priority, 7)
        finally:
            _close(client, server)

    def test_group_zero_at_open_or_before_the_opener_is_no_group(self):
        client, server = _session_pair()
        try:
            opened = client.open_stream(zmux.OpenOptions(initial_group=0, initial_priority=1))
            self.assertIsNone(opened.metadata.group)
            opened.write(b"a", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertIsNone(inbound.metadata.group)
            self.assertEqual(inbound.metadata.priority, 1)

            updated = client.open_stream(zmux.OpenOptions(initial_group=6))
            updated.update_metadata(zmux.MetadataUpdate(group=0))
            self.assertIsNone(updated.metadata.group)
            updated.write(b"b", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertIsNone(inbound.metadata.group)
        finally:
            _close(client, server)

    def test_received_group_zero_is_stored_as_no_group(self):
        session, peer = _server_with_raw_client()
        try:
            prefix = zmux.build_open_metadata_prefix(zmux.DEFAULT_CAPABILITIES, group=5)
            peer.send_frame(_data(4, prefix + b"x", zmux.FRAME_FLAG_OPEN_METADATA))
            inbound = session.accept_stream(timeout=1.0)
            self.assertEqual(inbound.metadata.group, 5)
            payload = zmux.build_priority_update_payload(
                zmux.DEFAULT_CAPABILITIES,
                zmux.MetadataUpdate(group=0),
            )
            peer.send_frame(zmux.Frame(zmux.FrameType.EXT, 4, 0, payload))
            peer.barrier()
            self.assertIsNone(inbound.metadata.group)
        finally:
            _close(session)
            peer.close()


class GracefulCloseOpenAdmissionTest(unittest.TestCase):
    """Finding 24: a local graceful close stops admitting local opens."""

    def test_opens_during_graceful_drain_fail_and_the_drain_completes(self):
        config = zmux.Config(graceful_close_drain_timeout=2.0, keepalive_interval=None)
        client, server = _session_pair(server_config=config, client_config=config)
        try:
            outbound = client.open_stream()
            outbound.write(b"x", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"x")
            started = time.monotonic()
            closer, closed = _run(client.close)
            self.assertTrue(
                _wait_until(
                    lambda: client._graceful_close_active
                    and client.state is zmux.SessionState.DRAINING
                )
            )
            attempts = (
                client.open_stream,
                client.open_uni_stream,
                lambda: client.open_and_send(b"y"),
                lambda: client.open_uni_and_send(b"y"),
            )
            for attempt in attempts:
                with self.assertRaises(zmux.SessionClosed) as raised:
                    attempt()
                self.assertEqual(raised.exception.operation, zmux.ErrorOperation.OPEN)
            with self.assertRaises(zmux.AcceptTimeout):
                server.accept_stream(timeout=0.2)

            outbound.close_write()
            self.assertEqual(inbound.read(timeout=1.0), b"")
            inbound.close_write()
            closer.join(3.0)
            self.assertFalse(closer.is_alive())
            self.assertNotIn("error", closed)
            self.assertLess(time.monotonic() - started, 1.5)
        finally:
            _close(client, server)

    def test_open_is_refused_while_closing(self):
        client, server = _session_pair()
        try:
            with client._lock:
                client._state = zmux.SessionState.CLOSING
            try:
                with self.assertRaises(zmux.SessionClosed):
                    client.open_stream()
            finally:
                with client._lock:
                    client._state = zmux.SessionState.READY
            # A peer GOAWAY alone keeps local opens below its watermark.
            server.go_away(_LAST_CLIENT_BIDI_ID, (1 << 62) - 2)
            self.assertTrue(_wait_until(lambda: client.state is zmux.SessionState.DRAINING))
            stream = client.open_stream()
            stream.write(b"ok", timeout=1.0)
            self.assertEqual(server.accept_stream(timeout=1.0).read_exact(2, timeout=1.0), b"ok")
        finally:
            _close(client, server)


class GracefulDrainScopeTest(unittest.TestCase):
    """Finding 59: graceful close only waits for outstanding local send work."""

    def _assert_close_is_prompt(self, session):
        started = time.monotonic()
        session.close()
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertEqual(session.stats.diagnostics.graceful_close_timeouts, 0)

    def test_never_written_local_opens_are_refused_instead_of_waited_for(self):
        client, server = _session_pair()
        try:
            bidi = client.open_stream()
            uni = client.open_uni_stream()
            self._assert_close_is_prompt(client)
            for stream in (bidi, uni):
                with self.assertRaises(zmux.ApplicationError) as raised:
                    stream.write(b"late", timeout=0.1)
                self.assertEqual(raised.exception.code, int(zmux.ErrorCode.REFUSED_STREAM))
                self.assertEqual(stream.stream_id, 0)
        finally:
            _close(client, server)

    def test_writer_waiting_for_its_commit_turn_is_refused(self):
        client, server = _session_pair()
        try:
            client.open_stream()
            second = client.open_stream()
            writer, result = _run(second.write, b"x", timeout=5.0)
            time.sleep(0.05)
            self.assertTrue(writer.is_alive())
            self._assert_close_is_prompt(client)
            writer.join(1.0)
            self.assertIsInstance(result.get("error"), zmux.ApplicationError)
            self.assertEqual(result["error"].code, int(zmux.ErrorCode.REFUSED_STREAM))
            # No stream ID reached the peer.
            self.assertEqual(server._next_peer_bidi, 4)
        finally:
            _close(client, server)

    def test_unread_peer_uni_stream_does_not_delay_close(self):
        client, server = _session_pair()
        try:
            sender = server.open_uni_stream()
            sender.write(b"peer", timeout=1.0)
            inbound = client.accept_uni_stream(timeout=1.0)
            self.assertFalse(inbound.closed)
            self._assert_close_is_prompt(client)
        finally:
            _close(client, server)

    def test_unaccepted_peer_streams_do_not_delay_close(self):
        client, server = _session_pair()
        try:
            server.open_and_send(b"bidi", timeout=1.0)
            server.open_uni_and_send(b"uni", timeout=1.0)
            self.assertTrue(_wait_until(lambda: client.stats.accept_backlog.count == 2))
            self._assert_close_is_prompt(client)
        finally:
            _close(client, server)

    def test_peer_bidi_stream_without_local_send_does_not_delay_close(self):
        client, server = _session_pair()
        try:
            server.open_and_send(b"request", timeout=1.0).close_write()
            inbound = client.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read(timeout=1.0), b"request")
            self._assert_close_is_prompt(client)
        finally:
            _close(client, server)

    def test_peer_bidi_stream_with_open_local_send_half_still_delays_close(self):
        config = zmux.Config(graceful_close_drain_timeout=0.2, keepalive_interval=None)
        client, server = _session_pair(server_config=config, client_config=config)
        try:
            server.open_and_send(b"request", timeout=1.0)
            inbound = client.accept_stream(timeout=1.0)
            inbound.write(b"reply", timeout=1.0)
            started = time.monotonic()
            with self.assertRaises(zmux.GracefulCloseTimeout):
                client.close()
            self.assertGreaterEqual(time.monotonic() - started, 0.2)
            self.assertEqual(client.stats.diagnostics.graceful_close_timeouts, 1)
        finally:
            _close(client, server)

    def test_local_stream_with_open_send_half_still_delays_close(self):
        config = zmux.Config(graceful_close_drain_timeout=0.2, keepalive_interval=None)
        client, server = _session_pair(server_config=config, client_config=config)
        try:
            client.open_stream().write(b"x", timeout=1.0)
            with self.assertRaises(zmux.GracefulCloseTimeout):
                client.close()
        finally:
            _close(client, server)

    def test_local_request_awaiting_its_response_delays_close_until_it_arrives(self):
        # The request's send half is finished, but a locally opened stream
        # keeps the drain open until it is fully terminal, so the response is
        # not cut off by the final CLOSE.
        config = zmux.Config(graceful_close_drain_timeout=2.0, keepalive_interval=None)
        client, server = _session_pair(server_config=config, client_config=config)
        try:
            request = client.open_stream()
            request.write_final(b"req", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(3, timeout=1.0), b"req")
            started = time.monotonic()
            closer, closed = _run(client.close)
            self.assertTrue(_wait_until(lambda: client.state is zmux.SessionState.DRAINING))
            time.sleep(0.1)
            self.assertTrue(closer.is_alive())
            inbound.write_final(b"resp", timeout=1.0)
            self.assertEqual(request.read_exact(4, timeout=1.0), b"resp")
            self.assertEqual(request.read(timeout=1.0), b"")
            closer.join(2.0)
            self.assertFalse(closer.is_alive())
            self.assertNotIn("error", closed)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(client.stats.diagnostics.graceful_close_timeouts, 0)
        finally:
            _close(client, server)

    def test_peer_stream_reply_still_queued_for_the_writer_delays_close(self):
        # A reply whose DATA|FIN is committed but still queued behind a
        # stalled transport write is local send work: the drain waits for it
        # instead of letting the final CLOSE drop it.
        left, right = socket.socketpair()
        peer = RawPeer(left)
        peer.send_preface(zmux.Role.INITIATOR)
        transport = _GatedTransport(right)
        session = zmux.server(
            transport,
            zmux.Config(graceful_close_drain_timeout=2.0, keepalive_interval=None),
        )
        peer.start_collecting()
        try:
            peer.send_frame(_data(4, b"req"))
            inbound = session.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(3, timeout=1.0), b"req")
            transport.gate.clear()
            # The writer is now stuck on this frame, so the reply below
            # stays queued; both writes are committed when they time out.
            with self.assertRaises(zmux.WriteTimeout):
                inbound.write(b"a", timeout=0.2)
            self.assertTrue(transport.blocked.wait(1.0))
            with self.assertRaises(zmux.WriteTimeout):
                inbound.write_final(b"reply", timeout=0.1)
            closer, closed = _run(session.close)
            time.sleep(0.2)
            self.assertTrue(closer.is_alive())
            transport.gate.set()
            closer.join(2.0)
            self.assertFalse(closer.is_alive())
            self.assertNotIn("error", closed)
            self.assertIsNotNone(peer.wait_for(lambda f: f.frame_type == zmux.FrameType.CLOSE))
            frames = peer.snapshot()
            kinds = [(frame.frame_type, frame.stream_id) for frame in frames]
            replies = [
                frame
                for frame in frames[: kinds.index((zmux.FrameType.CLOSE, 0))]
                if frame.frame_type == zmux.FrameType.DATA and frame.stream_id == 4
            ]
            self.assertEqual(b"".join(frame.payload for frame in replies), b"areply")
            self.assertTrue(replies[-1].flags & zmux.FRAME_FLAG_FIN)
            self.assertEqual(session.stats.diagnostics.graceful_close_timeouts, 0)
        finally:
            transport.gate.set()
            _close(session)
            peer.close()


class IncomingStreamLimitTest(unittest.TestCase):
    """Finding 107: fully terminal queued peer streams release their slot."""

    def test_aborted_unaccepted_streams_do_not_hold_incoming_slots(self):
        session, peer = _server_with_raw_client(zmux.Settings(max_incoming_streams_bidi=4))
        try:
            for stream_id in (4, 8, 12, 16):
                peer.send_frame(_data(stream_id, b"x"))
                peer.send_frame(
                    _error_frame(zmux.FrameType.ABORT, stream_id, int(zmux.ErrorCode.CANCELLED))
                )
            peer.send_frame(_data(20, b"y"))
            peer.barrier()
            self.assertIn(20, session._streams)
            self.assertFalse(session._terminal_state.has_terminal_marker(20))
            self.assertEqual(_frames_of(peer, zmux.FrameType.ABORT), [])
            accepted = [session.accept_stream(timeout=1.0) for _ in range(5)]
            self.assertEqual([stream.stream_id for stream in accepted], [4, 8, 12, 16, 20])
            self.assertEqual(accepted[-1].read_exact(1, timeout=1.0), b"y")
        finally:
            _close(session)
            peer.close()

    def test_finished_unaccepted_uni_streams_do_not_hold_incoming_slots(self):
        settings = zmux.Settings(max_incoming_streams_uni=2)
        client, server = _session_pair(server_config=zmux.Config(settings=settings))
        try:
            for payload in (b"a", b"b", b"c"):
                client.open_uni_and_send(payload, timeout=1.0)
            self.assertTrue(_wait_until(lambda: len(server._accept_uni) == 3))
            self.assertEqual(
                [server.accept_uni_stream(timeout=1.0).read(timeout=1.0) for _ in range(3)],
                [b"a", b"b", b"c"],
            )
        finally:
            _close(client, server)

    def test_python_opener_and_receiver_agree_after_aborted_streams(self):
        settings = zmux.Settings(max_incoming_streams_bidi=4)
        config = zmux.Config(settings=settings, keepalive_interval=None)
        client, server = _session_pair(server_config=config, client_config=config)
        try:
            for _ in range(4):
                stream = client.open_stream()
                stream.write(b"x", timeout=1.0)
                stream.close_with_error(int(zmux.ErrorCode.CANCELLED))
            self.assertTrue(
                _wait_until(lambda: sum(1 for s in server._accept_bidi if s.closed) == 4)
            )
            fifth = client.open_stream()
            fifth.write(b"fifth", timeout=1.0)
            accepted = [server.accept_stream(timeout=1.0) for _ in range(5)]
            self.assertEqual(accepted[-1].stream_id, fifth.stream_id)
            self.assertEqual(accepted[-1].read_exact(5, timeout=1.0), b"fifth")
        finally:
            _close(client, server)

    def test_half_finished_peer_stream_keeps_holding_its_slot(self):
        session, peer = _server_with_raw_client(zmux.Settings(max_incoming_streams_bidi=1))
        try:
            # Peer FIN while our send half is still open: not fully terminal.
            peer.send_frame(_data(4, b"x", zmux.FRAME_FLAG_FIN))
            peer.send_frame(_data(8, b"y"))
            refused = peer.wait_for(
                lambda f: f.frame_type == zmux.FrameType.ABORT and f.stream_id == 8
            )
            self.assertIsNotNone(refused)
            self.assertEqual(_error_code(refused), int(zmux.ErrorCode.REFUSED_STREAM))
        finally:
            _close(session)
            peer.close()


class GoAwayRefusalTest(unittest.TestCase):
    """Findings 21 and 19: opens above our GOAWAY watermark are refused cleanly."""

    def _assert_refused_once(self, peer, stream_id):
        peer.barrier()
        refusals = _frames_of(peer, zmux.FrameType.ABORT, stream_id)
        self.assertEqual(len(refusals), 1)
        self.assertEqual(_error_code(refusals[0]), int(zmux.ErrorCode.REFUSED_STREAM))

    def test_out_of_sequence_open_above_watermark_is_refused_not_fatal(self):
        session, peer = _server_with_raw_client()
        try:
            session.go_away(0, 0)
            peer.send_frame(_data(8, b"x"))
            peer.send_frame(_data(10, b"u"))
            self._assert_refused_once(peer, 8)
            self._assert_refused_once(peer, 10)
            self.assertEqual((session._next_peer_bidi, session._next_peer_uni), (4, 2))
            self.assertFalse(session._terminal_state.has_terminal_marker(8))
            self.assertEqual(session.state, zmux.SessionState.DRAINING)
        finally:
            _close(session)
            peer.close()

    def test_in_sequence_open_above_watermark_does_not_consume_the_id(self):
        session, peer = _server_with_raw_client()
        try:
            session.go_away(0, 0)
            peer.send_frame(_data(4, b"x"))
            self._assert_refused_once(peer, 4)
            self.assertEqual(session._next_peer_bidi, 4)
            self.assertFalse(session._terminal_state.has_terminal_marker(4))
        finally:
            _close(session)
            peer.close()

    def test_abort_first_open_above_watermark_is_refused_not_fatal(self):
        session, peer = _server_with_raw_client()
        try:
            session.go_away(0, 0)
            abort = _error_frame(zmux.FrameType.ABORT, 8, int(zmux.ErrorCode.CANCELLED))
            peer.send_frame(abort)
            peer.send_frame(abort)
            self._assert_refused_once(peer, 8)
            self.assertEqual(session._next_peer_bidi, 4)
            self.assertEqual(session.state, zmux.SessionState.DRAINING)
            # The repeat is ignored control.
            self.assertEqual(session.stats.abuse.ignored_control, 1)
        finally:
            _close(session)
            peer.close()

    def test_later_frames_on_a_refused_id_are_ignored_and_refused_once(self):
        session, peer = _server_with_raw_client(ignored_control_budget=100)
        try:
            session.go_away(0, 0)
            before = session.stats
            peer.send_frame(_data(4, b"a" * 1000))
            peer.send_frame(_data(4, b"b" * 1000))
            peer.send_frame(_data(4, b"c" * 1000, zmux.FRAME_FLAG_FIN))
            for frame_type in (zmux.FrameType.RESET, zmux.FrameType.STOP_SENDING):
                peer.send_frame(_error_frame(frame_type, 4, int(zmux.ErrorCode.CANCELLED)))
            peer.send_frame(_varint_frame(zmux.FrameType.MAX_DATA, 4, 1 << 20))
            peer.send_frame(_varint_frame(zmux.FrameType.BLOCKED, 4, 0))
            self._assert_refused_once(peer, 4)
            after = session.stats
            self.assertEqual(session.state, zmux.SessionState.DRAINING)
            # RESET and STOP_SENDING are ignored control; MAX_DATA and
            # BLOCKED are no-op flow control (also counted as ignored).
            self.assertEqual(after.abuse.ignored_control - before.abuse.ignored_control, 4)
            self.assertEqual(after.abuse.no_op_max_data - before.abuse.no_op_max_data, 1)
            self.assertEqual(after.abuse.no_op_blocked - before.abuse.no_op_blocked, 1)
            # Every refused byte was charged and its session credit returned
            # (SPEC section 8); none of it is late data.
            pressure = after.pressure
            self.assertEqual(
                pressure.recv_session_received_bytes - before.pressure.recv_session_received_bytes,
                3000,
            )
            self.assertEqual(
                pressure.recv_session_advertised_bytes
                - before.pressure.recv_session_advertised_bytes,
                3000,
            )
            self.assertEqual(pressure.aggregate_late_data_bytes, 0)
            max_data = _frames_of(peer, zmux.FrameType.MAX_DATA, 0)
            self.assertEqual(
                zmux.parse_varint(max_data[-1].payload)[0],
                pressure.recv_session_advertised_bytes,
            )
        finally:
            _close(session)
            peer.close()

    def test_skipped_id_without_go_away_still_fails_the_session(self):
        session, peer = _server_with_raw_client()
        try:
            peer.send_frame(_data(8, b"x"))
            self.assertIsNotNone(peer.wait_for(_is_close(zmux.ErrorCode.PROTOCOL)))
            self.assertTrue(_wait_until(lambda: session.closed))
        finally:
            _close(session)
            peer.close()


class RefusedOpenerCreditTest(unittest.TestCase):
    """Finding 19: a refused opener's bytes are charged and released."""

    def test_limit_refused_opener_returns_its_session_credit(self):
        session, peer = _server_with_raw_client(zmux.Settings(max_incoming_streams_bidi=0))
        try:
            initial = session.stats.pressure.recv_session_advertised_bytes
            prefix = zmux.build_open_metadata_prefix(zmux.DEFAULT_CAPABILITIES, open_info=b"meta")
            peer.send_frame(_data(4, prefix + b"a" * 1000, zmux.FRAME_FLAG_OPEN_METADATA))
            peer.send_frame(_data(4, b"b" * 1000))
            peer.send_frame(_data(4, b"c" * 1000))
            peer.barrier()
            pressure = session.stats.pressure
            # OPEN_METADATA bytes are not flow controlled.
            self.assertEqual(pressure.recv_session_received_bytes, 3000)
            self.assertEqual(pressure.recv_session_advertised_bytes, initial + 3000)
            max_data = _frames_of(peer, zmux.FrameType.MAX_DATA, 0)
            self.assertEqual(zmux.parse_varint(max_data[-1].payload)[0], initial + 3000)
            refusals = [_error_code(frame) for frame in _frames_of(peer, zmux.FrameType.ABORT, 4)]
            self.assertEqual(refusals, [int(zmux.ErrorCode.REFUSED_STREAM)])
        finally:
            _close(session)
            peer.close()

    def test_refused_opener_beyond_the_session_window_fails_with_flow_control(self):
        settings = zmux.Settings(max_incoming_streams_bidi=0, initial_max_data=100)
        session, peer = _server_with_raw_client(settings)
        try:
            peer.send_frame(_data(4, b"x" * 1000))
            self.assertIsNotNone(peer.wait_for(_is_close(zmux.ErrorCode.FLOW_CONTROL)))
        finally:
            _close(session)
            peer.close()

    def test_go_away_refused_opener_beyond_the_session_window_fails_with_flow_control(self):
        session, peer = _server_with_raw_client(zmux.Settings(initial_max_data=100))
        try:
            session.go_away(0, 0)
            peer.send_frame(_data(4, b"x" * 1000))
            self.assertIsNotNone(peer.wait_for(_is_close(zmux.ErrorCode.FLOW_CONTROL)))
        finally:
            _close(session)
            peer.close()

    def test_refused_openers_never_shrink_the_usable_session_window(self):
        settings = zmux.Settings(initial_max_data=8192)
        server_config = zmux.Config(
            settings=settings,
            accept_backlog_limit=1,
            keepalive_interval=None,
        )
        client, server = _session_pair(server_config=server_config)
        try:
            first = client.open_stream()
            first.write(b"1", timeout=1.0)
            self.assertTrue(_wait_until(lambda: server.stats.accept_backlog.count == 1))
            for _ in range(4):
                refused = client.open_stream()
                try:
                    refused.write(b"r" * 4096, timeout=2.0)
                except zmux.ApplicationError as exc:
                    # The refusal may overtake the rest of the write.
                    self.assertEqual(exc.code, int(zmux.ErrorCode.REFUSED_STREAM))
            self.assertTrue(_wait_until(lambda: server.stats.accept_backlog.refused == 4))
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.read_exact(1, timeout=1.0), b"1")
            first.write(b"z" * 8000, timeout=2.0)
            self.assertEqual(inbound.read_exact(8000, timeout=2.0), b"z" * 8000)
        finally:
            _close(client, server)


class LocalStreamIdExhaustionTest(unittest.TestCase):
    """Finding 25: running out of local stream IDs starts a GOAWAY once."""

    def test_exhaustion_fails_locally_and_sends_one_non_tightening_go_away(self):
        session, peer = _client_with_raw_server()
        try:
            with session._lock:
                session._next_bidi = _LAST_CLIENT_BIDI_ID
            last = session.open_stream()
            last.write(b"last", timeout=1.0)
            self.assertEqual(last.stream_id, _LAST_CLIENT_BIDI_ID)
            for _ in range(2):
                with self.assertRaises(zmux.OpenLimited) as raised:
                    session.open_stream()
                self.assertTrue(zmux.open_limited(raised.exception))
                self.assertIn("local stream ID space exhausted", str(raised.exception))
                self.assertNotEqual(raised.exception.code, int(zmux.ErrorCode.PROTOCOL))
            self.assertEqual(session.state, zmux.SessionState.DRAINING)
            uni = session.open_uni_stream()
            uni.write_final(b"uni", timeout=1.0)
            self.assertIsNotNone(peer.wait_for(lambda f: f.stream_id == uni.stream_id))
            go_aways = _frames_of(peer, zmux.FrameType.GOAWAY)
            self.assertEqual(len(go_aways), 1)
            parsed = zmux.parse_go_away_payload(go_aways[0].payload)
            self.assertEqual(parsed.code, int(zmux.ErrorCode.NO_ERROR))
            # The largest server-owned IDs: no peer stream is refused.
            self.assertEqual(
                (parsed.last_accepted_bidi, parsed.last_accepted_uni),
                ((1 << 62) - 3, (1 << 62) - 1),
            )
            self.assertEqual([f for f in peer.snapshot() if f.stream_id > _LAST_CLIENT_BIDI_ID], [])
        finally:
            _close(session)
            peer.close()

    def test_exhaustion_found_at_commit_also_sends_one_go_away(self):
        # A commit never gets a higher ID than its open-time projection, so
        # this check is defence in depth: run the class out between open and
        # commit by hand.
        session, peer = _client_with_raw_server()
        try:
            with session._lock:
                session._next_bidi = _LAST_CLIENT_BIDI_ID
            stream = session.open_stream()
            with session._lock:
                session._next_bidi = _LAST_CLIENT_BIDI_ID + 4
            with self.assertRaises(zmux.OpenLimited) as raised:
                stream.write(b"x", timeout=1.0)
            self.assertIn("local stream ID space exhausted", str(raised.exception))
            self.assertEqual(stream.stream_id, 0)
            self.assertEqual(session.stats.provisionals.bidi, 0)
            self.assertEqual(session.state, zmux.SessionState.DRAINING)
            with self.assertRaises(zmux.OpenLimited):
                session.open_stream()
            uni = session.open_uni_stream()
            uni.write_final(b"uni", timeout=1.0)
            self.assertIsNotNone(peer.wait_for(lambda f: f.stream_id == uni.stream_id))
            go_aways = _frames_of(peer, zmux.FrameType.GOAWAY)
            self.assertEqual(len(go_aways), 1)
            parsed = zmux.parse_go_away_payload(go_aways[0].payload)
            self.assertEqual(
                (parsed.last_accepted_bidi, parsed.last_accepted_uni),
                ((1 << 62) - 3, (1 << 62) - 1),
            )
            self.assertEqual(
                [f for f in peer.snapshot() if f.stream_id % 4 == 0 and f.stream_id != 0],
                [],
            )
        finally:
            _close(session)
            peer.close()

    def test_peer_sees_draining_and_keeps_its_streams(self):
        client, server = _session_pair()
        try:
            with client._lock:
                client._next_bidi = _LAST_CLIENT_BIDI_ID
            with server._lock:
                server._next_peer_bidi = _LAST_CLIENT_BIDI_ID
            last = client.open_stream()
            last.write(b"last", timeout=1.0)
            inbound = server.accept_stream(timeout=1.0)
            self.assertEqual(inbound.stream_id, _LAST_CLIENT_BIDI_ID)
            with self.assertRaises(zmux.OpenLimited):
                client.open_stream()
            self.assertTrue(_wait_until(lambda: server.state is zmux.SessionState.DRAINING))
            # The exhaustion GOAWAY carries NO_ERROR (finding 63: a NO_ERROR
            # GOAWAY cause is reported as code 0, not hidden as None).
            self.assertEqual(server.peer_go_away_error.code, int(zmux.ErrorCode.NO_ERROR))
            self.assertEqual(server.peer_go_away_error.reason, "")
            peer_stream = server.open_stream()
            peer_stream.write(b"still open", timeout=1.0)
            self.assertEqual(
                client.accept_stream(timeout=1.0).read_exact(10, timeout=1.0),
                b"still open",
            )
        finally:
            _close(client, server)


if __name__ == "__main__":
    unittest.main()
