"""Session establishment regressions for the native session.

Covers the concurrent preface write, the configurable establishment timeout
(``Config.establishment_timeout``), short-write transports and the rule that
an establishment CLOSE only ever follows a complete local preface.
"""

import math
import socket
import threading
import time
import unittest

import zmux


class _ShortWriteTransport(object):
    """Transport exposing only ``write`` that accepts a few bytes per call."""

    def __init__(self, sock, chunk=3):
        self.socket = sock
        self.chunk = chunk

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def write(self, data):
        return self.socket.send(bytes(memoryview(data)[: self.chunk]))

    def close(self):
        self.socket.close()


class _WouldBlockTransport(object):
    """Write-only-``write`` transport with ``io.RawIOBase`` non-blocking semantics.

    ``write()`` returns ``None`` (nothing written) once ``blocked`` is set.
    """

    def __init__(self, sock, blocked=False):
        self.socket = sock
        self.blocked = blocked
        self.closed = False

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def write(self, data):
        if self.blocked:
            return None
        return self.socket.send(bytes(memoryview(data)))

    def close(self):
        self.closed = True
        self.socket.close()


class _FailingWriteTransport(object):
    """Transport whose write_all sends a prefix and then fails."""

    def __init__(self, sock, prefix=4):
        self.socket = sock
        self.prefix = prefix
        self.closed = False

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def write_all(self, data):
        self.socket.sendall(bytes(memoryview(data)[: self.prefix]))
        raise OSError("write failed")

    def close(self):
        self.closed = True
        self.socket.close()


class _RecordingTransport(object):
    def __init__(self):
        self.writes = []
        self.closed = False

    def read(self, max_bytes):
        return b""

    def write_all(self, data):
        self.writes.append(bytes(data))

    def close(self):
        self.closed = True


class _RendezvousPipe(object):
    """One direction of a zero-capacity pipe: writes wait for the reader."""

    def __init__(self):
        self._cond = threading.Condition()
        self._buffer = bytearray()
        self._closed = False

    def write(self, data):
        with self._cond:
            if self._closed:
                raise BrokenPipeError("pipe closed")
            self._buffer += bytes(data)
            self._cond.notify_all()
            while self._buffer and not self._closed:
                self._cond.wait()
            if self._buffer:
                raise BrokenPipeError("pipe closed")

    def read(self, max_bytes):
        with self._cond:
            while not self._buffer and not self._closed:
                self._cond.wait()
            chunk = bytes(self._buffer[:max_bytes])
            del self._buffer[:max_bytes]
            self._cond.notify_all()
            return chunk

    def close(self):
        with self._cond:
            self._closed = True
            self._cond.notify_all()


class _RendezvousEnd(object):
    def __init__(self, inbound, outbound):
        self._inbound = inbound
        self._outbound = outbound

    def read(self, max_bytes):
        return self._inbound.read(max_bytes)

    def write_all(self, data):
        self._outbound.write(data)

    def close(self):
        self._inbound.close()
        self._outbound.close()


def _rendezvous_pair():
    forward = _RendezvousPipe()
    backward = _RendezvousPipe()
    return _RendezvousEnd(backward, forward), _RendezvousEnd(forward, backward)


class _SocketReader(object):
    def __init__(self, sock):
        self.socket = sock

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)


def _assert_transport_closed(test, sock):
    # Linux answers a close() that leaves unread inbound bytes with RST rather
    # than FIN, so after the frames sent before the close have been read, the
    # peer may see ECONNRESET instead of EOF. Both mean the transport closed.
    try:
        test.assertEqual(sock.recv(4096), b"")
    except ConnectionResetError:
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


def _exchange_and_close(test, client, server):
    try:
        outbound = client.open_stream(timeout=1.0)
        outbound.write_final(b"hello", timeout=2.0)
        inbound = server.accept_stream(timeout=2.0)
        test.assertEqual(inbound.read_exact(5, timeout=2.0), b"hello")
        inbound.write_final(b"world", timeout=2.0)
        test.assertEqual(outbound.read_exact(5, timeout=2.0), b"world")
    finally:
        client.close()
        server.close()


class EstablishmentTimeoutConfigTest(unittest.TestCase):
    def test_establishment_timeout_defaults_and_disable(self):
        self.assertEqual(zmux.Config().establishment_timeout, zmux.DEFAULT_ESTABLISHMENT_TIMEOUT)
        self.assertEqual(zmux.DEFAULT_ESTABLISHMENT_TIMEOUT, 10.0)
        self.assertEqual(
            zmux.Config(establishment_timeout=None).establishment_timeout,
            zmux.DEFAULT_ESTABLISHMENT_TIMEOUT,
        )
        self.assertEqual(
            zmux.Config(establishment_timeout=0).establishment_timeout,
            zmux.DEFAULT_ESTABLISHMENT_TIMEOUT,
        )
        self.assertEqual(zmux.Config(establishment_timeout=2.5).establishment_timeout, 2.5)
        self.assertTrue(math.isinf(zmux.Config(establishment_timeout=math.inf).establishment_timeout))
        with self.assertRaises(ValueError):
            zmux.Config(establishment_timeout=-1.0)
        with self.assertRaises(ValueError):
            zmux.Config(establishment_timeout=math.nan)
        with self.assertRaises(TypeError):
            zmux.Config(establishment_timeout="1")


class EstablishmentTest(unittest.TestCase):
    def test_silent_peer_fails_with_internal_after_establishment_timeout(self):
        left, right = socket.socketpair()
        try:
            started = time.monotonic()
            with self.assertRaises(zmux.ZmuxError) as caught:
                zmux.client(left, zmux.Config(establishment_timeout=0.3))
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual(caught.exception.code, int(zmux.ErrorCode.INTERNAL))
            self.assertIn("peer preface read stalled", str(caught.exception))
            # The complete local preface went out, followed by CLOSE(INTERNAL).
            right.settimeout(2.0)
            reader = _SocketReader(right)
            self.assertEqual(zmux.read_preface(reader).role, zmux.Role.INITIATOR)
            close = zmux.read_frame(reader)
            self.assertEqual(close.frame_type, zmux.FrameType.CLOSE)
            code, _ = zmux.parse_error_payload(close.payload)
            self.assertEqual(code, int(zmux.ErrorCode.INTERNAL))
        finally:
            left.close()
            right.close()

    def test_peer_preface_arriving_before_timeout_establishes(self):
        for timeout in (2.0, math.inf):
            left, right = socket.socketpair()
            config = zmux.Config(establishment_timeout=timeout)
            thread, result = _run(zmux.client, left, config)
            time.sleep(0.2)
            server = zmux.server(right)
            thread.join(2.0)
            self.assertNotIn("error", result)
            _exchange_and_close(self, result["value"], server)

    def test_establishment_timeout_does_not_outlive_establishment(self):
        left, right = socket.socketpair()
        config = zmux.Config(establishment_timeout=0.2, keepalive_interval=None)
        thread, result = _run(zmux.server, right, config)
        client = zmux.client(left, config)
        thread.join(2.0)
        server = result["value"]
        time.sleep(0.4)
        self.assertEqual(client.state, zmux.SessionState.READY)
        self.assertEqual(server.state, zmux.SessionState.READY)
        _exchange_and_close(self, client, server)

    def test_python_peers_establish_on_rendezvous_transport(self):
        # Writes complete only once the peer read them, so writing the preface
        # before reading deadlocked two Python endpoints.
        client_end, server_end = _rendezvous_pair()
        config = zmux.Config(keepalive_interval=None, establishment_timeout=3.0)
        server_thread, server_result = _run(zmux.server, server_end, config)
        client_thread, client_result = _run(zmux.client, client_end, config)
        server_thread.join(3.0)
        client_thread.join(3.0)
        self.assertNotIn("error", server_result)
        self.assertNotIn("error", client_result)
        _exchange_and_close(self, client_result["value"], server_result["value"])

    def test_short_write_transport_sends_complete_preface(self):
        left, right = socket.socketpair()
        thread, result = _run(zmux.server, right)
        client = zmux.client(_ShortWriteTransport(left))
        thread.join(2.0)
        self.assertNotIn("error", result)
        server = result["value"]
        self.assertEqual(server.peer_preface().role, zmux.Role.INITIATOR)
        _exchange_and_close(self, client, server)

    def test_write_returning_none_is_no_progress_not_a_full_write(self):
        # A None from a bare write() used to count as "everything written",
        # so the preface or frames were dropped while the session carried on.
        left, right = socket.socketpair()
        transport = _WouldBlockTransport(left, blocked=True)
        try:
            started = time.monotonic()
            with self.assertRaises(zmux.TransportError) as raised:
                zmux.client(transport, zmux.Config(establishment_timeout=5.0))
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertIsInstance(raised.exception.__cause__, BlockingIOError)
            self.assertTrue(transport.closed)
            right.settimeout(2.0)
            self.assertEqual(right.recv(4096), b"")
        finally:
            right.close()

        left, right = socket.socketpair()
        transport = _WouldBlockTransport(left)
        thread, result = _run(zmux.server, right)
        client = zmux.client(transport)
        thread.join(2.0)
        server = result["value"]
        try:
            transport.blocked = True
            stream = client.open_stream(timeout=1.0)
            with self.assertRaises(zmux.ZmuxError):
                stream.write_final(b"lost", timeout=2.0)
            with self.assertRaises(zmux.TransportError):
                client.wait(2.0)
            self.assertEqual(client.state, zmux.SessionState.FAILED)
        finally:
            client.close()
            server.close()

    def test_nonce_source_failure_before_preface_closes_transport_silently(self):
        for failing_call in (1, 2):
            calls = []

            def source(n, calls=calls, failing_call=failing_call):
                calls.append(n)
                if len(calls) >= failing_call:
                    raise OSError("entropy source failed")
                return b"\x01" * n

            left, right = socket.socketpair()
            try:
                with self.assertRaises(OSError):
                    zmux.server(left, zmux.Config(nonce_source=source))
                self.assertEqual(left.fileno(), -1)
                right.settimeout(2.0)
                self.assertEqual(right.recv(4096), b"")
            finally:
                right.close()

    def test_nonce_source_failure_writes_nothing_to_custom_transport(self):
        def source(n):
            raise OSError("entropy source failed")

        transport = _RecordingTransport()
        with self.assertRaises(OSError):
            zmux.server(transport, zmux.Config(nonce_source=source))
        self.assertTrue(transport.closed)
        self.assertEqual(transport.writes, [])

    def test_failed_preface_write_is_not_followed_by_close(self):
        left, right = socket.socketpair()
        transport = _FailingWriteTransport(left)
        try:
            started = time.monotonic()
            with self.assertRaises(zmux.ZmuxError):
                zmux.client(transport, zmux.Config(establishment_timeout=5.0))
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertTrue(transport.closed)
            right.settimeout(2.0)
            received = b""
            while True:
                chunk = right.recv(4096)
                if not chunk:
                    break
                received += chunk
            self.assertEqual(received, b"ZMUX")
        finally:
            right.close()

    def test_invalid_peer_preface_gets_complete_preface_then_close(self):
        for wrap in (lambda sock: sock, _ShortWriteTransport):
            left, right = socket.socketpair()
            try:
                right.sendall(b"XXXX" + bytes(64))
                with self.assertRaises(zmux.ProtocolError):
                    zmux.client(wrap(left))
                right.settimeout(2.0)
                reader = _SocketReader(right)
                self.assertEqual(zmux.read_preface(reader).role, zmux.Role.INITIATOR)
                close = zmux.read_frame(reader)
                self.assertEqual(close.frame_type, zmux.FrameType.CLOSE)
                code, _ = zmux.parse_error_payload(close.payload)
                self.assertEqual(code, int(zmux.ErrorCode.PROTOCOL))
                _assert_transport_closed(self, right)
            finally:
                right.close()


if __name__ == "__main__":
    unittest.main()
