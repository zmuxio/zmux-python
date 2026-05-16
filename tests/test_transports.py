import gc
import socket
import threading
import time
import unittest
from io import BytesIO

import zmux


class RecordingReadHalf(object):
    def __init__(self, data=b"", local=None, remote=None):
        self._data = bytearray(data)
        self.local = local
        self.remote = remote
        self.close_count = 0
        self.close_read_count = 0
        self.deadlines = []

    def recv(self, max_bytes):
        if max_bytes == 0:
            return b""
        n = min(max_bytes, len(self._data))
        chunk = bytes(self._data[:n])
        del self._data[:n]
        return chunk

    def close_read(self):
        self.close_read_count += 1

    def close(self):
        self.close_count += 1

    def set_read_deadline(self, deadline):
        self.deadlines.append(deadline)

    def local_addr(self):
        return self.local

    def remote_addr(self):
        return self.remote


class RecordingWriteHalf(object):
    def __init__(self, local=None, remote=None):
        self.data = bytearray()
        self.local = local
        self.remote = remote
        self.close_count = 0
        self.close_write_count = 0
        self.deadlines = []

    def write_all(self, data):
        self.data.extend(memoryview(data))

    def close_write(self):
        self.close_write_count += 1

    def close(self):
        self.close_count += 1

    def set_write_deadline(self, deadline):
        self.deadlines.append(deadline)

    def local_addr(self):
        return self.local

    def remote_addr(self):
        return self.remote


class RecordingVectoredWriteHalf(RecordingWriteHalf):
    def __init__(self, local=None, remote=None):
        super().__init__(local, remote)
        self.vectored_calls = 0

    def write_vectored(self, parts):
        self.vectored_calls += 1
        total = 0
        for part in parts:
            view = memoryview(part)
            self.data.extend(view)
            total += len(view)
        return total


class RecordingDuplexHalf(RecordingReadHalf, RecordingWriteHalf):
    def __init__(self, data=b"", local=None, remote=None):
        RecordingReadHalf.__init__(self, data, local, remote)
        self.data = bytearray()
        self.close_write_count = 0

    def write_all(self, data):
        self.data.extend(memoryview(data))

    def close_write(self):
        self.close_write_count += 1

    def set_write_deadline(self, deadline):
        self.deadlines.append(("write", deadline))


class BlockingReadHalf(RecordingReadHalf):
    def __init__(self):
        super().__init__(b"x")
        self.entered = threading.Event()
        self.release = threading.Event()

    def recv(self, max_bytes):
        self.entered.set()
        self.release.wait(1.0)
        return super().recv(max_bytes)


class BlockingDeadlineReadHalf(RecordingReadHalf):
    def __init__(self):
        super().__init__(b"")
        self.first_started = threading.Event()
        self.release_first = threading.Event()

    def set_read_deadline(self, deadline):
        self.deadlines.append(deadline)
        if len(self.deadlines) == 1:
            self.first_started.set()
            self.release_first.wait(1.0)


class FailingReadDeadlineHalf(RecordingReadHalf):
    def set_read_deadline(self, deadline):
        self.deadlines.append(deadline)
        raise RuntimeError("synthetic read deadline failure")


class FailingWriteDeadlineHalf(RecordingWriteHalf):
    def set_write_deadline(self, deadline):
        self.deadlines.append(deadline)
        raise RuntimeError("synthetic write deadline failure")


class RecordingControl(object):
    def __init__(self):
        self.read_timeouts = []
        self.write_timeouts = []
        self.close_count = 0

    def set_read_timeout(self, timeout):
        self.read_timeouts.append(timeout)

    def set_write_timeout(self, timeout):
        self.write_timeouts.append(timeout)

    def close(self):
        self.close_count += 1


class CloseCountingResource(object):
    def __init__(self):
        self.close_count = 0

    def read(self, max_bytes):
        return b""

    def write(self, data):
        return len(memoryview(data))

    def close(self):
        self.close_count += 1


class TransportTest(unittest.TestCase):
    def test_basic_duplex_transport_wraps_file_like_halves_and_closes_once(self):
        reader = BytesIO(b"abcdef")
        writer = BytesIO()
        closer = BytesIO()

        transport = zmux.BasicDuplexTransport(
            reader,
            writer,
            closer=closer,
            local_addr="local",
            remote_addr="remote",
        )

        self.assertEqual(transport.read(3), b"abc")
        buffer = bytearray(2)
        self.assertEqual(transport.readinto(buffer), 2)
        self.assertEqual(buffer, bytearray(b"de"))
        self.assertEqual(transport.write(b"xy"), 2)
        self.assertEqual(writer.getvalue(), b"xy")
        self.assertEqual(transport.local_addr(), "local")
        self.assertEqual(transport.remote_addr(), "remote")
        self.assertFalse(hasattr(transport, "recv"))
        self.assertFalse(hasattr(transport, "peer_addr"))
        self.assertFalse(hasattr(zmux.BasicDuplexTransport, "builder"))
        self.assertFalse(hasattr(zmux, "DuplexTransport"))
        self.assertFalse(hasattr(zmux, "join_streams"))
        self.assertFalse(hasattr(zmux, "SocketStream"))

        transport.close()
        self.assertTrue(reader.closed)
        self.assertTrue(writer.closed)
        self.assertTrue(closer.closed)
        transport.close()

    def test_basic_duplex_transport_closes_wrapped_shared_resource_once(self):
        resource = CloseCountingResource()
        transport = zmux.BasicDuplexTransport(
            zmux.FileReadHalf(resource),
            zmux.FileWriteHalf(resource),
        )

        transport.close()
        transport.close()

        self.assertEqual(resource.close_count, 1)

    def test_duplex_transport_control_handles_timeouts_and_close_hook(self):
        control = RecordingControl()
        closed = []
        transport = zmux.BasicDuplexTransport(
            BytesIO(b""),
            BytesIO(),
            closer=lambda: closed.append(True),
            control=control,
        )

        transport.set_read_timeout(1.0)
        transport.set_write_timeout(None)
        transport.close()

        self.assertEqual(len(control.read_timeouts), 1)
        self.assertGreater(control.read_timeouts[0], 0)
        self.assertEqual(control.write_timeouts, [None])
        self.assertEqual(closed, [True])
        self.assertEqual(control.close_count, 0)

    def test_socket_transport_round_trips_and_maps_deadline_timeout(self):
        left, right = socket.socketpair()
        try:
            transport = zmux.SocketTransport(left)
            right.sendall(b"hi")
            self.assertEqual(transport.read(2), b"hi")
            right.sendall(b"zz")
            buffer = bytearray(2)
            self.assertEqual(transport.readinto(buffer), 2)
            self.assertEqual(buffer, bytearray(b"zz"))
            transport.write_all(b"ok")
            self.assertEqual(right.recv(2), b"ok")

            transport.set_read_timeout(0)
            with self.assertRaises(zmux.ReadTimeout):
                transport.read(1)
        finally:
            left.close()
            right.close()

    def test_joined_transport_exposes_nil_half_errors_and_synthetic_addresses(self):
        joined = zmux.JoinedTransport(None, None)

        with self.assertRaises(zmux.StreamNotReadable):
            joined.read(1)
        with self.assertRaises(zmux.StreamNotWritable):
            joined.write_all(b"x")
        self.assertEqual(str(joined.local_addr()), "local/stream/pending")
        self.assertEqual(str(joined.remote_addr()), "remote/stream/pending")

    def test_join_helper_builds_joined_transport_with_addresses(self):
        read_half = RecordingReadHalf(b"abc", "rlocal", "rremote")
        write_half = RecordingWriteHalf("wlocal", "wremote")

        joined = zmux.join(read_half, write_half, local_addr="fallback-local")

        self.assertIsInstance(joined, zmux.JoinedTransport)
        self.assertEqual(joined.read(2), b"ab")
        buffer = bytearray(1)
        self.assertEqual(joined.readinto(buffer), 1)
        self.assertEqual(buffer, bytearray(b"c"))
        self.assertEqual(joined.write(b"xy"), 2)
        self.assertEqual(write_half.data, bytearray(b"xy"))
        self.assertEqual(joined.local_addr(), "rlocal")
        self.assertEqual(joined.remote_addr(), "rremote")
        joined.close()

    def test_joined_transport_accepts_plain_file_like_directional_halves(self):
        reader = BytesIO(b"abc")
        writer = BytesIO()
        joined = zmux.JoinedTransport(reader, writer)

        self.assertEqual(joined.read(2), b"ab")
        self.assertEqual(joined.write(b"xy"), 2)
        self.assertEqual(writer.getvalue(), b"xy")

        joined.close()

        self.assertTrue(reader.closed)
        self.assertTrue(writer.closed)

    def test_joined_transport_directional_close_and_full_close_deduplicate(self):
        read_half = RecordingReadHalf(b"", "rlocal", "rremote")
        write_half = RecordingWriteHalf("wlocal", "wremote")
        joined = zmux.JoinedTransport(read_half, write_half)

        self.assertEqual(joined.local_addr(), "rlocal")
        self.assertEqual(joined.remote_addr(), "rremote")
        joined.close_read()
        joined.close_write()
        self.assertEqual(read_half.close_read_count, 1)
        self.assertEqual(read_half.close_count, 0)
        self.assertEqual(write_half.close_write_count, 1)
        self.assertEqual(write_half.close_count, 0)

        shared = RecordingDuplexHalf()
        shared_joined = zmux.JoinedTransport(shared, shared)
        shared_joined.close()
        self.assertEqual(shared.close_count, 1)
        self.assertEqual(shared.close_read_count, 0)
        self.assertEqual(shared.close_write_count, 0)

    def test_joined_transport_full_close_deduplicates_wrapped_shared_resource(self):
        resource = CloseCountingResource()
        joined = zmux.JoinedTransport(zmux.FileReadHalf(resource), zmux.FileWriteHalf(resource))

        joined.close()
        joined.close()

        self.assertEqual(resource.close_count, 1)

    def test_joined_transport_full_duplex_resource_can_be_used_as_both_halves(self):
        resource = CloseCountingResource()
        joined = zmux.JoinedTransport(resource, resource)

        self.assertEqual(joined.write(b"x"), 1)
        self.assertEqual(joined.read(1), b"")
        joined.close()
        joined.close()

        self.assertEqual(resource.close_count, 1)

    def test_joined_transport_close_aggregates_read_and_write_close_errors(self):
        read_error = OSError("read close failed")
        write_error = OSError("write close failed")

        class FailingReadClose(object):
            def close_read(self):
                raise read_error

        class FailingWriteClose(object):
            def close_write(self):
                raise write_error

        joined = zmux.JoinedTransport(FailingReadClose(), FailingWriteClose())

        with self.assertRaises(OSError) as caught:
            joined.close()

        self.assertEqual(str(caught.exception), "zmux: multiple close errors")
        self.assertEqual(caught.exception.close_errors, (read_error, write_error))

    def test_joined_transport_close_keeps_detached_halves_caller_owned(self):
        read_half = RecordingReadHalf(b"x")
        write_half = RecordingWriteHalf()
        joined = zmux.JoinedTransport(read_half, write_half)

        paused = joined.pause_read()
        self.assertIs(paused.current(), read_half)
        joined.close()

        self.assertEqual(read_half.close_count, 0)
        self.assertEqual(read_half.close_read_count, 0)
        self.assertEqual(write_half.close_count, 1)

    def test_joined_transport_pause_handle_can_detach_direction(self):
        read_half = RecordingReadHalf(b"x")
        write_half = RecordingWriteHalf()
        joined = zmux.JoinedTransport(read_half, write_half)

        paused_read = joined.pause_read()
        self.assertIs(paused_read.set(None), read_half)
        paused_read.resume()

        paused_write = joined.pause_write()
        self.assertIs(paused_write.set(None), write_half)
        paused_write.resume()

        self.assertIsNone(joined.read_half())
        self.assertIsNone(joined.write_half())
        with self.assertRaises(zmux.StreamNotReadable):
            joined.read(1)
        with self.assertRaises(zmux.StreamNotWritable):
            joined.write_all(b"x")
        joined.close()
        self.assertEqual(read_half.close_count, 0)
        self.assertEqual(write_half.close_count, 0)

    def test_joined_transport_pause_blocks_read_until_resume_with_replacement(self):
        joined = zmux.JoinedTransport(RecordingReadHalf(b"old"), RecordingWriteHalf())
        paused = joined.pause_read()
        result = []
        errors = []

        def reader():
            try:
                result.append(joined.read(5))
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=reader)
        thread.start()
        time.sleep(0.05)
        self.assertEqual(result, [])
        self.assertEqual(errors, [])

        replacement = RecordingReadHalf(b"hello")
        self.assertIsNotNone(paused.set(replacement))
        paused.resume()
        thread.join(1.0)

        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [b"hello"])
        self.assertEqual(errors, [])
        self.assertIs(joined.read_half(), replacement)
        self.assertIsNone(paused.current())
        with self.assertRaises(RuntimeError):
            paused.set(RecordingReadHalf(b"late"))

    def test_joined_transport_pause_handle_drop_resumes_best_effort(self):
        read_half = RecordingReadHalf(b"x")
        joined = zmux.JoinedTransport(read_half, RecordingWriteHalf())
        paused = joined.pause_read()

        self.assertIs(paused.current(), read_half)
        del paused
        gc.collect()

        self.assertIs(joined.read_half(), read_half)
        self.assertEqual(joined.read(1), b"x")

    def test_joined_transport_pause_handle_context_manager_resumes(self):
        write_half = RecordingWriteHalf()
        joined = zmux.JoinedTransport(RecordingReadHalf(), write_half)

        with joined.pause_write() as paused:
            self.assertIs(paused.current(), write_half)
            replacement = RecordingWriteHalf()
            paused.set(replacement)

        self.assertIs(joined.write_half(), replacement)
        self.assertIsNone(paused.current())

    def test_joined_transport_pause_waits_for_inflight_read_to_drain(self):
        read_half = BlockingReadHalf()
        joined = zmux.JoinedTransport(read_half, None)
        read_result = []
        pause_result = []

        reader = threading.Thread(target=lambda: read_result.append(joined.read(1)))
        reader.start()
        self.assertTrue(read_half.entered.wait(1.0))

        pauser = threading.Thread(target=lambda: pause_result.append(joined.pause_read()))
        pauser.start()
        time.sleep(0.05)
        self.assertEqual(pause_result, [])

        read_half.release.set()
        reader.join(1.0)
        pauser.join(1.0)

        self.assertEqual(read_result, [b"x"])
        self.assertFalse(pauser.is_alive())
        self.assertIs(pause_result[0].current(), read_half)

    def test_joined_transport_pause_blocks_directional_close_until_resume(self):
        read_half = RecordingReadHalf()
        joined = zmux.JoinedTransport(read_half, None)
        paused = joined.pause_read()
        close_errors = []

        def close_read():
            try:
                joined.close_read()
            except BaseException as exc:
                close_errors.append(exc)

        closer = threading.Thread(target=close_read)
        closer.start()
        time.sleep(0.05)
        self.assertEqual(read_half.close_read_count, 0)
        self.assertEqual(close_errors, [])

        paused.resume()
        closer.join(1.0)

        self.assertFalse(closer.is_alive())
        self.assertEqual(close_errors, [])
        self.assertEqual(read_half.close_read_count, 1)

    def test_joined_transport_write_vectored_uses_one_write_operation(self):
        write_half = RecordingVectoredWriteHalf()
        joined = zmux.JoinedTransport(None, write_half)

        written = joined.write_vectored((b"a", b"", bytearray(b"bc")))

        self.assertEqual(written, 3)
        self.assertEqual(write_half.vectored_calls, 1)
        self.assertEqual(write_half.data, bytearray(b"abc"))

    def test_transport_progress_rejects_bool_results(self):
        class BoolReadIntoHalf(object):
            def readinto(self, buffer):
                buffer[0:1] = b"x"
                return True

        class BoolWriteHalf(object):
            def write(self, data):
                del data
                return True

        class BoolVectoredHalf(object):
            def write_vectored(self, parts):
                del parts
                return True

        with self.assertRaisesRegex(OSError, "invalid progress"):
            zmux.BasicDuplexTransport(BoolReadIntoHalf(), BytesIO()).read(1)
        with self.assertRaisesRegex(OSError, "invalid progress"):
            zmux.BasicDuplexTransport(BoolReadIntoHalf(), BytesIO()).readinto(bytearray(1))
        with self.assertRaisesRegex(OSError, "invalid progress"):
            zmux.BasicDuplexTransport(BytesIO(), BoolWriteHalf()).write_all(b"x")
        with self.assertRaisesRegex(OSError, "invalid progress"):
            zmux.BasicDuplexTransport(BytesIO(), BoolVectoredHalf()).write_vectored((b"x",))

    def test_joined_transport_resume_replays_latest_read_deadline(self):
        joined = zmux.JoinedTransport(RecordingReadHalf(), None)
        paused = joined.pause_read()
        replacement = BlockingDeadlineReadHalf()
        paused.set(replacement)

        first = time.monotonic() + 60.0
        second = time.monotonic() + 120.0
        joined.set_read_deadline(first)

        errors = []

        def resume_pause():
            try:
                paused.resume()
                errors.append(None)
            except BaseException as exc:
                errors.append(exc)

        resume = threading.Thread(target=resume_pause)
        resume.start()
        self.assertTrue(replacement.first_started.wait(1.0))
        joined.set_read_deadline(second)
        replacement.release_first.set()
        resume.join(1.0)

        self.assertFalse(resume.is_alive())
        self.assertEqual(errors, [None])
        self.assertEqual(replacement.deadlines, [first, second])
        self.assertIs(joined.read_half(), replacement)

    def test_joined_transport_paused_write_honors_write_deadline(self):
        joined = zmux.JoinedTransport(None, RecordingWriteHalf())
        joined.set_write_timeout(0.05)
        paused = joined.pause_write()

        with self.assertRaises(zmux.WriteTimeout):
            joined.write_all(b"x")
        paused.set(RecordingWriteHalf())
        paused.resume()
        joined.write_all(b"y")
        self.assertEqual(joined.write_half().data, bytearray(b"y"))

    def test_joined_transport_deadline_setter_failure_rolls_back_deadline(self):
        read_half = FailingReadDeadlineHalf()
        write_half = FailingWriteDeadlineHalf()
        joined = zmux.JoinedTransport(read_half, write_half)
        read_deadline = time.monotonic() + 30.0
        write_deadline = time.monotonic() + 40.0

        with self.assertRaisesRegex(RuntimeError, "read deadline failure"):
            joined.set_read_deadline(read_deadline)
        with self.assertRaisesRegex(RuntimeError, "write deadline failure"):
            joined.set_write_deadline(write_deadline)

        self.assertIsNone(joined._read_deadline)
        self.assertIsNone(joined._write_deadline)
        self.assertEqual(read_half.deadlines, [read_deadline])
        self.assertEqual(write_half.deadlines, [write_deadline])


if __name__ == "__main__":
    unittest.main()
