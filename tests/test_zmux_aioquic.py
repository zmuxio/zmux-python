import asyncio
import inspect
import sys
import unittest
from pathlib import Path

import zmux

_AIOQUIC_SRC = Path(__file__).resolve().parents[1] / "packages" / "zmuxio-aioquic" / "src"
if str(_AIOQUIC_SRC) not in sys.path:
    sys.path.insert(0, str(_AIOQUIC_SRC))

import zmux_aioquic
from zmux.conformance import SUITE_STREAM_ADAPTER_PROFILE
from zmux.protocol import CLAIM_STREAM_ADAPTER_PROFILE_V1


class MemoryReader:
    def __init__(self, data=b""):
        self.data = bytearray(data)
        self.closed = False

    async def read(self, n=-1):
        if self.closed:
            return b""
        if n is None or n < 0 or n > len(self.data):
            n = len(self.data)
        out = bytes(self.data[:n])
        del self.data[:n]
        return out

    async def readexactly(self, n):
        out = await self.read(n)
        if len(out) != n:
            raise EOFError("short read")
        return out

    async def close(self):
        self.closed = True


class MemoryWriter:
    def __init__(self, stream_id=0):
        self.stream_id = stream_id
        self.chunks = []
        self.closed = False
        self.reset_codes = []

    def write(self, data):
        self.chunks.append(bytes(data))

    async def drain(self):
        return None

    async def write_eof(self):
        self.closed = True

    async def reset(self, code):
        self.reset_codes.append(code)
        self.closed = True

    def bytes(self):
        return b"".join(self.chunks)


class PartialWriter(MemoryWriter):
    def __init__(self, stream_id=0, max_chunk=2):
        super().__init__(stream_id)
        self.max_chunk = max_chunk

    def write(self, data):
        view = memoryview(data)
        chunk = bytes(view[: self.max_chunk])
        self.chunks.append(chunk)
        return len(chunk)


class YieldingWriter(MemoryWriter):
    async def write(self, data):
        self.chunks.append(bytes(data))
        await asyncio.sleep(0)


class BoolProgressWriter(MemoryWriter):
    def write(self, data):
        del data
        return True


class ShortExactReader(MemoryReader):
    async def readexactly(self, n):
        del n
        return b""


class FakeConnection:
    def __init__(self):
        self.next_stream_id = 4
        self.opened = []
        self.stop_calls = []
        self.reset_calls = []
        self.closed_value = False
        self.close_args = None

    async def create_stream(self, is_unidirectional=False):
        stream_id = self.next_stream_id
        self.next_stream_id += 4
        reader = None if is_unidirectional else MemoryReader()
        writer = MemoryWriter(stream_id)
        self.opened.append((reader, writer, is_unidirectional))
        return reader, writer

    async def stop_sending(self, stream_id, code):
        self.stop_calls.append((stream_id, code))

    async def reset_stream(self, stream_id, code):
        self.reset_calls.append((stream_id, code))

    async def close(self, error_code=0, reason_phrase=""):
        self.closed_value = True
        self.close_args = (error_code, reason_phrase)

    def closed(self):
        return self.closed_value


class SlowOpenConnection(FakeConnection):
    async def create_stream(self, is_unidirectional=False):
        await asyncio.sleep(0.05)
        return await super().create_stream(is_unidirectional)


class WaitOnlyConnection(FakeConnection):
    def __init__(self):
        super().__init__()
        self.waited = False

    async def wait_closed(self):
        self.waited = True

    def closed(self):
        return False


class NormalApplicationClose(Exception):
    error_code = 0
    reason_phrase = ""


class NormalWaitCloseConnection(FakeConnection):
    async def wait_closed(self):
        raise NormalApplicationClose()

    def closed(self):
        return False


class PartialWriteConnection(FakeConnection):
    async def create_stream(self, is_unidirectional=False):
        stream_id = self.next_stream_id
        self.next_stream_id += 4
        reader = None if is_unidirectional else MemoryReader()
        writer = PartialWriter(stream_id, 2)
        self.opened.append((reader, writer, is_unidirectional))
        return reader, writer


class YieldingWriteConnection(FakeConnection):
    async def create_stream(self, is_unidirectional=False):
        stream_id = self.next_stream_id
        self.next_stream_id += 4
        reader = None if is_unidirectional else MemoryReader()
        writer = YieldingWriter(stream_id)
        self.opened.append((reader, writer, is_unidirectional))
        return reader, writer


class BoolProgressConnection(FakeConnection):
    async def create_stream(self, is_unidirectional=False):
        stream_id = self.next_stream_id
        self.next_stream_id += 4
        reader = None if is_unidirectional else MemoryReader()
        writer = BoolProgressWriter(stream_id)
        self.opened.append((reader, writer, is_unidirectional))
        return reader, writer


class BlockingReader:
    def __init__(self):
        self.released = asyncio.Event()
        self.closed = False

    async def read(self, n=-1):
        await self.released.wait()
        return b""

    async def readexactly(self, n):
        await self.released.wait()
        raise EOFError("short read")

    async def close(self):
        self.closed = True
        self.released.set()

    def release(self):
        self.released.set()


class DirectAcceptConnection(FakeConnection):
    def __init__(self, streams):
        super().__init__()
        self.accepted = asyncio.Queue()
        for stream in streams:
            self.accepted.put_nowait(stream)

    async def accept_stream(self):
        return await self.accepted.get()


class AioquicPreludeTest(unittest.IsolatedAsyncioTestCase):
    async def test_options_defaults_and_clamps(self):
        previous = zmux_aioquic.default_accepted_prelude_max_concurrent()
        try:
            zmux_aioquic.set_default_accepted_prelude_max_concurrent(0)
            self.assertEqual(
                zmux_aioquic.default_accepted_prelude_max_concurrent(),
                zmux_aioquic.DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT,
            )
            zmux_aioquic.set_default_accepted_prelude_max_concurrent(
                zmux_aioquic.MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT + 10
            )
            self.assertEqual(
                zmux_aioquic.default_accepted_prelude_max_concurrent(),
                zmux_aioquic.MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT,
            )
            self.assertIsNone(zmux_aioquic.normalize_accepted_prelude_read_timeout(None))
            self.assertEqual(
                zmux_aioquic.normalize_accepted_prelude_read_timeout(0),
                zmux_aioquic.DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT,
            )
            self.assertIsNone(zmux_aioquic.normalize_accepted_prelude_read_timeout(-1))
            with self.assertRaises(TypeError):
                zmux_aioquic.set_default_accepted_prelude_max_concurrent(True)
            with self.assertRaises(TypeError):
                zmux_aioquic.normalize_accepted_prelude_max_concurrent("2")
            with self.assertRaises(ValueError):
                zmux_aioquic.normalize_accepted_prelude_read_timeout(float("nan"))
            with self.assertRaises(TypeError):
                zmux_aioquic.SessionOptions(accepted_prelude_max_concurrent=True)
            with self.assertRaises(TypeError):
                zmux_aioquic.AcceptedStreamMetadata(metadata_valid=1)
        finally:
            zmux_aioquic.set_default_accepted_prelude_max_concurrent(previous)

    async def test_conformance_targets_match_stream_adapter_profile(self):
        self.assertEqual(
            zmux_aioquic.target_claims(),
            (CLAIM_STREAM_ADAPTER_PROFILE_V1,),
        )
        self.assertEqual(zmux_aioquic.target_implementation_profiles(), ())
        self.assertEqual(
            zmux_aioquic.target_suites(),
            (SUITE_STREAM_ADAPTER_PROFILE,),
        )

    async def test_stream_prelude_round_trip_and_payload_is_left_for_reader(self):
        options = zmux.OpenOptions(initial_priority=3, initial_group=5, open_info=b"meta")
        prelude = zmux_aioquic.build_stream_prelude(options)
        reader = MemoryReader(prelude + b"app")

        metadata = await zmux_aioquic.read_stream_prelude(reader)

        self.assertTrue(metadata.metadata_valid)
        self.assertEqual(metadata.metadata.priority, 3)
        self.assertEqual(metadata.metadata.group, 5)
        self.assertEqual(metadata.open_info, b"meta")
        self.assertEqual(await reader.read(), b"app")

    async def test_over_limit_prelude_is_rejected_before_payload_allocation(self):
        reader = MemoryReader(zmux.encode_varint(zmux_aioquic.STREAM_PRELUDE_MAX_PAYLOAD))

        with self.assertRaises(zmux.OpenMetadataTooLarge):
            await zmux_aioquic.read_stream_prelude(reader)

    async def test_short_exact_prelude_read_is_rejected(self):
        with self.assertRaises(zmux.ProtocolError):
            await zmux_aioquic.read_stream_prelude(ShortExactReader())


class AioquicSessionTest(unittest.IsolatedAsyncioTestCase):
    async def test_placeholder_preface_and_negotiation_use_current_role_registry(self):
        session = zmux_aioquic.wrap_session(FakeConnection())

        async with session as managed:
            self.assertIs(managed, session)
        self.assertEqual(session.local_preface().role, zmux.Role.AUTO)
        self.assertEqual(session.peer_preface().role, zmux.Role.AUTO)
        self.assertEqual(session.negotiated().local_role, zmux.Role.INITIATOR)
        self.assertEqual(session.negotiated().peer_role, zmux.Role.RESPONDER)
        self.assertFalse(hasattr(zmux_aioquic, "wrap_session_with_options"))
        self.assertFalse(hasattr(zmux_aioquic.SessionOptions, "defaults"))
        self.assertNotIn("peer_addr", zmux_aioquic.SessionOptions.__dataclass_fields__)

    async def test_open_stream_writes_prelude_before_payload(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        options = zmux.OpenOptions(initial_priority=9, open_info=b"hello")

        stream = await session.open_stream(options)
        writer = conn.opened[0][1]
        expected = zmux_aioquic.build_stream_prelude(options)
        self.assertIsInstance(session, zmux.AsyncSession)
        self.assertIsInstance(stream, zmux.AsyncStream)
        self.assertIsInstance(session.stats, zmux.SessionStats)
        self.assertIsInstance(stream.metadata, zmux.StreamMetadata)
        self.assertEqual(writer.bytes(), expected)

        written = await stream.write(b"payload")

        self.assertEqual(written, len(b"payload"))
        self.assertEqual(writer.bytes(), expected + b"payload")
        self.assertEqual(session.stats.sent_data_bytes, len(b"payload"))

    async def test_pythonic_read_write_aliases_match_async_stream_surface(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream(zmux.OpenOptions())

        written = await stream.write(b"abc", timeout=1.0)
        written += await stream.write_vectored((b"d", b"ef"), timeout=1.0)
        written += await stream.write_final(b"!", timeout=1.0)

        writer = conn.opened[0][1]
        self.assertIsInstance(stream, zmux.AsyncStream)
        self.assertEqual(written, 7)
        self.assertFalse(hasattr(stream, "write_timeout"))
        self.assertFalse(hasattr(stream, "read_timeout"))
        self.assertFalse(hasattr(stream, "read_all"))
        self.assertFalse(hasattr(stream, "read_to_end"))
        self.assertFalse(hasattr(stream, "read_all_bytes"))
        self.assertTrue(callable(stream.readinto))
        self.assertEqual(writer.bytes(), zmux_aioquic.build_stream_prelude() + b"abcdef!")
        self.assertTrue(writer.closed)

        prelude = zmux_aioquic.build_stream_prelude()
        await session.add_incoming_stream(MemoryReader(prelude + b"hello"), MemoryWriter(44), 44)
        accepted = await session.accept_stream(0.1)

        self.assertIsInstance(accepted, zmux.AsyncStream)
        self.assertEqual(await accepted.read(2, timeout=1.0), b"he")
        buffer = bytearray(2)
        self.assertEqual(await accepted.readinto(buffer, timeout=1.0), 2)
        self.assertEqual(buffer, bytearray(b"ll"))
        self.assertEqual(await accepted.read_exact(1, timeout=1.0), b"o")

    async def test_open_and_send_is_the_single_session_convenience_name(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)

        stream = await session.open_and_send(
            memoryview(b"hello"), options=zmux.OpenOptions(open_info=b"meta"), timeout=1.0
        )
        send_stream = await session.open_uni_and_send(bytearray(b"done"), timeout=1.0)

        first_writer = conn.opened[0][1]
        second_writer = conn.opened[1][1]
        self.assertIsInstance(session, zmux.AsyncSession)
        self.assertIsInstance(stream, zmux.AsyncStream)
        self.assertIsInstance(send_stream, zmux.AsyncSendStream)
        self.assertFalse(hasattr(session, "open_and_write"))
        self.assertFalse(hasattr(session, "open_uni_and_write"))
        self.assertEqual(
            first_writer.bytes(),
            zmux_aioquic.build_stream_prelude(zmux.OpenOptions(open_info=b"meta"))
            + b"hello",
        )
        self.assertEqual(second_writer.bytes(), zmux_aioquic.build_stream_prelude() + b"done")
        self.assertTrue(second_writer.closed)

    async def test_quic_session_can_be_used_through_public_async_session_surface(self):
        async def use_session(session: zmux.AsyncSession):
            stream = await session.open_and_send(b"request", timeout=1.0)
            uni_stream = await session.open_uni_and_send(b"event", timeout=1.0)
            await session.close()
            return stream, uni_stream

        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)

        stream, uni_stream = await use_session(session)

        self.assertIsInstance(session, zmux.AsyncSession)
        self.assertIsInstance(stream, zmux.AsyncStream)
        self.assertIsInstance(uni_stream, zmux.AsyncSendStream)
        self.assertEqual(conn.opened[0][1].bytes(), zmux_aioquic.build_stream_prelude() + b"request")
        self.assertEqual(conn.opened[1][1].bytes(), zmux_aioquic.build_stream_prelude() + b"event")
        self.assertTrue(conn.closed_value)

    def test_session_timeouts_are_keyword_only(self):
        for owner in (zmux.AsyncSession, zmux_aioquic.AioquicSession):
            for name in ("open_stream", "open_uni_stream", "open_and_send", "open_uni_and_send"):
                signature = inspect.signature(getattr(owner, name))
                self.assertEqual(
                    signature.parameters["timeout"].kind,
                    inspect.Parameter.KEYWORD_ONLY,
                    "%s.%s timeout should be keyword-only" % (owner.__name__, name),
                )
            self.assertEqual(
                inspect.signature(getattr(owner, "ping")).parameters["timeout"].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )

    async def test_streams_are_async_context_managers(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream()

        async with stream as managed:
            self.assertIs(managed, stream)
            self.assertIsInstance(managed, zmux.AsyncStream)

        writer = conn.opened[0][1]
        self.assertEqual(writer.bytes(), zmux_aioquic.build_stream_prelude())
        self.assertEqual(conn.stop_calls, [(writer.stream_id, int(zmux.ErrorCode.CANCELLED))])
        self.assertTrue(writer.closed)
        self.assertTrue(stream.read_closed)
        self.assertTrue(stream.write_closed)

    async def test_stream_api_rejects_implicit_python_coercions(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream(zmux.OpenOptions())

        with self.assertRaises(TypeError):
            stream.set_timeout(True)
        with self.assertRaises(TypeError):
            await stream.read(True)
        with self.assertRaises(TypeError):
            await stream.readinto(b"readonly")
        with self.assertRaises(TypeError):
            await stream.read_exact(True)
        with self.assertRaises(TypeError):
            await stream.write(None)
        with self.assertRaises(TypeError):
            await session.open_stream(timeout=True)
        with self.assertRaises(TypeError):
            await session.wait(timeout=True)
        with self.assertRaises(TypeError):
            await session.add_incoming_stream(
                MemoryReader(zmux_aioquic.build_stream_prelude()),
                MemoryWriter(44),
                "44",
            )

        await session.add_incoming_stream(
            MemoryReader(zmux_aioquic.build_stream_prelude()),
            None,
            48,
            False,
        )
        recv_stream = await session.accept_uni_stream(0.1)
        send_stream = await session.open_uni_stream()
        with self.assertRaises(zmux.StreamNotWritable):
            await recv_stream.write_final(b"x")
        with self.assertRaises(zmux.StreamNotReadable):
            await send_stream.read_exact(1)

    async def test_session_wait_timeout_uses_session_wait_error(self):
        session = zmux_aioquic.wrap_session(FakeConnection())

        with self.assertRaises(zmux.SessionWaitTimeout):
            await session.wait(0.001)

    async def test_session_wait_marks_adapter_closed_after_backend_wait_returns(self):
        conn = WaitOnlyConnection()
        session = zmux_aioquic.wrap_session(conn)

        await session.wait(0.1)

        self.assertTrue(conn.waited)
        self.assertTrue(session.closed)
        self.assertEqual(session.state, zmux.SessionState.CLOSED)

    async def test_session_wait_treats_empty_application_close_as_normal(self):
        session = zmux_aioquic.wrap_session(NormalWaitCloseConnection())

        await session.wait(0.1)

        self.assertTrue(session.closed)
        self.assertEqual(session.state, zmux.SessionState.CLOSED)

    async def test_open_prelude_failure_discards_backend_stream(self):
        conn = BoolProgressConnection()
        session = zmux_aioquic.wrap_session(conn)

        with self.assertRaises(zmux.SessionClosed):
            await session.open_stream(zmux.OpenOptions(open_info=b"meta"))

        writer = conn.opened[0][1]
        self.assertEqual(conn.stop_calls, [(writer.stream_id, int(zmux.ErrorCode.INTERNAL))])
        self.assertEqual(writer.reset_codes, [int(zmux.ErrorCode.INTERNAL)])
        self.assertEqual(session.stats.active_streams.total, 0)

    async def test_writer_bool_progress_is_rejected(self):
        session = zmux_aioquic.wrap_session(BoolProgressConnection())
        stream = await session.open_stream(zmux.OpenOptions())

        with self.assertRaises(zmux.SessionClosed):
            await stream.write(b"x")

    async def test_zero_write_is_noop_but_close_read_submits_prelude_first(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        options = zmux.OpenOptions()
        stream = await session.open_stream(options)

        self.assertEqual(await stream.write(b""), 0)
        writer = conn.opened[0][1]
        self.assertEqual(writer.bytes(), b"")

        await stream.close_read()

        self.assertEqual(writer.bytes(), zmux_aioquic.build_stream_prelude(options))
        self.assertEqual(conn.stop_calls, [(writer.stream_id, int(zmux.ErrorCode.CANCELLED))])

    async def test_partial_writer_progress_is_completed_without_losing_bytes(self):
        conn = PartialWriteConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream(zmux.OpenOptions())

        written = await stream.write(b"abcdef")

        writer = conn.opened[0][1]
        self.assertEqual(written, 6)
        self.assertEqual(writer.bytes(), zmux_aioquic.build_stream_prelude() + b"abcdef")
        self.assertGreater(len(writer.chunks), 2)

    async def test_vectored_write_coalesces_small_payload(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream(zmux.OpenOptions())

        written = await stream.write_vectored((b"a", b"bc", b"def"))

        writer = conn.opened[0][1]
        self.assertEqual(written, 6)
        self.assertEqual(writer.chunks, [zmux_aioquic.build_stream_prelude(), b"abcdef"])

    async def test_large_vectored_send_holds_write_lock_for_all_segments(self):
        conn = YieldingWriteConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream(zmux.OpenOptions(open_info=b"ready"))
        writer = conn.opened[0][1]
        writer.chunks.clear()

        await asyncio.gather(
            stream.write_vectored((b"a" * 40_000, b"A" * 40_000)),
            stream.write_vectored((b"b" * 40_000, b"B" * 40_000)),
        )

        labels = [chunk[:1] for chunk in writer.chunks]
        self.assertIn(
            labels,
            ([b"a", b"A", b"b", b"B"], [b"b", b"B", b"a", b"A"]),
        )

    async def test_write_final_serializes_with_concurrent_write(self):
        conn = YieldingWriteConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_uni_stream()
        writer = conn.opened[0][1]

        final_task = asyncio.create_task(stream.write_final(b"final"))
        await asyncio.sleep(0)
        late = await asyncio.gather(
            final_task,
            stream.write(b"late"),
            return_exceptions=True,
        )

        self.assertEqual(late[0], 5)
        self.assertIsInstance(late[1], zmux.WriteClosed)
        self.assertEqual(writer.bytes(), zmux_aioquic.build_stream_prelude() + b"final")
        self.assertTrue(writer.closed)

    async def test_update_metadata_only_before_prelude(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream(zmux.OpenOptions())

        await stream.update_metadata(zmux.MetadataUpdate(priority=7, group=11))
        await stream.write_final(b"")

        writer = conn.opened[0][1]
        metadata = await zmux_aioquic.read_stream_prelude(MemoryReader(writer.bytes()))
        self.assertEqual(metadata.metadata.priority, 7)
        self.assertEqual(metadata.metadata.group, 11)
        self.assertEqual(metadata.metadata.open_info, b"")
        with self.assertRaises(zmux.WriteClosed):
            await stream.update_metadata(zmux.MetadataUpdate(priority=1))

    async def test_update_metadata_after_write_cancel_reports_write_closed(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_uni_stream()

        await stream.cancel_write(99)

        with self.assertRaises(zmux.WriteClosed):
            await stream.update_metadata(zmux.MetadataUpdate(priority=1))

    async def test_stream_abort_and_reset_reasons_are_classified(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        reset_stream = await session.open_stream()
        abort_stream = await session.open_stream()

        await reset_stream.cancel_write(77)
        await abort_stream.close_with_error(88, "abort")

        reasons = session.stats.reasons
        self.assertEqual(reasons.reset[77], 1)
        self.assertEqual(reasons.abort[88], 1)

    async def test_close_with_error_is_idempotent_for_adapter_streams(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_stream()
        writer = conn.opened[0][1]

        await stream.close_with_error(88, "abort")
        await stream.close_with_error(88, "abort")

        self.assertEqual(conn.stop_calls, [(writer.stream_id, 88)])
        self.assertEqual(writer.reset_codes, [88])
        self.assertEqual(session.stats.reasons.abort[88], 1)
        with self.assertRaises(TypeError):
            await (await session.open_stream()).close_with_error(1, 5)

    async def test_unidirectional_close_with_error_only_closes_present_direction(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        send_stream = await session.open_uni_stream()

        await send_stream.close_with_error(55, "send")

        send_writer = conn.opened[0][1]
        self.assertEqual(send_writer.reset_codes, [55])
        self.assertEqual(conn.reset_calls, [])
        self.assertEqual(conn.stop_calls, [])

        prelude = zmux_aioquic.build_stream_prelude()
        await session.add_incoming_stream(MemoryReader(prelude), None, 12, False)
        recv_stream = await session.accept_uni_stream(0.1)

        await recv_stream.close_with_error(66, "recv")

        self.assertEqual(conn.stop_calls, [(12, 66)])
        self.assertEqual(conn.reset_calls, [])

    async def test_accept_stream_decodes_prelude_under_public_session_surface(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        prelude = zmux_aioquic.build_stream_prelude(
            zmux.OpenOptions(initial_group=12, open_info=b"peer")
        )
        await session.add_incoming_stream(MemoryReader(prelude + b"abc"), MemoryWriter(44), 44)

        stream = await session.accept_stream(0.1)

        self.assertEqual(stream.stream_id, 44)
        self.assertFalse(stream.opened_locally)
        self.assertTrue(stream.bidirectional)
        self.assertEqual(stream.open_info, b"peer")
        self.assertEqual(stream.metadata.group, 12)
        self.assertEqual(await stream.read(2), b"ab")
        stats = session.stats
        self.assertEqual(stats.accepted_streams, 1)
        self.assertEqual(stats.active_streams.peer_bidi, 1)

    async def test_read_exact_short_remote_close_is_structured(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        prelude = zmux_aioquic.build_stream_prelude()
        await session.add_incoming_stream(MemoryReader(prelude + b"ab"), MemoryWriter(44), 44)
        stream = await session.accept_stream(0.1)

        with self.assertRaises(zmux.ReadClosed) as caught:
            await stream.read_exact(3, timeout=1.0)

        self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.GRACEFUL)
        self.assertTrue(stream.read_closed)
        with self.assertRaises(zmux.ReadClosed) as again:
            await stream.read(1)
        self.assertIs(again.exception, caught.exception)

    async def test_read_eof_records_remote_graceful_close_for_future_reads(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        prelude = zmux_aioquic.build_stream_prelude()
        await session.add_incoming_stream(MemoryReader(prelude), MemoryWriter(44), 44)
        stream = await session.accept_stream(0.1)

        self.assertEqual(await stream.read(1), b"")

        with self.assertRaises(zmux.ReadClosed) as caught:
            await stream.read(1)
        self.assertEqual(caught.exception.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.GRACEFUL)

    async def test_direct_accept_prepares_preludes_concurrently(self):
        slow_reader = BlockingReader()
        ready_prelude = zmux_aioquic.build_stream_prelude(
            zmux.OpenOptions(open_info=b"ready")
        )
        ready_reader = MemoryReader(ready_prelude + b"x")
        conn = DirectAcceptConnection(
            (
                (slow_reader, MemoryWriter(40)),
                (ready_reader, MemoryWriter(44)),
            )
        )
        options = zmux_aioquic.SessionOptions(
            accepted_prelude_read_timeout=None,
            accepted_prelude_max_concurrent=2,
        )
        session = zmux_aioquic.wrap_session(conn, options)
        try:
            stream = await session.accept_stream(0.2)

            self.assertEqual(stream.stream_id, 44)
            self.assertEqual(stream.open_info, b"ready")
            self.assertEqual(await stream.read(1), b"x")
            self.assertEqual(session.stats.accepted_streams, 1)
        finally:
            slow_reader.release()
            await session.close()

    async def test_vectored_final_write_and_open_timeout(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        stream = await session.open_uni_stream(timeout=0.01)

        written = await stream.write_vectored_final((b"a", b"bc"))

        writer = conn.opened[0][1]
        self.assertEqual(written, 3)
        self.assertEqual(writer.bytes(), zmux_aioquic.build_stream_prelude() + b"abc")
        self.assertTrue(writer.closed)

        slow = zmux_aioquic.wrap_session(SlowOpenConnection())
        with self.assertRaises(zmux.OpenTimeout):
            await slow.open_stream(timeout=0.001)

    async def test_wrap_none_uses_closed_async_session(self):
        session = zmux_aioquic.wrap_session(None)
        self.assertIsInstance(session, zmux.AsyncInvalidSession)
        self.assertTrue(session.closed)
        self.assertEqual(session.state, zmux.SessionState.INVALID)
        self.assertEqual(session.stats.state, zmux.SessionState.INVALID)
        with self.assertRaises(zmux.SessionClosed):
            await session.open_stream()

    async def test_normal_session_close_does_not_record_abort_reason(self):
        session = zmux_aioquic.wrap_session(FakeConnection())

        await session.close()

        self.assertNotIn(0, session.stats.reasons.abort)

    async def test_accept_stream_wakes_when_session_closes(self):
        session = zmux_aioquic.wrap_session(FakeConnection())
        task = asyncio.create_task(session.accept_stream())
        await asyncio.sleep(0)

        await session.close()

        with self.assertRaises(zmux.SessionClosed):
            await asyncio.wait_for(task, 0.1)

    async def test_queue_incoming_stream_task_exposes_but_consumes_prepare_error(self):
        conn = FakeConnection()
        session = zmux_aioquic.wrap_session(conn)
        writer = MemoryWriter(9)

        task = session.queue_incoming_stream(MemoryReader(b""), writer, 9)

        with self.assertRaises(zmux.ProtocolError):
            await task
        self.assertEqual(writer.reset_codes, [int(zmux.ErrorCode.PROTOCOL)])
        with self.assertRaises(zmux.AcceptTimeout):
            await session.accept_stream(0.001)


if __name__ == "__main__":
    unittest.main()
