import unittest
from dataclasses import dataclass

import zmux
from zmux._runtime.queue import (
    OpenerVisibilityMark,
    QueueLane,
    TxFrame,
    WriteJob,
    make_tx_frame,
)
from zmux._runtime.writer import (
    BatchConfig,
    BatchScheduler,
    EncodedFrame,
    EncodedBatchStats,
    FALLBACK_GROUP_BUCKET,
    GroupKey,
    MAX_EXPLICIT_GROUPS,
    StreamMeta,
    StreamValueAccumulator,
    WriteBatchScratch,
    append_frame_binary_trusted,
    data_batch_items,
    encode_write_batch,
    frame_data_bytes_tx,
    frame_is_priority_update_tx,
    ordinary_batch_coalesce_seconds,
    ordinary_batch_cost_limit,
    order_write_batch,
    prepare_write_batch_size,
    queued_request_from_job,
    request_from_frames,
    should_use_vectored_batch,
    urgent_batch_items,
    write_batch,
    write_vectored_all,
)
from zmux.errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    TerminationKind,
    TransportError,
)
from zmux.frame import Frame
from zmux.payload import MetadataUpdate, build_priority_update_payload
from zmux.protocol import (
    CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE,
    EXT_PRIORITY_UPDATE,
    FRAME_FLAG_OPEN_METADATA,
    FrameType,
    SchedulerHint,
)
from zmux.settings import Settings
from zmux.varint import encode_varint

CAPS = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS


def tx(frame_type, stream_id=0, payload=b"", flags=0):
    frame = make_tx_frame(frame_type, flags, stream_id)
    frame.set_flat_payload(payload)
    return frame


def priority_update(stream_id):
    payload = build_priority_update_payload(
        CAPS, MetadataUpdate(priority=1), 4096
    )
    frame = make_tx_frame(FrameType.EXT, 0, stream_id)
    frame.set_flat_payload(payload)
    return frame


class PartialWriter:
    def __init__(self, chunk=3):
        self.chunk = chunk
        self.bytes = bytearray()
        self.flushes = 0

    def write(self, data):
        view = memoryview(data)
        n = min(self.chunk, len(view))
        self.bytes.extend(view[:n])
        return n

    def flush(self):
        self.flushes += 1


class VectoredWriter:
    def __init__(self, chunk=4096):
        self.chunk = chunk
        self.bytes = bytearray()
        self.vectored_calls = 0
        self.write_calls = 0
        self.flushes = 0

    def write_vectored(self, parts):
        self.vectored_calls += 1
        remaining = self.chunk
        written = 0
        for part in parts:
            if remaining == 0:
                break
            view = memoryview(part)
            n = min(remaining, len(view))
            self.bytes.extend(view[:n])
            written += n
            remaining -= n
        return written

    def write(self, data):
        self.write_calls += 1
        view = memoryview(data)
        self.bytes.extend(view)
        return len(view)

    def flush(self):
        self.flushes += 1


class BadVectoredWriter:
    def write_vectored(self, parts):
        del parts
        return True


class FailingWriter:
    def __init__(self):
        self.error = BrokenPipeError("pipe closed")
        self.flushes = 0

    def write(self, data):
        del data
        raise self.error

    def flush(self):
        self.flushes += 1


class RuntimeWriterEncodingTests(unittest.TestCase):
    def test_tx_frame_batch_encoding_matches_public_frame_codec(self):
        prefix = encode_varint(0)
        parts = [b"abc", bytearray(b"defg")]
        data = make_tx_frame(FrameType.DATA, FRAME_FLAG_OPEN_METADATA, 7)
        data.set_prefixed_parts_payload(prefix, parts, 0, 1, 5)
        ping = tx(FrameType.PING, 0, b"12345678")
        req = request_from_frames([data, ping])

        encoded = encode_write_batch([req])
        trusted = bytearray()
        append_frame_binary_trusted(trusted, data)

        expected_data = Frame(
            FrameType.DATA,
            7,
            FRAME_FLAG_OPEN_METADATA,
            b"\x00bcdef",
        ).marshal()
        expected = expected_data + Frame(FrameType.PING, 0, 0, b"12345678").marshal()
        size = prepare_write_batch_size([req])

        self.assertEqual(bytes(trusted), expected_data)
        self.assertEqual(encoded.to_bytes(), expected)
        self.assertEqual(size.encoded_bytes, len(expected))
        self.assertEqual(size.frame_count, 2)
        self.assertEqual(encoded.stats.payload_bytes, len(b"\x00bcdef") + 8)
        self.assertEqual(encoded.stats.data_bytes, 5)
        self.assertEqual(encoded.stats.opened_stream_ids, (7,))

    def test_write_batch_handles_partial_scalar_writer(self):
        req = request_from_frames(
            [
                tx(FrameType.DATA, 1, b"hello"),
                tx(FrameType.PONG, 0, b"12345678"),
            ]
        )
        writer = PartialWriter(chunk=2)

        stats = write_batch(writer, [req], prefer_vectored=False)

        expected = (
                Frame(FrameType.DATA, 1, 0, b"hello").marshal()
                + Frame(FrameType.PONG, 0, 0, b"12345678").marshal()
        )
        self.assertEqual(bytes(writer.bytes), expected)
        self.assertEqual(stats.encoded_bytes, len(expected))
        self.assertEqual(writer.flushes, 1)

    def test_empty_batch_does_not_flush_writer(self):
        writer = PartialWriter()

        stats = write_batch(writer, [], flush=True)

        self.assertEqual(stats.encoded_bytes, 0)
        self.assertEqual(stats.frame_count, 0)
        self.assertEqual(writer.bytes, bytearray())
        self.assertEqual(writer.flushes, 0)

    def test_large_part_payload_uses_vectored_write_without_concatenating_payload(self):
        first = bytearray(b"a" * 9000)
        second = bytearray(b"b" * 9000)
        frame = make_tx_frame(FrameType.DATA, 0, 9)
        frame.set_parts_payload([first, second], 0, 0, 18000)
        req = request_from_frames([frame])
        encoded = encode_write_batch([req])
        writer = VectoredWriter(chunk=2048)

        self.assertTrue(should_use_vectored_batch(encoded.stats))
        stats = write_batch(writer, [req])

        expected = Frame(FrameType.DATA, 9, 0, b"a" * 9000 + b"b" * 9000).marshal()
        self.assertEqual(bytes(writer.bytes), expected)
        self.assertEqual(stats.encoded_bytes, len(expected))
        self.assertGreater(writer.vectored_calls, 1)
        self.assertEqual(writer.write_calls, 0)
        self.assertEqual(writer.flushes, 1)

    def test_transport_write_failure_is_structured_like_java_writer_transport(self):
        req = request_from_frames([tx(FrameType.DATA, 1, b"hello")])
        writer = FailingWriter()

        with self.assertRaises(TransportError) as caught:
            write_batch(writer, [req], prefer_vectored=False)

        error = caught.exception
        self.assertIs(error.source_error, writer.error)
        self.assertIs(error.__cause__, writer.error)
        self.assertEqual(error.code, int(zmux.ErrorCode.INTERNAL))
        self.assertEqual(error.scope, ErrorScope.SESSION)
        self.assertEqual(error.operation, ErrorOperation.WRITE)
        self.assertEqual(error.source, ErrorSource.TRANSPORT)
        self.assertEqual(error.direction, ErrorDirection.BOTH)
        self.assertEqual(error.termination_kind, TerminationKind.SESSION_TERMINATION)
        self.assertEqual(writer.flushes, 0)


class RuntimeWriterOrderingTests(unittest.TestCase):
    def test_urgent_order_uses_rank_then_stream_scope_and_stream_id(self):
        ping = request_from_frames([tx(FrameType.PING, 0, b"12345678")])
        reset = request_from_frames([tx(FrameType.RESET, 9, encode_varint(1))])
        goaway = request_from_frames([tx(FrameType.GOAWAY, 0, encode_varint(1) * 3)])

        ordered = order_write_batch([ping, reset, goaway], QueueLane.URGENT)

        self.assertEqual(
            [req.frames[0].frame_type for req in ordered],
            [FrameType.GOAWAY, FrameType.RESET, FrameType.PING],
        )

    def test_same_stream_ordinary_burst_keeps_original_order(self):
        first = request_from_frames([tx(FrameType.DATA, 5, b"first")])
        second = request_from_frames([tx(FrameType.DATA, 5, b"second")])

        ordered = order_write_batch([first, second], QueueLane.ORDINARY)

        self.assertIs(ordered[0], first)
        self.assertIs(ordered[1], second)

    def test_priority_update_can_precede_same_stream_data_when_ordering_needed(self):
        data = request_from_frames([tx(FrameType.DATA, 5, b"body")])
        update = request_from_frames([priority_update(5)])

        ordered = order_write_batch([data, update], QueueLane.ORDINARY)

        self.assertEqual(ordered[0].frames[0].frame_type, FrameType.EXT)
        self.assertEqual(ordered[1].frames[0].frame_type, FrameType.DATA)

    def test_batch_scheduler_retains_weighted_fairness_across_calls(self):
        scheduler = BatchScheduler()
        low = request_from_frames([tx(FrameType.DATA, 1, b"x")])
        high = request_from_frames([tx(FrameType.DATA, 3, b"x")])
        meta = {1: StreamMeta(priority=0), 3: StreamMeta(priority=0)}
        cfg = BatchConfig(scheduler_hint=SchedulerHint.LATENCY)

        first = order_write_batch(
            [low, high],
            QueueLane.ORDINARY,
            scheduler=scheduler,
            config=cfg,
            stream_meta=meta,
        )
        second = order_write_batch(
            [low, high],
            QueueLane.ORDINARY,
            scheduler=scheduler,
            config=cfg,
            stream_meta=meta,
        )

        self.assertEqual(first[0].frames[0].stream_id, 1)
        self.assertEqual(second[0].frames[0].stream_id, 3)

    def test_group_fair_items_use_existing_scheduler_group_tracking(self):
        scheduler = BatchScheduler()
        for group_id in range(1, MAX_EXPLICIT_GROUPS + 1):
            scheduler.track_explicit_group(group_id)
        tracked = scheduler.group_key_for_stream(99, 777, True)
        self.assertEqual(tracked, GroupKey.explicit(FALLBACK_GROUP_BUCKET))
        req = request_from_frames([tx(FrameType.DATA, 99, b"x")])
        cfg = BatchConfig(group_fair=True)

        items = data_batch_items(
            [req],
            cfg,
            {99: StreamMeta(group=777)},
            scheduler=scheduler,
        )

        self.assertEqual(items[0].request.group_key, GroupKey.explicit(FALLBACK_GROUP_BUCKET))

    def test_group_fair_item_building_updates_scheduler_tracking(self):
        scheduler = BatchScheduler()
        req = request_from_frames([tx(FrameType.DATA, 77, b"x")])
        cfg = BatchConfig(group_fair=True)

        items = data_batch_items(
            [req],
            cfg,
            {77: StreamMeta(group=123)},
            scheduler=scheduler,
        )

        self.assertEqual(items[0].request.group_key, GroupKey.explicit(123))
        self.assertEqual(scheduler.stream_groups[77].group, 123)
        self.assertEqual(scheduler.active_group_refs[123], 1)

    def test_group_fair_item_building_rebinds_stale_scheduler_binding(self):
        scheduler = BatchScheduler()
        self.assertEqual(
            scheduler.group_key_for_stream(77, 123, True),
            GroupKey.explicit(123),
        )
        req = request_from_frames([tx(FrameType.DATA, 77, b"x")])
        cfg = BatchConfig(group_fair=True)

        items = data_batch_items(
            [req],
            cfg,
            {77: StreamMeta(group=456)},
            scheduler=scheduler,
        )

        self.assertEqual(items[0].request.group_key, GroupKey.explicit(456))
        self.assertEqual(scheduler.stream_groups[77].group, 456)
        self.assertNotIn(123, scheduler.active_group_refs)
        self.assertEqual(scheduler.active_group_refs[456], 1)

    def test_group_fair_disabled_item_building_releases_scheduler_binding(self):
        scheduler = BatchScheduler()
        self.assertEqual(
            scheduler.group_key_for_stream(77, 123, True),
            GroupKey.explicit(123),
        )
        req = request_from_frames([tx(FrameType.DATA, 77, b"x")])
        cfg = BatchConfig(group_fair=False)

        items = data_batch_items(
            [req],
            cfg,
            {77: StreamMeta(group=123)},
            scheduler=scheduler,
        )

        self.assertEqual(items[0].request.group_key, GroupKey.stream(77))
        self.assertEqual(scheduler.stream_groups, {})
        self.assertEqual(scheduler.active_group_refs, {})

    def test_data_batch_items_preserve_opening_frame_barrier_metadata(self):
        req = request_from_frames([tx(FrameType.DATA, 77, b"x")])
        req.prepared_opener_visibility = OpenerVisibilityMark.PEER_VISIBLE

        items = data_batch_items([req], BatchConfig(), {77: StreamMeta()})

        self.assertTrue(items[0].request.opening_frame)

    def test_urgent_batch_items_preserve_opening_frame_barrier_metadata(self):
        req = request_from_frames([tx(FrameType.DATA, 77, b"x")])
        req.prepared_opener_visibility = OpenerVisibilityMark.PEER_VISIBLE

        items = urgent_batch_items([req])

        self.assertTrue(items[0].request.opening_frame)


class RuntimeWriterPolicyTests(unittest.TestCase):
    def test_batch_cost_limit_and_coalesce_policy_follow_scheduler_hints(self):
        latency = Settings(scheduler_hints=SchedulerHint.LATENCY)
        bulk = Settings(scheduler_hints=SchedulerHint.BULK_THROUGHPUT)
        req = request_from_frames([tx(FrameType.DATA, 1, b"x")])

        self.assertLess(
            ordinary_batch_cost_limit(latency),
            ordinary_batch_cost_limit(bulk),
        )
        self.assertEqual(
            ordinary_batch_coalesce_seconds(
                [req],
                2,
                100,
                peer_settings=latency,
            ),
            0.001,
        )
        self.assertEqual(
            ordinary_batch_coalesce_seconds(
                [req, req],
                20,
                100,
                peer_settings=bulk,
            ),
            0.004,
        )
        self.assertEqual(
            ordinary_batch_coalesce_seconds(
                [req],
                2,
                100,
                urgent_queued=True,
                peer_settings=bulk,
            ),
            0.0,
        )

    def test_stream_value_accumulator_uses_single_stream_fast_path_then_promotes(self):
        left = object()
        right = object()
        acc = StreamValueAccumulator()

        acc.add(left, 2)
        acc.add(left, 3)
        self.assertEqual(acc.items(), ((left, 5),))

        acc.remember_first(left, 9)
        acc.remember_first(right, 4)
        acc.add(right, 6)

        self.assertEqual(acc.items(), ((left, 5), (right, 10)))

    def test_stream_value_accumulator_uses_identity_for_unhashable_streams(self):
        @dataclass
        class StreamRef:
            stream_id: int

        left = StreamRef(7)
        equal_but_distinct = StreamRef(7)
        acc = StreamValueAccumulator()

        acc.add(left, 2)
        acc.add(left, 3)
        acc.add(equal_but_distinct, 5)

        items = acc.items()
        self.assertEqual(len(items), 2)
        self.assertIs(items[0][0], left)
        self.assertEqual(items[0][1], 5)
        self.assertIs(items[1][0], equal_but_distinct)
        self.assertEqual(items[1][1], 5)

    def test_write_batch_scratch_tracks_queued_streams_by_identity(self):
        @dataclass
        class StreamRef:
            stream_id: int

        left = StreamRef(9)
        equal_but_distinct = StreamRef(9)
        scratch = WriteBatchScratch()

        scratch.queued_stream_scratch(2)
        scratch.add_queued_stream(left, 2)
        scratch.add_queued_stream(left, 3)
        scratch.add_queued_stream(equal_but_distinct, 4)

        items = scratch.queued_stream_items()
        self.assertEqual(len(items), 2)
        self.assertIs(items[0][0], left)
        self.assertEqual(items[0][1], 5)
        self.assertIs(items[1][0], equal_but_distinct)
        self.assertEqual(items[1][1], 4)

        scratch.clear_retained_batch_refs()
        self.assertEqual(scratch.queued_by_stream, {})
        self.assertEqual(scratch.queued_streams, [])

    def test_priority_update_detection_and_data_bytes_handle_open_metadata(self):
        update = make_tx_frame(FrameType.EXT, 0, 7)
        update.set_flat_payload(encode_varint(EXT_PRIORITY_UPDATE))
        data = make_tx_frame(FrameType.DATA, FRAME_FLAG_OPEN_METADATA, 7)
        data.set_prefixed_parts_payload(
            encode_varint(0),
            [bytearray(b"abc"), b"def"],
            0,
            0,
            6,
        )

        self.assertTrue(frame_is_priority_update_tx(update))
        self.assertEqual(frame_data_bytes_tx(data), 6)

    def test_stream_accounting_is_validated_and_sorted_like_rust(self):
        req = request_from_frames(
            [
                tx(FrameType.DATA, 9, b"abcdef"),
                tx(FrameType.DATA, 1, b"abc"),
                tx(FrameType.DATA, 5, b"ab"),
                tx(FrameType.DATA, 5, b"cdef"),
            ]
        )

        encoded = encode_write_batch([req])

        self.assertEqual(list(encoded.stats.data_cost_by_stream), [1, 5, 9])
        self.assertEqual(encoded.stats.data_frame_count_by_stream[5], 2)
        self.assertEqual(encoded.stats.opened_stream_ids, (9, 1, 5))

    def test_queued_request_from_job_returns_classified_request(self):
        job = WriteJob.frame_job(Frame(FrameType.DATA, 3, 0, b"abc"))

        req = queued_request_from_job(job)

        self.assertTrue(req.request_meta_ready)
        self.assertTrue(req.request_stream_scoped)
        self.assertEqual(req.request_stream_id, 3)
        self.assertEqual(req.request_cost, 4)
        self.assertEqual(req.queued_bytes, 4)

    def test_writer_rejects_implicit_python_coercions(self):
        req = request_from_frames([tx(FrameType.DATA, 1, b"x")])
        writer = PartialWriter()

        with self.assertRaises(TypeError):
            write_batch(writer, [req], flush=1)
        with self.assertRaises(TypeError):
            write_batch(writer, [req], prefer_vectored=1)
        with self.assertRaises(TypeError):
            request_from_frames([Frame(FrameType.DATA, 1, 0, b"x")])
        with self.assertRaises(TypeError):
            frame_data_bytes_tx("not-a-tx-frame")
        with self.assertRaises(TypeError):
            ordinary_batch_cost_limit(send_rate_estimate="1")
        with self.assertRaises(TypeError):
            ordinary_batch_coalesce_seconds([req], 1, 10, urgent_queued=1)
        with self.assertRaises(TypeError):
            EncodedFrame(5)
        with self.assertRaises(TypeError):
            EncodedBatchStats(data_cost_by_stream={"1": 1})
        with self.assertRaises(ValueError):
            EncodedBatchStats(opened_stream_ids=(0,))
        with self.assertRaises(OSError):
            write_vectored_all(BadVectoredWriter(), [b"x"])


if __name__ == "__main__":
    unittest.main()
