import sys
import threading
import time
import unittest
from collections import deque
from queue import Queue

from zmux._runtime.queue import (
    ChunkSpan,
    DataCosts,
    PENDING_CONTROL_BUDGET_MESSAGE,
    PENDING_PRIORITY_BUDGET_MESSAGE,
    QueueCost,
    QUEUED_DATA_HWM_MESSAGE,
    QueueReservationResult,
    QueuedWriteResult,
    URGENT_WRITER_QUEUE_FULL_MESSAGE,
    WRITER_QUEUE_FULL_MESSAGE,
    OpenerVisibilityMark,
    QueueLane,
    QueuedWriteRequest,
    PreparedPriorityUpdate,
    StreamDiscardStats,
    TxFrame,
    WriteCompletion,
    WriteJob,
    WriteQueuePopStatus,
    WriteQueue,
    WriteQueueLimits,
    WriteRequestOrigin,
    WriterQueueStats,
    add_request_cost,
    add_tx_payload_lengths,
    batch_stream_id,
    build_tx_lane_request,
    checked_tx_payload_length,
    clone_tx_frames_if_needed,
    collect_ready_batch_into,
    effective_deadline,
    frame_data_app_bytes,
    frame_buffered_bytes,
    frame_chunk_spans,
    frames_buffered_bytes,
    make_tx_frame,
    max_tx_payload_length,
    prepared_priority_update_from_frames,
    retained_frame_queue_cost,
    request_cost_from_bytes,
    send_by_deadline,
    trim_tx_payload_parts,
    tx_frame_chunk_spans,
    tx_frame_encoded_bytes,
    tx_frame_queue_cost,
    tx_frames_queue_cost,
    validate_outbound_tx_frames_with_limits,
    wait_by_deadline,
    write_all,
)
from zmux._wire.varint import encode_varint
from zmux.frame import Frame
from zmux.payload import (
    MetadataUpdate,
    build_priority_update_payload,
    parse_priority_update_payload,
)
from zmux.protocol import (
    CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE,
    CAPABILITY_STREAM_GROUPS,
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    FrameType,
)

CAPS = (
        CAPABILITY_PRIORITY_UPDATE
        | CAPABILITY_PRIORITY_HINTS
        | CAPABILITY_STREAM_GROUPS
)


def frame(frame_type, stream_id=0, payload=b"", flags=0):
    return Frame(frame_type, stream_id, flags, payload)


def data(stream_id, payload=b"x", flags=0):
    return frame(FrameType.DATA, stream_id, payload, flags)


def priority_update(stream_id, priority=None, group=None):
    payload = build_priority_update_payload(
        CAPS, MetadataUpdate(priority=priority, group=group), 4096
    )
    return frame(FrameType.EXT, stream_id, payload)


def queue_limits(
        max_bytes=1024,
        urgent_max_bytes=1024,
        session_data_max_bytes=1024,
        per_stream_data_max_bytes=1024,
        pending_control_max_bytes=1024,
        pending_priority_max_bytes=1024,
        max_batch_bytes=1024,
        max_batch_frames=8,
):
    return WriteQueueLimits(
        max_bytes=max_bytes,
        urgent_max_bytes=urgent_max_bytes,
        session_data_max_bytes=session_data_max_bytes,
        per_stream_data_max_bytes=per_stream_data_max_bytes,
        pending_control_max_bytes=pending_control_max_bytes,
        pending_priority_max_bytes=pending_priority_max_bytes,
        max_batch_bytes=max_batch_bytes,
        max_batch_frames=max_batch_frames,
    )


class TxFrameViewTests(unittest.TestCase):
    def test_go_queue_frame_spans_deadlines_and_ready_helpers(self):
        frames = [frame(FrameType.PING, 0, b"12345678"), data(1, b"xx"), data(5, b"yyy")]
        self.assertEqual(frame_buffered_bytes(frames[0]), 9)
        self.assertEqual(frames_buffered_bytes(frames), 9 + 3 + 4)
        equal_frames = [frame(FrameType.PING, 0, b"12345678") for _ in range(3)]
        self.assertEqual(
            frame_chunk_spans(equal_frames, max_frames=2, max_bytes=0),
            (
                type(frame_chunk_spans(equal_frames)[0])(0, 2),
                type(frame_chunk_spans(equal_frames)[0])(2, 3),
            ),
        )
        self.assertEqual(
            frame_chunk_spans(equal_frames, max_frames=16, max_bytes=18),
            (
                type(frame_chunk_spans(equal_frames)[0])(0, 2),
                type(frame_chunk_spans(equal_frames)[0])(2, 3),
            ),
        )
        self.assertEqual(
            frame_chunk_spans(frames, max_frames=2, max_bytes=11),
            (type(frame_chunk_spans(frames)[0])(0, 1), type(frame_chunk_spans(frames)[0])(1, 3)),
        )

        lane = deque(["a", "b", "c"])
        self.assertEqual(
            collect_ready_batch_into(
                ["first"], lane, 3, order=lambda batch: list(reversed(batch))
            ),
            ["b", "a", "first"],
        )

        out = deque()
        self.assertTrue(send_by_deadline(None, None, out, "x"))
        self.assertEqual(list(out), ["x"])
        closed = threading.Event()
        closed.set()
        self.assertFalse(send_by_deadline(None, closed, out, "y"))
        full = Queue(maxsize=1)
        full.put("occupied")
        self.assertFalse(send_by_deadline(time.monotonic() - 0.001, None, full, "late"))
        self.assertFalse(send_by_deadline(time.monotonic() + 0.01, None, full, "late"))
        done = threading.Event()
        done.set()
        wait_by_deadline(None, None, done)
        wait_by_deadline(None, None, None)
        self.assertEqual(effective_deadline(None, 5.0), 5.0)
        self.assertEqual(effective_deadline(10.0, None), 10.0)
        self.assertEqual(effective_deadline(10.0, 5.0), 5.0)
        self.assertEqual(effective_deadline(5.0, 10.0), 5.0)

        class Partial(object):
            def __init__(self):
                self.data = bytearray()

            def write(self, chunk):
                view = memoryview(chunk)
                take = min(2, len(view))
                self.data.extend(view[:take])
                return take

        writer = Partial()
        write_all(writer, b"hello")
        self.assertEqual(bytes(writer.data), b"hello")

        class ZeroProgress(object):
            def write(self, _chunk):
                return 0

        class InvalidProgress(object):
            def __init__(self, written):
                self.written = written

            def write(self, _chunk):
                return self.written

        with self.assertRaises(OSError):
            write_all(ZeroProgress(), b"abc")
        with self.assertRaises(OSError):
            write_all(InvalidProgress(-1), b"abc")
        with self.assertRaises(OSError):
            write_all(InvalidProgress(4), b"abc")
        with self.assertRaises(OSError):
            write_all(InvalidProgress(True), b"abc")
        with self.assertRaises(OSError):
            write_all(InvalidProgress(1.0), b"abc")

    def test_parts_payload_cost_validation_clone_and_chunk_spans(self):
        prefix = encode_varint(0)
        parts = [b"ab", bytearray(b"cdef"), b"gh"]
        tx = make_tx_frame(FrameType.DATA, FRAME_FLAG_OPEN_METADATA, 4)
        tx.set_prefixed_parts_payload(prefix, parts, 1, 1, 4)

        self.assertEqual(tx.payload_length(), 1 + 4)
        self.assertEqual(bytes(tx.cloned_payload()), b"\x00defg")
        self.assertEqual(tx_frame_queue_cost(tx), 1 + 5)
        self.assertGreaterEqual(tx_frame_encoded_bytes(tx), tx_frame_queue_cost(tx))
        validate_outbound_tx_frames_with_limits([tx])
        self.assertEqual(max_tx_payload_length(), sys.maxsize)

        flat = make_tx_frame(FrameType.DATA, 0, 8)
        flat.set_flat_payload(b"12")
        flat.payload_len = 9
        self.assertEqual(flat.cloned_payload(), b"12")
        flat.payload_len = 2
        clone, reused = clone_tx_frames_if_needed([tx, flat], True)
        self.assertFalse(reused)
        self.assertEqual([f.cloned_payload() for f in clone], [b"\x00defg", b"12"])
        self.assertEqual(tx_frames_queue_cost([tx, flat]), 9)
        self.assertEqual(
            tx_frame_chunk_spans([tx, flat, flat], max_frames=2, max_bytes=8),
            (
                type(tx_frame_chunk_spans([tx])[0])(0, 1),
                type(tx_frame_chunk_spans([tx])[0])(1, 3),
            ),
        )

        huge = make_tx_frame(FrameType.DATA, 0, 8)
        huge.set_prefixed_parts_payload(b"p", [], 0, 0, sys.maxsize)
        self.assertEqual(huge.payload_length(), sys.maxsize)
        self.assertEqual(huge.cloned_payload(), b"p")

    def test_stream_generated_request_classification_tracks_terminal_fin(self):
        priority = make_tx_frame(FrameType.EXT, 0, 4)
        priority.set_flat_payload(priority_update(4, priority=1).payload)
        fin = make_tx_frame(FrameType.DATA, FRAME_FLAG_FIN, 4)
        fin.set_flat_payload(b"")
        req = build_tx_lane_request(
            [priority, fin], origin=WriteRequestOrigin.STREAM
        )

        stream_id, known = batch_stream_id(req)
        self.assertTrue(known)
        self.assertEqual(stream_id, 4)
        self.assertTrue(req.terminal_data_priority)
        self.assertTrue(req.terminal_has_fin)
        self.assertEqual(req.queued_bytes, tx_frames_queue_cost(req.frames))

    def test_prepared_priority_update_requires_same_stream_data_tail(self):
        first = make_tx_frame(FrameType.EXT, 0, 4)
        first.set_flat_payload(priority_update(4, priority=7).payload)
        body = make_tx_frame(FrameType.DATA, 0, 4)
        body.set_flat_payload(b"body")

        prepared = prepared_priority_update_from_frames([first, body])

        self.assertTrue(prepared.has_frame())
        self.assertEqual(prepared.stream_id, 4)
        self.assertGreater(prepared.frame_bytes, 0)


class WriteQueuePolicyTests(unittest.TestCase):
    def test_data_accounting_releases_only_popped_batch(self):
        q = WriteQueue(queue_limits(max_batch_frames=1))
        first = data(1, b"body")
        second = data(1, b"tail")
        q.try_push(WriteJob.frame_job(first))
        q.try_push(WriteJob.frame_job(second))
        self.assertEqual(
            q.stats().data_queued_bytes,
            retained_frame_queue_cost(first) + retained_frame_queue_cost(second),
        )

        batch = q.pop_batch()

        self.assertEqual(len(batch), 1)
        self.assertEqual(q.data_queued_bytes_for_stream(1), retained_frame_queue_cost(second))
        self.assertEqual(q.stats().data_queued_bytes, retained_frame_queue_cost(second))

    def test_urgent_and_nonurgent_share_one_batch_in_lane_order(self):
        q = WriteQueue(queue_limits(max_batch_frames=8))
        q.try_push(WriteJob.frame_job(data(1, b"d")))
        q.try_push(WriteJob.frame_job(priority_update(5, priority=2)))
        q.try_push(WriteJob.frame_job(frame(FrameType.CLOSE, 0, b"")))
        q.try_push(WriteJob.frame_job(frame(FrameType.GOAWAY, 0, encode_varint(1) * 3)))
        q.try_push(WriteJob.frame_job(frame(FrameType.PING, 0, b"12345678")))

        batch = q.pop_batch()

        self.assertEqual(
            [job.all_frames()[0].frame_type for job in batch],
            [FrameType.CLOSE, FrameType.GOAWAY, FrameType.PING, FrameType.DATA, FrameType.EXT],
        )

        into = deque()
        q.try_push(WriteJob.frame_job(frame(FrameType.CLOSE, 0, b"")))
        q.try_push(WriteJob.frame_job(frame(FrameType.GOAWAY, 0, encode_varint(2) * 3)))
        self.assertIs(q.pop_batch_into(into), WriteQueuePopStatus.BATCH)
        self.assertEqual(
            [job.all_frames()[0].frame_type for job in into],
            [FrameType.CLOSE, FrameType.GOAWAY],
        )

    def test_priority_update_for_stream_with_queued_data_stays_ordinary(self):
        q = WriteQueue(queue_limits(max_batch_frames=8))
        q.try_push(WriteJob.frame_job(data(1, b"d")))
        q.try_push(WriteJob.frame_job(priority_update(1, priority=4)))

        stats = q.stats()
        self.assertEqual(stats.ordinary_jobs, 2)
        self.assertEqual(
            [job.all_frames()[0].frame_type for job in q.pop_batch()],
            [FrameType.DATA, FrameType.EXT],
        )

    def test_priority_updates_without_data_use_ordinary_fifo_lane(self):
        q = WriteQueue(queue_limits(max_batch_frames=1))
        q.try_push(WriteJob.frame_job(data(1, b"d")))
        q.try_push(WriteJob.frame_job(priority_update(5, priority=2)))
        q.try_push(WriteJob.frame_job(priority_update(9, priority=3)))

        first = q.pop_batch()
        second = q.pop_batch()
        third = q.pop_batch()

        self.assertEqual(first[0].all_frames()[0].frame_type, FrameType.DATA)
        self.assertEqual(second[0].all_frames()[0].stream_id, 5)
        self.assertEqual(third[0].all_frames()[0].stream_id, 9)
        self.assertEqual(q.stats().ordinary_jobs, 0)

    def test_coalesces_max_data_and_priority_update_with_delta_budget(self):
        q = WriteQueue(queue_limits(pending_priority_max_bytes=16))
        q.try_push(WriteJob.frame_job(frame(FrameType.MAX_DATA, 0, encode_varint(1))))
        q.try_push(WriteJob.frame_job(frame(FrameType.MAX_DATA, 0, encode_varint(9))))
        self.assertEqual(
            q.stats().pending_control_bytes,
            retained_frame_queue_cost(frame(FrameType.MAX_DATA, 0, encode_varint(9))),
        )

        q.try_push(WriteJob.frame_job(priority_update(4, priority=1)))
        q.try_push(WriteJob.frame_job(priority_update(4, group=9)))
        batch = q.pop_batch()
        max_data = batch[0].all_frames()[0]
        update = batch[1].all_frames()[0]
        parsed, valid = parse_priority_update_payload(update.payload)

        self.assertEqual(max_data.payload, encode_varint(9))
        self.assertTrue(valid)
        self.assertEqual(parsed.priority, 1)
        self.assertEqual(parsed.group, 9)

        stream_control = WriteQueue(queue_limits())
        stream_control.try_push(
            WriteJob.frame_job(
                frame(FrameType.BLOCKED, 0x4000, encode_varint(1))
            )
        )
        self.assertEqual(
            stream_control.stats().pending_control_bytes,
            retained_frame_queue_cost(frame(FrameType.BLOCKED, 0x4000, encode_varint(1))),
        )

        payload = priority_update(12, priority=1).payload
        priority_budget = WriteQueue(
            queue_limits(pending_priority_max_bytes=len(payload))
        )
        priority_budget.try_push(WriteJob.frame_job(priority_update(12, priority=1)))
        too_small_priority_budget = WriteQueue(
            queue_limits(pending_priority_max_bytes=len(payload) - 1)
        )
        with self.assertRaisesRegex(Exception, PENDING_PRIORITY_BUDGET_MESSAGE):
            too_small_priority_budget.try_push(
                WriteJob.frame_job(priority_update(12, priority=1))
            )

        invalid = WriteQueue(queue_limits(max_batch_frames=8))
        invalid.try_push(WriteJob.frame_job(frame(FrameType.MAX_DATA, 0, b"\x00x")))
        invalid.try_push(WriteJob.frame_job(frame(FrameType.MAX_DATA, 0, b"\x00y")))
        self.assertEqual(
            [job.all_frames()[0].payload for job in invalid.pop_batch()],
            [b"\x00y"],
        )

    def test_capacity_errors_are_structured_and_distinct(self):
        q = WriteQueue(queue_limits(max_bytes=2))
        q.try_push(WriteJob.frame_job(data(1, b"x")))
        with self.assertRaisesRegex(Exception, WRITER_QUEUE_FULL_MESSAGE):
            q.try_push(WriteJob.frame_job(data(5, b"x")))

        urgent = WriteQueue(queue_limits(urgent_max_bytes=1))
        with self.assertRaisesRegex(Exception, URGENT_WRITER_QUEUE_FULL_MESSAGE):
            urgent.try_push(
                WriteJob.frame_job(frame(FrameType.MAX_DATA, 0, encode_varint(1)))
            )
        terminal_urgent = WriteQueue(
            queue_limits(urgent_max_bytes=1, pending_control_max_bytes=1024)
        )
        terminal_urgent.try_push(
            WriteJob.frame_job(frame(FrameType.RESET, 1, encode_varint(1)))
        )
        self.assertEqual(terminal_urgent.stats().urgent_queued_bytes, 0)
        self.assertGreater(terminal_urgent.stats().pending_control_bytes, 0)
        terminal_pending = WriteQueue(
            queue_limits(urgent_max_bytes=1024, pending_control_max_bytes=1)
        )
        with self.assertRaisesRegex(Exception, PENDING_CONTROL_BUDGET_MESSAGE):
            terminal_pending.try_push(
                WriteJob.frame_job(frame(FrameType.RESET, 1, encode_varint(1)))
            )

        terminal_pressure = WriteQueue(
            queue_limits(urgent_max_bytes=1024, pending_control_max_bytes=33)
        )
        terminal_pressure.try_push(
            WriteJob.frame_job(frame(FrameType.RESET, 1, bytes(16)))
        )
        self.assertEqual(terminal_pressure.stats().pending_control_bytes, 17)
        with self.assertRaisesRegex(Exception, PENDING_CONTROL_BUDGET_MESSAGE):
            terminal_pressure.try_push(
                WriteJob.frame_job(frame(FrameType.STOP_SENDING, 5, bytes(16)))
            )
        self.assertEqual(terminal_pressure.pop_batch()[0].all_frames()[0].frame_type, FrameType.RESET)
        self.assertEqual(terminal_pressure.stats().pending_control_bytes, 0)

        control = WriteQueue(queue_limits(pending_control_max_bytes=1))
        with self.assertRaisesRegex(Exception, PENDING_CONTROL_BUDGET_MESSAGE):
            control.try_push(
                WriteJob.frame_job(frame(FrameType.BLOCKED, 0x4000, encode_varint(1)))
            )

        hwm = WriteQueue(queue_limits(session_data_max_bytes=1))
        with self.assertRaisesRegex(Exception, QUEUED_DATA_HWM_MESSAGE):
            hwm.try_push(WriteJob.frame_job(data(1, b"xx")))

        with self.assertRaisesRegex(Exception, QUEUED_DATA_HWM_MESSAGE):
            hwm.push_until(WriteJob.frame_job(data(1, b"xx")), deadline=None)

    def test_force_push_bypasses_queue_and_watermark_caps(self):
        q = WriteQueue(
            queue_limits(
                max_bytes=1,
                urgent_max_bytes=1,
                session_data_max_bytes=1,
                per_stream_data_max_bytes=1,
                pending_control_max_bytes=1,
                pending_priority_max_bytes=1,
            )
        )

        q.force_push(WriteJob.frame_job(data(1, b"oversized")))

        self.assertGreater(q.stats().queued_bytes, 1)
        self.assertGreater(q.stats().data_queued_bytes, 1)

    def test_discard_stream_send_tail_preserves_receive_terminal_and_max_data(self):
        q = WriteQueue(queue_limits())
        q.try_push(
            WriteJob.frames_job(
                [
                    data(64, b"hello"),
                    priority_update(64, priority=7),
                    frame(FrameType.STOP_SENDING, 64, encode_varint(1)),
                ]
            )
        )
        q.try_push(WriteJob.frame_job(frame(FrameType.BLOCKED, 64, encode_varint(2))))
        q.try_push(WriteJob.frame_job(frame(FrameType.MAX_DATA, 64, encode_varint(3))))

        discarded = q.discard_stream_send_tail(64)
        types = [job.all_frames()[0].frame_type for job in q.pop_batch()]

        self.assertEqual(discarded.data_frames, 1)
        self.assertEqual(discarded.data_bytes, 5)
        self.assertEqual(discarded.terminal_frames, 0)
        self.assertIn(FrameType.STOP_SENDING, types)
        self.assertIn(FrameType.MAX_DATA, types)
        self.assertNotIn(FrameType.DATA, types)
        self.assertNotIn(FrameType.BLOCKED, types)
        self.assertNotIn(FrameType.EXT, types)

    def test_tracked_completion_cancel_and_shutdown_complete_waiters(self):
        success = WriteCompletion()
        observed = success.generation
        self.assertIsNone(success.try_result())
        success.notify_waiters()
        self.assertNotEqual(success.generation, observed)
        success.complete_success()
        result = success.try_result()
        self.assertIsNotNone(result)
        self.assertTrue(result.ok)
        self.assertIsNone(success.wait(0.0))
        result.raise_if_failed()
        success.wait_for_change_since(success.generation, 0.0)

        q = WriteQueue(queue_limits())
        completion = WriteCompletion()
        q.try_push(WriteJob.tracked_frames([data(1, b"queued")], completion))

        tracked = q.cancel_tracked_write(completion)

        self.assertIsNotNone(tracked)
        self.assertEqual(q.stats().queued_bytes, 0)

        pending = WriteCompletion()
        q.try_push(WriteJob.tracked_frames([data(1, b"pending")], pending))
        q.shutdown()
        self.assertIsNotNone(pending.try_result())

    def test_blocking_push_wakes_after_pop(self):
        q = WriteQueue(queue_limits(max_bytes=2))
        q.try_push(WriteJob.frame_job(data(1, b"x")))
        errors = []

        def worker():
            try:
                q.push(WriteJob.frame_job(data(5, b"y")), timeout=1.0)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.05)
        self.assertEqual(q.stats().ordinary_jobs, 1)
        q.pop_batch()
        thread.join(1.0)

        self.assertFalse(errors)
        self.assertEqual(q.stats().ordinary_jobs, 1)


class QueueHelperTests(unittest.TestCase):
    def test_frame_data_app_bytes_skips_open_metadata_prefix(self):
        tx = TxFrame(FrameType.DATA, FRAME_FLAG_OPEN_METADATA, 4)
        tx.set_prefixed_flat_payload(encode_varint(0), b"abc")
        self.assertEqual(frame_data_app_bytes(tx.to_frame()), 3)

    def test_empty_manual_request_defaults_are_stable(self):
        req = QueuedWriteRequest()
        self.assertEqual(batch_stream_id(req), (0, False))
        self.assertEqual(req.prepared_opener_visibility, OpenerVisibilityMark.UNCHANGED)

    def test_queue_helpers_reject_python_invalid_input_shapes(self):
        with self.assertRaises(ValueError):
            ChunkSpan(2, 1)
        with self.assertRaises(TypeError):
            frame_chunk_spans([frame(FrameType.PING)], max_frames=True)
        with self.assertRaises(ValueError):
            frame_chunk_spans([frame(FrameType.PING)], max_bytes=-1)
        with self.assertRaises(TypeError):
            collect_ready_batch_into([], deque(), True)
        with self.assertRaises(TypeError):
            QueuedWriteResult(admitted=1)
        with self.assertRaises(TypeError):
            QueueReservationResult(state=True)
        with self.assertRaises(ValueError):
            DataCosts(total=-1)
        with self.assertRaises(ValueError):
            DataCosts(by_stream={0: 1})
        with self.assertRaises(TypeError):
            QueueCost(data=object())
        with self.assertRaises(ValueError):
            StreamDiscardStats(removed_frames=-1)
        with self.assertRaises(ValueError):
            WriterQueueStats(urgent_jobs=-1)
        with self.assertRaises(TypeError):
            QueuedWriteRequest(clone_frames_before_send=1)
        with self.assertRaises(TypeError):
            WriteQueueLimits(max_bytes=True)
        with self.assertRaises(ValueError):
            checked_tx_payload_length(-1)
        with self.assertRaises(ValueError):
            add_tx_payload_lengths(-1, 0)
        self.assertEqual(add_tx_payload_lengths(sys.maxsize, 1), sys.maxsize)
        with self.assertRaises(ValueError):
            trim_tx_payload_parts([b"x"], -1, 0, 1)
        with self.assertRaises(TypeError):
            request_cost_from_bytes(True)
        with self.assertRaises(ValueError):
            add_request_cost(-1, 1)
        with self.assertRaises(TypeError):
            TxFrame(FrameType.DATA, payload=8)
        with self.assertRaises(TypeError):
            make_tx_frame(FrameType.DATA, 0, 4).set_flat_payload(8)
        with self.assertRaises(TypeError):
            make_tx_frame(FrameType.DATA, 0, 4).set_prefixed_flat_payload(b"p", 8)
        with self.assertRaises(TypeError):
            PreparedPriorityUpdate(stream_id=4, payload=8, frame_bytes=1)
        with self.assertRaises(ValueError):
            PreparedPriorityUpdate(stream_id=(1 << 62), payload=b"x", frame_bytes=1)
        with self.assertRaises(ValueError):
            QueuedWriteRequest(prepared_priority_stream_id=(1 << 62))
        with self.assertRaises(TypeError):
            tx_frame_chunk_spans([TxFrame(FrameType.PING)], max_frames=True)
        with self.assertRaises(TypeError):
            WriteCompletion().wait(True)


if __name__ == "__main__":
    unittest.main()
