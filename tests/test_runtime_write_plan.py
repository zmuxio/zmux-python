import unittest

import zmux
from zmux._runtime import write_policy
from zmux._runtime.write_plan import (
    DEFAULT_WRITE_BURST_FRAMES,
    MILD_WRITE_BURST_FRAMES,
    SATURATED_WRITE_BURST_FRAMES,
    STRONG_WRITE_BURST_FRAMES,
    MAX_UINT64,
    OpenerVisibilityMark,
    PreparedPriorityFrame,
    QueuedWriteCommit,
    WriteBatchStart,
    WriteBurstFinalState,
    WriteBurstState,
    WriteChunkMode,
    WriteFinReservation,
    WritePrepareWindow,
    WriteStep,
    advance_parts,
    bounded_write_chunk,
    build_prepared_write_step,
    checked_total_part_len,
    fragment_cap,
    frame_buffered_bytes,
    rate_limited_fragment_cap,
    saturating_add,
    scaled_fragment_cap,
    total_part_len,
    total_part_len_within,
    tx_fragment_cap,
    writable_data_bytes,
    write_burst_limit,
    write_deadline_policy_after_error,
    WriteDeadlinePolicy,
)


class WritePlanPartTests(unittest.TestCase):
    def test_total_len_and_part_advance_match_go_boundaries(self):
        parts = (b"ab", bytearray(b""), memoryview(b"cde"))

        self.assertEqual(total_part_len(parts), (5, True))
        self.assertEqual(total_part_len_within(parts, 8), (5, True))
        self.assertEqual(total_part_len_within(parts, 4), (0, False))
        self.assertEqual(checked_total_part_len(parts, 8), 5)
        with self.assertRaises(zmux.FrameSizeError):
            checked_total_part_len((b"abc", b"de"), 4)

        self.assertEqual(advance_parts(parts, 0, 0, 3), (2, 1))
        self.assertEqual(advance_parts(parts, 2, 1, 9), (3, 0))
        self.assertEqual(advance_parts(parts, -1, -5, 0), (0, 0))

    def test_bounded_write_chunk_uses_all_credit_caps(self):
        self.assertEqual(bounded_write_chunk(100, 80, 70, 60), 60)
        self.assertEqual(writable_data_bytes(9, 8, 7, 6), 6)
        self.assertEqual(bounded_write_chunk(100, 0, 70, 60), 0)


class WritePlanFragmentTests(unittest.TestCase):
    def test_fragment_policy_matches_priority_latency_and_prefix_caps(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED
        self.assertEqual(fragment_cap(16_384, 0, 2, balanced), 12_288)
        self.assertEqual(fragment_cap(16_384, 0, 6, balanced), 8_192)
        self.assertEqual(fragment_cap(16_384, 0, 20, balanced), 4_096)
        self.assertEqual(fragment_cap(16_384, 0, 0, zmux.SchedulerHint.LATENCY), 8_192)
        self.assertEqual(
            fragment_cap(16_384, 11, 20, balanced),
            scaled_fragment_cap(16_384 - 11, 1, 4),
        )
        self.assertEqual(fragment_cap(16_384, 16_384, 20, balanced), 0)

    def test_fragment_rate_limit_and_scaling_use_wide_arithmetic(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED
        self.assertEqual(rate_limited_fragment_cap(16_384, 1_000, 0, balanced), 200)
        self.assertEqual(
            rate_limited_fragment_cap(1_000_000_000_000, 50_000_000_000_000, 0, balanced),
            1_000_000_000_000,
        )
        self.assertEqual(rate_limited_fragment_cap(4_096, 1 << 20, 20, balanced), 4_096)
        self.assertEqual(scaled_fragment_cap(zmux.MAX_VARINT62, 3, 4), 3_458_764_513_820_540_927)
        self.assertEqual(scaled_fragment_cap(MAX_UINT64, MAX_UINT64, 1), MAX_UINT64)
        self.assertEqual(tx_fragment_cap(16_384, 0, 0, balanced, send_rate_estimate=1_000), 200)

    def test_write_burst_limit_follows_priority_bands_and_latency_hint(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED
        self.assertEqual(write_burst_limit(0, balanced), DEFAULT_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(0, zmux.SchedulerHint.LATENCY), MILD_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(2, balanced), MILD_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(6, balanced), STRONG_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(20, balanced), SATURATED_WRITE_BURST_FRAMES)

    def test_write_plan_reexports_write_policy_single_source(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED

        self.assertIs(fragment_cap, write_policy.fragment_cap)
        self.assertIs(rate_limited_fragment_cap, write_policy.rate_limited_fragment_cap)
        self.assertIs(write_burst_limit, write_policy.write_burst_limit)
        self.assertEqual(write_policy.fragment_time_budget(0, balanced), 0.200)
        self.assertEqual(write_policy.fragment_time_budget_nanos(0, balanced), 200_000_000)


class WritePlanStepAndBatchTests(unittest.TestCase):
    def test_prepared_step_handles_opener_only_blocked_and_final_frames(self):
        built = []

        def build_frame(chunk, flags):
            frame = zmux.Frame(zmux.FrameType.DATA, 4, flags, b"x" * chunk)
            built.append(frame)
            return frame

        window = WritePrepareWindow(
            opener_visibility=OpenerVisibilityMark.PEER_VISIBLE,
            available_session=0,
            available_stream=10,
            frame_cap=10,
        )
        opener_only = build_prepared_write_step(5, WriteChunkMode.STREAMING, window, build_frame)
        self.assertTrue(opener_only.has_step())
        self.assertEqual(opener_only.step.app_n, 0)
        self.assertEqual(opener_only.step.frame.flags, zmux.FRAME_FLAG_OPEN_METADATA)

        final_empty = build_prepared_write_step(0, WriteChunkMode.FINAL, window, build_frame)
        self.assertTrue(final_empty.has_step())
        self.assertEqual(
            final_empty.step.frame.flags,
            zmux.FRAME_FLAG_FIN | zmux.FRAME_FLAG_OPEN_METADATA,
        )

        no_opener_final = build_prepared_write_step(
            0,
            WriteChunkMode.FINAL,
            WritePrepareWindow(
                available_session=0,
                available_stream=0,
                frame_cap=0,
            ),
            build_frame,
        )
        self.assertFalse(no_opener_final.has_step())

        data_window = WritePrepareWindow(
            opener_visibility=OpenerVisibilityMark.PEER_VISIBLE,
            available_session=9,
            available_stream=8,
            frame_cap=7,
        )
        data = build_prepared_write_step(7, WriteChunkMode.FINAL, data_window, build_frame)
        self.assertTrue(data.has_step())
        self.assertEqual(data.chunk, 7)
        self.assertEqual(data.fin_reservation, WriteFinReservation.RESERVE)
        self.assertEqual(
            data.step.frame.flags,
            zmux.FRAME_FLAG_FIN | zmux.FRAME_FLAG_OPEN_METADATA,
        )

    def test_batch_start_allows_first_frame_then_enforces_cap(self):
        start = WriteBatchStart(queue_byte_cap=10)
        self.assertTrue(start.allows_next_queued_frame(0, 100))
        self.assertTrue(start.allows_next_queued_frame(4, 6))
        self.assertFalse(start.allows_next_queued_frame(5, 6))

    def test_burst_state_tracks_priority_frame_progress_and_finalize(self):
        priority = zmux.Frame(zmux.FrameType.EXT, 4, 0, b"p")
        empty_priority = zmux.Frame(zmux.FrameType.EXT, 4, 0, b"")
        zero_stream_priority = zmux.Frame(zmux.FrameType.EXT, 0, 0, b"p")
        data = zmux.Frame(zmux.FrameType.DATA, 4, zmux.FRAME_FLAG_FIN, b"abc")
        self.assertFalse(PreparedPriorityFrame().has_frame())
        self.assertFalse(PreparedPriorityFrame(empty_priority).has_frame())
        self.assertFalse(PreparedPriorityFrame(zero_stream_priority).has_frame())
        self.assertTrue(PreparedPriorityFrame(priority).has_frame())
        state = WriteBurstState()
        state.init_frame_buffer(
            WriteBatchStart(
                priority=PreparedPriorityFrame(priority)
            )
        )
        self.assertEqual(state.frames, [priority])
        self.assertEqual(frame_buffered_bytes(priority), 2)
        self.assertEqual(frame_buffered_bytes(data), 4)
        self.assertEqual(state.queued_bytes, frame_buffered_bytes(priority))

        state.append_step(WriteStep(data, 3, OpenerVisibilityMark.PEER_VISIBLE))

        self.assertEqual(state.frames, [priority, data])
        self.assertEqual(
            state.queued_bytes,
            frame_buffered_bytes(priority) + frame_buffered_bytes(data),
        )
        self.assertEqual(state.commit.progress, 3)
        self.assertTrue(state.commit.opener_visibility.marks_peer_visible())
        self.assertTrue(state.commit.finalize)
        self.assertEqual(state.commit.burst_final_state(), WriteBurstFinalState.FINALIZED)
        self.assertFalse(QueuedWriteCommit().finalize)

        extra = WriteBurstState()
        extra.append_prepared((data,), 0, 3, WriteBurstFinalState.FINALIZED)
        self.assertEqual(extra.queued_bytes, frame_buffered_bytes(data))

    def test_deadline_policy_after_timeout_error_uses_override_only(self):
        self.assertEqual(
            write_deadline_policy_after_error(TimeoutError()),
            WriteDeadlinePolicy.OVERRIDE_ONLY,
        )
        self.assertFalse(WriteDeadlinePolicy.OVERRIDE_ONLY.uses_stream_deadline())
        self.assertEqual(
            write_deadline_policy_after_error(RuntimeError()),
            WriteDeadlinePolicy.USE_STREAM,
        )
        self.assertTrue(WriteDeadlinePolicy.USE_STREAM.uses_stream_deadline())

    def test_saturating_add_clamps_uint64(self):
        self.assertEqual(saturating_add(MAX_UINT64, 1), MAX_UINT64)

    def test_write_plan_rejects_implicit_python_coercions(self):
        frame = zmux.Frame(zmux.FrameType.DATA, 4, 0, b"")

        with self.assertRaises(TypeError):
            WritePrepareWindow(available_session=True)
        with self.assertRaises(TypeError):
            QueuedWriteCommit(finalize=1)
        with self.assertRaises(TypeError):
            advance_parts((b"a",), "0", 0, 0)
        with self.assertRaises(TypeError):
            frame_buffered_bytes("not-a-frame")
        with self.assertRaises(TypeError):
            total_part_len_within((b"a",), True)
        with self.assertRaises(TypeError):
            fragment_cap(1024, 0, 0, "latency")
        with self.assertRaises(TypeError):
            write_burst_limit(0, True)
        with self.assertRaises(TypeError):
            WriteStep(frame, opener_visibility=True)
        with self.assertRaises(TypeError):
            build_prepared_write_step(
                1,
                True,
                WritePrepareWindow(available_session=1, available_stream=1, frame_cap=1),
                lambda chunk, flags: frame,
            )


if __name__ == "__main__":
    unittest.main()
