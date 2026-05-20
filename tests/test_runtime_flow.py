import unittest

import zmux._runtime as runtime_package
from zmux._runtime import control as runtime_control
from zmux._runtime import flow as runtime_flow
from zmux._runtime import keepalive as runtime_keepalive
from zmux._runtime import sched as runtime_sched
from zmux._runtime import write_policy as runtime_write_policy
from zmux._runtime import writer as runtime_writer
from zmux._runtime.flow import (
    MAX_UINT64,
    ReleaseWakePlan,
    aggregate_late_data_cap,
    crossed_low_watermark,
    elapsed_exceeds,
    elapsed_nanos,
    gained_credit,
    late_data_per_stream_cap,
    low_watermark,
    max_uint64,
    memory_wake_needed,
    min_nonzero,
    negotiated_frame_payload,
    next_credit_limit,
    plan_lane_release_wake,
    plan_prepared_release_wake,
    plan_queue_release_wake,
    positive_elapsed_nanos,
    projected_exceeds_threshold,
    quarter_threshold,
    queue_would_block,
    receive_window_exceeded,
    replenish_min_pending,
    repo_default_per_stream_data_hwm,
    repo_default_session_data_hwm,
    repo_default_urgent_lane_cap,
    saturating_add,
    saturating_mul,
    saturating_mul_div_ceil,
    saturating_mul_div_floor,
    session_window_target,
    should_flush_receive_credit,
    should_replenish_pending_window,
    standing_growth_allowed,
    stream_emergency_threshold,
    stream_standing_growth_allowed,
    stream_window_target,
    visible_accept_backlog_bytes_hard_cap,
    window_remaining,
)
from zmux.config import Settings
from zmux.protocol import MAX_VARINT62


class RuntimeFlowTest(unittest.TestCase):
    def test_runtime_package_keeps_helpers_in_explicit_modules(self) -> None:
        self.assertEqual(runtime_package.__all__, ())
        self.assertIs(runtime_flow.window_remaining, window_remaining)
        self.assertIn("window_remaining", runtime_flow.__all__)
        self.assertIn("rate_limited_fragment_cap", runtime_write_policy.__all__)
        self.assertIn("next_session_nonce", runtime_keepalive.__all__)
        self.assertIn("init_session_nonce_state", runtime_keepalive.__all__)
        self.assertIn("urgency_rank", runtime_control.__all__)
        self.assertIn("MAX_EXPLICIT_GROUPS", runtime_sched.__all__)
        self.assertIn("write_all", runtime_writer.__all__)

    def test_go_flow_thresholds_defaults_and_window_helpers(self) -> None:
        self.assertEqual(quarter_threshold(0), 1)
        self.assertEqual(quarter_threshold(4), 1)
        self.assertEqual(quarter_threshold(8), 2)
        self.assertEqual(window_remaining(8, 10), 0)
        self.assertFalse(receive_window_exceeded(8, 10, 2))
        self.assertTrue(receive_window_exceeded(8, 10, 3))

        local = Settings(max_frame_payload=4096)
        peer = Settings(max_frame_payload=2048)
        self.assertEqual(negotiated_frame_payload(local, peer), 2048)
        self.assertEqual(negotiated_frame_payload(Settings(), Settings()), 16384)
        self.assertEqual(min_nonzero(0, 7), 7)
        self.assertEqual(max_uint64(1, 2), 2)

        per_stream = repo_default_per_stream_data_hwm(16384)
        self.assertEqual(per_stream, 256 * 1024)
        self.assertEqual(repo_default_session_data_hwm(per_stream), 4 * 1024 * 1024)
        self.assertEqual(repo_default_urgent_lane_cap(0), 64 * 1024)
        self.assertEqual(repo_default_urgent_lane_cap(16 * 1024), 128 * 1024)

    def test_go_flow_saturating_arithmetic_and_mul_div(self) -> None:
        self.assertEqual(saturating_add(10, 5), 15)
        self.assertEqual(saturating_add(MAX_UINT64, 1), MAX_UINT64)
        self.assertEqual(saturating_mul(7, 6), 42)
        self.assertEqual(saturating_mul(MAX_UINT64, 2), MAX_UINT64)
        self.assertEqual(saturating_mul_div_floor(10, 3, 4), 7)
        self.assertEqual(saturating_mul_div_ceil(10, 3, 4), 8)
        self.assertEqual(saturating_mul_div_floor(10, 3, 0), MAX_UINT64)
        self.assertEqual(saturating_mul_div_ceil(MAX_UINT64, 2, 1), MAX_UINT64)
        self.assertEqual(
            saturating_mul_div_floor(MAX_UINT64, MAX_UINT64, MAX_UINT64),
            MAX_UINT64,
        )
        self.assertEqual(saturating_mul_div_floor(MAX_UINT64, 2, MAX_UINT64), 2)
        self.assertEqual(saturating_mul_div_ceil(MAX_UINT64, 2, MAX_UINT64), 2)
        self.assertEqual(elapsed_nanos(20, 10), 10)
        self.assertEqual(elapsed_nanos(10, 20), 0)
        self.assertEqual(elapsed_nanos(MAX_UINT64 + 10, 0), MAX_UINT64)
        self.assertEqual(positive_elapsed_nanos(10, 20), 1)
        self.assertTrue(elapsed_exceeds(20, 10, 9))
        self.assertFalse(elapsed_exceeds(20, 10, 10))
        with self.assertRaises(TypeError):
            saturating_add(True, 1)

    def test_go_flow_queue_pressure_and_release_wake_plans(self) -> None:
        self.assertTrue(queue_would_block(True, 0, 0, 0, 0, 0))
        self.assertFalse(queue_would_block(False, 10, 10, 0, 10, 10))
        self.assertTrue(queue_would_block(False, 9, 0, 2, 10, 100))
        self.assertTrue(queue_would_block(False, 0, 9, 2, 100, 10))
        self.assertFalse(queue_would_block(False, 8, 8, 2, 10, 10))

        self.assertEqual(low_watermark(9), 4)
        self.assertTrue(crossed_low_watermark(10, 5, 5))
        self.assertFalse(crossed_low_watermark(5, 4, 5))
        self.assertTrue(gained_credit(0, 1))
        self.assertFalse(gained_credit(1, 2))
        self.assertTrue(memory_wake_needed(8, 7, 8))
        self.assertTrue(memory_wake_needed(7, 6, 8))
        self.assertFalse(memory_wake_needed(9, 8, 8))
        self.assertFalse(memory_wake_needed(8, 8, 8))
        self.assertTrue(memory_wake_needed(100, 40, 50))
        self.assertFalse(memory_wake_needed(40, 100, 50))
        self.assertTrue(projected_exceeds_threshold(MAX_UINT64, 1, MAX_UINT64 - 1))
        self.assertTrue(projected_exceeds_threshold(0, 9, 8))

        self.assertEqual(
            plan_queue_release_wake(100, 40, 50, 100, 40, 50, 100, 40, 50, False),
            ReleaseWakePlan(True, False, True, True),
        )
        self.assertEqual(
            plan_queue_release_wake(100, 80, 50, 100, 90, 50, 100, 40, 50, True),
            ReleaseWakePlan(False, True, True, False),
        )
        self.assertEqual(
            plan_prepared_release_wake(
                100, 80, 50, 100, 90, 50, 100, 90, 50, 0, 1, 0, 0, False
            ),
            ReleaseWakePlan(True, False, False, False),
        )
        self.assertEqual(
            plan_prepared_release_wake(
                10, 10, 80, 4, 4, 4, 6, 3, 4, 1, 1, 0, 5, False
            ),
            ReleaseWakePlan(False, True, False, False),
        )
        self.assertEqual(
            plan_prepared_release_wake(
                70, 60, 80, 4, 4, 4, 6, 3, 4, 1, 1, 0, 5, False
            ),
            ReleaseWakePlan(True, True, True, True),
        )
        self.assertEqual(
            plan_lane_release_wake(100, 80, 50, True),
            ReleaseWakePlan(False, False, True, False),
        )
        self.assertEqual(
            plan_lane_release_wake(100, 60, 80, False),
            ReleaseWakePlan(True, False, True, True),
        )

    def test_flow_caps_and_receive_credit_helpers(self) -> None:
        self.assertEqual(visible_accept_backlog_bytes_hard_cap(0), 4 * 1024 * 1024)
        self.assertEqual(
            visible_accept_backlog_bytes_hard_cap(128 * 1024),
            8 * 1024 * 1024,
        )
        self.assertEqual(
            visible_accept_backlog_bytes_hard_cap(1024 * 1024),
            64 * 1024 * 1024,
        )
        self.assertEqual(late_data_per_stream_cap(65536, 16384), 8192)
        self.assertEqual(late_data_per_stream_cap(1024 * 1024, 16384), 32768)
        self.assertEqual(late_data_per_stream_cap(0, 1), 1024)
        self.assertEqual(aggregate_late_data_cap(16384), 64 * 1024)
        self.assertEqual(aggregate_late_data_cap(0), 64 * 1024)
        self.assertEqual(aggregate_late_data_cap(32 * 1024), 128 * 1024)
        self.assertEqual(aggregate_late_data_cap(1024 * 1024), 4 * 1024 * 1024)

        self.assertEqual(
            session_window_target(Settings(initial_max_data=4096), 2048),
            8192,
        )
        self.assertEqual(stream_window_target(1024, 2048), 4096)
        self.assertEqual(
            session_window_target(Settings(initial_max_data=0), MAX_VARINT62),
            MAX_VARINT62,
        )
        self.assertEqual(stream_window_target(0, MAX_VARINT62), MAX_VARINT62)
        self.assertEqual(
            next_credit_limit(MAX_VARINT62 - 2, 10, MAX_VARINT62 - 1, 16, True),
            MAX_VARINT62,
        )
        self.assertEqual(stream_emergency_threshold(0, 16384), 1)
        self.assertEqual(stream_emergency_threshold(64, 0), 16)
        self.assertEqual(replenish_min_pending(0, 16384), 1)
        self.assertFalse(should_flush_receive_credit(100, 10, 15, 64, 2, 16, False))
        self.assertTrue(should_flush_receive_credit(100, 10, 16, 64, 2, 16, False))
        with self.assertRaises(TypeError):
            stream_emergency_threshold(64, False)
        with self.assertRaises(TypeError):
            replenish_min_pending(64, False)

    def test_flow_helpers_reject_python_invalid_bool_shapes(self) -> None:
        with self.assertRaises(TypeError):
            ReleaseWakePlan(broadcast=1)
        with self.assertRaises(TypeError):
            should_replenish_pending_window(10, 64, 64, 1, 1, 1, force=1)
        with self.assertRaises(TypeError):
            should_flush_receive_credit(64, 0, 1, 64, 1, 1, force=1)
        with self.assertRaises(TypeError):
            next_credit_limit(64, 1, 64, 128, 1)
        with self.assertRaises(TypeError):
            standing_growth_allowed(0, 1, 1, 8)
        with self.assertRaises(TypeError):
            stream_standing_growth_allowed(0, 1, 1, 8)
        with self.assertRaises(TypeError):
            plan_queue_release_wake(1, 0, 1, 1, 0, 1, 1, 0, 1, 1)
        with self.assertRaises(TypeError):
            plan_prepared_release_wake(
                1,
                0,
                1,
                1,
                0,
                1,
                1,
                0,
                1,
                0,
                1,
                0,
                1,
                1,
            )
        with self.assertRaises(TypeError):
            plan_lane_release_wake(1, 0, 1, 1)


if __name__ == "__main__":
    unittest.main()
