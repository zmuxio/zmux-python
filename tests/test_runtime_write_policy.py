import unittest

import zmux
from zmux._runtime.flow import MAX_UINT64
from zmux._runtime.write_policy import (
    DEFAULT_FRAGMENT_TIME_BUDGET,
    DEFAULT_FRAGMENT_TIME_BUDGET_NANOS,
    DEFAULT_WRITE_BURST_FRAMES,
    MILD_FRAGMENT_TIME_BUDGET,
    MILD_FRAGMENT_TIME_BUDGET_NANOS,
    MILD_WRITE_BURST_FRAMES,
    NANOS_PER_SECOND,
    SATURATED_FRAGMENT_TIME_BUDGET,
    SATURATED_FRAGMENT_TIME_BUDGET_NANOS,
    SATURATED_WRITE_BURST_FRAMES,
    STRONG_FRAGMENT_TIME_BUDGET,
    STRONG_FRAGMENT_TIME_BUDGET_NANOS,
    STRONG_WRITE_BURST_FRAMES,
    fragment_cap,
    fragment_time_budget,
    fragment_time_budget_nanos,
    rate_limited_fragment_cap,
    scaled_fragment_cap,
    tx_fragment_cap,
    write_burst_limit,
)


class RuntimeWritePolicyTests(unittest.TestCase):
    def test_write_burst_limit_matches_go_priority_bands(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED

        self.assertEqual(write_burst_limit(0, balanced), DEFAULT_WRITE_BURST_FRAMES)
        self.assertEqual(
            write_burst_limit(0, zmux.SchedulerHint.LATENCY),
            MILD_WRITE_BURST_FRAMES,
        )
        self.assertEqual(write_burst_limit(1, balanced), MILD_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(3, balanced), MILD_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(4, balanced), STRONG_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(15, balanced), STRONG_WRITE_BURST_FRAMES)
        self.assertEqual(write_burst_limit(16, balanced), SATURATED_WRITE_BURST_FRAMES)
        self.assertEqual(
            write_burst_limit(MAX_UINT64, balanced),
            SATURATED_WRITE_BURST_FRAMES,
        )

    def test_fragment_cap_matches_go_priority_latency_prefix_and_default_payload(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED

        self.assertEqual(fragment_cap(16_384, 0, 0, balanced), 16_384)
        self.assertEqual(fragment_cap(16_384, 0, 2, balanced), 12_288)
        self.assertEqual(fragment_cap(16_384, 0, 6, balanced), 8_192)
        self.assertEqual(fragment_cap(16_384, 0, 20, balanced), 4_096)
        self.assertEqual(
            fragment_cap(16_384, 0, 0, zmux.SchedulerHint.LATENCY),
            8_192,
        )
        self.assertEqual(
            fragment_cap(16_384, 11, 20, balanced),
            scaled_fragment_cap(16_384 - 11, 1, 4),
        )
        self.assertEqual(fragment_cap(16_384, 16_384, 20, balanced), 0)
        self.assertEqual(fragment_cap(16_384, 16_385, 20, balanced), 0)
        self.assertEqual(
            fragment_cap(0, 0, 0, balanced),
            zmux.default_settings().max_frame_payload,
        )

    def test_fragment_time_budget_matches_go_priority_bands(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED

        self.assertEqual(fragment_time_budget(0, balanced), DEFAULT_FRAGMENT_TIME_BUDGET)
        self.assertEqual(fragment_time_budget(2, balanced), MILD_FRAGMENT_TIME_BUDGET)
        self.assertEqual(fragment_time_budget(6, balanced), STRONG_FRAGMENT_TIME_BUDGET)
        self.assertEqual(fragment_time_budget(20, balanced), SATURATED_FRAGMENT_TIME_BUDGET)
        self.assertEqual(
            fragment_time_budget(0, zmux.SchedulerHint.LATENCY),
            STRONG_FRAGMENT_TIME_BUDGET,
        )
        self.assertEqual(
            fragment_time_budget_nanos(0, balanced),
            DEFAULT_FRAGMENT_TIME_BUDGET_NANOS,
        )
        self.assertEqual(
            fragment_time_budget_nanos(2, balanced),
            MILD_FRAGMENT_TIME_BUDGET_NANOS,
        )
        self.assertEqual(
            fragment_time_budget_nanos(6, balanced),
            STRONG_FRAGMENT_TIME_BUDGET_NANOS,
        )
        self.assertEqual(
            fragment_time_budget_nanos(20, balanced),
            SATURATED_FRAGMENT_TIME_BUDGET_NANOS,
        )
        self.assertEqual(
            fragment_time_budget_nanos(0, zmux.SchedulerHint.LATENCY),
            STRONG_FRAGMENT_TIME_BUDGET_NANOS,
        )

    def test_rate_limited_fragment_cap_matches_go_slow_link_and_overflow_edges(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED

        self.assertEqual(rate_limited_fragment_cap(0, 1_000, 0, balanced), 0)
        self.assertEqual(rate_limited_fragment_cap(16_384, 0, 0, balanced), 16_384)
        self.assertEqual(rate_limited_fragment_cap(16_384, 1, 0, balanced), 1)
        self.assertEqual(rate_limited_fragment_cap(16_384, 1_000, 0, balanced), 200)
        self.assertEqual(rate_limited_fragment_cap(4_096, 1 << 20, 20, balanced), 4_096)
        self.assertEqual(
            rate_limited_fragment_cap(
                1_000_000_000_000,
                50_000_000_000_000,
                0,
                balanced,
            ),
            1_000_000_000_000,
        )

    def test_scaled_fragment_cap_matches_go_minimum_and_saturation_edges(self):
        self.assertEqual(scaled_fragment_cap(0, 1, 4), 0)
        self.assertEqual(scaled_fragment_cap(1, 1, 4), 1)
        self.assertEqual(scaled_fragment_cap(100, 0, 4), 1)
        self.assertEqual(scaled_fragment_cap(100, 3, 0), 100)
        self.assertEqual(
            scaled_fragment_cap(zmux.MAX_VARINT62, 3, 4),
            3_458_764_513_820_540_927,
        )
        self.assertEqual(scaled_fragment_cap(MAX_UINT64, MAX_UINT64, 1), MAX_UINT64)

    def test_tx_fragment_cap_composes_static_and_rate_limited_policy(self):
        balanced = zmux.SchedulerHint.UNSPECIFIED_OR_BALANCED

        self.assertEqual(tx_fragment_cap(16_384, 0, 0, balanced), 16_384)
        self.assertEqual(
            tx_fragment_cap(16_384, 0, 0, balanced, send_rate_estimate=1_000),
            200,
        )
        self.assertEqual(tx_fragment_cap(16_384, 0, 20, balanced, send_rate_estimate=1), 1)

    def test_scheduler_hint_integer_coercion_uses_protocol_fallback(self):
        self.assertEqual(
            write_burst_limit(0, int(zmux.SchedulerHint.LATENCY)),
            MILD_WRITE_BURST_FRAMES,
        )
        self.assertEqual(write_burst_limit(0, 99), DEFAULT_WRITE_BURST_FRAMES)
        self.assertEqual(fragment_cap(16_384, 0, 0, 99), 16_384)

    def test_rejects_non_integer_or_negative_numeric_inputs(self):
        with self.assertRaises(TypeError):
            write_burst_limit(True)
        with self.assertRaises(ValueError):
            write_burst_limit(-1)
        with self.assertRaises(ValueError):
            fragment_cap(16_384, -1, 0)
        with self.assertRaises(TypeError):
            rate_limited_fragment_cap(1, 1, 0, True)

    def test_public_time_unit_constant_is_exact(self):
        self.assertEqual(NANOS_PER_SECOND, 1_000_000_000)


if __name__ == "__main__":
    unittest.main()
