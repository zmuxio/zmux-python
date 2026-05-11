import unittest

from zmux._runtime.flow import MAX_UINT64
from zmux._runtime.stop_sending import (
    REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW,
    REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW_MAX,
    StopSendingGracefulDeadlineQueue,
    StopSendingGracefulDecision,
    StopSendingGracefulInput,
    evaluate_stop_sending_graceful,
    stop_sending_committed_tail,
    stop_sending_drain_window,
    stop_sending_graceful_rate_budget,
    stop_sending_queued_only_tail,
    stop_sending_static_tail_cap,
    stop_sending_tail_budget,
)


class RuntimeStopSendingGracefulTests(unittest.TestCase):
    def test_rejects_abortive_or_unopened_paths(self):
        for policy_input in (
                StopSendingGracefulInput(
                    recv_abortive=True,
                    local_opened=True,
                    send_committed=True,
                ),
                StopSendingGracefulInput(
                    needs_local_opener=True,
                    local_opened=True,
                    send_committed=True,
                ),
        ):
            self.assertFalse(evaluate_stop_sending_graceful(policy_input).attempt)

    def test_allows_committed_empty_tail_after_local_open(self):
        decision = evaluate_stop_sending_graceful(
            StopSendingGracefulInput(local_opened=True, send_committed=True)
        )

        self.assertTrue(decision.attempt)
        self.assertEqual(decision.committed_tail, 0)

    def test_uses_inflight_tail_before_queued_only_tail(self):
        decision = evaluate_stop_sending_graceful(
            StopSendingGracefulInput(
                local_opened=True,
                send_committed=True,
                queued_data_bytes=768,
                inflight_queued=64,
                fragment_cap=256,
                send_rate_estimate=1024,
                drain_window=0.1,
            )
        )

        self.assertTrue(decision.attempt)
        self.assertEqual(decision.inflight_tail, 64)
        self.assertEqual(decision.queued_only_tail, 704)
        self.assertLess(decision.tail_budget, decision.queued_only_tail)

    def test_uses_inflight_tail_without_rate_budget(self):
        decision = evaluate_stop_sending_graceful(
            StopSendingGracefulInput(
                local_opened=True,
                send_committed=True,
                queued_data_bytes=1024,
                inflight_queued=64,
                fragment_cap=256,
                send_rate_estimate=0,
            )
        )

        self.assertTrue(decision.attempt)
        self.assertEqual(decision.tail_budget, 64)
        self.assertEqual(decision.inflight_tail, 64)

    def test_explicit_tail_cap_wins_over_rate_budget(self):
        decision = evaluate_stop_sending_graceful(
            StopSendingGracefulInput(
                local_opened=True,
                send_committed=True,
                queued_data_bytes=384,
                fragment_cap=256,
                send_rate_estimate=16 << 10,
                explicit_tail_cap=256,
                drain_window=0.1,
            )
        )

        self.assertFalse(decision.attempt)
        self.assertEqual(decision.tail_budget, 256)

    def test_explicit_tail_cap_still_allows_inflight_tail(self):
        decision = evaluate_stop_sending_graceful(
            StopSendingGracefulInput(
                local_opened=True,
                send_committed=True,
                queued_data_bytes=384,
                inflight_queued=64,
                fragment_cap=256,
                send_rate_estimate=16 << 10,
                explicit_tail_cap=256,
                drain_window=0.1,
            )
        )

        self.assertTrue(decision.attempt)
        self.assertEqual(decision.tail_budget, 256)
        self.assertEqual(decision.inflight_tail, 64)

    def test_queued_only_tail_can_use_rate_budget(self):
        decision = evaluate_stop_sending_graceful(
            StopSendingGracefulInput(
                local_opened=True,
                send_committed=True,
                queued_data_bytes=768,
                fragment_cap=256,
                send_rate_estimate=16 << 10,
                drain_window=0.1,
            )
        )

        self.assertTrue(decision.attempt)
        self.assertEqual(decision.queued_only_tail, 768)
        self.assertGreaterEqual(decision.tail_budget, 768)

    def test_tail_helpers_match_reference_edges(self):
        self.assertEqual(stop_sending_committed_tail(8, 10), 10)
        self.assertEqual(stop_sending_queued_only_tail(8, 10), 0)
        self.assertEqual(stop_sending_queued_only_tail(10, 8), 2)
        self.assertEqual(stop_sending_static_tail_cap(0), 0)
        self.assertEqual(stop_sending_static_tail_cap(1), 1)
        self.assertEqual(stop_sending_static_tail_cap(MAX_UINT64), 512)
        self.assertEqual(stop_sending_tail_budget(256, 99, 16 << 10, 0.1), 99)

    def test_rate_budget_and_drain_window_edges_are_bounded(self):
        self.assertEqual(stop_sending_graceful_rate_budget(1, 1e-9), 1)
        self.assertEqual(stop_sending_graceful_rate_budget(0, 0.1), 0)
        self.assertEqual(
            stop_sending_graceful_rate_budget(MAX_UINT64, float("inf")),
            MAX_UINT64,
        )
        self.assertEqual(
            stop_sending_drain_window(0),
            REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW,
        )
        self.assertEqual(stop_sending_drain_window(0.25), 0.25)
        self.assertEqual(stop_sending_drain_window(None, 0.8), 1.6)
        self.assertEqual(
            stop_sending_drain_window(None, 0.001),
            REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW,
        )
        self.assertEqual(
            stop_sending_drain_window(None, float("inf")),
            REPO_DEFAULT_STOP_SENDING_DRAIN_WINDOW_MAX,
        )

    def test_rejects_implicit_python_coercions(self):
        with self.assertRaises(TypeError):
            StopSendingGracefulInput(recv_abortive=1)
        with self.assertRaises(TypeError):
            StopSendingGracefulInput(queued_data_bytes="1")
        with self.assertRaises(TypeError):
            StopSendingGracefulDecision(attempt=1)
        with self.assertRaises(TypeError):
            stop_sending_graceful_rate_budget("1", 0.1)
        with self.assertRaises(TypeError):
            stop_sending_drain_window(True)
        with self.assertRaises(ValueError):
            StopSendingGracefulInput(queued_data_bytes=-1)
        with self.assertRaises(ValueError):
            stop_sending_tail_budget(1, -1, 0, 0.1)
        with self.assertRaises(ValueError):
            StopSendingGracefulInput(drain_window=-0.1)
        with self.assertRaises(ValueError):
            stop_sending_drain_window(-1)
        with self.assertRaises(ValueError):
            stop_sending_drain_window(None, float("nan"))

    def test_deadline_queue_tracks_next_and_expired_streams(self):
        queue = StopSendingGracefulDeadlineQueue()
        first = object()
        second = object()

        self.assertTrue(queue.update(first, 3.0))
        self.assertTrue(queue.update(second, 2.0))

        self.assertEqual(len(queue), 2)
        self.assertEqual(queue.next_deadline(), 2.0)
        self.assertIsNone(queue.pop_expired(1.999))
        self.assertIs(queue.pop_expired(2.0), second)
        self.assertEqual(queue.next_deadline(), 3.0)
        self.assertIs(queue.pop_expired(3.0), first)
        self.assertFalse(queue)
        self.assertIsNone(queue.next_deadline())

    def test_deadline_queue_skips_stale_entries_and_removals(self):
        queue = StopSendingGracefulDeadlineQueue()
        stream = object()

        self.assertTrue(queue.update(stream, 5.0))
        self.assertTrue(queue.update(stream, 1.0))
        self.assertEqual(queue.deadline_for(stream), 1.0)
        self.assertIs(queue.pop_expired(1.0), stream)
        self.assertIsNone(queue.next_deadline())

        self.assertTrue(queue.update(stream, 2.0))
        self.assertFalse(queue.update(stream, 2.0))
        self.assertTrue(queue.discard(stream))
        self.assertFalse(queue.discard(stream))
        self.assertIsNone(queue.pop_expired(10.0))

    def test_deadline_queue_clear_and_input_edges(self):
        queue = StopSendingGracefulDeadlineQueue()
        stream = object()

        self.assertFalse(queue.update(None, 1.0))
        self.assertFalse(queue.update(stream, None))
        self.assertFalse(queue.update(stream, 0.0))
        self.assertFalse(queue.update(stream, -1.0))
        self.assertTrue(queue.update(stream, 1.0))
        queue.clear()
        self.assertFalse(queue)
        self.assertIsNone(queue.deadline_for(stream))

        with self.assertRaises(TypeError):
            queue.update(stream, True)
        with self.assertRaises(TypeError):
            queue.pop_expired("1.0")
        with self.assertRaises(ValueError):
            queue.update(stream, float("nan"))
        with self.assertRaises(ValueError):
            queue.update(stream, float("inf"))

    def test_deadline_queue_compaction_keeps_active_entries_bounded(self):
        queue = StopSendingGracefulDeadlineQueue()
        stream = object()
        for idx in range(200):
            self.assertTrue(queue.update(stream, float(idx + 1)))

        self.assertEqual(len(queue), 1)
        self.assertEqual(queue.deadline_for(stream), 200.0)
        self.assertEqual(queue.next_deadline(), 200.0)
        self.assertIs(queue.pop_expired(200.0), stream)
        self.assertFalse(queue)


if __name__ == "__main__":
    unittest.main()
