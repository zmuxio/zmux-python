import unittest

from zmux._runtime import stream as runtime_stream
from zmux._state.half import RecvHalfState, SendHalfState
from zmux._state.visibility import (
    LocalOpenPhase,
    LocalOpenVisibility,
    should_enqueue_accepted,
    should_finalize_peer_active,
    should_flush_priority_update,
    should_flush_stream_blocked,
    should_flush_stream_max_data,
    should_reclaim_unseen_local_stream,
)


class LocalOpenVisibilityTests(unittest.TestCase):
    def test_phase_enum_matches_go_iota_values(self):
        self.assertEqual([phase.value for phase in LocalOpenPhase], [0, 1, 2, 3, 4])

    def test_phase_table_matches_go_reference(self):
        cases = [
            (LocalOpenVisibility(False, False, False, False), LocalOpenPhase.NONE),
            (
                LocalOpenVisibility(True, False, False, False),
                LocalOpenPhase.NEEDS_COMMIT,
            ),
            (
                LocalOpenVisibility(True, True, False, False),
                LocalOpenPhase.NEEDS_EMIT,
            ),
            (
                LocalOpenVisibility(True, True, False, True),
                LocalOpenPhase.QUEUED,
            ),
            (
                LocalOpenVisibility(True, True, True, True),
                LocalOpenPhase.PEER_VISIBLE,
            ),
        ]
        for visibility, phase in cases:
            with self.subTest(visibility=visibility):
                self.assertEqual(visibility.phase(), phase)

    def test_phase_methods_match_go_reference(self):
        self.assertFalse(LocalOpenPhase.NONE.is_local())
        self.assertTrue(LocalOpenPhase.NEEDS_COMMIT.is_local())
        self.assertTrue(LocalOpenPhase.NEEDS_COMMIT.needs_local_opener())
        self.assertFalse(LocalOpenPhase.NEEDS_EMIT.needs_local_opener())
        self.assertTrue(LocalOpenPhase.NEEDS_COMMIT.awaiting_peer_visibility())
        self.assertTrue(LocalOpenPhase.NEEDS_EMIT.awaiting_peer_visibility())
        self.assertTrue(LocalOpenPhase.QUEUED.awaiting_peer_visibility())
        self.assertFalse(LocalOpenPhase.PEER_VISIBLE.awaiting_peer_visibility())
        self.assertTrue(LocalOpenPhase.NEEDS_COMMIT.should_emit_opener_frame())
        self.assertTrue(LocalOpenPhase.NEEDS_EMIT.should_emit_opener_frame())
        self.assertFalse(LocalOpenPhase.QUEUED.should_emit_opener_frame())
        self.assertFalse(LocalOpenPhase.NONE.should_mark_peer_visible())
        self.assertTrue(LocalOpenPhase.NEEDS_COMMIT.should_mark_peer_visible())
        self.assertTrue(LocalOpenPhase.NEEDS_EMIT.should_mark_peer_visible())
        self.assertFalse(LocalOpenPhase.PEER_VISIBLE.should_mark_peer_visible())
        self.assertFalse(LocalOpenPhase.NEEDS_COMMIT.can_take_pending_priority_update())
        self.assertTrue(LocalOpenPhase.NONE.can_take_pending_priority_update())
        self.assertTrue(LocalOpenPhase.PEER_VISIBLE.should_queue_stream_blocked(0))
        self.assertFalse(LocalOpenPhase.PEER_VISIBLE.should_queue_stream_blocked(1))
        self.assertFalse(LocalOpenPhase.NEEDS_EMIT.should_queue_stream_blocked(0))

    def test_flush_predicates_return_go_flush_keep_pairs(self):
        waiting = LocalOpenPhase.NEEDS_COMMIT
        visible = LocalOpenPhase.PEER_VISIBLE

        self.assertEqual(
            should_flush_stream_max_data(True, True, waiting, False, False),
            (False, True),
        )
        self.assertEqual(
            should_flush_stream_max_data(True, True, visible, False, False),
            (True, False),
        )
        self.assertEqual(
            should_flush_stream_max_data(True, True, visible, True, False),
            (False, False),
        )
        self.assertEqual(
            should_flush_stream_max_data(True, True, visible, False, True),
            (False, False),
        )
        self.assertEqual(
            should_flush_stream_max_data(False, True, visible, False, False),
            (False, False),
        )
        self.assertEqual(
            should_flush_stream_max_data(True, False, visible, False, False),
            (False, False),
        )

        self.assertEqual(
            should_flush_stream_blocked(True, True, waiting, SendHalfState.OPEN),
            (False, True),
        )
        self.assertEqual(
            should_flush_stream_blocked(True, True, visible, SendHalfState.OPEN),
            (True, False),
        )
        self.assertEqual(
            should_flush_stream_blocked(True, True, visible, SendHalfState.STOP_SEEN),
            (False, False),
        )
        self.assertEqual(
            should_flush_stream_blocked(True, False, visible, SendHalfState.OPEN),
            (False, False),
        )
        self.assertEqual(
            should_flush_stream_blocked(False, True, visible, SendHalfState.OPEN),
            (False, False),
        )
        self.assertEqual(
            should_flush_stream_blocked(True, True, visible, SendHalfState.RESET),
            (False, False),
        )

        self.assertEqual(
            should_flush_priority_update(waiting, SendHalfState.OPEN),
            (False, True),
        )
        self.assertEqual(
            should_flush_priority_update(visible, SendHalfState.OPEN),
            (True, False),
        )
        self.assertEqual(
            should_flush_priority_update(visible, SendHalfState.STOP_SEEN),
            (False, False),
        )
        self.assertEqual(
            should_flush_priority_update(visible, SendHalfState.RESET),
            (False, False),
        )
        self.assertEqual(
            should_flush_priority_update(visible, SendHalfState.FIN),
            (False, False),
        )

    def test_reclaim_and_finalize_predicates_match_go_reference(self):
        self.assertTrue(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                True,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )
        self.assertFalse(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.PEER_VISIBLE,
                True,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )
        self.assertFalse(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                True,
                False,
                12,
                99,
                20,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )
        self.assertTrue(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                True,
                False,
                101,
                8,
                100,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )
        self.assertFalse(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NONE,
                True,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )
        self.assertFalse(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                False,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )
        self.assertFalse(
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                True,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            )
        )
        self.assertFalse(
            should_finalize_peer_active(
                False,
                False,
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            )
        )

        self.assertTrue(
            should_finalize_peer_active(
                True,
                False,
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            )
        )
        self.assertFalse(
            should_finalize_peer_active(
                True,
                True,
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            )
        )
        self.assertTrue(should_enqueue_accepted(True, False, False))
        self.assertFalse(should_enqueue_accepted(False, False, False))
        self.assertFalse(should_enqueue_accepted(True, True, False))
        self.assertFalse(should_enqueue_accepted(True, False, True))

    def test_visibility_helpers_reject_python_invalid_input_shapes(self):
        with self.assertRaises(TypeError):
            LocalOpenVisibility(1, False, False, False)
        with self.assertRaises(TypeError):
            LocalOpenPhase.PEER_VISIBLE.should_queue_stream_blocked(True)
        with self.assertRaises(ValueError):
            LocalOpenPhase.PEER_VISIBLE.should_queue_stream_blocked(-1)
        with self.assertRaises(TypeError):
            should_enqueue_accepted(1, False, False)
        with self.assertRaises(TypeError):
            should_flush_stream_max_data(1, True, LocalOpenPhase.PEER_VISIBLE, False, False)
        with self.assertRaises(TypeError):
            should_flush_stream_max_data(True, True, LocalOpenPhase.PEER_VISIBLE, 1, False)
        with self.assertRaises(TypeError):
            should_flush_stream_blocked(True, 1, LocalOpenPhase.PEER_VISIBLE, SendHalfState.OPEN)
        with self.assertRaises(TypeError):
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                True,
                1,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        with self.assertRaises(ValueError):
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                True,
                True,
                -1,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        with self.assertRaises(TypeError):
            should_reclaim_unseen_local_stream(
                LocalOpenPhase.NEEDS_EMIT,
                1,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        with self.assertRaises(TypeError):
            should_finalize_peer_active(
                1,
                False,
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            )

    def test_runtime_stream_reexports_state_visibility_primitives(self):
        for name in (
                "LocalOpenPhase",
                "LocalOpenVisibility",
                "should_enqueue_accepted",
                "should_finalize_peer_active",
                "should_flush_priority_update",
                "should_flush_stream_blocked",
                "should_flush_stream_max_data",
                "should_reclaim_unseen_local_stream",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(runtime_stream, name), globals()[name])


if __name__ == "__main__":
    unittest.main()
