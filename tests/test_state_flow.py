import unittest

from zmux._state.flow import (
    PeerStreamControlAction,
    ignore_late_non_opening_control,
    peer_blocked_action,
    peer_max_data_action,
    should_advertise_blocked,
    should_advertise_max_data,
)
from zmux._state.half import RecvHalfState, SendHalfState


class StreamFlowControlPolicyTests(unittest.TestCase):
    def test_peer_stream_control_action_values_match_go_iota_order(self):
        self.assertEqual(PeerStreamControlAction.APPLY, 0)
        self.assertEqual(PeerStreamControlAction.IGNORE, 1)
        self.assertEqual(PeerStreamControlAction.ABORT_STATE, 2)

    def test_ignore_late_non_opening_control_matches_terminal_helper(self):
        self.assertFalse(
            ignore_late_non_opening_control(
                True,
                True,
                SendHalfState.FIN,
                RecvHalfState.STOP_SENT,
            )
        )
        self.assertTrue(
            ignore_late_non_opening_control(
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            )
        )
        self.assertTrue(
            ignore_late_non_opening_control(
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.ABORTED,
            )
        )

    def test_peer_stream_control_action_matches_go_reference(self):
        self.assertEqual(
            peer_max_data_action(
                False,
                True,
                SendHalfState.ABSENT,
                RecvHalfState.OPEN,
            ),
            PeerStreamControlAction.ABORT_STATE,
        )
        self.assertEqual(
            peer_max_data_action(
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            ),
            PeerStreamControlAction.IGNORE,
        )
        self.assertEqual(
            peer_max_data_action(
                True,
                True,
                SendHalfState.FIN,
                RecvHalfState.OPEN,
            ),
            PeerStreamControlAction.APPLY,
        )
        self.assertEqual(
            peer_max_data_action(
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.ABORTED,
            ),
            PeerStreamControlAction.IGNORE,
        )

        self.assertEqual(
            peer_blocked_action(
                True,
                False,
                SendHalfState.OPEN,
                RecvHalfState.ABSENT,
            ),
            PeerStreamControlAction.ABORT_STATE,
        )
        self.assertEqual(
            peer_blocked_action(
                True,
                True,
                SendHalfState.RESET,
                RecvHalfState.FIN,
            ),
            PeerStreamControlAction.IGNORE,
        )
        self.assertEqual(
            peer_blocked_action(
                True,
                True,
                SendHalfState.FIN,
                RecvHalfState.OPEN,
            ),
            PeerStreamControlAction.APPLY,
        )
        self.assertEqual(
            peer_blocked_action(
                True,
                True,
                SendHalfState.ABORTED,
                RecvHalfState.OPEN,
            ),
            PeerStreamControlAction.IGNORE,
        )

    def test_local_advertise_predicates_match_go_reference(self):
        self.assertTrue(should_advertise_max_data(True, RecvHalfState.OPEN))
        self.assertFalse(should_advertise_max_data(True, RecvHalfState.UNKNOWN))
        self.assertFalse(should_advertise_max_data(True, RecvHalfState.STOP_SENT))
        self.assertFalse(should_advertise_max_data(True, RecvHalfState.RESET))
        self.assertFalse(should_advertise_max_data(False, RecvHalfState.OPEN))

        self.assertTrue(should_advertise_blocked(True, SendHalfState.OPEN))
        self.assertFalse(should_advertise_blocked(True, SendHalfState.UNKNOWN))
        self.assertFalse(should_advertise_blocked(True, SendHalfState.STOP_SEEN))
        self.assertFalse(should_advertise_blocked(True, SendHalfState.FIN))
        self.assertFalse(should_advertise_blocked(False, SendHalfState.OPEN))

    def test_flow_predicates_reject_non_bool_shape_flags(self):
        with self.assertRaises(TypeError):
            ignore_late_non_opening_control(
                1,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        with self.assertRaises(TypeError):
            peer_max_data_action(
                True,
                0,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        with self.assertRaises(TypeError):
            peer_blocked_action(
                "yes",
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        with self.assertRaises(TypeError):
            should_advertise_max_data(1, RecvHalfState.OPEN)
        with self.assertRaises(TypeError):
            should_advertise_blocked(None, SendHalfState.OPEN)


if __name__ == "__main__":
    unittest.main()
