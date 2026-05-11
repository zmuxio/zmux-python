import unittest

from zmux._runtime import stream as runtime_stream
from zmux._state.half import RecvHalfState, SendHalfState
from zmux._state.terminal import (
    LocalAbortAction,
    LocalRecvAction,
    LocalSendAction,
    PeerAbortPlan,
    PeerDataOutcome,
    PeerDataPlan,
    PeerResetPlan,
    PeerStopSendingPlan,
    SessionClosePlan,
    StopSendingOutcome,
    TerminalErrorChoice,
    ignore_late_non_opening_control,
    ignore_peer_abort,
    ignore_peer_reset,
    ignore_peer_stop_sending,
    local_abort_action_for_stream,
    local_close_read_action,
    local_close_write_action,
    local_reset_action,
    peer_data_transition,
    peer_stop_sending_outcome,
    plan_peer_abort,
    plan_peer_reset,
    plan_peer_stop_sending,
    read_error_choice,
    session_close_transition,
    terminal_error_priority,
)


class TerminalStateTransitionTests(unittest.TestCase):
    def test_terminal_enums_match_go_iota_values(self):
        self.assertEqual(
            [choice.value for choice in TerminalErrorChoice],
            [0, 1, 2, 3, 4, 5, 6],
        )
        self.assertEqual([action.value for action in LocalSendAction], [0, 1, 2, 3])
        self.assertEqual([action.value for action in LocalRecvAction], [0, 1, 2, 3])
        self.assertEqual([action.value for action in LocalAbortAction], [0, 1])
        self.assertEqual([outcome.value for outcome in StopSendingOutcome], [0, 1, 2])
        self.assertEqual([outcome.value for outcome in PeerDataOutcome], [0, 1, 2, 3])

    def test_terminal_error_choices_match_go_priority_order(self):
        self.assertEqual(
            read_error_choice(False, False, RecvHalfState.ABSENT),
            TerminalErrorChoice.NONE,
        )
        self.assertEqual(
            read_error_choice(True, True, RecvHalfState.RESET),
            TerminalErrorChoice.RECV_CLOSED,
        )
        self.assertEqual(
            read_error_choice(True, False, RecvHalfState.ABORTED),
            TerminalErrorChoice.RECV_ABORT,
        )
        self.assertEqual(
            read_error_choice(True, False, RecvHalfState.RESET),
            TerminalErrorChoice.RECV_RESET,
        )
        self.assertEqual(
            read_error_choice(True, False, RecvHalfState.FIN),
            TerminalErrorChoice.RECV_CLOSED,
        )

        self.assertEqual(
            terminal_error_priority(SendHalfState.ABORTED, RecvHalfState.RESET),
            TerminalErrorChoice.SEND_ABORT,
        )
        self.assertEqual(
            terminal_error_priority(SendHalfState.OPEN, RecvHalfState.ABORTED),
            TerminalErrorChoice.RECV_ABORT,
        )
        self.assertEqual(
            terminal_error_priority(SendHalfState.RESET, RecvHalfState.RESET),
            TerminalErrorChoice.SEND_RESET,
        )
        self.assertEqual(
            terminal_error_priority(SendHalfState.FIN, RecvHalfState.OPEN),
            TerminalErrorChoice.SEND_CLOSED,
        )
        self.assertEqual(
            terminal_error_priority(SendHalfState.OPEN, RecvHalfState.STOP_SENT),
            TerminalErrorChoice.RECV_CLOSED,
        )
        self.assertEqual(
            terminal_error_priority(SendHalfState.OPEN, RecvHalfState.OPEN),
            TerminalErrorChoice.NONE,
        )

    def test_local_terminal_actions_match_half_presence_and_terminal_states(self):
        send_cases = (
            (False, SendHalfState.UNKNOWN, LocalSendAction.NOT_WRITABLE),
            (False, SendHalfState.ABSENT, LocalSendAction.NOT_WRITABLE),
            (True, SendHalfState.UNKNOWN, LocalSendAction.APPLY),
            (True, SendHalfState.OPEN, LocalSendAction.APPLY),
            (True, SendHalfState.STOP_SEEN, LocalSendAction.APPLY),
            (True, SendHalfState.FIN, LocalSendAction.CLOSED),
            (True, SendHalfState.RESET, LocalSendAction.TERMINAL),
            (True, SendHalfState.ABORTED, LocalSendAction.TERMINAL),
        )
        for local_send, send_half, want in send_cases:
            with self.subTest(local_send=local_send, send_half=send_half):
                self.assertEqual(local_close_write_action(local_send, send_half), want)
                self.assertEqual(local_reset_action(local_send, send_half), want)

        recv_cases = (
            (False, RecvHalfState.UNKNOWN, LocalRecvAction.NOT_READABLE),
            (False, RecvHalfState.ABSENT, LocalRecvAction.NOT_READABLE),
            (True, RecvHalfState.UNKNOWN, LocalRecvAction.APPLY),
            (True, RecvHalfState.OPEN, LocalRecvAction.APPLY),
            (True, RecvHalfState.FIN, LocalRecvAction.CLOSED),
            (True, RecvHalfState.STOP_SENT, LocalRecvAction.CLOSED),
            (True, RecvHalfState.RESET, LocalRecvAction.TERMINAL),
            (True, RecvHalfState.ABORTED, LocalRecvAction.TERMINAL),
        )
        for local_receive, recv_half, want in recv_cases:
            with self.subTest(local_receive=local_receive, recv_half=recv_half):
                self.assertEqual(local_close_read_action(local_receive, recv_half), want)

        self.assertEqual(
            local_abort_action_for_stream(SendHalfState.OPEN, RecvHalfState.OPEN),
            LocalAbortAction.APPLY,
        )
        self.assertEqual(
            local_abort_action_for_stream(SendHalfState.ABORTED, RecvHalfState.OPEN),
            LocalAbortAction.NO_OP,
        )
        self.assertEqual(
            local_abort_action_for_stream(SendHalfState.OPEN, RecvHalfState.ABORTED),
            LocalAbortAction.NO_OP,
        )
        self.assertEqual(
            local_abort_action_for_stream(SendHalfState.FIN, RecvHalfState.RESET),
            LocalAbortAction.APPLY,
        )

    def test_session_close_transition_matches_graceful_and_abortive_paths(self):
        self.assertEqual(
            session_close_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.OPEN, False
            ),
            SessionClosePlan(finish_send=True, finish_recv=True),
        )
        self.assertEqual(
            session_close_transition(
                True, True, SendHalfState.FIN, RecvHalfState.RESET, False
            ),
            SessionClosePlan(),
        )
        self.assertEqual(
            session_close_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.STOP_SENT, True
            ),
            SessionClosePlan(abort_send=True, abort_recv=True),
        )
        self.assertEqual(
            session_close_transition(
                False, True, SendHalfState.UNKNOWN, RecvHalfState.OPEN, True
            ),
            SessionClosePlan(abort_recv=True),
        )
        self.assertEqual(
            session_close_transition(
                True, True, SendHalfState.STOP_SEEN, RecvHalfState.STOP_SENT, False
            ),
            SessionClosePlan(finish_send=True, finish_recv=True),
        )
        self.assertEqual(
            session_close_transition(
                True, True, SendHalfState.RESET, RecvHalfState.STOP_SENT, True
            ),
            SessionClosePlan(abort_recv=True),
        )

    def test_peer_terminal_ignore_predicates_match_go_reference(self):
        self.assertTrue(
            ignore_late_non_opening_control(
                False, True, SendHalfState.ABSENT, RecvHalfState.FIN
            )
        )
        self.assertFalse(
            ignore_late_non_opening_control(
                True, True, SendHalfState.FIN, RecvHalfState.STOP_SENT
            )
        )
        self.assertTrue(
            ignore_peer_stop_sending(
                True, True, SendHalfState.STOP_SEEN, RecvHalfState.OPEN
            )
        )
        self.assertFalse(
            ignore_peer_stop_sending(
                True, True, SendHalfState.OPEN, RecvHalfState.RESET
            )
        )
        self.assertTrue(
            ignore_peer_reset(True, True, SendHalfState.OPEN, RecvHalfState.FIN)
        )
        self.assertFalse(
            ignore_peer_reset(True, True, SendHalfState.RESET, RecvHalfState.OPEN)
        )
        self.assertTrue(
            ignore_peer_abort(True, True, SendHalfState.ABORTED, RecvHalfState.OPEN)
        )
        self.assertFalse(
            ignore_peer_abort(True, True, SendHalfState.RESET, RecvHalfState.STOP_SENT)
        )

    def test_peer_data_transition_covers_absent_late_and_terminal_halves(self):
        self.assertEqual(
            peer_data_transition(
                True, False, SendHalfState.OPEN, RecvHalfState.UNKNOWN, False
            ).outcome,
            PeerDataOutcome.ABORT_STATE,
        )
        self.assertEqual(
            peer_data_transition(
                False, False, SendHalfState.UNKNOWN, RecvHalfState.UNKNOWN, False
            ).outcome,
            PeerDataOutcome.IGNORE,
        )
        self.assertEqual(
            peer_data_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.ABSENT, False
            ).outcome,
            PeerDataOutcome.ACCEPT,
        )
        self.assertEqual(
            peer_data_transition(
                True, True, SendHalfState.FIN, RecvHalfState.ABSENT, False
            ).outcome,
            PeerDataOutcome.ACCEPT,
        )
        stopped = peer_data_transition(
            True, True, SendHalfState.OPEN, RecvHalfState.STOP_SENT, True
        )
        self.assertEqual(stopped.outcome, PeerDataOutcome.IGNORE)
        self.assertTrue(stopped.advance_recv_fin)
        self.assertTrue(stopped.track_late_per_stream)

        reset = peer_data_transition(
            True, True, SendHalfState.OPEN, RecvHalfState.RESET, False
        )
        self.assertEqual(reset.outcome, PeerDataOutcome.IGNORE)
        self.assertTrue(reset.track_late_per_stream)

        aborted = peer_data_transition(
            True, True, SendHalfState.FIN, RecvHalfState.ABORTED, False
        )
        self.assertEqual(aborted.outcome, PeerDataOutcome.IGNORE)
        self.assertTrue(aborted.track_late_per_stream)

        self.assertEqual(
            peer_data_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.FIN, False
            ).outcome,
            PeerDataOutcome.ABORT_CLOSED,
        )
        self.assertEqual(
            peer_data_transition(
                True, True, SendHalfState.RESET, RecvHalfState.FIN, False
            ).outcome,
            PeerDataOutcome.IGNORE,
        )
        self.assertEqual(
            peer_data_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.OPEN, False
            ).outcome,
            PeerDataOutcome.ACCEPT,
        )

    def test_peer_terminal_plans_match_record_and_release_rules(self):
        self.assertEqual(
            peer_stop_sending_outcome(
                True, True, SendHalfState.OPEN, RecvHalfState.OPEN
            ),
            StopSendingOutcome.FINISH,
        )
        self.assertEqual(
            peer_stop_sending_outcome(
                True, True, SendHalfState.OPEN, RecvHalfState.RESET
            ),
            StopSendingOutcome.RESET,
        )
        self.assertEqual(
            peer_stop_sending_outcome(
                True, True, SendHalfState.FIN, RecvHalfState.OPEN
            ),
            StopSendingOutcome.IGNORE,
        )
        self.assertEqual(
            peer_stop_sending_outcome(
                True, True, SendHalfState.OPEN, RecvHalfState.ABORTED
            ),
            StopSendingOutcome.IGNORE,
        )
        self.assertEqual(
            plan_peer_stop_sending(
                True, True, SendHalfState.OPEN, RecvHalfState.OPEN
            ),
            PeerStopSendingPlan(record_stop=True, outcome=StopSendingOutcome.FINISH),
        )
        self.assertEqual(
            plan_peer_stop_sending(
                True, True, SendHalfState.FIN, RecvHalfState.OPEN
            ),
            PeerStopSendingPlan(ignore=True),
        )

        self.assertEqual(
            plan_peer_reset(True, True, SendHalfState.OPEN, RecvHalfState.OPEN),
            PeerResetPlan(record_reset=True, release_receive=True, clear_read_buf=True),
        )
        self.assertEqual(
            plan_peer_reset(False, True, SendHalfState.ABSENT, RecvHalfState.FIN),
            PeerResetPlan(ignore=True),
        )
        self.assertEqual(
            plan_peer_reset(True, True, SendHalfState.OPEN, RecvHalfState.STOP_SENT),
            PeerResetPlan(record_reset=True, release_receive=True, clear_read_buf=True),
        )

        self.assertEqual(
            plan_peer_abort(True, True, SendHalfState.OPEN, RecvHalfState.OPEN),
            PeerAbortPlan(
                record_abort=True,
                release_send=True,
                release_receive=True,
                clear_read_buf=True,
            ),
        )
        self.assertEqual(
            plan_peer_abort(True, True, SendHalfState.ABORTED, RecvHalfState.OPEN),
            PeerAbortPlan(ignore=True),
        )
        self.assertEqual(
            plan_peer_abort(True, True, SendHalfState.RESET, RecvHalfState.OPEN),
            PeerAbortPlan(
                record_abort=True,
                release_send=True,
                release_receive=True,
                clear_read_buf=True,
            ),
        )

    def test_runtime_stream_reexports_state_terminal_primitives(self):
        self.assertIs(runtime_stream.TerminalErrorChoice, TerminalErrorChoice)
        self.assertIs(runtime_stream.LocalSendAction, LocalSendAction)
        self.assertIs(runtime_stream.LocalRecvAction, LocalRecvAction)
        self.assertIs(runtime_stream.LocalAbortAction, LocalAbortAction)
        self.assertIs(runtime_stream.StopSendingOutcome, StopSendingOutcome)
        self.assertIs(runtime_stream.PeerDataOutcome, PeerDataOutcome)
        self.assertIs(runtime_stream.PeerDataPlan, PeerDataPlan)
        self.assertIs(runtime_stream.session_close_transition, session_close_transition)
        self.assertIs(runtime_stream.plan_peer_stop_sending, plan_peer_stop_sending)
        self.assertIs(runtime_stream.plan_peer_reset, plan_peer_reset)
        self.assertIs(runtime_stream.plan_peer_abort, plan_peer_abort)
        self.assertIs(runtime_stream.read_error_choice, read_error_choice)
        self.assertIs(runtime_stream.terminal_error_priority, terminal_error_priority)

    def test_terminal_helpers_reject_python_invalid_bool_shapes(self):
        with self.assertRaises(TypeError):
            read_error_choice(True, 1, RecvHalfState.OPEN)
        with self.assertRaises(TypeError):
            session_close_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.OPEN, 0
            )
        with self.assertRaises(TypeError):
            peer_data_transition(
                True, True, SendHalfState.OPEN, RecvHalfState.OPEN, 1
            )

        with self.assertRaises(TypeError):
            PeerDataPlan(PeerDataOutcome.ACCEPT, advance_recv_fin=1)
        with self.assertRaises(TypeError):
            SessionClosePlan(finish_send=1)
        with self.assertRaises(TypeError):
            PeerStopSendingPlan(ignore=1)
        with self.assertRaises(TypeError):
            PeerResetPlan(clear_read_buf=1)
        with self.assertRaises(TypeError):
            PeerAbortPlan(release_send=1)
        with self.assertRaises(TypeError):
            PeerDataPlan(True)
        with self.assertRaises(ValueError):
            PeerStopSendingPlan(outcome=99)


if __name__ == "__main__":
    unittest.main()
