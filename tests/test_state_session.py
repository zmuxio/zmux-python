import unittest

import zmux
from zmux._runtime import session as runtime_session
from zmux._state.session import (
    BeginCloseOutcome,
    BeginClosePlan,
    LocalOpenOutcome,
    PeerGoAwayPlan,
    PeerClosePlan,
    allow_local_non_close_control,
    begin_session_closing,
    can_open_locally,
    close_session_state,
    ignore_peer_close,
    ignore_peer_non_close_frame,
    is_benign_session_error,
    is_session_finished,
    plan_begin_close,
    plan_local_open,
    plan_peer_close,
    plan_peer_go_away,
    visible_session_error,
)


class SessionLifecyclePolicyTests(unittest.TestCase):
    def test_open_close_and_goaway_plans_match_go_reference(self):
        self.assertTrue(can_open_locally(zmux.SessionState.READY))
        self.assertTrue(can_open_locally(zmux.SessionState.DRAINING))
        self.assertFalse(can_open_locally(zmux.SessionState.CLOSING))
        self.assertTrue(is_session_finished(zmux.SessionState.CLOSED))
        self.assertTrue(is_session_finished(zmux.SessionState.FAILED))
        self.assertFalse(is_session_finished(zmux.SessionState.DRAINING))

        self.assertTrue(ignore_peer_non_close_frame(zmux.SessionState.READY, True))
        self.assertTrue(ignore_peer_non_close_frame(zmux.SessionState.CLOSING, False))
        self.assertFalse(ignore_peer_non_close_frame(zmux.SessionState.DRAINING, False))
        self.assertTrue(allow_local_non_close_control(zmux.SessionState.READY))
        self.assertFalse(
            allow_local_non_close_control(
                zmux.SessionState.READY,
                close_frame_outstanding=True,
            )
        )

        self.assertEqual(plan_local_open(zmux.SessionState.READY), LocalOpenOutcome.ALLOW)
        self.assertEqual(
            plan_local_open(zmux.SessionState.READY, graceful_close_active=True),
            LocalOpenOutcome.RETURN_CLOSED,
        )
        self.assertEqual(
            plan_local_open(zmux.SessionState.READY, close_error_present=True),
            LocalOpenOutcome.RETURN_EXISTING,
        )

        graceful = plan_begin_close(zmux.SessionState.READY, has_open_streams=True)
        self.assertEqual(graceful.outcome, BeginCloseOutcome.GRACEFUL)
        self.assertEqual(graceful.next_state, zmux.SessionState.DRAINING)
        self.assertEqual(
            plan_begin_close(zmux.SessionState.CLOSING).outcome,
            BeginCloseOutcome.WAIT_EXISTING,
        )
        self.assertEqual(
            plan_begin_close(zmux.SessionState.CLOSED).outcome,
            BeginCloseOutcome.RETURN_EXISTING,
        )

        goaway = plan_peer_go_away(zmux.SessionState.READY, False, 20, 24, 16, 24)
        self.assertTrue(goaway.changed)
        self.assertEqual(goaway.next_state, zmux.SessionState.DRAINING)
        ignored = plan_peer_go_away(zmux.SessionState.CLOSING, False, 20, 24, 16, 20)
        self.assertTrue(ignored.ignore)
        self.assertEqual(ignored.next_state, zmux.SessionState.CLOSING)
        self.assertEqual(begin_session_closing(zmux.SessionState.CLOSED), zmux.SessionState.CLOSED)
        self.assertEqual(begin_session_closing(zmux.SessionState.READY), zmux.SessionState.CLOSING)

    def test_session_error_visibility_and_peer_close_match_go_reference(self):
        closed = zmux.SessionClosed()
        no_error = zmux.ApplicationError(int(zmux.ErrorCode.NO_ERROR), "")
        cancelled = zmux.ApplicationError(int(zmux.ErrorCode.CANCELLED), "cancel")

        self.assertEqual(close_session_state(zmux.SessionState.READY, None), zmux.SessionState.CLOSED)
        self.assertEqual(close_session_state(zmux.SessionState.READY, closed), zmux.SessionState.CLOSED)
        self.assertEqual(close_session_state(zmux.SessionState.READY, no_error), zmux.SessionState.CLOSED)
        self.assertEqual(close_session_state(zmux.SessionState.READY, cancelled), zmux.SessionState.FAILED)
        self.assertEqual(close_session_state(zmux.SessionState.CLOSING, EOFError()), zmux.SessionState.CLOSED)
        self.assertEqual(close_session_state(zmux.SessionState.READY, EOFError()), zmux.SessionState.FAILED)
        self.assertEqual(
            close_session_state(zmux.SessionState.CLOSING, ConnectionResetError()),
            zmux.SessionState.FAILED,
        )
        self.assertEqual(close_session_state(zmux.SessionState.READY, RuntimeError("boom")), zmux.SessionState.FAILED)

        self.assertIsInstance(visible_session_error(zmux.SessionState.READY, None), zmux.SessionClosed)
        self.assertIsInstance(visible_session_error(zmux.SessionState.READY, no_error), zmux.SessionClosed)
        self.assertIsInstance(visible_session_error(zmux.SessionState.CLOSING, EOFError()), zmux.SessionClosed)
        reset = ConnectionResetError()
        self.assertIs(visible_session_error(zmux.SessionState.CLOSING, reset), reset)
        boom = RuntimeError("boom")
        self.assertIs(visible_session_error(zmux.SessionState.READY, boom), boom)
        self.assertTrue(is_benign_session_error(zmux.SessionState.CLOSING, EOFError()))
        self.assertFalse(
            is_benign_session_error(zmux.SessionState.CLOSING, ConnectionAbortedError())
        )
        self.assertFalse(is_benign_session_error(zmux.SessionState.READY, EOFError()))

        self.assertFalse(ignore_peer_close(None, False))
        self.assertTrue(ignore_peer_close(None, True))
        self.assertTrue(ignore_peer_close(closed, False))
        self.assertTrue(ignore_peer_close(cancelled, False))
        self.assertFalse(ignore_peer_close(EOFError(), False))
        self.assertTrue(ignore_peer_close(RuntimeError("boom"), False))
        self.assertEqual(plan_peer_close(None, False), PeerClosePlan(ignore=False))
        self.assertEqual(plan_peer_close(cancelled, False), PeerClosePlan(ignore=True))

    def test_session_error_helpers_walk_nested_and_cyclic_error_chains(self):
        closed = zmux.SessionClosed()
        nested_closed = RuntimeError("outer")
        nested_closed.__cause__ = closed
        self.assertEqual(
            close_session_state(zmux.SessionState.READY, nested_closed, closed),
            zmux.SessionState.CLOSED,
        )
        self.assertIs(
            visible_session_error(zmux.SessionState.READY, nested_closed, closed),
            closed,
        )
        self.assertTrue(ignore_peer_close(nested_closed, False, closed))

        nested_eof = RuntimeError("outer")
        nested_eof.__cause__ = EOFError()
        self.assertEqual(
            close_session_state(zmux.SessionState.CLOSING, nested_eof),
            zmux.SessionState.CLOSED,
        )
        self.assertIsInstance(
            visible_session_error(zmux.SessionState.CLOSING, nested_eof),
            zmux.SessionClosed,
        )
        self.assertFalse(ignore_peer_close(nested_eof, False))

        cyclic = RuntimeError("cycle")
        cyclic.__cause__ = cyclic
        self.assertEqual(
            close_session_state(zmux.SessionState.READY, cyclic, closed),
            zmux.SessionState.FAILED,
        )
        self.assertIs(visible_session_error(zmux.SessionState.READY, cyclic, closed), cyclic)
        self.assertTrue(ignore_peer_close(cyclic, False, closed))

        multi = RuntimeError("multi")
        multi.exceptions = (RuntimeError("ignored"), closed)
        self.assertEqual(
            close_session_state(zmux.SessionState.READY, multi, closed),
            zmux.SessionState.CLOSED,
        )
        malformed = RuntimeError("malformed")
        malformed.exceptions = 1
        self.assertEqual(
            close_session_state(zmux.SessionState.READY, malformed, closed),
            zmux.SessionState.FAILED,
        )

    def test_session_policy_rejects_invalid_flag_and_watermark_inputs(self):
        self.assertEqual(
            BeginClosePlan("graceful", "draining").outcome,
            BeginCloseOutcome.GRACEFUL,
        )
        self.assertEqual(
            BeginClosePlan("graceful", "draining").next_state,
            zmux.SessionState.DRAINING,
        )
        self.assertEqual(
            PeerGoAwayPlan(next_state="ready").next_state,
            zmux.SessionState.READY,
        )
        with self.assertRaises(TypeError):
            BeginClosePlan(True, zmux.SessionState.READY)
        with self.assertRaises(TypeError):
            PeerGoAwayPlan(ignore=1)
        with self.assertRaises(TypeError):
            PeerClosePlan(ignore=1)

        with self.assertRaises(TypeError):
            ignore_peer_non_close_frame(zmux.SessionState.READY, 1)
        with self.assertRaises(TypeError):
            allow_local_non_close_control(
                zmux.SessionState.READY,
                peer_close_error_present=1,
            )
        with self.assertRaises(TypeError):
            plan_local_open(zmux.SessionState.READY, graceful_close_active=1)
        with self.assertRaises(TypeError):
            plan_begin_close(zmux.SessionState.READY, has_open_streams=1)
        with self.assertRaises(TypeError):
            plan_peer_go_away(zmux.SessionState.READY, 0, 20, 24, 16, 24)
        with self.assertRaises(ValueError):
            plan_peer_go_away(zmux.SessionState.READY, False, -1, 24, 16, 24)
        with self.assertRaises(TypeError):
            ignore_peer_close(None, 1)

    def test_runtime_session_reexports_state_session_policy(self):
        self.assertIs(runtime_session.BeginCloseOutcome, BeginCloseOutcome)
        self.assertIs(runtime_session.LocalOpenOutcome, LocalOpenOutcome)
        self.assertIs(runtime_session.plan_begin_close, plan_begin_close)
        self.assertIs(runtime_session.close_session_state, close_session_state)
        self.assertIs(runtime_session.ignore_peer_close, ignore_peer_close)


if __name__ == "__main__":
    unittest.main()
