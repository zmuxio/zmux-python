import unittest

from zmux._runtime import stream as runtime_stream
from zmux._state.half import (
    RecvHalfState,
    SendHalfState,
    base_recv_half_state,
    base_send_half_state,
    fully_terminal,
    normalize_recv_half_state,
    normalize_send_half_state,
    read_stopped,
    recv_terminal,
    send_terminal,
)


class StreamHalfStatePrimitiveTests(unittest.TestCase):
    def test_half_state_values_match_go_iota_order(self):
        cases = (
            (SendHalfState.UNKNOWN, 0),
            (SendHalfState.ABSENT, 1),
            (SendHalfState.OPEN, 2),
            (SendHalfState.STOP_SEEN, 3),
            (SendHalfState.FIN, 4),
            (SendHalfState.RESET, 5),
            (SendHalfState.ABORTED, 6),
            (RecvHalfState.UNKNOWN, 0),
            (RecvHalfState.ABSENT, 1),
            (RecvHalfState.OPEN, 2),
            (RecvHalfState.FIN, 3),
            (RecvHalfState.STOP_SENT, 4),
            (RecvHalfState.RESET, 5),
            (RecvHalfState.ABORTED, 6),
        )
        for state, value in cases:
            with self.subTest(state=state):
                self.assertEqual(state, value)

    def test_base_and_normalized_halves_match_go_reference(self):
        self.assertEqual(base_send_half_state(True), SendHalfState.OPEN)
        self.assertEqual(base_send_half_state(False), SendHalfState.ABSENT)
        self.assertEqual(base_recv_half_state(True), RecvHalfState.OPEN)
        self.assertEqual(base_recv_half_state(False), RecvHalfState.ABSENT)

        self.assertEqual(
            normalize_send_half_state(True, SendHalfState.UNKNOWN),
            SendHalfState.OPEN,
        )
        self.assertEqual(
            normalize_send_half_state(False, SendHalfState.UNKNOWN),
            SendHalfState.ABSENT,
        )
        self.assertEqual(
            normalize_recv_half_state(True, RecvHalfState.UNKNOWN),
            RecvHalfState.OPEN,
        )
        self.assertEqual(
            normalize_recv_half_state(False, RecvHalfState.UNKNOWN),
            RecvHalfState.ABSENT,
        )

    def test_terminal_predicates_match_go_reference(self):
        self.assertFalse(send_terminal(SendHalfState.ABSENT))
        self.assertFalse(send_terminal(SendHalfState.OPEN))
        self.assertFalse(send_terminal(SendHalfState.STOP_SEEN))
        self.assertTrue(send_terminal(SendHalfState.FIN))
        self.assertTrue(send_terminal(SendHalfState.RESET))
        self.assertTrue(send_terminal(SendHalfState.ABORTED))

        self.assertFalse(recv_terminal(RecvHalfState.ABSENT))
        self.assertFalse(recv_terminal(RecvHalfState.OPEN))
        self.assertFalse(recv_terminal(RecvHalfState.STOP_SENT))
        self.assertTrue(recv_terminal(RecvHalfState.FIN))
        self.assertTrue(recv_terminal(RecvHalfState.RESET))
        self.assertTrue(recv_terminal(RecvHalfState.ABORTED))
        self.assertTrue(read_stopped(RecvHalfState.STOP_SENT))
        self.assertFalse(read_stopped(RecvHalfState.RESET))

    def test_fully_terminal_uses_half_presence_and_abort_override(self):
        self.assertFalse(
            fully_terminal(True, True, SendHalfState.FIN, RecvHalfState.STOP_SENT)
        )
        self.assertTrue(
            fully_terminal(True, True, SendHalfState.RESET, RecvHalfState.FIN)
        )
        self.assertTrue(
            fully_terminal(True, True, SendHalfState.OPEN, RecvHalfState.ABORTED)
        )
        self.assertTrue(
            fully_terminal(False, True, SendHalfState.ABSENT, RecvHalfState.FIN)
        )
        self.assertFalse(
            fully_terminal(False, True, SendHalfState.ABSENT, RecvHalfState.OPEN)
        )
        self.assertTrue(
            fully_terminal(False, False, SendHalfState.UNKNOWN, RecvHalfState.UNKNOWN)
        )
        self.assertFalse(
            fully_terminal(True, True, SendHalfState.ABSENT, RecvHalfState.FIN)
        )
        self.assertFalse(
            fully_terminal(True, True, SendHalfState.FIN, RecvHalfState.ABSENT)
        )

    def test_half_helpers_accept_int_states_but_reject_bools_and_unknown_values(self):
        self.assertEqual(normalize_send_half_state(True, 0), SendHalfState.OPEN)
        self.assertEqual(normalize_recv_half_state(False, 0), RecvHalfState.ABSENT)
        self.assertTrue(send_terminal(int(SendHalfState.RESET)))
        self.assertTrue(recv_terminal(int(RecvHalfState.ABORTED)))

        with self.assertRaises(TypeError):
            send_terminal(True)
        with self.assertRaises(TypeError):
            recv_terminal(object())
        with self.assertRaises(ValueError):
            normalize_send_half_state(True, 99)
        with self.assertRaises(TypeError):
            base_send_half_state(1)
        with self.assertRaises(TypeError):
            base_recv_half_state(0)
        with self.assertRaises(TypeError):
            normalize_send_half_state(1, SendHalfState.OPEN)
        with self.assertRaises(TypeError):
            normalize_recv_half_state(None, RecvHalfState.OPEN)
        with self.assertRaises(TypeError):
            fully_terminal(1, True, SendHalfState.OPEN, RecvHalfState.OPEN)

    def test_runtime_stream_reexports_state_half_primitives(self):
        self.assertIs(runtime_stream.SendHalfState, SendHalfState)
        self.assertIs(runtime_stream.RecvHalfState, RecvHalfState)
        self.assertIs(runtime_stream.fully_terminal, fully_terminal)
        self.assertIs(runtime_stream.send_terminal, send_terminal)
        self.assertIs(runtime_stream.recv_terminal, recv_terminal)


if __name__ == "__main__":
    unittest.main()
