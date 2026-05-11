import unittest

import zmux
from zmux._state.open import (
    DEFAULT_ADMISSION_HARD_CAP,
    DEFAULT_ADMISSION_SOFT_CAP,
    DEFAULT_PROVISIONAL_OPEN_HARD_CAP,
    PROVISIONAL_OPEN_MAX_AGE,
    active_stream_within_limit,
    admission_hard_cap,
    admission_soft_cap,
    decrement_active_peer_count,
    decrement_active_stream_count,
    expected_next_peer_stream_id,
    initial_local_opened_send_window,
    initial_receive_window,
    initial_send_window,
    local_open_refused_by_goaway,
    max_stream_id_for_class,
    peer_open_refused_by_goaway,
    peer_stream_within_limit,
    projected_local_open_id,
    provisional_available_count,
    provisional_expired,
    provisional_hard_cap,
    provisional_open_hard_cap,
    provisional_open_soft_cap,
    provisional_soft_cap,
)
from zmux._state.stream_id import (
    first_local_stream_id,
    first_peer_stream_id,
    stream_kind_for_local,
)


class StreamOpenAdmissionPolicyTests(unittest.TestCase):
    def test_goaway_and_projected_id_boundaries_match_go_reference(self):
        self.assertFalse(local_open_refused_by_goaway(8, True, 8, 6))
        self.assertTrue(local_open_refused_by_goaway(12, True, 8, 6))
        self.assertFalse(local_open_refused_by_goaway(6, False, 8, 6))
        self.assertTrue(local_open_refused_by_goaway(10, False, 8, 6))

        last = zmux.MAX_VARINT62
        self.assertEqual(max_stream_id_for_class(0), 0)
        self.assertEqual(max_stream_id_for_class(last + 1), 0)
        self.assertEqual(max_stream_id_for_class(last - 4), last)
        self.assertEqual(projected_local_open_id(9, 3), 21)
        self.assertEqual(projected_local_open_id(last - 4, 1), last)
        self.assertEqual(projected_local_open_id(last, 1), last + 1)
        self.assertEqual(projected_local_open_id(0, 1), 0)

    def test_admission_and_provisional_policy_match_go_reference(self):
        self.assertEqual(admission_soft_cap(0), DEFAULT_ADMISSION_SOFT_CAP)
        self.assertEqual(admission_hard_cap(0), DEFAULT_ADMISSION_HARD_CAP)
        self.assertEqual(admission_soft_cap(8), 16)
        self.assertEqual(admission_hard_cap(8), 32)
        self.assertEqual(admission_soft_cap(128), 32)
        self.assertEqual(admission_hard_cap(128), 64)
        self.assertEqual(provisional_soft_cap(True, 8), 16)
        self.assertEqual(provisional_hard_cap(False, 8), 32)
        self.assertEqual(provisional_open_soft_cap(8, bidi=True), 16)
        self.assertEqual(provisional_open_hard_cap(8, bidi=False), 32)
        self.assertEqual(
            DEFAULT_PROVISIONAL_OPEN_HARD_CAP,
            DEFAULT_ADMISSION_HARD_CAP,
        )

        self.assertFalse(provisional_expired(True, 0.0, now=100.0))
        self.assertFalse(provisional_expired(False, None, now=100.0))
        self.assertFalse(provisional_expired(False, 100.0, now=99.0))
        self.assertFalse(provisional_expired(False, 1.0, now=1.0 + PROVISIONAL_OPEN_MAX_AGE))
        self.assertTrue(
            provisional_expired(
                False,
                1.0,
                now=1.0 + PROVISIONAL_OPEN_MAX_AGE + 0.001,
            )
        )
        self.assertEqual(provisional_available_count(25, 21), 0)
        self.assertEqual(
            provisional_available_count(0, zmux.MAX_VARINT62),
            (zmux.MAX_VARINT62 // 4) + 1,
        )
        self.assertEqual(provisional_available_count(9, 21), 4)
        self.assertEqual(
            provisional_available_count(1, (1 << 64) - 1),
            (((1 << 64) - 2) // 4) + 1,
        )

    def test_peer_open_limits_and_active_counts_match_go_reference(self):
        self.assertFalse(peer_open_refused_by_goaway(4, 4, 6))
        self.assertTrue(peer_open_refused_by_goaway(8, 4, 6))
        self.assertFalse(peer_open_refused_by_goaway(6, 4, 6))
        self.assertTrue(peer_open_refused_by_goaway(10, 4, 6))
        self.assertEqual(expected_next_peer_stream_id(4, 12, 10), 12)
        self.assertEqual(expected_next_peer_stream_id(6, 12, 10), 10)

        self.assertTrue(active_stream_within_limit(True, 1, 9, 2, 10))
        self.assertFalse(active_stream_within_limit(True, 2, 9, 2, 10))
        self.assertTrue(peer_stream_within_limit(False, 9, 1, 10, 2))
        self.assertFalse(peer_stream_within_limit(False, 9, 2, 10, 2))
        self.assertEqual(decrement_active_stream_count(True, 2, 3), (1, 3))
        self.assertEqual(decrement_active_stream_count(False, 2, 3), (2, 2))
        self.assertEqual(decrement_active_stream_count(True, 0, 3), (0, 3))
        self.assertEqual(decrement_active_peer_count(False, 2, 0), (2, 0))

    def test_initial_windows_follow_stream_owner_and_direction(self):
        settings = zmux.Settings(
            initial_max_stream_data_bidi_locally_opened=11,
            initial_max_stream_data_bidi_peer_opened=22,
            initial_max_stream_data_uni=33,
        )
        self.assertEqual(initial_send_window(zmux.Role.RESPONDER, settings, 1), 22)
        self.assertEqual(initial_send_window(zmux.Role.RESPONDER, settings, 4), 11)
        self.assertEqual(initial_send_window(zmux.Role.RESPONDER, settings, 2), 0)
        self.assertEqual(initial_send_window(zmux.Role.RESPONDER, settings, 3), 33)
        self.assertEqual(initial_local_opened_send_window(settings, True), 22)
        self.assertEqual(initial_local_opened_send_window(settings, False), 33)

        self.assertEqual(initial_receive_window(zmux.Role.RESPONDER, settings, 1), 11)
        self.assertEqual(initial_receive_window(zmux.Role.RESPONDER, settings, 4), 22)
        self.assertEqual(initial_receive_window(zmux.Role.RESPONDER, settings, 2), 33)
        self.assertEqual(initial_receive_window(zmux.Role.RESPONDER, settings, 3), 0)

    def test_stream_id_helpers_are_available_for_open_policy(self):
        self.assertEqual(first_local_stream_id(zmux.Role.INITIATOR, True), 4)
        self.assertEqual(first_peer_stream_id(zmux.Role.RESPONDER, False), 2)
        self.assertEqual(stream_kind_for_local(zmux.Role.INITIATOR, 2), (True, False))
        self.assertEqual(stream_kind_for_local(zmux.Role.INITIATOR, 3), (False, True))

    def test_open_policy_rejects_non_bool_shape_flags(self):
        with self.assertRaises(TypeError):
            local_open_refused_by_goaway(8, 1, 8, 6)
        with self.assertRaises(TypeError):
            provisional_soft_cap(0, 8)
        with self.assertRaises(TypeError):
            provisional_hard_cap("bidi", 8)
        with self.assertRaises(TypeError):
            provisional_open_soft_cap(8, bidi=1)
        with self.assertRaises(TypeError):
            provisional_expired(1, 0.0, now=10.0)
        with self.assertRaises(TypeError):
            active_stream_within_limit(1, 1, 0, 2, 2)
        with self.assertRaises(TypeError):
            peer_stream_within_limit(None, 1, 0, 2, 2)
        with self.assertRaises(TypeError):
            decrement_active_stream_count(1, 1, 1)
        with self.assertRaises(TypeError):
            initial_local_opened_send_window(zmux.Settings(), 1)


if __name__ == "__main__":
    unittest.main()
