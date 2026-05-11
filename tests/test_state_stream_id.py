import unittest

import zmux
from zmux._runtime import read_loop
from zmux._state.stream_id import (
    first_local_stream_id,
    first_peer_stream_id,
    stream_is_bidi,
    stream_is_local,
    stream_kind_for_local,
    stream_opener,
    validate_local_open_id,
    validate_stream_id_for_role,
)


class StreamIDStateTests(unittest.TestCase):
    def test_stream_id_classification_matches_go_and_rust_reference(self):
        self.assertEqual(first_local_stream_id(zmux.Role.INITIATOR, True), 4)
        self.assertEqual(first_local_stream_id(zmux.Role.INITIATOR, False), 2)
        self.assertEqual(first_local_stream_id(zmux.Role.RESPONDER, True), 1)
        self.assertEqual(first_local_stream_id(zmux.Role.RESPONDER, False), 3)
        self.assertEqual(first_peer_stream_id(zmux.Role.INITIATOR, True), 1)
        self.assertEqual(first_peer_stream_id(zmux.Role.INITIATOR, False), 3)
        self.assertEqual(first_peer_stream_id(zmux.Role.RESPONDER, True), 4)
        self.assertEqual(first_peer_stream_id(zmux.Role.RESPONDER, False), 2)

        self.assertTrue(stream_is_bidi(4))
        self.assertFalse(stream_is_bidi(2))
        self.assertEqual(stream_opener(4), zmux.Role.INITIATOR)
        self.assertEqual(stream_opener(1), zmux.Role.RESPONDER)
        self.assertTrue(stream_is_local(zmux.Role.INITIATOR, 2))
        self.assertFalse(stream_is_local(zmux.Role.INITIATOR, 3))
        self.assertEqual(stream_kind_for_local(zmux.Role.INITIATOR, 4), (True, True))
        self.assertEqual(stream_kind_for_local(zmux.Role.INITIATOR, 2), (True, False))
        self.assertEqual(stream_kind_for_local(zmux.Role.INITIATOR, 3), (False, True))

    def test_stream_id_auto_role_and_integer_codes_match_reference(self):
        self.assertEqual(first_local_stream_id(zmux.Role.AUTO, True), 0)
        self.assertEqual(first_local_stream_id(zmux.Role.AUTO, False), 0)
        self.assertEqual(first_peer_stream_id(zmux.Role.AUTO, True), 0)
        self.assertEqual(first_peer_stream_id(zmux.Role.AUTO, False), 0)
        self.assertEqual(first_local_stream_id(0, True), 4)
        self.assertEqual(first_local_stream_id(1, False), 3)
        self.assertEqual(first_peer_stream_id(0, False), 3)
        self.assertEqual(first_peer_stream_id(1, True), 4)

        self.assertEqual(stream_opener(0), zmux.Role.INITIATOR)
        self.assertFalse(stream_is_local(zmux.Role.AUTO, 2))
        self.assertEqual(stream_kind_for_local(zmux.Role.AUTO, 2), (False, True))
        validate_stream_id_for_role(zmux.Role.AUTO, 4)
        with self.assertRaisesRegex(ValueError, "not locally owned"):
            validate_local_open_id(zmux.Role.AUTO, 4, True)

    def test_stream_id_validation_matches_go_reference(self):
        validate_stream_id_for_role(zmux.Role.INITIATOR, 4)
        validate_local_open_id(zmux.Role.INITIATOR, 4, True)
        validate_local_open_id(zmux.Role.INITIATOR, 2, False)
        with self.assertRaisesRegex(ValueError, "session-scoped"):
            validate_stream_id_for_role(zmux.Role.INITIATOR, 0)
        with self.assertRaisesRegex(ValueError, "varint62"):
            validate_stream_id_for_role(zmux.Role.INITIATOR, zmux.MAX_VARINT62 + 1)
        with self.assertRaisesRegex(ValueError, "not locally owned"):
            validate_local_open_id(zmux.Role.RESPONDER, 4, True)
        with self.assertRaisesRegex(ValueError, "not unidirectional"):
            validate_local_open_id(zmux.Role.INITIATOR, 4, False)

    def test_stream_id_validation_rejects_python_invalid_input_shapes(self):
        for invalid in (-1, True, "4"):
            with self.subTest(stream_id=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    stream_is_bidi(invalid)
                with self.assertRaises((TypeError, ValueError)):
                    stream_opener(invalid)
        with self.assertRaises(TypeError):
            first_local_stream_id(True, True)
        with self.assertRaises(TypeError):
            first_local_stream_id("0", True)
        with self.assertRaises(TypeError):
            first_peer_stream_id(zmux.Role.INITIATOR, 1)
        with self.assertRaises(TypeError):
            first_local_stream_id(zmux.Role.INITIATOR, 1)
        with self.assertRaises(TypeError):
            stream_is_local(True, 2)
        with self.assertRaises(TypeError):
            stream_kind_for_local(True, 2)
        with self.assertRaises(TypeError):
            validate_local_open_id(zmux.Role.INITIATOR, 4, 1)
        with self.assertRaises(ValueError):
            first_local_stream_id(99, True)

    def test_runtime_read_loop_reexports_state_stream_id_with_protocol_errors(self):
        self.assertIs(read_loop.first_local_stream_id, first_local_stream_id)
        self.assertIs(read_loop.stream_kind_for_local, stream_kind_for_local)
        with self.assertRaises(zmux.ProtocolError):
            read_loop.validate_stream_id_for_role(zmux.Role.INITIATOR, 0)
        with self.assertRaises(zmux.ProtocolError):
            read_loop.validate_local_open_id(zmux.Role.RESPONDER, 4, True)


if __name__ == "__main__":
    unittest.main()
