import unittest

import zmux._state as state
from zmux._state.half import base_send_half_state
from zmux._state.session import close_session_state
from zmux._state.stream import StreamState
from zmux._state.tombstone import StreamTombstone


class StatePackageSurfaceTests(unittest.TestCase):
    def test_private_package_has_no_reexport_surface(self):
        self.assertIn("Private protocol-state helpers", state.__doc__)
        self.assertEqual(state.__all__, ())
        self.assertFalse(hasattr(state, "StreamState"))
        self.assertFalse(hasattr(state, "StreamTombstone"))

    def test_state_helpers_are_imported_from_owning_modules(self):
        self.assertTrue(callable(base_send_half_state))
        self.assertTrue(callable(close_session_state))
        self.assertEqual(StreamState.__name__, "StreamState")
        self.assertEqual(StreamTombstone.__name__, "StreamTombstone")

    def test_unknown_state_export_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            getattr(state, "missing_state_helper")


if __name__ == "__main__":
    unittest.main()
