import time
import unittest

from zmux._runtime import stream as runtime_stream
from zmux._runtime.read_loop import LateDataCause as RuntimeLateDataCause
from zmux._state.half import RecvHalfState, SendHalfState
from zmux._state.tombstone import (
    LateDataAction,
    LateDataCause,
    MAX_UINT64,
    StreamTombstone,
    TerminalBookkeepingState,
    TerminalKind,
    TerminalDataDisposition,
    TerminalLateDataResult,
    UsedStreamMarker,
    UsedStreamRange,
    StreamTombstoneRecord,
    build_stream_tombstone,
    should_compact_terminal,
    tombstone_late_data_action,
    tombstone_terminal_code,
    tombstone_terminal_kind,
    upsert_used_stream_range,
    used_stream_marker_for,
    used_stream_marker_from_tombstone,
)
from zmux.config import DEFAULT_TOMBSTONE_LIMIT, DEFAULT_USED_MARKER_LIMIT


def disposition(
        action=LateDataAction.IGNORE,
        cause=LateDataCause.NONE,
):
    return TerminalDataDisposition(action, cause)


def marker(
        action=LateDataAction.IGNORE,
        cause=LateDataCause.NONE,
):
    return UsedStreamMarker(action, cause)


def tombstone_record(
        hidden=False,
        action=LateDataAction.IGNORE,
        cause=LateDataCause.NONE,
        created_at=None,
        late_data_received=0,
        late_data_cap=None,
):
    return StreamTombstoneRecord(
        tombstone=StreamTombstone(
            data_action=action,
            terminal_kind=TerminalKind.UNKNOWN,
        ),
        hidden=hidden,
        created_at=time.monotonic() if created_at is None else created_at,
        late_data_cause=cause,
        late_data_received=late_data_received,
        late_data_cap=late_data_cap,
    )


class UsedStreamRangeTests(unittest.TestCase):
    def test_range_upsert_merges_by_stream_stride_and_splits_changed_marker(self):
        graceful = marker()
        abortive = marker(LateDataAction.ABORT_CLOSED, LateDataCause.ABORT)
        ranges = []

        for stream_id in (4, 8, 16, 12):
            upsert_used_stream_range(ranges, stream_id, graceful)

        self.assertEqual([(r.start, r.end, r.marker) for r in ranges], [(4, 16, graceful)])

        upsert_used_stream_range(ranges, 8, abortive)

        self.assertEqual(
            [(r.start, r.end, r.marker) for r in ranges],
            [
                (4, 4, graceful),
                (8, 8, abortive),
                (12, 16, graceful),
            ],
        )
        self.assertEqual(used_stream_marker_for(ranges, {}, 8), (abortive, True))
        self.assertEqual(used_stream_marker_for(ranges, {}, 20), (UsedStreamMarker(), False))

    def test_range_upsert_handles_uint64_tail_without_overflow(self):
        graceful = marker()
        ranges = []

        upsert_used_stream_range(ranges, MAX_UINT64 - 4, graceful)
        upsert_used_stream_range(ranges, MAX_UINT64, graceful)

        self.assertEqual(
            [(r.start, r.end, r.marker) for r in ranges],
            [(MAX_UINT64 - 4, MAX_UINT64, graceful)],
        )

    def test_range_mode_marker_update_drops_stale_map_entry(self):
        graceful = marker()
        abortive = marker(LateDataAction.ABORT_CLOSED, LateDataCause.ABORT)
        state = TerminalBookkeepingState()
        state.used_stream_range_mode = True
        state.used_stream_ranges.append(UsedStreamRange(4, 4 + 63 * 4, graceful))
        state.used_stream_data[4] = graceful

        state.mark_used_stream(4, abortive)

        self.assertFalse(state.used_stream_data)
        self.assertEqual(
            [(r.start, r.end, r.marker) for r in state.used_stream_ranges],
            [(4, 4, abortive), (8, 4 + 63 * 4, graceful)],
        )
        self.assertEqual(state.marker_only_retained(), 2)


class StreamTombstonePrimitiveTests(unittest.TestCase):
    def test_tombstone_enums_match_go_iota_values(self):
        self.assertEqual([action.value for action in LateDataAction], [1, 2, 3])
        self.assertEqual([kind.value for kind in TerminalKind], [0, 1, 2, 3])
        self.assertEqual([cause.value for cause in LateDataCause], [0, 1, 2, 3])
        self.assertIs(RuntimeLateDataCause, LateDataCause)

    def test_tombstone_late_data_action_matches_go_reference(self):
        self.assertEqual(
            tombstone_late_data_action(False, RecvHalfState.FIN),
            LateDataAction.IGNORE,
        )
        self.assertEqual(
            tombstone_late_data_action(True, RecvHalfState.FIN),
            LateDataAction.ABORT_CLOSED,
        )
        self.assertEqual(
            tombstone_late_data_action(True, RecvHalfState.RESET),
            LateDataAction.IGNORE,
        )
        self.assertEqual(
            tombstone_late_data_action(True, RecvHalfState.STOP_SENT),
            LateDataAction.IGNORE,
        )
        self.assertEqual(
            tombstone_late_data_action(True, RecvHalfState.ABORTED),
            LateDataAction.IGNORE,
        )

    def test_tombstone_kind_and_code_follow_terminal_error_priority(self):
        self.assertEqual(
            tombstone_terminal_kind(SendHalfState.ABORTED, RecvHalfState.RESET),
            TerminalKind.ABORTED,
        )
        self.assertEqual(
            tombstone_terminal_kind(SendHalfState.RESET, RecvHalfState.OPEN),
            TerminalKind.RESET,
        )
        self.assertEqual(
            tombstone_terminal_kind(SendHalfState.FIN, RecvHalfState.FIN),
            TerminalKind.GRACEFUL,
        )
        self.assertEqual(
            tombstone_terminal_kind(SendHalfState.OPEN, RecvHalfState.OPEN),
            TerminalKind.UNKNOWN,
        )

        self.assertEqual(
            tombstone_terminal_code(
                SendHalfState.ABORTED,
                RecvHalfState.RESET,
                send_reset_code=7,
                send_abort_code=9,
                recv_reset_code=11,
            ),
            (9, True),
        )
        self.assertEqual(
            tombstone_terminal_code(
                SendHalfState.OPEN,
                RecvHalfState.RESET,
                recv_reset_code=11,
            ),
            (11, True),
        )
        self.assertEqual(
            tombstone_terminal_code(SendHalfState.FIN, RecvHalfState.FIN),
            (0, False),
        )
        self.assertEqual(
            tombstone_terminal_code(
                SendHalfState.RESET,
                RecvHalfState.ABORTED,
                send_reset_code=7,
                recv_abort_code=13,
            ),
            (13, True),
        )
        self.assertEqual(
            tombstone_terminal_code(SendHalfState.RESET, RecvHalfState.OPEN),
            (0, False),
        )

    def test_build_tombstone_and_compaction_predicate_match_go_reference(self):
        tombstone = build_stream_tombstone(
            True,
            SendHalfState.RESET,
            RecvHalfState.ABORTED,
            send_reset_code=7,
            recv_abort_code=11,
        )
        self.assertEqual(
            tombstone,
            StreamTombstone(
                data_action=LateDataAction.IGNORE,
                terminal_kind=TerminalKind.ABORTED,
                has_terminal_code=True,
                terminal_code=11,
            ),
        )
        self.assertEqual(
            build_stream_tombstone(
                True, SendHalfState.FIN, RecvHalfState.FIN
            ).data_action,
            LateDataAction.ABORT_CLOSED,
        )

        self.assertFalse(should_compact_terminal(False, True, 0, 0, True))
        self.assertFalse(should_compact_terminal(True, False, 0, 0, True))
        self.assertFalse(should_compact_terminal(True, True, 1, 0, True))
        self.assertFalse(should_compact_terminal(True, True, 0, 1, True))
        self.assertFalse(should_compact_terminal(True, True, 0, 0, False))
        self.assertTrue(should_compact_terminal(True, True, 0, 0, True))

    def test_tombstone_primitives_reject_python_invalid_input_shapes(self):
        with self.assertRaises(TypeError):
            tombstone_late_data_action(1, RecvHalfState.FIN)
        with self.assertRaises(TypeError):
            should_compact_terminal(1, True, 0, 0, True)
        with self.assertRaises(ValueError):
            should_compact_terminal(True, True, -1, 0, True)
        with self.assertRaises(TypeError):
            StreamTombstone(data_action=True)
        with self.assertRaises(TypeError):
            StreamTombstone(has_terminal_code=1)
        with self.assertRaises(ValueError):
            StreamTombstone(terminal_code=MAX_UINT64 + 1)
        with self.assertRaises(TypeError):
            TerminalDataDisposition(action=True)
        with self.assertRaises(TypeError):
            UsedStreamMarker(cause=True)
        with self.assertRaises(ValueError):
            UsedStreamRange(8, 4)
        with self.assertRaises(TypeError):
            StreamTombstoneRecord(hidden=1)
        with self.assertRaises(TypeError):
            StreamTombstoneRecord().queue_index(1)
        with self.assertRaises(TypeError):
            StreamTombstoneRecord().set_queue_index(True, True)
        with self.assertRaises(TypeError):
            used_stream_marker_from_tombstone(StreamTombstone(), True)
        with self.assertRaises(TypeError):
            TerminalBookkeepingState(tombstone_limit=True)
        with self.assertRaises(ValueError):
            TerminalBookkeepingState(tombstone_limit=-1)
        with self.assertRaises(TypeError):
            TerminalBookkeepingState(marker_only_limit_exceeded=1)
        self.assertEqual(
            TerminalBookkeepingState(marker_only_used_stream_limit=0).marker_only_hard_cap(),
            DEFAULT_USED_MARKER_LIMIT,
        )

    def test_runtime_stream_reexports_state_tombstone_primitives(self):
        for name in (
                "LateDataAction",
                "TerminalKind",
                "TerminalLateDataResult",
                "StreamTombstone",
                "build_stream_tombstone",
                "should_compact_terminal",
                "tombstone_late_data_action",
                "tombstone_terminal_code",
                "tombstone_terminal_kind",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(runtime_stream, name), globals()[name])


class TerminalBookkeepingTests(unittest.TestCase):
    def test_marker_map_compacts_to_ranges_after_limit(self):
        state = TerminalBookkeepingState(marker_only_used_stream_limit=4)
        graceful = marker()

        for index in range(64):
            state.mark_used_stream(4 + index * 4, graceful)

        self.assertFalse(state.used_stream_data)
        self.assertTrue(state.used_stream_range_mode)
        self.assertEqual(
            [(r.start, r.end, r.marker) for r in state.used_stream_ranges],
            [(4, 256, graceful)],
        )
        self.assertEqual(state.marker_only_retained(), 1)
        self.assertFalse(state.marker_only_limit_exceeded)

    def test_tombstone_disposition_survives_reap_as_marker(self):
        state = TerminalBookkeepingState()
        state.record_tombstone(
            4,
            tombstone_record(
                action=LateDataAction.ABORT_CLOSED,
                cause=LateDataCause.RESET,
            ),
        )

        lookup = state.terminal_data_disposition_for(4)
        self.assertTrue(lookup.found())
        self.assertEqual(
            lookup.disposition,
            disposition(LateDataAction.ABORT_CLOSED, LateDataCause.RESET),
        )

        self.assertTrue(state.remove_tombstone(4))

        lookup = state.terminal_data_disposition_for(4)
        self.assertTrue(lookup.found())
        self.assertEqual(
            lookup.disposition,
            disposition(LateDataAction.ABORT_CLOSED, LateDataCause.RESET),
        )
        self.assertEqual(state.marker_only_retained(), 1)

    def test_tombstone_limit_zero_uses_go_default_retention_limit(self):
        state = TerminalBookkeepingState(tombstone_limit=0)

        removed = state.record_tombstone(
            4,
            tombstone_record(
                action=LateDataAction.ABORT_CLOSED,
                cause=LateDataCause.RESET,
            ),
        )

        self.assertEqual(removed, [])
        self.assertTrue(state.tombstone_for(4).found())
        self.assertEqual(state.effective_tombstone_limit(), DEFAULT_TOMBSTONE_LIMIT)
        self.assertEqual(state.tombstone_order_ids(), [4])
        self.assertEqual(state.hidden_tombstone_order_ids(), [])
        self.assertEqual(
            state.terminal_data_disposition_for(4).disposition,
            disposition(LateDataAction.ABORT_CLOSED, LateDataCause.RESET),
        )
        self.assertEqual(state.marker_only_retained(), 0)

    def test_terminal_late_data_counts_tombstone_budget_like_java(self):
        state = TerminalBookkeepingState()
        state.record_tombstone(
            4,
            tombstone_record(
                action=LateDataAction.ABORT_CLOSED,
                cause=LateDataCause.RESET,
                late_data_cap=1,
            ),
        )

        self.assertEqual(
            state.record_terminal_late_data(4, 1),
            TerminalLateDataResult(hidden=False, cap_exceeded=False),
        )
        self.assertEqual(state.tombstones[4].late_data_received, 1)
        self.assertEqual(
            state.record_terminal_late_data(4, 1),
            TerminalLateDataResult(hidden=False, cap_exceeded=True),
        )
        self.assertEqual(state.tombstones[4].late_data_received, 2)

    def test_terminal_late_data_result_reports_hidden_tombstones(self):
        state = TerminalBookkeepingState()
        state.record_tombstone(
            4,
            tombstone_record(hidden=True, cause=LateDataCause.ABORT),
            enforce=False,
        )

        self.assertEqual(
            state.record_terminal_late_data(4, 8),
            TerminalLateDataResult(hidden=True, cap_exceeded=False),
        )
        self.assertEqual(state.tombstones[4].late_data_received, 8)
        self.assertEqual(
            state.record_terminal_late_data(8, 8),
            TerminalLateDataResult(),
        )
        self.assertEqual(
            state.record_terminal_late_data(4, 0),
            TerminalLateDataResult(),
        )

    def test_retained_state_byte_estimates_saturate_like_go_uint64(self):
        state = TerminalBookkeepingState()
        state.hidden_tombstones_init = True
        state.hidden_tombstone_count_value = MAX_UINT64
        self.assertEqual(state.hidden_control_state_bytes(2), MAX_UINT64)

        state.hidden_tombstone_count_value = 0
        state.tombstones_init = True
        state.tombstone_count = MAX_UINT64
        self.assertEqual(state.retained_state_bytes(1, 2), MAX_UINT64)

    def test_tombstone_bookkeeping_rejects_invalid_runtime_shapes(self):
        state = TerminalBookkeepingState()
        with self.assertRaises(TypeError):
            state.record_tombstone(4, tombstone_record(), enforce=1)
        with self.assertRaises(TypeError):
            state.record_tombstone(4, tombstone_record(), now=True)
        with self.assertRaises(TypeError):
            state.mark_used_stream(4, object())
        with self.assertRaises(ValueError):
            state.hidden_control_state_bytes(-1)
        with self.assertRaises(TypeError):
            state.retained_state_bytes(retained_state_unit=True)
        with self.assertRaises(ValueError):
            state.reap_tombstones_for_memory_pressure(-1, 0)
        with self.assertRaises(TypeError):
            state.enforce_hidden_control_state_budget(session_memory_hard_cap=True)
        with self.assertRaises(TypeError):
            state.reap_expired_hidden_control_state(now=True)
        with self.assertRaises(TypeError):
            state.record_terminal_late_data(4, True)
        with self.assertRaises(TypeError):
            StreamTombstoneRecord(late_data_received=True)
        with self.assertRaises(ValueError):
            StreamTombstoneRecord(late_data_cap=-1)
        with self.assertRaises(TypeError):
            TerminalLateDataResult(cap_exceeded=1)

    def test_stream_id_zero_is_not_treated_as_queue_hole(self):
        state = TerminalBookkeepingState()
        state.record_tombstone(0, tombstone_record(cause=LateDataCause.RESET))

        self.assertEqual(state.tombstone_order_ids(), [0])
        self.assertTrue(state.remove_tombstone(0))
        self.assertEqual(state.tombstone_order_ids(), [])
        self.assertEqual(
            state.terminal_data_disposition_for(0).disposition,
            disposition(LateDataAction.IGNORE, LateDataCause.RESET),
        )

    def test_tombstone_replacement_cleans_hidden_order(self):
        state = TerminalBookkeepingState(hidden_tombstone_limit=16)
        state.record_tombstone(4, tombstone_record(hidden=True, cause=LateDataCause.ABORT))
        self.assertEqual(state.hidden_control_state_retained(), 1)
        self.assertEqual(state.hidden_tombstone_order_ids(), [4])

        state.record_tombstone(4, tombstone_record(hidden=False))

        self.assertEqual(state.hidden_control_state_retained(), 0)
        self.assertEqual(state.hidden_tombstone_order_ids(), [])
        self.assertTrue(state.tombstone_for(4).found())
        self.assertFalse(state.tombstone_for(4).tombstone.hidden)

    def test_expired_hidden_tombstone_releases_orders_and_preserves_marker(self):
        state = TerminalBookkeepingState(hidden_tombstone_limit=16)
        state.record_tombstone(4, tombstone_record(hidden=True, cause=LateDataCause.ABORT))
        state.tombstones[4].created_at = time.monotonic() - 2.0

        removed = state.reap_expired_hidden_control_state()

        self.assertEqual(removed, [4])
        self.assertFalse(state.tombstones)
        self.assertEqual(state.tombstone_order_ids(), [])
        self.assertEqual(state.hidden_tombstone_order_ids(), [])
        self.assertEqual(state.hidden_control_state_retained(), 0)
        self.assertEqual(
            state.terminal_data_disposition_for(4).disposition,
            disposition(LateDataAction.IGNORE, LateDataCause.ABORT),
        )

    def test_tracked_memory_pressure_reaps_oldest_visible_to_marker(self):
        state = TerminalBookkeepingState(tombstone_limit=16)
        state.record_tombstone(4, tombstone_record(), enforce=False)
        state.record_tombstone(8, tombstone_record(), enforce=False)
        state.tombstone_order.insert(0, 999)
        state.tombstones_init = False

        removed = state.reap_tombstones_for_memory_pressure(
            tracked_session_memory=128,
            session_memory_hard_cap=64,
            compact_terminal_state_unit=64,
        )

        self.assertEqual(removed, [4])
        self.assertNotIn(4, state.tombstones)
        self.assertIn(8, state.tombstones)
        self.assertEqual(state.tombstone_order_ids(), [8])
        self.assertTrue(state.terminal_data_disposition_for(4).found())
        self.assertEqual(state.marker_only_retained(), 1)

    def test_hidden_tombstone_hard_cap_sheds_newest_and_cleans_order(self):
        state = TerminalBookkeepingState(tombstone_limit=16, hidden_tombstone_limit=2)

        for stream_id in (4, 8, 12):
            state.record_tombstone(
                stream_id,
                tombstone_record(hidden=True, cause=LateDataCause.ABORT),
            )

        self.assertEqual(state.hidden_control_state_retained(), 2)
        self.assertIn(4, state.tombstones)
        self.assertIn(8, state.tombstones)
        self.assertNotIn(12, state.tombstones)
        self.assertEqual(state.hidden_tombstone_order_ids(), [4, 8])
        self.assertEqual(
            state.terminal_data_disposition_for(12).disposition,
            disposition(LateDataAction.IGNORE, LateDataCause.ABORT),
        )

    def test_visible_insert_drops_stale_hidden_tail_without_shedding_live_hidden(self):
        state = TerminalBookkeepingState(tombstone_limit=16, hidden_tombstone_limit=2)
        for stream_id in (4, 8):
            state.record_tombstone(
                stream_id,
                tombstone_record(hidden=True, cause=LateDataCause.ABORT),
            )
        state.hidden_tombstone_order.append(10_000)

        state.record_tombstone(12, tombstone_record(hidden=False))

        self.assertEqual(state.hidden_control_state_retained(), 2)
        self.assertTrue(state.tombstones[4].hidden)
        self.assertTrue(state.tombstones[8].hidden)
        self.assertFalse(state.tombstones[12].hidden)
        self.assertEqual(state.hidden_tombstone_order_ids(), [4, 8])

    def test_sparse_tombstone_queues_compact_amortized_like_go(self):
        state = TerminalBookkeepingState(tombstone_limit=16, hidden_tombstone_limit=16)
        for stream_id in (4, 8, 12):
            state.record_tombstone(
                stream_id,
                tombstone_record(hidden=True, cause=LateDataCause.ABORT),
                enforce=False,
            )

        self.assertTrue(state.remove_tombstone(8))

        self.assertEqual(state.tombstone_order, [4, None, 12])
        self.assertEqual(state.hidden_tombstone_order, [4, None, 12])
        self.assertEqual(state.tombstone_order_ids(), [4, 12])
        self.assertEqual(state.hidden_tombstone_order_ids(), [4, 12])
        self.assertEqual(state.tombstones[12].order_index, 2)
        self.assertEqual(state.tombstones[12].hidden_index, 2)

    def test_remove_hidden_tombstone_falls_back_from_stale_hidden_index(self):
        state = TerminalBookkeepingState(tombstone_limit=16, hidden_tombstone_limit=16)
        for stream_id in (4, 8, 12):
            state.record_tombstone(
                stream_id,
                tombstone_record(hidden=True, cause=LateDataCause.ABORT),
                enforce=False,
            )
        state.tombstones[8].hidden_index = 0

        state.remove_hidden_tombstone(8, state.tombstones[8])

        self.assertEqual(state.hidden_control_state_retained(), 2)
        self.assertEqual(state.hidden_tombstone_order, [4, None, 12])
        self.assertEqual(state.hidden_tombstone_order_ids(), [4, 12])
        self.assertEqual(state.tombstones[8].hidden_index, -1)


if __name__ == "__main__":
    unittest.main()
