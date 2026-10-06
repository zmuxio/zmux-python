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
    TOMBSTONE_QUEUE_COMPACT_MIN_DEAD,
    build_stream_tombstone,
    coarsen_used_stream_ranges,
    should_compact_terminal,
    tombstone_late_data_action,
    tombstone_terminal_code,
    tombstone_terminal_kind,
    upsert_used_stream_range,
    used_stream_marker_for,
    used_stream_marker_from_tombstone,
)


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


class UsedStreamRangeClassTests(unittest.TestCase):
    """Used-stream ranges are partitioned by stream class (finding 43, D4)."""

    def test_interleaved_stream_classes_merge_within_each_class(self):
        graceful = marker()
        ranges = []
        for index in range(1, 2001):
            for stream_class in (0, 1, 2):
                upsert_used_stream_range(ranges, 4 * index + stream_class, graceful)

        self.assertEqual(
            [(r.start, r.end) for r in ranges],
            [(4, 8000), (5, 8001), (6, 8002)],
        )
        for index in range(1, 2001):
            for stream_class in (0, 1, 2):
                stream_id = 4 * index + stream_class
                self.assertEqual(
                    used_stream_marker_for(ranges, {}, stream_id),
                    (graceful, True),
                )
        self.assertEqual(used_stream_marker_for(ranges, {}, 7), (UsedStreamMarker(), False))
        self.assertEqual(used_stream_marker_for(ranges, {}, 8004), (UsedStreamMarker(), False))

    def test_range_of_another_class_inside_a_span_does_not_hide_ids(self):
        graceful = marker()
        abortive = marker(LateDataAction.IGNORE, LateDataCause.ABORT)
        ranges = []
        upsert_used_stream_range(ranges, 4, graceful)
        upsert_used_stream_range(ranges, 8, graceful)
        upsert_used_stream_range(ranges, 5, abortive)

        self.assertEqual(used_stream_marker_for(ranges, {}, 8), (graceful, True))
        self.assertEqual(used_stream_marker_for(ranges, {}, 4), (graceful, True))
        self.assertEqual(used_stream_marker_for(ranges, {}, 5), (abortive, True))
        self.assertEqual(used_stream_marker_for(ranges, {}, 9), (UsedStreamMarker(), False))

    def test_coarsening_folds_lowest_ranges_of_largest_classes(self):
        graceful = marker()
        abortive = marker(LateDataAction.IGNORE, LateDataCause.ABORT)
        ranges = []
        for index in range(1, 9):
            upsert_used_stream_range(
                ranges, 4 * index, graceful if index % 2 else abortive
            )
        upsert_used_stream_range(ranges, 5, graceful)
        floors = [None] * 4

        coarsen_used_stream_ranges(ranges, floors, 4)

        # Nine ranges (eight in class 0): the five lowest class-0 ranges fold.
        self.assertEqual(len(ranges), 4)
        self.assertEqual(floors, [20, None, None, None])
        self.assertEqual([r.start for r in ranges], [24, 28, 32, 5])


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
            0,
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

    def test_tombstone_limit_zero_retains_only_used_marker(self):
        state = TerminalBookkeepingState(tombstone_limit=0)

        removed = state.record_tombstone(
            4,
            tombstone_record(
                action=LateDataAction.ABORT_CLOSED,
                cause=LateDataCause.RESET,
            ),
        )

        self.assertEqual(removed, [4])
        self.assertFalse(state.tombstone_for(4).found())
        self.assertEqual(state.effective_tombstone_limit(), 0)
        self.assertEqual(state.tombstone_order_ids(), [])
        self.assertEqual(state.hidden_tombstone_order_ids(), [])
        self.assertEqual(
            state.terminal_data_disposition_for(4).disposition,
            disposition(LateDataAction.ABORT_CLOSED, LateDataCause.RESET),
        )
        self.assertEqual(state.marker_only_retained(), 1)

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

    def test_marker_budget_is_enforced_by_coarsening_without_losing_used_ids(self):
        state = TerminalBookkeepingState(tombstone_limit=4, marker_only_used_stream_limit=8)
        graceful = marker()
        abortive = marker(LateDataAction.ABORT_CLOSED, LateDataCause.RESET)
        count = 4 * 8 * 4
        for index in range(1, count + 1):
            for stream_id in (4 * index, 4 * index + 1):
                state.record_tombstone(
                    stream_id,
                    tombstone_record(
                        action=abortive.action if index % 2 else graceful.action,
                        cause=abortive.cause if index % 2 else graceful.cause,
                    ),
                )
                self.assertLessEqual(state.marker_only_retained(), 8)
                self.assertFalse(state.marker_only_limit_exceeded)

        for index in range(1, count + 1):
            for stream_id in (4 * index, 4 * index + 1):
                self.assertTrue(state.has_terminal_marker(stream_id), stream_id)
        # Never-used IDs stay unknown; coarsened ones are ignored.
        self.assertFalse(state.has_terminal_marker(4 * (count + 1)))
        self.assertFalse(state.has_terminal_marker(2))
        self.assertEqual(
            state.terminal_data_disposition_for(4).disposition,
            disposition(LateDataAction.IGNORE, LateDataCause.NONE),
        )
        # The newest reaped markers keep their exact disposition.
        newest_reaped = 4 * (count - 2)
        self.assertNotIn(newest_reaped, state.tombstones)
        self.assertEqual(
            state.terminal_data_disposition_for(newest_reaped).disposition,
            disposition(LateDataAction.ABORT_CLOSED, LateDataCause.RESET)
            if (count - 2) % 2
            else disposition(),
        )

    def test_forty_thousand_alternating_tombstones_keep_markers_bounded(self):
        state = TerminalBookkeepingState(tombstone_limit=64, marker_only_used_stream_limit=256)
        abortive = (LateDataAction.ABORT_CLOSED, LateDataCause.RESET)
        for index in range(1, 40_001):
            action, cause = abortive if index % 2 else (LateDataAction.IGNORE, LateDataCause.NONE)
            state.record_tombstone(4 * index, tombstone_record(action=action, cause=cause))
        self.assertLessEqual(len(state.used_stream_ranges), 256)
        self.assertLessEqual(len(state.used_stream_data), 64)
        self.assertEqual(state.tombstone_count_current(), 64)
        self.assertTrue(state.has_terminal_marker(4))
        self.assertTrue(state.has_terminal_marker(4 * 40_000))

    def test_marker_limit_zero_coarsens_every_reaped_marker(self):
        state = TerminalBookkeepingState(tombstone_limit=0, marker_only_used_stream_limit=0)
        for stream_id in (4, 8, 9, 13, 2):
            state.record_tombstone(stream_id, tombstone_record(cause=LateDataCause.RESET))
        self.assertEqual(state.marker_only_retained(), 0)
        for stream_id in (4, 8, 9, 13, 2):
            self.assertTrue(state.has_terminal_marker(stream_id))
        self.assertFalse(state.has_terminal_marker(12))
        self.assertFalse(state.has_terminal_marker(3))

    def test_marks_at_or_below_a_coarsened_floor_are_absorbed(self):
        state = TerminalBookkeepingState(tombstone_limit=0, marker_only_used_stream_limit=4)
        abortive = (LateDataAction.ABORT_CLOSED, LateDataCause.RESET)
        for index in range(2, 40):
            action, cause = abortive if index % 2 else (LateDataAction.IGNORE, LateDataCause.NONE)
            state.record_tombstone(4 * index, tombstone_record(action=action, cause=cause))
        self.assertGreater(state.used_stream_floors[0] or 0, 4)
        ranges = [(r.start, r.end, r.marker) for r in state.used_stream_ranges]

        # A long-lived stream below the floor that closes only now is already
        # covered by the coarsened prefix: it adds no range.
        state.record_tombstone(4, tombstone_record(action=abortive[0], cause=abortive[1]))
        self.assertEqual([(r.start, r.end, r.marker) for r in state.used_stream_ranges], ranges)
        self.assertEqual(state.terminal_data_disposition_for(4).disposition, disposition())

    def test_retained_tombstones_are_not_marker_only_state(self):
        state = TerminalBookkeepingState(tombstone_limit=128, marker_only_used_stream_limit=4)
        for index in range(1, 101):
            cause = LateDataCause.RESET if index % 2 else LateDataCause.NONE
            state.record_tombstone(4 * index, tombstone_record(cause=cause))

        # A retained tombstone classifies late frames itself; it becomes a
        # used-stream marker only once it is reaped, so marker bookkeeping
        # stays proportional to reaped IDs (finding 105).
        self.assertEqual(state.marker_only_retained(), 0)
        self.assertEqual(state.used_stream_data, {})
        self.assertEqual(state.used_stream_ranges, [])
        for index in range(1, 101):
            self.assertTrue(state.has_terminal_marker(4 * index))
        self.assertTrue(state.remove_tombstone(8))
        self.assertEqual(state.marker_only_retained(), 1)
        self.assertEqual(
            state.terminal_data_disposition_for(8).disposition,
            disposition(LateDataAction.IGNORE, LateDataCause.NONE),
        )

    def test_new_tombstones_are_appended_without_scanning_the_queue(self):
        class CountingList(list):
            reads = 0

            def __getitem__(self, index):
                self.reads += 1
                return list.__getitem__(self, index)

        state = TerminalBookkeepingState(tombstone_limit=4096)
        order = CountingList()
        state.tombstone_order = order
        for index in range(1, 2001):
            state.record_tombstone(4 * index, tombstone_record())

        self.assertIs(state.tombstone_order, order)
        self.assertEqual(state.tombstone_count_current(), 2000)
        # A new record has no queue index yet, so it is appended directly;
        # looking for it in the queue would read every live slot.
        self.assertLessEqual(order.reads, 2000)
        self.assertEqual(state.tombstone_head_id().stream_id, 4)
        self.assertEqual(state.tombstones[4 * 2000].order_index, 1999)

    def test_retained_late_data_follows_tombstone_lifetime(self):
        state = TerminalBookkeepingState(tombstone_limit=2)
        state.record_tombstone(4, tombstone_record(late_data_received=100))
        state.record_tombstone(8, tombstone_record(late_data_received=10))
        state.record_terminal_late_data(4, 5)
        self.assertEqual(state.late_data_retained, 115)
        # Late bytes on a marker-only ID are not retained by anything.
        state.record_terminal_late_data(12, 7)
        self.assertEqual(state.late_data_retained, 115)

        state.record_tombstone(12, tombstone_record(late_data_received=1))
        self.assertNotIn(4, state.tombstones)
        self.assertEqual(state.late_data_retained, 11)
        state.record_tombstone(8, tombstone_record(late_data_received=2))
        self.assertEqual(state.late_data_retained, 3)
        self.assertTrue(state.remove_tombstone(8))
        self.assertTrue(state.remove_tombstone(12))
        self.assertEqual(state.late_data_retained, 0)

        state.record_tombstone(16, tombstone_record(late_data_received=9))
        state.clear()
        self.assertEqual(state.late_data_retained, 0)
        self.assertEqual(state.used_stream_floors, [None] * 4)

    def test_reaping_at_the_limit_does_not_rewrite_the_queue_each_time(self):
        limit = 4096
        state = TerminalBookkeepingState(tombstone_limit=limit)
        for index in range(1, limit + 2):
            state.record_tombstone(4 * index, tombstone_record())

        # One reap moved the head; the queue was not rewritten for it.
        self.assertEqual(state.tombstone_count_current(), limit)
        self.assertEqual(state.tombstone_head, 1)
        self.assertEqual(len(state.tombstone_order), limit + 1)

        rewrites = 0
        order = state.tombstone_order
        extra = 5 * limit
        for index in range(limit + 2, limit + 2 + extra):
            state.record_tombstone(4 * index, tombstone_record())
            if state.tombstone_order is not order:
                rewrites += 1
                order = state.tombstone_order
            self.assertLessEqual(
                len(state.tombstone_order),
                2 * state.tombstone_count + TOMBSTONE_QUEUE_COMPACT_MIN_DEAD,
            )
        self.assertLessEqual(rewrites, extra // limit + 1)

        last = limit + 1 + extra
        oldest = last - limit + 1
        self.assertEqual(state.tombstone_head_id().stream_id, 4 * oldest)
        self.assertEqual(state.tombstone_order_ids(), [4 * i for i in range(oldest, last + 1)])
        for stream_id in (4 * oldest, 4 * (oldest + 7), 4 * last):
            record = state.tombstones[stream_id]
            self.assertEqual(state.tombstone_order[record.order_index], stream_id)

    def test_delayed_compaction_keeps_fifo_order_with_middle_removals(self):
        state = TerminalBookkeepingState(tombstone_limit=8, hidden_tombstone_limit=8)
        for index in range(1, 9):
            state.record_tombstone(
                4 * index,
                tombstone_record(hidden=index % 3 == 0, cause=LateDataCause.ABORT),
            )
        self.assertTrue(state.remove_tombstone(12))
        self.assertTrue(state.remove_tombstone(20))
        for index in range(9, 200):
            state.record_tombstone(
                4 * index,
                tombstone_record(hidden=index % 3 == 0, cause=LateDataCause.ABORT),
            )
            if index % 5 == 0:
                middle = state.tombstone_order_ids()[3]
                self.assertTrue(state.remove_tombstone(middle))
            ids = state.tombstone_order_ids()
            self.assertEqual(ids, sorted(ids))
            self.assertEqual(state.tombstone_head_id().stream_id, ids[0])
            for stream_id in ids:
                record = state.tombstones[stream_id]
                self.assertEqual(state.tombstone_order[record.order_index], stream_id)
                if record.hidden:
                    self.assertEqual(
                        state.hidden_tombstone_order[record.hidden_index],
                        stream_id,
                    )
            hidden_ids = state.hidden_tombstone_order_ids()
            self.assertEqual(hidden_ids, [i for i in ids if state.tombstones[i].hidden])

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
