import unittest

from zmux._runtime.flow import MAX_UINT64
from zmux._runtime.sched import (
    BATCH_SCRATCH_RETAIN_FACTOR,
    BATCH_SCRATCH_RETAIN_MIN_CAP,
    BULK_RESERVE_WINDOW,
    INTERACTIVE_BURST_LIMIT,
    FALLBACK_GROUP_BUCKET,
    MAX_EXPLICIT_GROUPS,
    MAX_SIGNED_INT64,
    BatchConfig,
    BatchItem,
    BatchState,
    BatchTiePrefs,
    BatchScheduler,
    GroupKey,
    RequestMeta,
    StreamMeta,
    TrafficClass,
    WFQGroupCandidate,
    WFQStreamCandidate,
    adjust_weight_for_lag,
    apply_lag_feedback,
    banded_weight,
    batch_scratch_oversized,
    batch_scratch_retain_limit,
    better_eligible_window,
    better_group_candidate,
    build_batch_groups,
    choose_traffic_class,
    class_adjusted_weight,
    class_bias_weight,
    classify_stream_class,
    clamp_lag,
    fair_share,
    feedback_window,
    group_lag,
    group_virtual_time,
    group_weight,
    is_fresh_group,
    is_fresh_stream,
    is_synthetic_stream_key,
    is_transient_group_key,
    maybe_rebase_wfq_state,
    normalize_cost,
    order_batch_indices,
    prepare_batch_scratch_for_build,
    priority_weight,
    release_idle_batch_state_storage,
    scheduler_quantum,
    service_tag,
    selected_list,
    set_group_virtual_time,
    set_group_lag,
    set_stream_finish_tag,
    set_stream_lag,
    should_apply_aging,
    scaled_class_tag,
    stream_lag,
    stream_finish_tag,
    stream_weight,
    transient_batch_state,
    update_bypass_selections,
)
from zmux.config import default_settings
from zmux.protocol import MAX_VARINT62, SchedulerHint


class RuntimeSchedulerPolicyTests(unittest.TestCase):
    def assert_empty_containers(self, owner, names):
        for name in names:
            value = getattr(owner, name)
            with self.subTest(name=name):
                self.assertEqual(value, type(value)())

    def test_weights_and_feedback_windows_follow_go_scheduler_policy(self):
        max_payload = 1024

        self.assertEqual(scheduler_quantum(0), default_settings().max_frame_payload)
        self.assertEqual(scheduler_quantum(max_payload), max_payload)

        self.assertEqual(priority_weight(0, SchedulerHint.LATENCY), 16)
        self.assertEqual(priority_weight(4, SchedulerHint.LATENCY), 32)
        self.assertEqual(priority_weight(32, SchedulerHint.LATENCY), 96)
        self.assertEqual(priority_weight(16, SchedulerHint.BULK_THROUGHPUT), 28)
        self.assertEqual(priority_weight(1, SchedulerHint.UNSPECIFIED_OR_BALANCED), 20)
        self.assertEqual(
            banded_weight(8, 1, 2, 3, 4, 5, 6),
            4,
        )

        self.assertEqual(
            stream_weight(0, max_payload, SchedulerHint.LATENCY, max_payload),
            64,
        )
        self.assertEqual(
            stream_weight(0, max_payload * 2, SchedulerHint.LATENCY, max_payload),
            32,
        )
        self.assertEqual(
            stream_weight(0, max_payload * 2 + 1, SchedulerHint.LATENCY, max_payload),
            16,
        )
        self.assertEqual(
            stream_weight(0, max_payload, SchedulerHint.UNSPECIFIED_OR_BALANCED, max_payload),
            32,
        )
        self.assertEqual(
            stream_weight(0, max_payload // 2, SchedulerHint.BULK_THROUGHPUT, max_payload),
            24,
        )

        self.assertEqual(feedback_window(SchedulerHint.LATENCY, max_payload), max_payload * 6)
        self.assertEqual(
            feedback_window(SchedulerHint.BULK_THROUGHPUT, max_payload),
            max_payload * 2,
        )
        self.assertEqual(
            feedback_window(SchedulerHint.UNSPECIFIED_OR_BALANCED, max_payload),
            max_payload * 4,
        )
        self.assertEqual(feedback_window(SchedulerHint.LATENCY, MAX_UINT64), MAX_SIGNED_INT64)

    def test_lag_and_service_tag_math_clamps_without_wrapping(self):
        self.assertEqual(normalize_cost(0), 1)
        self.assertEqual(normalize_cost(-10), 1)
        self.assertEqual(service_tag(0, 0), 256)
        self.assertEqual(service_tag(1024, 64), 4096)

        self.assertEqual(adjust_weight_for_lag(16, 0, 100, True), 24)
        self.assertEqual(adjust_weight_for_lag(16, 100, 100, False), 32)
        self.assertEqual(adjust_weight_for_lag(16, -100, 100, False), 8)
        self.assertEqual(adjust_weight_for_lag(0, 0, 0, False), 1)
        self.assertGreaterEqual(
            adjust_weight_for_lag(MAX_UINT64, MAX_SIGNED_INT64, MAX_SIGNED_INT64, False),
            1,
        )
        self.assertGreaterEqual(
            adjust_weight_for_lag(10, -MAX_SIGNED_INT64 - 1, MAX_SIGNED_INT64, False),
            1,
        )

    def test_lag_feedback_math_and_fresh_state_checks_match_go(self):
        state = BatchScheduler().state
        stream_id = 9
        group = GroupKey.explicit(3)
        synthetic = (1 << 63) | 2

        self.assertEqual(fair_share(100, 2, 5), 40)
        self.assertEqual(fair_share(-1, 2, 5), 0)
        self.assertEqual(fair_share(100, 0, 5), 0)
        self.assertEqual(fair_share(100, 2, 0), 0)
        self.assertEqual(fair_share(MAX_SIGNED_INT64, MAX_UINT64, 1), MAX_SIGNED_INT64)

        self.assertEqual(clamp_lag(999, 10), 20)
        self.assertEqual(clamp_lag(-999, 10), -20)
        self.assertEqual(clamp_lag(123, 0), 0)
        self.assertEqual(clamp_lag(MAX_SIGNED_INT64, MAX_SIGNED_INT64), MAX_SIGNED_INT64)
        self.assertEqual(
            clamp_lag(-MAX_SIGNED_INT64, MAX_SIGNED_INT64),
            -MAX_SIGNED_INT64,
        )
        self.assertEqual(apply_lag_feedback(0, 10, 4, 10), 6)
        self.assertEqual(apply_lag_feedback(0, 4, 10, 10), -6)
        self.assertEqual(apply_lag_feedback(1, 1, 1, 0), 0)
        self.assertEqual(apply_lag_feedback(MAX_SIGNED_INT64, 10, 0, 10), 20)
        self.assertEqual(apply_lag_feedback(-MAX_SIGNED_INT64, 0, 10, 10), -20)

        self.assertTrue(is_fresh_stream(state, stream_id))
        self.assertFalse(is_fresh_stream(state, synthetic))
        set_stream_lag(state, stream_id, 5)
        set_stream_lag(state, synthetic, 99)
        self.assertEqual(stream_lag(state, stream_id), 5)
        self.assertEqual(stream_lag(state, synthetic), 0)
        self.assertFalse(is_fresh_stream(state, stream_id))
        self.assertEqual(stream_lag(None, stream_id), 0)
        set_stream_lag(None, stream_id, 1)

        fresh_state = BatchState()
        fresh_state.stream_finish_tag[stream_id] = 1
        self.assertFalse(is_fresh_stream(fresh_state, stream_id))
        fresh_state = BatchState()
        fresh_state.stream_last_service[stream_id] = 1
        self.assertFalse(is_fresh_stream(fresh_state, stream_id))

        self.assertTrue(is_fresh_group(state, group))
        self.assertFalse(is_fresh_group(state, GroupKey.transient(1)))
        set_group_lag(state, group, -7)
        set_group_lag(state, GroupKey.transient(1), 99)
        self.assertEqual(group_lag(state, group), -7)
        self.assertEqual(group_lag(state, GroupKey.transient(1)), 0)
        self.assertFalse(is_fresh_group(state, group))
        self.assertEqual(group_lag(None, group), 0)
        set_group_lag(None, group, 1)

        fresh_state = BatchState()
        fresh_state.group_finish_tag[group] = 1
        self.assertFalse(is_fresh_group(fresh_state, group))
        fresh_state = BatchState()
        fresh_state.group_last_service[group] = 1
        self.assertFalse(is_fresh_group(fresh_state, group))
        self.assertTrue(is_synthetic_stream_key(synthetic))
        self.assertTrue(is_transient_group_key(GroupKey.transient(2)))

    def test_group_weight_and_explicit_group_tracking(self):
        stream_group = GroupKey.stream(4)
        explicit_group = GroupKey.explicit(7)

        self.assertEqual(group_weight(stream_group, 96, SchedulerHint.LATENCY), 96)
        self.assertEqual(group_weight(stream_group, 0, SchedulerHint.LATENCY), 1)
        self.assertEqual(group_weight(explicit_group, 96, SchedulerHint.LATENCY), 32)
        self.assertEqual(group_weight(explicit_group, 96, SchedulerHint.BULK_THROUGHPUT), 16)
        self.assertEqual(
            group_weight(explicit_group, 96, SchedulerHint.UNSPECIFIED_OR_BALANCED),
            24,
        )

        scheduler = BatchScheduler()
        for group_id in range(1, MAX_EXPLICIT_GROUPS + 1):
            scheduler.track_explicit_group(group_id)
        self.assertEqual(scheduler.tracked_explicit_group_count(), MAX_EXPLICIT_GROUPS)
        self.assertEqual(
            scheduler.group_key_for_stream(99, 777, True),
            GroupKey.explicit(FALLBACK_GROUP_BUCKET),
        )
        self.assertEqual(scheduler.tracked_explicit_group_count(), MAX_EXPLICIT_GROUPS)

    def test_tracked_explicit_group_count_ignores_zero_and_fallback(self):
        scheduler = BatchScheduler()
        scheduler.active_group_refs[0] = 1
        scheduler.active_group_refs[7] = 2
        scheduler.active_group_refs[9] = 1
        scheduler.active_group_refs[FALLBACK_GROUP_BUCKET] = 3

        self.assertEqual(scheduler.tracked_explicit_group_count(), 2)

    def test_untrack_group_and_drop_stream_prune_retained_state(self):
        scheduler = BatchScheduler()
        state = scheduler.state
        explicit = GroupKey.explicit(7)
        stream_group = GroupKey.stream(5)

        self.assertEqual(scheduler.group_key_for_stream(5, 7, True), explicit)
        state.group_virtual_time[explicit] = 1
        state.group_finish_tag[explicit] = 2
        state.group_last_service[explicit] = 3
        state.group_lag[explicit] = 4
        state.preferred_stream_head[explicit] = 5
        state.preferred_group_head = explicit
        state.has_preferred_group_head = True
        state.stream_finish_tag[5] = 6
        state.stream_last_service[5] = 7
        state.stream_lag[5] = 8
        state.stream_class[5] = TrafficClass.INTERACTIVE
        state.stream_last_seen_batch[5] = 9
        state.small_burst_disarmed[5] = None
        state.group_finish_tag[stream_group] = 10

        scheduler.untrack_explicit_group(7)

        self.assertNotIn(7, scheduler.active_group_refs)
        self.assertNotIn(explicit, state.group_virtual_time)
        self.assertNotIn(explicit, state.group_finish_tag)
        self.assertNotIn(explicit, state.group_last_service)
        self.assertNotIn(explicit, state.group_lag)
        self.assertNotIn(explicit, state.preferred_stream_head)
        self.assertFalse(state.has_preferred_group_head)
        self.assertIn(5, state.stream_finish_tag)

        scheduler.drop_stream(5)

        self.assertEqual(scheduler.stream_groups, {})
        self.assertNotIn(5, state.stream_finish_tag)
        self.assertNotIn(5, state.stream_last_service)
        self.assertNotIn(5, state.stream_lag)
        self.assertNotIn(5, state.stream_class)
        self.assertNotIn(5, state.stream_last_seen_batch)
        self.assertNotIn(5, state.small_burst_disarmed)
        self.assertNotIn(stream_group, state.group_finish_tag)

    def test_scheduler_clear_resets_ownership_and_state(self):
        scheduler = BatchScheduler()
        scheduler.state.root_virtual_time = 17
        scheduler.state.service_seq = 4
        scheduler.state.stream_finish_tag[4] = 1
        scheduler.active_group_refs[7] = 1
        scheduler.group_key_for_stream(4, 7, True)

        scheduler.clear()

        self.assertEqual(scheduler.active_group_refs, {})
        self.assertEqual(scheduler.stream_groups, {})
        self.assertEqual(scheduler.state.root_virtual_time, 0)
        self.assertEqual(scheduler.state.service_seq, 0)
        self.assertEqual(scheduler.state.stream_finish_tag, {})

    def test_explicit_group_refs_do_not_wrap_at_uint32_boundary(self):
        scheduler = BatchScheduler()
        scheduler.active_group_refs[7] = (1 << 32) - 1

        scheduler.track_explicit_group(7)

        self.assertEqual(scheduler.active_group_refs[7], 1 << 32)
        scheduler.untrack_explicit_group(7)
        self.assertEqual(scheduler.active_group_refs[7], (1 << 32) - 1)

    def test_stream_group_binding_preserves_fallback_bucket_on_same_group(self):
        scheduler = BatchScheduler()
        for stream_id in range(1, MAX_EXPLICIT_GROUPS + 1):
            self.assertEqual(
                scheduler.group_key_for_stream(stream_id, stream_id, True),
                GroupKey.explicit(stream_id),
            )
        fallback = GroupKey.explicit(FALLBACK_GROUP_BUCKET)
        self.assertEqual(scheduler.group_key_for_stream(99, 99, True), fallback)
        scheduler.state.group_virtual_time[fallback] = 11

        self.assertEqual(scheduler.group_key_for_stream(99, 99, True), fallback)

        self.assertEqual(scheduler.active_group_refs[FALLBACK_GROUP_BUCKET], 1)
        self.assertEqual(scheduler.stream_groups[99].group, 99)
        self.assertEqual(scheduler.stream_groups[99].bucket, FALLBACK_GROUP_BUCKET)
        self.assertEqual(scheduler.state.group_virtual_time[fallback], 11)

        scheduler.drop_stream(1)
        self.assertEqual(
            scheduler.group_key_for_stream(100, 100, True),
            GroupKey.explicit(100),
        )

    def test_group_change_drops_last_departure_state_only_after_ref_released(self):
        scheduler = BatchScheduler()
        old_group = GroupKey.explicit(7)
        new_group = GroupKey.explicit(9)
        self.assertEqual(scheduler.group_key_for_stream(4, 7, True), old_group)
        self.assertEqual(scheduler.group_key_for_stream(8, 7, True), old_group)
        scheduler.state.group_virtual_time[old_group] = 11
        scheduler.state.group_virtual_time[new_group] = 13

        self.assertEqual(scheduler.group_key_for_stream(4, 9, True), new_group)

        self.assertEqual(scheduler.active_group_refs[7], 1)
        self.assertEqual(scheduler.active_group_refs[9], 1)
        self.assertIn(old_group, scheduler.state.group_virtual_time)
        self.assertEqual(scheduler.stream_groups[8].bucket, 7)

        self.assertEqual(scheduler.group_key_for_stream(8, 9, True), new_group)

        self.assertNotIn(7, scheduler.active_group_refs)
        self.assertEqual(scheduler.active_group_refs[9], 2)
        self.assertNotIn(old_group, scheduler.state.group_virtual_time)
        self.assertIn(new_group, scheduler.state.group_virtual_time)

    def test_group_reset_to_zero_releases_tracking_and_retained_group_state(self):
        scheduler = BatchScheduler()
        group = GroupKey.explicit(7)
        self.assertEqual(scheduler.group_key_for_stream(4, 7, True), group)
        scheduler.state.group_virtual_time[group] = 11

        self.assertEqual(
            scheduler.group_key_for_stream(4, 0, True),
            GroupKey.stream(4),
        )

        self.assertNotIn(7, scheduler.active_group_refs)
        self.assertNotIn(4, scheduler.stream_groups)
        self.assertNotIn(group, scheduler.state.group_virtual_time)

    def test_drop_stream_removes_retained_stream_and_explicit_group_state(self):
        scheduler = BatchScheduler()
        group = GroupKey.explicit(7)
        self.assertEqual(scheduler.group_key_for_stream(4, 7, True), group)
        scheduler.state.stream_finish_tag[4] = 1
        scheduler.state.stream_last_service[4] = 2
        scheduler.state.stream_lag[4] = 3
        scheduler.state.stream_class[4] = TrafficClass.INTERACTIVE
        scheduler.state.group_virtual_time[group] = 4
        scheduler.state.group_finish_tag[group] = 5
        scheduler.state.group_last_service[group] = 6
        scheduler.state.group_lag[group] = 7
        scheduler.state.preferred_stream_head[group] = 4

        scheduler.drop_stream(4)

        self.assertNotIn(7, scheduler.active_group_refs)
        self.assertNotIn(4, scheduler.stream_groups)
        self.assertNotIn(4, scheduler.state.stream_finish_tag)
        self.assertNotIn(4, scheduler.state.stream_last_service)
        self.assertNotIn(4, scheduler.state.stream_lag)
        self.assertNotIn(4, scheduler.state.stream_class)
        self.assertNotIn(group, scheduler.state.group_virtual_time)
        self.assertNotIn(group, scheduler.state.group_finish_tag)
        self.assertNotIn(group, scheduler.state.group_last_service)
        self.assertNotIn(group, scheduler.state.group_lag)
        self.assertNotIn(group, scheduler.state.preferred_stream_head)

    def test_dropped_last_stream_releases_idle_scheduler_state(self):
        scheduler = BatchScheduler()
        items = [self._batch_item(4), self._batch_item(8)]

        order = scheduler.order(BatchConfig(max_frame_payload=16_384), items)
        self.assertEqual(len(order), len(items))
        self.assertGreater(scheduler.state.root_virtual_time, 0)

        scheduler.drop_stream(4)
        scheduler.drop_stream(8)

        self.assertEqual(scheduler.state.root_virtual_time, 0)
        self.assertEqual(scheduler.state.service_seq, 0)
        self.assert_empty_containers(
            scheduler.state,
            (
                "group_virtual_time",
                "group_finish_tag",
                "group_last_service",
                "group_lag",
                "stream_finish_tag",
                "stream_last_service",
                "stream_lag",
                "stream_class",
                "stream_last_seen_batch",
                "small_burst_disarmed",
            ),
        )
        self.assertFalse(scheduler.state.has_preferred_group_head)
        self.assertEqual(scheduler.state.preferred_stream_head, {})
        self.assertEqual(scheduler.state.scratch.groups, [])
        self.assertEqual(scheduler.state.scratch.prepared_streams, {})
        self.assertEqual(scheduler.state.scratch.selected, [])

    def test_stream_classification_matches_reference_thresholds(self):
        quantum = 100

        self.assertIs(
            classify_stream_class(
                100,
                0,
                SchedulerHint.UNSPECIFIED_OR_BALANCED,
                interactive_quantum=quantum,
            ),
            TrafficClass.INTERACTIVE,
        )
        self.assertIs(
            classify_stream_class(
                201,
                0,
                SchedulerHint.UNSPECIFIED_OR_BALANCED,
                interactive_quantum=quantum,
            ),
            TrafficClass.BULK,
        )
        self.assertIs(
            classify_stream_class(
                150,
                0,
                SchedulerHint.UNSPECIFIED_OR_BALANCED,
                previous=TrafficClass.BULK,
                interactive_quantum=quantum,
            ),
            TrafficClass.BULK,
        )
        self.assertIs(
            classify_stream_class(
                150,
                0,
                SchedulerHint.BULK_THROUGHPUT,
                interactive_quantum=quantum,
            ),
            TrafficClass.BULK,
        )
        self.assertIs(
            classify_stream_class(150, 0, SchedulerHint.LATENCY, interactive_quantum=quantum),
            TrafficClass.INTERACTIVE,
        )
        self.assertIs(
            classify_stream_class(
                150,
                4,
                SchedulerHint.UNSPECIFIED_OR_BALANCED,
                interactive_quantum=quantum,
            ),
            TrafficClass.INTERACTIVE,
        )
        self.assertIs(
            classify_stream_class(
                150,
                0,
                SchedulerHint.UNSPECIFIED_OR_BALANCED,
                interactive_quantum=quantum,
            ),
            TrafficClass.BULK,
        )
        self.assertIs(
            classify_stream_class(
                150,
                2,
                SchedulerHint.UNSPECIFIED_OR_BALANCED,
                interactive_quantum=quantum,
            ),
            TrafficClass.INTERACTIVE,
        )

    def test_class_candidate_bias_and_bulk_reservation_policy(self):
        prefs = BatchTiePrefs(True, GroupKey.explicit(7))
        interactive = self._candidate(
            GroupKey.explicit(7),
            TrafficClass.INTERACTIVE,
            start=100,
            finish=100,
            stream_id=11,
            stream_finish=100,
            eligible=True,
        )
        bulk = self._candidate(
            GroupKey.explicit(9),
            TrafficClass.BULK,
            start=50,
            finish=50,
            stream_id=22,
            stream_finish=50,
            eligible=True,
        )

        self.assertIs(
            choose_traffic_class(prefs, SchedulerHint.LATENCY, None, bulk, 0, 0),
            TrafficClass.BULK,
        )
        self.assertIs(
            choose_traffic_class(prefs, SchedulerHint.LATENCY, interactive, None, 0, 0),
            TrafficClass.INTERACTIVE,
        )
        self.assertIs(
            choose_traffic_class(
                prefs,
                SchedulerHint.LATENCY,
                interactive,
                bulk,
                INTERACTIVE_BURST_LIMIT,
                0,
            ),
            TrafficClass.BULK,
        )
        self.assertIs(
            choose_traffic_class(
                prefs,
                SchedulerHint.LATENCY,
                interactive,
                bulk,
                0,
                BULK_RESERVE_WINDOW - 1,
            ),
            TrafficClass.BULK,
        )
        self.assertIs(
            choose_traffic_class(prefs, SchedulerHint.LATENCY, interactive, bulk, 0, 0),
            TrafficClass.INTERACTIVE,
        )

        self.assertEqual(class_bias_weight(TrafficClass.INTERACTIVE, SchedulerHint.LATENCY), 8)
        self.assertEqual(class_bias_weight(TrafficClass.BULK, SchedulerHint.LATENCY), 2)
        self.assertEqual(
            class_bias_weight(TrafficClass.INTERACTIVE, SchedulerHint.BULK_THROUGHPUT),
            2,
        )
        self.assertEqual(class_bias_weight(TrafficClass.BULK, SchedulerHint.BULK_THROUGHPUT), 8)
        self.assertEqual(
            class_bias_weight(TrafficClass.INTERACTIVE, SchedulerHint.UNSPECIFIED_OR_BALANCED),
            6,
        )
        self.assertEqual(scaled_class_tag(interactive, SchedulerHint.LATENCY, 80), 80)
        self.assertEqual(scaled_class_tag(bulk, SchedulerHint.LATENCY, 80), 320)

    def test_order_batch_indices_reserves_bulk_within_four_selections(self):
        state = BatchState()
        items = [
            self._batch_item(4, cost=64),
            self._batch_item(4, cost=64),
            self._batch_item(4, cost=64),
            self._batch_item(4, cost=64),
            self._batch_item(8, cost=900),
            self._batch_item(8, cost=900),
            self._batch_item(8, cost=900),
            self._batch_item(8, cost=900),
        ]

        order = order_batch_indices(
            BatchConfig(
                scheduler_hint=SchedulerHint.LATENCY,
                max_frame_payload=1024,
            ),
            state,
            items,
        )

        self.assertIn(8, self._stream_ids(items, order[:4]))

    def test_retained_class_hysteresis_keeps_mid_queue_bulk_across_batches(self):
        state = BatchState()
        cfg = BatchConfig(
            scheduler_hint=SchedulerHint.BULK_THROUGHPUT,
            max_frame_payload=1024,
        )
        first = [
            self._batch_item(8, cost=64),
            self._batch_item(4, cost=900),
            self._batch_item(4, cost=900),
            self._batch_item(4, cost=900),
        ]
        second = [
            self._batch_item(4, cost=768),
            self._batch_item(4, cost=768),
            self._batch_item(8, cost=64),
        ]

        first_order = order_batch_indices(cfg, state, first)
        self.assertEqual(len(first_order), len(first))
        self.assertIs(state.stream_class[4], TrafficClass.BULK)

        second_order = order_batch_indices(cfg, state, second)

        self.assertEqual(len(second_order), len(second))
        self.assertIs(state.stream_class[4], TrafficClass.BULK)
        self.assertIs(state.stream_class[8], TrafficClass.INTERACTIVE)

    def test_group_tiebreaks_aging_and_class_adjusted_weight(self):
        group = GroupKey.explicit(3)
        preferred = self._candidate(
            group,
            TrafficClass.INTERACTIVE,
            start=10,
            finish=20,
            stream_id=3,
            stream_finish=30,
            eligible=True,
            group_order=2,
        )
        other = self._candidate(
            GroupKey.explicit(4),
            TrafficClass.INTERACTIVE,
            start=10,
            finish=20,
            stream_id=4,
            stream_finish=30,
            eligible=True,
            group_order=1,
        )
        prefs = BatchTiePrefs(True, group)

        self.assertIsNone(better_eligible_window(True, 1, 2, 1, 2))
        self.assertFalse(better_eligible_window(False, 3, 4, 2, 4))
        self.assertTrue(better_group_candidate(prefs, preferred, other))
        self.assertTrue(should_apply_aging(3, 2, {3: 4}))
        self.assertFalse(should_apply_aging(3, 1, {3: 99}))
        self.assertEqual(class_adjusted_weight(10, 20, 50, True, 100, True), 45)
        self.assertEqual(class_adjusted_weight(10, 0, 101, True, 100, False), 1)

    def test_bypass_selection_counters_ignore_synthetic_stream_keys(self):
        synthetic = (1 << 63) | 3
        bypass_selections = {7: MAX_UINT64}

        update_bypass_selections([7, 9, synthetic], 9, bypass_selections)

        self.assertEqual(bypass_selections[7], MAX_UINT64)
        self.assertEqual(bypass_selections[9], 0)
        self.assertNotIn(synthetic, bypass_selections)

    def test_scheduler_boundary_validation_rejects_ambiguous_python_values(self):
        group = GroupKey.explicit(7)

        with self.assertRaises(ValueError):
            GroupKey(3, 0)
        with self.assertRaises(TypeError):
            RequestMeta(stream_scoped=1)
        with self.assertRaises(TypeError):
            RequestMeta(is_priority_update=1)
        with self.assertRaises(TypeError):
            RequestMeta(opening_frame=1)
        with self.assertRaises(ValueError):
            StreamMeta(priority=MAX_VARINT62 + 1)
        with self.assertRaises(ValueError):
            StreamMeta(group=MAX_VARINT62 + 1)
        with self.assertRaises(TypeError):
            BatchConfig(urgent=1)
        with self.assertRaises(TypeError):
            BatchConfig(group_fair=1)
        with self.assertRaises(TypeError):
            BatchTiePrefs(1, group)
        with self.assertRaises(TypeError):
            WFQStreamCandidate(eligible=1)
        with self.assertRaises(TypeError):
            WFQStreamCandidate(is_priority_update=1)
        with self.assertRaises(TypeError):
            WFQGroupCandidate(eligible=1)
        with self.assertRaises(TypeError):
            better_eligible_window(1, 1, 2, 1, 2)
        with self.assertRaises(TypeError):
            class_adjusted_weight(10, 20, 50, 1, 100, False)
        with self.assertRaises(ValueError):
            BatchScheduler().group_key_for_stream(4, MAX_VARINT62 + 1, True)

    def test_order_batch_indices_rotates_flat_batch_head_across_batches(self):
        state = BatchState()
        items = [self._batch_item(4), self._batch_item(8)]
        cfg = BatchConfig(max_frame_payload=16_384)

        first = order_batch_indices(cfg, state, items)
        second = order_batch_indices(cfg, state, items)

        self.assertEqual(self._stream_ids(items, first), [4, 8])
        self.assertEqual(self._stream_ids(items, second), [8, 4])
        self.assertEqual(state.service_seq, 4)
        self.assertTrue(state.has_preferred_group_head)

    def test_session_scoped_head_does_not_consume_retained_flat_head(self):
        state = BatchState()
        cfg = BatchConfig(max_frame_payload=16_384)
        seed = [self._batch_item(4), self._batch_item(8)]
        order_batch_indices(cfg, state, seed)
        mixed = [
            BatchItem(RequestMeta(group_key=GroupKey.transient(0), cost=1)),
            self._batch_item(4),
            self._batch_item(8),
        ]

        order = order_batch_indices(cfg, state, mixed)

        self.assertEqual(order, (0, 2, 1))

    def test_order_urgent_batch_sorts_rank_then_stream_scope_and_id(self):
        items = [
            self._batch_item(8, urgency_rank=2),
            BatchItem(RequestMeta(urgency_rank=2, stream_scoped=False, cost=1)),
            self._batch_item(4, urgency_rank=2),
            self._batch_item(12, urgency_rank=1),
            BatchItem(RequestMeta(urgency_rank=3, stream_scoped=False, cost=1)),
            BatchItem(RequestMeta(urgency_rank=3, stream_scoped=True, cost=1)),
        ]

        order = order_batch_indices(BatchConfig(urgent=True), BatchState(), items)

        self.assertEqual(order, (3, 2, 0, 1, 5, 4))

    def test_urgent_opening_frame_precedes_same_stream_terminal_rank(self):
        items = [
            self._batch_item(5, urgency_rank=2),
            self._batch_item(5, urgency_rank=9, opening_frame=True),
            self._batch_item(3, urgency_rank=1),
        ]

        order = order_batch_indices(BatchConfig(urgent=True), BatchState(), items)

        self.assertEqual(order, (2, 1, 0))

    def test_session_scoped_only_batch_releases_idle_scheduler_state(self):
        state = BatchState()
        items = [
            BatchItem(RequestMeta(group_key=GroupKey.transient(0), cost=1)),
            BatchItem(RequestMeta(group_key=GroupKey.transient(1), cost=2)),
        ]

        order = order_batch_indices(
            BatchConfig(group_fair=True, max_frame_payload=16_384),
            state,
            items,
        )

        self.assertEqual(order, (0, 1))
        self.assertEqual(state.root_virtual_time, 0)
        self.assertEqual(state.service_seq, 0)
        self.assertEqual(state.stream_finish_tag, {})
        self.assertEqual(state.stream_last_service, {})
        self.assertEqual(state.stream_lag, {})
        self.assertEqual(state.group_virtual_time, {})
        self.assertEqual(state.group_finish_tag, {})
        self.assertEqual(state.group_last_service, {})
        self.assertEqual(state.group_lag, {})
        self.assertEqual(state.preferred_stream_head, {})
        self.assertEqual(state.scratch.group_state, {})
        self.assertEqual(state.scratch.ordered, [])

    def test_session_scoped_only_batch_preserves_retained_wfq_state(self):
        state = BatchState(root_virtual_time=77, service_seq=9)
        group = GroupKey.stream(4)
        state.group_virtual_time[group] = 21
        state.group_finish_tag[group] = 33
        state.group_last_service[group] = 5
        state.stream_finish_tag[4] = 21
        state.stream_last_service[4] = 5
        items = [
            BatchItem(RequestMeta(group_key=GroupKey.transient(0), cost=1)),
            BatchItem(RequestMeta(group_key=GroupKey.transient(1), cost=2)),
        ]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(order, (0, 1))
        self.assertEqual(state.root_virtual_time, 77)
        self.assertEqual(state.service_seq, 9)
        self.assertEqual(state.group_virtual_time[group], 21)
        self.assertEqual(state.group_finish_tag[group], 33)
        self.assertEqual(state.group_last_service[group], 5)
        self.assertEqual(state.stream_finish_tag[4], 21)
        self.assertEqual(state.stream_last_service[4], 5)

    def test_equal_streams_interleave_within_batch(self):
        state = BatchState()
        items = [self._batch_item(4), self._batch_item(4), self._batch_item(8)]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(self._stream_ids(items, order), [4, 8, 4])

    def test_order_batch_indices_advances_virtual_times_by_active_weight(self):
        state = BatchState()
        items = [self._batch_item(4), self._batch_item(8)]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(self._stream_ids(items, order), [4, 8])
        self.assertEqual(state.root_virtual_time, 11)
        self.assertEqual(state.service_seq, 2)

        group = GroupKey.explicit(7)
        state = BatchState()
        grouped = [self._batch_item(4, group_key=group), self._batch_item(8, group_key=group)]

        order = order_batch_indices(
            BatchConfig(group_fair=True, max_frame_payload=16_384),
            state,
            grouped,
        )

        self.assertEqual(self._stream_ids(grouped, order), [4, 8])
        self.assertEqual(state.root_virtual_time, 19)
        self.assertEqual(state.group_virtual_time[group], 6)

    def test_feedback_fresh_peer_beats_stale_preferred_head(self):
        state = BatchState()
        group = GroupKey.stream(4)
        state.group_virtual_time[group] = 0
        state.group_finish_tag[group] = 0
        state.group_last_service[group] = 1
        state.stream_finish_tag[4] = 0
        state.stream_last_service[4] = 1
        state.preferred_group_head = group
        state.has_preferred_group_head = True
        items = [self._batch_item(4), self._batch_item(8)]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(self._stream_ids(items, order), [8, 4])

    def test_session_scoped_head_stays_out_of_wfq_competition(self):
        state = BatchState()
        items = [
            BatchItem(RequestMeta(group_key=GroupKey.transient(0), cost=1)),
            self._batch_item(4, cost=40_000),
            self._batch_item(8, cost=40_000, priority=20),
        ]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(order[0], 0)
        self.assertEqual(self._stream_ids(items, order[1:]), [8, 4])

    def test_session_scoped_request_uses_transient_group_even_with_default_key(self):
        state = BatchState()
        items = [
            BatchItem(RequestMeta(cost=1)),
            self._batch_item(4),
        ]

        prepared = build_batch_groups(state, items)
        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertTrue(prepared.groups[0].key.is_transient())
        self.assertEqual(order, (0, 1))

    def test_eligible_stream_and_group_beat_lower_finish_ineligible_peer(self):
        state = BatchState()
        state.group_virtual_time[GroupKey.stream(4)] = 0
        state.group_virtual_time[GroupKey.stream(8)] = 0
        state.stream_finish_tag[4] = 12
        items = [self._batch_item(4, priority=20), self._batch_item(8, cost=8)]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(self._stream_ids(items, order), [8, 4])

        group_a = GroupKey.explicit(7)
        group_b = GroupKey.explicit(9)
        state = BatchState(root_virtual_time=4)
        state.group_finish_tag[group_a] = 12
        state.group_finish_tag[group_b] = 4
        grouped = [
            self._batch_item(4, group_key=group_a),
            self._batch_item(8, group_key=group_b),
        ]

        order = order_batch_indices(
            BatchConfig(group_fair=True, max_frame_payload=16_384),
            state,
            grouped,
        )

        self.assertEqual(self._stream_ids(grouped, order), [8, 4])

    def test_higher_priority_short_flow_is_selected_first(self):
        items = [
            self._batch_item(4, cost=40_000),
            self._batch_item(8, cost=512, priority=20),
        ]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), BatchState(), items)

        self.assertEqual(self._stream_ids(items, order), [8, 4])

    def test_priority_update_gets_one_cross_stream_head_opportunity(self):
        state = BatchState()
        items = [
            self._batch_item(8),
            self._batch_item(4),
            self._batch_item(4, is_priority_update=True),
        ]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(order, (2, 0, 1))

    def test_priority_update_does_not_pass_opening_frame_for_same_stream(self):
        state = BatchState()
        items = [
            self._batch_item(4, opening_frame=True),
            self._batch_item(4, is_priority_update=True),
        ]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(order, (0, 1))

    def test_group_fair_interleaves_groups_and_retains_next_heads(self):
        state = BatchState()
        group_a = GroupKey.explicit(7)
        group_b = GroupKey.explicit(9)
        items = [
            self._batch_item(4, group_key=group_a),
            self._batch_item(8, group_key=group_a),
            self._batch_item(12, group_key=group_b),
            self._batch_item(16, group_key=group_b),
        ]
        cfg = BatchConfig(group_fair=True, max_frame_payload=16_384)

        first = order_batch_indices(cfg, state, items)
        second = order_batch_indices(cfg, state, items)

        self.assertEqual(self._stream_ids(items, first), [4, 12, 8, 16])
        self.assertEqual(self._stream_ids(items, second), [16, 8, 12, 4])
        self.assertEqual(state.preferred_stream_head[group_a], 4)
        self.assertEqual(state.preferred_stream_head[group_b], 12)

    def test_build_batch_groups_accumulates_stream_bytes_and_priority_metadata(self):
        group_a = GroupKey.explicit(7)
        group_b = GroupKey.explicit(9)
        priority = StreamMeta(priority=9)
        items = [
            self._batch_item(4, cost=2, group_key=group_a),
            self._batch_item(
                4,
                cost=3,
                group_key=group_a,
                stream=priority,
                is_priority_update=True,
            ),
            self._batch_item(4, cost=5, group_key=group_b, stream=priority),
            BatchItem(RequestMeta(group_key=GroupKey.transient(0), cost=7)),
        ]

        prepared = build_batch_groups(BatchState(), items)

        self.assertTrue(prepared.has_real_stream_scoped)
        self.assertTrue(prepared.has_priority_update)
        self.assertEqual(prepared.queued_bytes[4], 10)
        self.assertEqual(prepared.stream_meta[4], priority)

    def test_mixed_batch_retains_only_real_stream_scheduler_state(self):
        state = BatchState()
        items = [
            BatchItem(RequestMeta(group_key=GroupKey.transient(1), cost=1)),
            self._batch_item(4),
            BatchItem(RequestMeta(group_key=GroupKey.transient(2), cost=1)),
        ]

        order = order_batch_indices(BatchConfig(max_frame_payload=16_384), state, items)

        self.assertEqual(order, (0, 1, 2))
        self.assertEqual(set(state.stream_finish_tag), {4})
        self.assertTrue(all(not key.is_transient() for key in state.group_finish_tag))
        self.assertTrue(
            all(not is_synthetic_stream_key(stream_id) for stream_id in state.stream_lag)
        )

    def test_batch_scratch_retain_helpers_and_prepare_drop_oversized_refs(self):
        self.assertEqual(
            batch_scratch_retain_limit(0),
            BATCH_SCRATCH_RETAIN_MIN_CAP,
        )
        self.assertEqual(batch_scratch_retain_limit(1), BATCH_SCRATCH_RETAIN_MIN_CAP)
        self.assertEqual(
            batch_scratch_retain_limit(BATCH_SCRATCH_RETAIN_MIN_CAP),
            BATCH_SCRATCH_RETAIN_MIN_CAP * BATCH_SCRATCH_RETAIN_FACTOR,
        )
        self.assertEqual(
            batch_scratch_retain_limit(BATCH_SCRATCH_RETAIN_MIN_CAP + 1),
            (BATCH_SCRATCH_RETAIN_MIN_CAP + 1) * BATCH_SCRATCH_RETAIN_FACTOR,
        )
        self.assertTrue(batch_scratch_oversized(batch_scratch_retain_limit(1) + 1, 1))
        self.assertFalse(batch_scratch_oversized(batch_scratch_retain_limit(1), 1))

        state = BatchState()
        state.scratch.last_build_cap_hint = batch_scratch_retain_limit(1) + 1
        state.scratch.groups.append(object())
        state.scratch.group_queues.append({4: [0]})
        state.scratch.prepared_streams[4] = object()
        state.scratch.bypass_selections[4] = 3
        state.scratch.interactive_active_streams.append(4)
        state.scratch.bulk_active_streams.append(8)
        state.scratch.interactive_candidates.append(object())
        state.scratch.bulk_candidates.append(object())
        state.scratch.transient_stream_finish[4] = 1
        state.scratch.transient_stream_last_served[4] = 2
        state.scratch.transient_group_virtual[GroupKey.transient(1)] = 3
        state.scratch.transient_group_finish[GroupKey.transient(1)] = 4
        state.scratch.transient_group_last_served[GroupKey.transient(1)] = 5
        state.scratch.tie_pref_streams[GroupKey.stream(4)] = 4

        prepare_batch_scratch_for_build(state, 1)

        self.assertEqual(state.scratch.last_build_cap_hint, 1)
        self.assert_empty_containers(
            state.scratch,
            (
                "groups",
                "group_queues",
                "prepared_streams",
                "bypass_selections",
                "interactive_active_streams",
                "bulk_active_streams",
                "interactive_candidates",
                "bulk_candidates",
                "transient_stream_finish",
                "transient_stream_last_served",
                "transient_group_virtual",
                "transient_group_finish",
                "transient_group_last_served",
                "tie_pref_streams",
            ),
        )

    def test_selected_list_reuse_resets_previous_marks(self):
        state = BatchState()
        selected = selected_list(state, 3)
        selected[1] = True

        reused = selected_list(state, 3)

        self.assertIs(reused, selected)
        self.assertEqual(reused, [False, False, False])

    def test_build_batch_groups_reuses_nested_queue_maps_without_stale_streams(self):
        state = BatchState()
        group = GroupKey.stream(4)
        first = [self._batch_item(4, group_key=group), self._batch_item(8, group_key=group)]
        second = [self._batch_item(4, group_key=group)]

        first_prepared = build_batch_groups(state, first)
        self.assertEqual(len(first_prepared.group_state[group]), 2)
        second_prepared = build_batch_groups(state, second)

        self.assertEqual(len(second_prepared.group_state[group]), 1)
        self.assertIn(4, second_prepared.group_state[group])
        self.assertNotIn(8, second_prepared.group_state[group])

    def test_build_batch_groups_recycles_nested_queue_and_order_entries(self):
        state = BatchState()
        group = GroupKey.stream(4)
        first = [self._batch_item(4, group_key=group), self._batch_item(8, group_key=group)]
        second = [self._batch_item(4, group_key=group)]

        build_batch_groups(state, first)
        build_batch_groups(state, second)

        self.assertGreater(len(state.scratch.group_queue_entries), 0)
        self.assertGreater(state.scratch.group_queue_entry_count, 0)
        self.assertGreater(len(state.scratch.stream_order_entries), 0)
        self.assertGreater(state.scratch.stream_order_entry_count, 0)

    def test_release_idle_batch_state_storage_drops_scheduler_scratch_refs(self):
        state = BatchState()
        state.group_virtual_time[GroupKey.stream(4)] = 1
        state.stream_finish_tag[4] = 2
        state.preferred_stream_head[GroupKey.stream(4)] = 4
        state.scratch.groups.append(object())
        state.scratch.group_queues.append({4: [0]})
        state.scratch.ordered.extend([0, 1])
        state.scratch.last_build_cap_hint = 10

        release_idle_batch_state_storage(state)

        self.assertEqual(state.group_virtual_time, {})
        self.assertEqual(state.stream_finish_tag, {})
        self.assertEqual(state.preferred_stream_head, {})
        self.assertEqual(state.scratch.groups, [])
        self.assertEqual(state.scratch.group_queues, [])
        self.assertEqual(state.scratch.ordered, [])
        self.assertEqual(state.scratch.last_build_cap_hint, 0)

    def test_scheduler_idle_clear_keeps_lag_only_state_and_active_groups(self):
        scheduler = BatchScheduler()
        scheduler.state.stream_lag[4] = 9

        scheduler.maybe_clear_idle_head_state()

        self.assertEqual(scheduler.state.stream_lag, {4: 9})

        scheduler.active_group_refs[7] = 1
        scheduler.maybe_clear_idle_head_state()

        self.assertEqual(scheduler.state.stream_lag, {4: 9})

    def test_transient_state_keeps_synthetic_scheduler_tags_out_of_retained_state(self):
        state = BatchState()
        transient = transient_batch_state(state, 4)
        synthetic = (1 << 63) | 7
        group = GroupKey.transient(3)

        set_stream_finish_tag(state, transient, synthetic, 11)
        set_group_virtual_time(state, transient, group, 13)

        self.assertEqual(stream_finish_tag(state, transient, synthetic), 11)
        self.assertEqual(group_virtual_time(state, transient, group), 13)
        self.assertEqual(state.stream_finish_tag, {})
        self.assertEqual(state.group_virtual_time, {})
        self.assertEqual(transient.stream_finish[synthetic], 11)
        self.assertEqual(transient.group_virtual[group], 13)

    def test_maybe_rebase_wfq_state_subtracts_lowest_retained_tag(self):
        base = 1 << 48
        group = GroupKey.stream(4)
        state = BatchState(
            root_virtual_time=base + 100,
            group_virtual_time={group: base + 50},
            group_finish_tag={group: base + 20},
            stream_finish_tag={4: base + 10},
        )

        maybe_rebase_wfq_state(state)

        self.assertEqual(state.root_virtual_time, 90)
        self.assertEqual(state.group_virtual_time[group], 40)
        self.assertEqual(state.group_finish_tag[group], 10)
        self.assertEqual(state.stream_finish_tag[4], 0)

    def _batch_item(
            self,
            stream_id,
            *,
            cost=1,
            priority=0,
            group_key=None,
            stream=None,
            is_priority_update=False,
            opening_frame=False,
            urgency_rank=0,
    ):
        if group_key is None:
            group_key = GroupKey.stream(stream_id)
        if stream is None:
            stream = StreamMeta(priority=priority)
        return BatchItem(
            RequestMeta(
                group_key=group_key,
                stream_id=stream_id,
                stream_scoped=True,
                is_priority_update=is_priority_update,
                opening_frame=opening_frame,
                cost=cost,
                urgency_rank=urgency_rank,
            ),
            stream,
        )

    def _stream_ids(self, items, order):
        return [items[index].request.stream_id for index in order]

    def _candidate(
            self,
            group_key,
            traffic_class,
            *,
            start,
            finish,
            stream_id,
            stream_finish,
            eligible,
            group_order=0,
    ):
        return WFQGroupCandidate(
            group_key=group_key,
            group_start=start,
            group_finish=finish,
            group_last_served=0,
            eligible=eligible,
            group_order=group_order,
            traffic_class=traffic_class,
            stream=WFQStreamCandidate(
                stream_id=stream_id,
                stream_start=start,
                stream_finish=stream_finish,
                stream_last_served=0,
                eligible=eligible,
                stream_order=group_order,
            ),
        )


if __name__ == "__main__":
    unittest.main()
