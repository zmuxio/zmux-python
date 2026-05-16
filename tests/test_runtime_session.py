import unittest
from dataclasses import replace

from zmux._runtime.keepalive import (
    KEEPALIVE_JITTER_GAMMA,
    fill_ping_padding_from_state,
    init_session_nonce_state,
    next_keepalive_jitter,
    next_keepalive_jitter_value_from_state,
    next_session_nonce,
    next_uint64n_from_state,
    splitmix64_from_state,
)
from zmux._runtime.session import (
    BeginCloseOutcome,
    EventDispatcher,
    LivenessState,
    LocalOpenOutcome,
    LocalOpenTracker,
    PingPayloadFingerprint,
    QueueItem,
    ReasonCounter,
    RegistryState,
    RetentionState,
    RuntimePolicy,
    SESSION_GO_AWAY_DRAIN_INTERVAL_MAX,
    SessionRuntimeState,
    SparseQueue,
    StreamArity,
    accepted_peer_go_away_watermark,
    admission_hard_cap,
    admission_soft_cap,
    allow_local_non_close_control,
    build_establishment_close_frame,
    build_padded_ping_echo,
    build_ping_payload,
    close_frame_send_timeout,
    close_session_state,
    default_urgent_queue_max_bytes,
    effective_go_away_send_watermark,
    establishment_close_max_payload,
    go_away_drain_interval,
    graceful_close_drain_timeout,
    has_ping_padding_tag,
    init_keepalive_jitter_state,
    max_peer_go_away_watermark,
    ping_padding_bounds,
    ping_padding_tag,
    ping_payload_hash,
    ping_payload_len,
    plan_begin_close,
    plan_local_open,
    plan_peer_go_away,
    pong_payload_for_ping,
    projected_local_open_id,
    provisional_available_count,
    provisional_expired,
    provisional_open_max_age,
    retained_open_info_budget,
    retained_peer_reason_budget,
    session_memory_high_threshold,
    stop_sending_drain_window,
    stream_event,
    truncate_string_to_bytes,
    validate_local_go_away,
)
from zmux.config import Config, Settings
from zmux.errors import OpenExpired
from zmux.events import Event, EventType
from zmux.frame import Frame
from zmux.payload import parse_error_payload, parse_go_away_payload
from zmux.preface import Negotiated, Preface
from zmux.protocol import ErrorCode, FrameType, MAX_VARINT62, PROTO_VERSION, Role
from zmux.session import SessionState


def _prefaces():
    config = Config(role=Role.INITIATOR)
    local = config.local_preface()
    peer = Preface(
        preface_version=local.preface_version,
        role=Role.RESPONDER,
        tie_breaker_nonce=99,
        min_proto=PROTO_VERSION,
        max_proto=PROTO_VERSION,
        capabilities=local.capabilities,
        settings=Settings(),
    )
    negotiated = Negotiated(
        proto=PROTO_VERSION,
        capabilities=0,
        local_role=Role.INITIATOR,
        peer_role=Role.RESPONDER,
        peer_settings=peer.settings,
    )
    return config, local, peer, negotiated


class RuntimeSessionLifecycleTests(unittest.TestCase):
    def test_lifecycle_plans_match_go_state_table(self):
        self.assertTrue(allow_local_non_close_control(SessionState.READY))
        self.assertFalse(
            allow_local_non_close_control(SessionState.READY, close_frame_outstanding=True)
        )
        self.assertEqual(
            plan_local_open(SessionState.READY), LocalOpenOutcome.ALLOW
        )
        self.assertEqual(
            plan_local_open(SessionState.READY, graceful_close_active=True),
            LocalOpenOutcome.RETURN_CLOSED,
        )

        plan = plan_begin_close(SessionState.READY, has_open_streams=True)
        self.assertEqual(plan.outcome, BeginCloseOutcome.GRACEFUL)
        self.assertEqual(plan.next_state, SessionState.DRAINING)
        self.assertEqual(
            plan_begin_close(SessionState.CLOSING).outcome,
            BeginCloseOutcome.WAIT_EXISTING,
        )
        self.assertEqual(close_session_state(SessionState.READY, None), SessionState.CLOSED)
        self.assertEqual(
            close_session_state(SessionState.READY, RuntimeError("boom")),
            SessionState.FAILED,
        )

    def test_peer_goaway_plans_and_watermarks(self):
        plan = plan_peer_go_away(SessionState.READY, False, 20, 24, 16, 24)
        self.assertTrue(plan.changed)
        self.assertEqual(plan.next_state, SessionState.DRAINING)
        ignored = plan_peer_go_away(SessionState.CLOSING, False, 20, 24, 16, 20)
        self.assertTrue(ignored.ignore)

        self.assertEqual(
            accepted_peer_go_away_watermark(Role.INITIATOR, StreamArity.BIDI, 1),
            0,
        )
        self.assertEqual(
            accepted_peer_go_away_watermark(Role.INITIATOR, StreamArity.BIDI, 9),
            5,
        )
        self.assertEqual(
            effective_go_away_send_watermark(
                Role.INITIATOR, StreamArity.UNI, MAX_VARINT62
            ),
            max_peer_go_away_watermark(Role.INITIATOR, StreamArity.UNI),
        )
        validate_local_go_away(Role.INITIATOR, Role.RESPONDER, 1, 3)
        with self.assertRaises(Exception):
            validate_local_go_away(Role.INITIATOR, Role.RESPONDER, 4, 3)

    def test_establishment_close_payload_uses_peer_limit_and_encodes_close(self):
        _, local, peer, _ = _prefaces()
        peer = Preface(
            peer.preface_version,
            peer.role,
            peer.tie_breaker_nonce,
            peer.min_proto,
            peer.max_proto,
            peer.capabilities,
            Settings(max_control_payload_bytes=16),
        )
        self.assertEqual(establishment_close_max_payload(local, peer), 16)
        encoded = build_establishment_close_frame(local, peer, RuntimeError("hello world"))
        frame, consumed = Frame.parse(encoded)
        self.assertEqual(consumed, len(encoded))
        self.assertEqual(frame.frame_type, FrameType.CLOSE)
        code, reason = parse_error_payload(frame.payload)
        self.assertEqual(code, int(ErrorCode.INTERNAL))
        self.assertLessEqual(len(frame.payload), 16)
        self.assertTrue(reason == "" or reason.startswith("hello"))


class RuntimeSessionPolicyTests(unittest.TestCase):
    def test_policy_derives_defaults_from_negotiated_settings(self):
        config, local, peer, negotiated = _prefaces()
        policy = RuntimePolicy.from_config(config, local, peer, negotiated)

        self.assertEqual(policy.per_stream_queued_data_hwm, 256 * 1024)
        self.assertEqual(policy.session_queued_data_hwm, 4 * 1024 * 1024)
        self.assertEqual(
            policy.urgent_queued_bytes_cap,
            default_urgent_queue_max_bytes(local.settings, peer.settings),
        )
        self.assertGreaterEqual(policy.pending_control_bytes_budget, 64 * 1024)
        self.assertGreaterEqual(policy.pending_priority_bytes_budget, 64 * 1024)
        self.assertEqual(policy.accept_backlog_limit, 128)
        self.assertGreaterEqual(policy.accept_backlog_bytes_limit, 4 * 1024 * 1024)

    def test_policy_honors_explicit_overrides_and_memory_threshold(self):
        config, local, peer, negotiated = _prefaces()
        config = replace(
            config,
            session_memory_cap=12345,
            per_stream_queued_data_hwm=111,
            session_queued_data_hwm=222,
            urgent_queued_bytes_cap=333,
            pending_control_bytes_budget=444,
            pending_priority_bytes_budget=555,
            accept_backlog_limit=9,
            accept_backlog_bytes_limit=10,
            ping_padding=True,
            ping_padding_min_bytes=9,
            ping_padding_max_bytes=11,
        )
        policy = RuntimePolicy.from_config(config, local, peer, negotiated)
        self.assertEqual(policy.session_memory_cap, 12345)
        self.assertEqual(policy.per_stream_queued_data_hwm, 111)
        self.assertEqual(policy.session_queued_data_hwm, 222)
        self.assertEqual(policy.urgent_queued_bytes_cap, 333)
        self.assertEqual(policy.pending_control_bytes_budget, 444)
        self.assertEqual(policy.pending_priority_bytes_budget, 555)
        self.assertEqual(policy.accept_backlog_limit, 9)
        self.assertEqual(policy.accept_backlog_bytes_limit, 10)
        self.assertTrue(policy.ping_padding)
        self.assertEqual(policy.ping_padding_min_bytes, 9)
        self.assertEqual(policy.ping_padding_max_bytes, 11)
        self.assertEqual(session_memory_high_threshold(100), 75)

    def test_policy_zero_optional_limits_fall_back_to_java_defaults(self):
        config, local, peer, negotiated = _prefaces()
        baseline = RuntimePolicy.from_config(config, local, peer, negotiated)
        zeroed = RuntimePolicy.from_config(
            replace(
                config,
                per_stream_queued_data_hwm=0,
                session_queued_data_hwm=0,
                urgent_queued_bytes_cap=0,
                pending_control_bytes_budget=0,
                pending_priority_bytes_budget=0,
                accept_backlog_limit=0,
                accept_backlog_bytes_limit=0,
                tombstone_limit=0,
                aggregate_late_data_cap=0,
            ),
            local,
            peer,
            negotiated,
        )

        self.assertEqual(zeroed.per_stream_queued_data_hwm, baseline.per_stream_queued_data_hwm)
        self.assertEqual(zeroed.session_queued_data_hwm, baseline.session_queued_data_hwm)
        self.assertEqual(zeroed.urgent_queued_bytes_cap, baseline.urgent_queued_bytes_cap)
        self.assertEqual(zeroed.pending_control_bytes_budget, baseline.pending_control_bytes_budget)
        self.assertEqual(zeroed.pending_priority_bytes_budget, baseline.pending_priority_bytes_budget)
        self.assertEqual(zeroed.accept_backlog_limit, baseline.accept_backlog_limit)
        self.assertEqual(zeroed.accept_backlog_bytes_limit, baseline.accept_backlog_bytes_limit)
        self.assertEqual(zeroed.tombstone_limit, baseline.tombstone_limit)
        self.assertEqual(zeroed.aggregate_late_data_cap, baseline.aggregate_late_data_cap)

    def test_adaptive_session_timers_match_rust_edges(self):
        self.assertEqual(go_away_drain_interval(0.010, 0.0), 0.010)
        self.assertEqual(go_away_drain_interval(0.010, 0.800), 0.200)
        self.assertEqual(
            go_away_drain_interval(0.010, 10.0),
            SESSION_GO_AWAY_DRAIN_INTERVAL_MAX,
        )
        self.assertEqual(go_away_drain_interval(0.500, 10.0), 0.500)
        self.assertEqual(go_away_drain_interval(0.0, 0.800), 0.0)

        self.assertEqual(graceful_close_drain_timeout(0.0, 1.0), 0.0)
        self.assertEqual(graceful_close_drain_timeout(0.250, 1.0), 0.250)
        self.assertAlmostEqual(graceful_close_drain_timeout(0.500, 1.0), 4.100)

        self.assertEqual(close_frame_send_timeout(0.0), 0.100)
        self.assertAlmostEqual(close_frame_send_timeout(0.100), 0.450)
        self.assertEqual(close_frame_send_timeout(1.0), 2.0)

        self.assertEqual(stop_sending_drain_window(0.250, 1.0), 0.250)
        self.assertEqual(stop_sending_drain_window(0.0, 0.001), 0.100)
        self.assertEqual(stop_sending_drain_window(0.0, 100.0), 2.0)

        self.assertEqual(provisional_open_max_age(None), 5.0)
        self.assertAlmostEqual(provisional_open_max_age(1.0), 6.250)
        self.assertEqual(provisional_open_max_age(100.0), 20.0)

    def test_retention_budgets_and_reason_truncation_are_bounded(self):
        settings = Settings(max_frame_payload=1, max_control_payload_bytes=1)
        self.assertEqual(retained_open_info_budget(settings, settings), 64 * 1024)
        self.assertEqual(retained_peer_reason_budget(settings), 64 * 1024)
        self.assertEqual(truncate_string_to_bytes("éabc", 3), "éa")

        retention = RetentionState(retained_peer_reason_bytes=4)
        text, used = retention.retain_peer_reason(4, "éabc", 5, 5)
        self.assertEqual(text, "éabc")
        self.assertEqual(used, 5)
        text, used = retention.retain_peer_reason(used, "abcdef", 5, 2)
        self.assertEqual(text, "ab")
        self.assertEqual(used, 2)


class RuntimeSessionQueueTests(unittest.TestCase):
    def test_stream_arity_and_projection_helpers(self):
        registry = RegistryState.for_role(Role.INITIATOR)
        self.assertIs(StreamArity(0), StreamArity.UNI)
        self.assertIs(StreamArity.from_bidi(True), StreamArity.BIDI)
        self.assertEqual(StreamArity.BIDI.next_local_id(registry), 4)
        self.assertEqual(StreamArity.UNI.next_local_id(registry), 2)
        StreamArity.BIDI.advance_local_id(registry, 4)
        self.assertEqual(registry.next_local_bidi, 8)
        with self.assertRaises(TypeError):
            StreamArity.from_bidi(1)

        self.assertEqual(projected_local_open_id(9, 3), 21)
        self.assertEqual(projected_local_open_id(MAX_VARINT62, 1), MAX_VARINT62 + 1)
        self.assertEqual(provisional_available_count(4, 12), 3)
        self.assertEqual(admission_soft_cap(8), 16)
        self.assertEqual(admission_hard_cap(8), 32)
        self.assertTrue(provisional_expired(False, 1.0, now=6.1, max_age=5.0))

    def test_sparse_queue_removes_holes_and_compacts(self):
        queue = SparseQueue[int](compact_min_head=2)
        a = queue.append(1)
        b = queue.append(2)
        c = queue.append(3)
        self.assertEqual((a, b, c), (0, 1, 2))
        self.assertEqual(queue.remove_index(0), 1)
        self.assertEqual(queue.head_item(), 2)
        self.assertEqual(queue.remove_index(1), 2)
        queue.maybe_compact()
        self.assertEqual(queue.items, [3])
        self.assertEqual(queue.head, 0)
        self.assertEqual(queue.pop_head(), 3)
        self.assertEqual(len(queue), 0)
        with self.assertRaises(TypeError):
            SparseQueue(init=1)

    def test_local_open_tracker_reaps_expired_and_reclaims_goaway_tail(self):
        tracker = LocalOpenTracker()
        first = QueueItem("first", bidi=True)
        second = QueueItem("second", bidi=True)
        tracker.append_provisional(first, now=0.0)
        tracker.append_provisional(first, now=1.0)
        self.assertEqual(tracker.provisional_count(StreamArity.BIDI), 1)
        self.assertEqual(first.created_at, 0.0)
        tracker.append_provisional(second, now=4.9)

        expired = tracker.reap_expired(StreamArity.BIDI, now=5.1, max_age=5.0)
        self.assertEqual(expired, (first,))
        self.assertIsInstance(first.failed, OpenExpired)
        self.assertEqual(tracker.expired_count, 1)
        self.assertEqual(tracker.provisional_count(StreamArity.BIDI), 1)

        third = QueueItem("third", bidi=True)
        tracker.append_provisional(third, now=5.2)
        reclaimed = tracker.reclaim_by_goaway(StreamArity.BIDI, next_local_id=4, peer_watermark=4)
        self.assertEqual(reclaimed, (third,))
        self.assertEqual(tracker.provisional_count(StreamArity.BIDI), 1)
        with self.assertRaises(TypeError):
            QueueItem("bad", id_set=1)
        with self.assertRaises(TypeError):
            QueueItem("bad", bidi=1)
        with self.assertRaises(ValueError):
            QueueItem("bad", id_set=True, stream_id=0)
        with self.assertRaises(ValueError):
            QueueItem("bad", stream_id=MAX_VARINT62 + 1)


class RuntimeSessionPingTests(unittest.TestCase):
    def test_ping_payload_hash_fingerprint_and_padding_tag(self):
        payload = build_ping_payload(b"abc", 0x0102030405060708)
        self.assertEqual(ping_payload_len(3), 11)
        self.assertEqual(payload[:8], b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertEqual(ping_payload_hash(payload), ping_payload_hash(payload))

        strict = PingPayloadFingerprint.from_payload(payload)
        padded = PingPayloadFingerprint.from_payload(payload, allow_padding=True)
        self.assertTrue(strict.matches(payload))
        self.assertFalse(strict.matches(payload + b"x"))
        self.assertTrue(padded.matches(payload + b"x"))

        tag = ping_padding_tag(123, 0x0102030405060708)
        tagged_payload = payload[:8] + tag.to_bytes(8, "big") + b"abc"
        self.assertTrue(has_ping_padding_tag(tagged_payload, 123))
        self.assertEqual(ping_padding_bounds(4, 16, 64), (4, 4))

    def test_liveness_ping_padding_pong_and_keepalive_action(self):
        key = 0xABC
        local = Settings(ping_padding_key=key)
        peer = Settings(ping_padding_key=key)
        liveness = LivenessState(
            keepalive_interval=10.0,
            keepalive_max_ping_interval=30.0,
            ping_padding=True,
            ping_padding_min=8,
            ping_padding_max=8,
            keepalive_jitter_state=init_keepalive_jitter_state(1),
            ping_nonce_state=init_keepalive_jitter_state(2),
        )

        wire_echo, padded = build_padded_ping_echo(liveness, local, peer, b"hi", 7)
        self.assertTrue(padded)
        ping_payload = build_ping_payload(wire_echo, 7)
        self.assertTrue(has_ping_padding_tag(ping_payload, key))
        reply = pong_payload_for_ping(liveness, local, peer, ping_payload)
        self.assertGreaterEqual(len(reply), len(ping_payload))

        liveness.begin_ping_payload(ping_payload, sent_at=1.0, accepts_padded_pong=True)
        self.assertTrue(liveness.handle_pong_payload(ping_payload + b"pad", now=1.5))
        self.assertFalse(liveness.ping_outstanding)
        self.assertAlmostEqual(liveness.last_ping_rtt, 0.5)

        liveness.reset_keepalive_schedules(now=2.0)
        action = liveness.next_keepalive_action(now=100.0)
        self.assertTrue(action.should_send_ping())

        with self.assertRaises(TypeError):
            liveness.begin_ping_payload(8)
        with self.assertRaises(TypeError):
            liveness.handle_pong_payload("not bytes")

    def test_liveness_reports_outstanding_keepalive_timeout(self):
        payload = build_ping_payload(b"", 1)
        liveness = LivenessState(keepalive_interval=10.0, keepalive_timeout=5.0)
        liveness.begin_ping_payload(payload, sent_at=1.0)
        pending = liveness.next_keepalive_action(now=4.0)
        self.assertFalse(pending.should_close())
        self.assertEqual(pending.delay, 2.0)
        expired = liveness.next_keepalive_action(now=6.1)
        self.assertTrue(expired.should_close())
        self.assertFalse(expired.should_send_ping())

    def test_keepalive_jitter_nonce_state_matches_reference_mix(self):
        self.assertEqual(init_keepalive_jitter_state(123), 123)
        first_default = init_keepalive_jitter_state(0)
        second_default = init_keepalive_jitter_state(0)
        self.assertNotEqual(first_default, 0)
        self.assertNotEqual(second_default, 0)
        self.assertNotEqual(first_default, second_default)

        class Holder(object):
            ping_nonce_state = 1
            keepalive_jitter_state = 1

        holder = Holder()
        mask = (1 << 64) - 1
        expected_state = (1 + KEEPALIVE_JITTER_GAMMA) & mask
        self.assertEqual(
            next_keepalive_jitter_value_from_state(1),
            (expected_state, splitmix64_from_state(expected_state)),
        )
        self.assertEqual(next_session_nonce(holder), splitmix64_from_state(expected_state))
        self.assertEqual(holder.ping_nonce_state, expected_state)
        self.assertEqual(init_session_nonce_state(123), 123)

        wrapped_state = (mask + KEEPALIVE_JITTER_GAMMA) & mask
        self.assertEqual(
            next_keepalive_jitter_value_from_state(mask),
            (wrapped_state, splitmix64_from_state(wrapped_state)),
        )

        jitter = next_keepalive_jitter(8.0, holder)
        self.assertGreaterEqual(jitter, 0.0)
        self.assertLessEqual(jitter, 1.0)
        self.assertGreaterEqual(8.0 - jitter, 7.0)
        before_jitter_state = holder.keepalive_jitter_state
        next_keepalive_jitter(0.08, holder)
        middle_jitter_state = holder.keepalive_jitter_state
        next_keepalive_jitter(0.08, holder)
        self.assertNotEqual(before_jitter_state, middle_jitter_state)
        self.assertNotEqual(middle_jitter_state, holder.keepalive_jitter_state)
        self.assertEqual(next_keepalive_jitter(1e-10, holder), 0.0)

        self.assertIsInstance(next_session_nonce(None), int)
        self.assertGreaterEqual(next_keepalive_jitter(8.0, None), 0.0)
        self.assertEqual(next_uint64n_from_state(holder, 1), 0)
        padding_holder = Holder()
        padding = fill_ping_padding_from_state(9, padding_holder)
        first_state = (1 + KEEPALIVE_JITTER_GAMMA) & mask
        second_state = (first_state + KEEPALIVE_JITTER_GAMMA) & mask
        expected_padding = (
                splitmix64_from_state(first_state).to_bytes(8, "big")
                + splitmix64_from_state(second_state).to_bytes(8, "big")[:1]
        )
        self.assertEqual(padding, expected_padding)
        with self.assertRaises(OverflowError):
            next_uint64n_from_state(holder, 1 << 65)
        with self.assertRaises(TypeError):
            splitmix64_from_state(False)
        with self.assertRaises(TypeError):
            init_keepalive_jitter_state(True)
        with self.assertRaises(TypeError):
            next_keepalive_jitter_value_from_state(1.0)
        with self.assertRaises(ValueError):
            init_keepalive_jitter_state(-1)


class RuntimeSessionStateTests(unittest.TestCase):
    def test_reason_counter_caps_distinct_codes(self):
        counter = ReasonCounter(limit=2)
        counter.note(1)
        counter.note(2)
        counter.note(1)
        counter.note(3)
        counts, overflow = counter.snapshot()
        self.assertEqual(counts, {1: 2, 2: 1})
        self.assertEqual(overflow, 1)

        restored = ReasonCounter(limit=1, counts={1: 2, 2: 3}, overflow=4)
        self.assertEqual(restored.snapshot(), ({1: 2}, 7))
        with self.assertRaises(ValueError):
            ReasonCounter(limit=-1)
        with self.assertRaises(TypeError):
            ReasonCounter(limit=True)
        with self.assertRaises(ValueError):
            counter.note(-1)

    def test_event_dispatcher_queues_reentrant_events_and_catches_handler_errors(self):
        seen = []
        dispatcher = EventDispatcher()

        def handler(event):
            seen.append(event.event_type)
            if event.event_type is EventType.STREAM_OPENED:
                dispatcher.emit(Event(EventType.STREAM_ACCEPTED))
                raise RuntimeError("ignored")

        dispatcher.handler = handler
        dispatcher.emit(Event(EventType.STREAM_OPENED))
        self.assertEqual(seen, [EventType.STREAM_OPENED, EventType.STREAM_ACCEPTED])
        self.assertEqual(dispatcher.dropped_handler_exceptions, 1)
        event = stream_event(
            EventType.STREAM_OPENED,
            1,
            True,
            True,
            local_addr="local",
            remote_addr="remote",
        )
        self.assertEqual(event.stream.local_addr, "local")
        self.assertEqual(event.stream.remote_addr, "remote")
        with self.assertRaises(TypeError):
            stream_event(EventType.STREAM_OPENED, 1, 1, True)

    def test_runtime_state_stats_snapshot_includes_memory_liveness_and_reasons(self):
        config, local, peer, negotiated = _prefaces()
        runtime = SessionRuntimeState.established(local, peer, negotiated, config, now=1.0)
        runtime.flow.recv_session_used = 100
        runtime.flow.recv_session_advertised = 150
        runtime.flow.queued_data_bytes = 11
        runtime.flow.advisory_queued_bytes = 12
        runtime.flow.urgent_queued_bytes = 13
        runtime.flow.read_buffer_overhead = 14
        runtime.retention.retained_open_info_bytes = 20
        runtime.retention.retained_peer_reason_bytes = 21
        runtime.retention.hidden_control_retained = 2
        runtime.retention.visible_tombstone_retained = 3
        runtime.retention.marker_only_retained = 4
        runtime.retention.marker_only_range_count = 5
        runtime.metrics.close_frame_admission_timeout = 5
        runtime.metrics.close_frame_flush_timeout = 6
        runtime.metrics.close_completion_timeout = 7
        runtime.metrics.protocol_backlog_blocked = 8
        runtime.metrics.visible_terminal_churn_events = 9
        runtime.metrics.group_rebucket_events = 10
        runtime.metrics.hidden_abort_churn_events = 11
        runtime.metrics.last_open_latency = 0.25
        runtime.ingress.dropped_priority_update = 12
        runtime.note_reset_reason(7)
        runtime.note_abort_reason(8)
        runtime.metrics.note_flush(4096, 2, data_bytes=1024, elapsed=0.1, now=2.0)
        runtime.liveness.begin_ping_payload(build_ping_payload(b"", 9), sent_at=2.0)

        stats = runtime.stats()
        self.assertEqual(stats.state, SessionState.READY)
        self.assertEqual(stats.sent_frames, 2)
        self.assertEqual(stats.sent_data_bytes, 1024)
        self.assertEqual(stats.reasons.reset[7], 1)
        self.assertEqual(stats.reasons.abort[8], 1)
        self.assertTrue(stats.ping_outstanding)
        self.assertEqual(stats.pressure.outstanding_ping_bytes, 8)
        self.assertEqual(stats.pressure.retained_open_info_bytes, 20)
        self.assertEqual(stats.pressure.retained_peer_reason_bytes, 21)
        self.assertEqual(stats.pressure.ordinary_queued_bytes, 11)
        self.assertEqual(stats.pressure.advisory_queued_bytes, 12)
        self.assertEqual(stats.pressure.urgent_queued_bytes, 13)
        self.assertEqual(stats.pressure.buffered_receive_storage_bytes, 14)
        self.assertEqual(stats.pressure.retained_buckets.hidden_control.count, 2)
        self.assertEqual(stats.pressure.retained_buckets.visible_tombstone.count, 3)
        self.assertEqual(stats.pressure.retained_buckets.marker_only.count, 4)
        self.assertEqual(stats.diagnostics.close_frame_admission_timeouts, 5)
        self.assertEqual(stats.diagnostics.close_frame_flush_timeouts, 6)
        self.assertEqual(stats.diagnostics.close_completion_timeouts, 7)
        self.assertEqual(stats.diagnostics.protocol_backlog_blocked, 8)
        self.assertEqual(stats.diagnostics.visible_terminal_churn_events, 9)
        self.assertEqual(stats.diagnostics.group_rebucket_events, 10)
        self.assertEqual(stats.diagnostics.hidden_abort_churn_events, 11)
        self.assertEqual(stats.diagnostics.marker_only_range_count, 5)
        self.assertGreater(stats.pressure.tracked_buffered_bytes, 0)
        self.assertEqual(stats.telemetry.last_open_latency, 0.25)
        self.assertGreater(stats.telemetry.send_rate_estimate_bytes_per_second, 0)
        self.assertEqual(stats.writer_queue.queued_bytes, 36)
        self.assertEqual(
            stats.writer_queue.urgent_max_bytes,
            runtime.policy.urgent_queued_bytes_cap,
        )
        self.assertEqual(
            stats.writer_queue.max_batch_frames,
            runtime.policy.write_batch_max_frames,
        )
        self.assertEqual(stats.liveness.keepalive_interval, runtime.liveness.keepalive_interval)
        self.assertTrue(stats.liveness.ping_outstanding)
        self.assertGreaterEqual(stats.liveness.inbound_idle_for, 0.0)
        self.assertEqual(stats.retention.tombstones, 3)
        self.assertEqual(stats.retention.marker_only_used_streams, 4)
        self.assertEqual(stats.retention.marker_only_used_stream_ranges, 5)
        self.assertEqual(
            stats.retention.retained_open_info_bytes_budget,
            runtime.policy.retained_open_info_bytes_budget,
        )
        self.assertEqual(stats.memory.tracked_bytes, stats.pressure.tracked_buffered_bytes)
        self.assertEqual(stats.memory.hard_cap, stats.pressure.tracked_buffered_limit)
        self.assertEqual(stats.abuse.dropped_priority_update, 12)
        self.assertEqual(
            stats.abuse.inbound_control_frame_budget,
            runtime.policy.abuse.inbound_control_frame_budget,
        )

    def test_runtime_goaway_payload_caps_reason_to_peer_control_limit(self):
        config, local, peer, negotiated = _prefaces()
        peer = Preface(
            peer.preface_version,
            peer.role,
            peer.tie_breaker_nonce,
            peer.min_proto,
            peer.max_proto,
            peer.capabilities,
            Settings(max_control_payload_bytes=8),
        )
        runtime = SessionRuntimeState.established(local, peer, negotiated, config, now=1.0)
        payload = runtime.go_away_payload(1, 3, int(ErrorCode.NO_ERROR), "abcdefgh")
        parsed = parse_go_away_payload(payload)
        self.assertLessEqual(len(payload), 8)
        self.assertEqual(parsed.last_accepted_bidi, 1)
        self.assertEqual(parsed.last_accepted_uni, 3)
        self.assertEqual(parsed.code, int(ErrorCode.NO_ERROR))
        self.assertTrue(parsed.reason == "" or "abcdefgh".startswith(parsed.reason))


if __name__ == "__main__":
    unittest.main()
