import io
import unittest

from zmux._runtime.read_loop import (
    InboundBudgetTracker,
    LateDataCause,
    LateDataTracker,
    ParsedInboundFrame,
    ParsedFrameKind,
    ProtocolQueueSnapshot,
    ProtocolTask,
    ProtocolTaskKind,
    ReadLoopAbuseConfig,
    ReadLoopDispatchResult,
    ReadLoopFrameDispatcher,
    ReadLoopProtocolQueue,
    ReceiveWindowState,
    ReplenishDecision,
    aggregate_late_data_cap,
    build_max_data_frame,
    classify_inbound_frame,
    first_local_stream_id,
    first_peer_stream_id,
    initial_receive_window,
    initial_send_window,
    late_data_per_stream_cap,
    next_credit_limit,
    quarter_threshold,
    read_loop_once,
    receive_window_exceeded,
    replenish_decision,
    replenish_min_pending,
    repo_default_per_stream_data_hwm,
    repo_default_session_data_hwm,
    session_emergency_threshold,
    should_flush_receive_credit,
    stream_id_previously_used,
    stream_emergency_threshold,
    stream_is_bidi,
    stream_kind_for_local,
    TrafficBudgetCounter,
    WindowedCounter,
    validate_go_away_watermark_for_direction,
    validate_peer_go_away_payload,
    window_remaining,
)
from zmux.config import (
    DEFAULT_ABUSE_WINDOW,
    DEFAULT_GROUP_REBUCKET_CHURN_BUDGET,
    DEFAULT_HIDDEN_ABORT_CHURN_BUDGET,
    DEFAULT_HIDDEN_ABORT_CHURN_WINDOW,
    DEFAULT_IGNORED_CONTROL_BUDGET,
    DEFAULT_INBOUND_CONTROL_FRAME_BUDGET,
    DEFAULT_INBOUND_EXT_FRAME_BUDGET,
    DEFAULT_INBOUND_PING_BUDGET,
    DEFAULT_NO_OP_BLOCKED_BUDGET,
    DEFAULT_NO_OP_MAX_DATA_BUDGET,
    DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET,
    DEFAULT_NO_OP_ZERO_DATA_BUDGET,
    DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET,
    DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW,
    Config,
    Settings,
)
from zmux.errors import FrameSizeError, ProtocolError
from zmux.frame import Frame
from zmux.payload import (
    MetadataUpdate,
    build_go_away_payload,
    build_open_metadata_prefix,
    build_priority_update_payload,
)
from zmux.protocol import (
    CAPABILITY_OPEN_METADATA,
    CAPABILITY_PRIORITY_HINTS,
    CAPABILITY_PRIORITY_UPDATE,
    CAPABILITY_STREAM_GROUPS,
    ErrorCode,
    FRAME_FLAG_OPEN_METADATA,
    FrameType,
    MAX_VARINT62,
    Role,
)


class RuntimeReadLoopFlowTests(unittest.TestCase):
    def test_receive_window_and_replenish_boundaries_match_reference_policy(self):
        self.assertFalse(receive_window_exceeded(8, 10, 2))
        self.assertTrue(receive_window_exceeded(8, 10, 3))
        self.assertTrue(receive_window_exceeded((1 << 64) - 2, (1 << 64) - 1, 2))
        self.assertEqual(window_remaining(8, 10), 0)

        self.assertEqual(quarter_threshold(0), 1)
        self.assertEqual(quarter_threshold(4), 1)
        self.assertEqual(quarter_threshold(8), 2)
        self.assertEqual(session_emergency_threshold(64), 128)
        self.assertEqual(stream_emergency_threshold(64, 256), 16)
        self.assertEqual(replenish_min_pending(0, 16384), 1)

        self.assertFalse(
            should_flush_receive_credit(100, 10, 15, 64, 2, 16, False)
        )
        self.assertTrue(
            should_flush_receive_credit(100, 10, 16, 64, 2, 16, False)
        )
        self.assertEqual(next_credit_limit(64, 8, 60, 128, True), 188)
        self.assertEqual(next_credit_limit(64, 8, 60, 128, False), 72)
        self.assertEqual(
            next_credit_limit(MAX_VARINT62 - 2, 10, MAX_VARINT62 - 1, 16, True),
            MAX_VARINT62,
        )

        decision = replenish_decision(
            advertised=100,
            received=98,
            pending=1,
            target=64,
            emergency_threshold=2,
            min_pending=16,
            allow_standing_growth=False,
        )
        self.assertTrue(decision.should_flush)
        self.assertEqual(decision.desired_limit, 101)

    def test_default_high_watermarks_and_late_data_caps(self):
        per_stream = repo_default_per_stream_data_hwm(16384)
        self.assertEqual(per_stream, 256 * 1024)
        self.assertEqual(repo_default_session_data_hwm(per_stream), 4 * 1024 * 1024)
        self.assertEqual(late_data_per_stream_cap(65536, 16384), 8192)
        self.assertEqual(late_data_per_stream_cap(0, 1), 1024)
        self.assertEqual(aggregate_late_data_cap(16384), 64 * 1024)

    def test_receive_window_state_and_max_data_builder_clamp_edges(self):
        state = ReceiveWindowState(received=8, advertised=10, buffered=5)
        state.check_available(2)
        with self.assertRaises(ProtocolError) as ctx:
            state.check_available(3)
        self.assertEqual(ctx.exception.code, int(ErrorCode.FLOW_CONTROL))
        self.assertEqual(state.release_buffered(99), 5)
        self.assertEqual(state.pending, 5)

        frame = build_max_data_frame(0, MAX_VARINT62 + 100)
        self.assertEqual(frame.stream_id, 0)
        self.assertEqual(frame.payload, b"\xff\xff\xff\xff\xff\xff\xff\xff")
        with self.assertRaises(ValueError):
            build_max_data_frame(MAX_VARINT62 + 1, 1)

    def test_stream_id_ownership_and_initial_windows(self):
        self.assertEqual(first_local_stream_id(Role.INITIATOR, True), 4)
        self.assertEqual(first_local_stream_id(Role.INITIATOR, False), 2)
        self.assertEqual(first_peer_stream_id(Role.INITIATOR, True), 1)
        self.assertEqual(first_peer_stream_id(Role.INITIATOR, False), 3)
        self.assertTrue(stream_is_bidi(4))
        self.assertEqual(stream_kind_for_local(Role.INITIATOR, 2), (True, False))
        self.assertEqual(stream_kind_for_local(Role.INITIATOR, 3), (False, True))

        local = Settings(
            initial_max_stream_data_bidi_locally_opened=11,
            initial_max_stream_data_bidi_peer_opened=22,
            initial_max_stream_data_uni=33,
        )
        peer = Settings(
            initial_max_stream_data_bidi_locally_opened=44,
            initial_max_stream_data_bidi_peer_opened=55,
            initial_max_stream_data_uni=66,
        )
        self.assertEqual(initial_receive_window(Role.INITIATOR, local, 4), 11)
        self.assertEqual(initial_receive_window(Role.INITIATOR, local, 1), 22)
        self.assertEqual(initial_receive_window(Role.INITIATOR, local, 2), 0)
        self.assertEqual(initial_receive_window(Role.INITIATOR, local, 3), 33)
        self.assertEqual(initial_send_window(Role.INITIATOR, peer, 4), 55)
        self.assertEqual(initial_send_window(Role.INITIATOR, peer, 1), 44)
        self.assertEqual(initial_send_window(Role.INITIATOR, peer, 2), 66)
        self.assertEqual(initial_send_window(Role.INITIATOR, peer, 3), 0)


class RuntimeReadLoopBudgetTests(unittest.TestCase):
    def test_inbound_control_budget_skips_data_and_resets_by_window(self):
        tracker = InboundBudgetTracker(
            ReadLoopAbuseConfig(
                abuse_window=1.0,
                inbound_control_frame_budget=1,
                inbound_control_bytes_budget=1024,
                inbound_ext_frame_budget=100,
                inbound_ext_bytes_budget=1024,
                inbound_mixed_frame_budget=100,
                inbound_mixed_bytes_budget=4096,
            )
        )
        tracker.record_frame(Frame(FrameType.DATA, 1, 0, b"x" * 4096), now=1.0)
        tracker.record_frame(Frame(FrameType.PING, 0, 0, b"12345678"), now=1.1)
        with self.assertRaises(ProtocolError):
            tracker.record_frame(Frame(FrameType.PONG, 0, 0, b"12345678"), now=1.2)
        tracker.record_frame(Frame(FrameType.PONG, 0, 0, b"12345678"), now=2.3)

    def test_no_op_zero_data_clears_independently_from_ping_budget(self):
        tracker = InboundBudgetTracker(
            ReadLoopAbuseConfig(
                abuse_window=1.0,
                no_op_zero_data_budget=1,
                inbound_ping_budget=1,
            )
        )
        tracker.record_inbound_ping(now=1.0)
        tracker.update_no_op_zero_data(
            stream_existed=True, app_len=0, flags=0, now=1.1
        )
        with self.assertRaises(ProtocolError):
            tracker.update_no_op_zero_data(
                stream_existed=True, app_len=0, flags=0, now=1.2
            )
        tracker.update_no_op_zero_data(
            stream_existed=True, app_len=1, flags=0, now=1.3
        )
        tracker.update_no_op_zero_data(
            stream_existed=True, app_len=0, flags=0, now=1.35
        )
        with self.assertRaises(ProtocolError):
            tracker.record_inbound_ping(now=1.4)

        tracker.update_no_op_zero_data(
            stream_existed=False, app_len=0, flags=0, now=1.5
        )
        tracker.update_no_op_zero_data(
            stream_existed=True, app_len=0, flags=0, now=1.6
        )

    def test_late_data_tracker_uses_strict_greater_than_caps(self):
        tracker = LateDataTracker(aggregate_cap=4, per_stream_cap=3)
        tracker.record(3, LateDataCause.RESET, hidden=True)
        self.assertEqual(tracker.after_reset, 3)
        self.assertEqual(tracker.hidden_unread_discarded, 3)
        with self.assertRaises(ProtocolError):
            tracker.record(1, LateDataCause.ABORT)

    def test_churn_window_boundary_is_strictly_greater_than_window_like_java(self):
        tracker = InboundBudgetTracker(
            ReadLoopAbuseConfig(
                hidden_abort_churn_window=1.0,
                hidden_abort_churn_budget=1,
            )
        )
        tracker.record_hidden_abort_churn(now=1.0)
        with self.assertRaises(ProtocolError):
            tracker.record_hidden_abort_churn(now=2.0)


class RuntimeReadLoopProtocolQueueTests(unittest.TestCase):
    def test_protocol_queue_drops_pong_abort_overflow_but_rejects_other_tasks(self):
        queue = ReadLoopProtocolQueue(max_jobs=1)
        data = Frame(FrameType.DATA, 1, 0, b"x")
        pong = Frame(FrameType.PONG, 0, 0, b"12345678")
        self.assertTrue(queue.queue_frame(data))
        self.assertFalse(queue.queue_frame(pong))
        self.assertEqual(queue.snapshot().backlog_blocked, 1)
        with self.assertRaises(ProtocolError) as ctx:
            queue.enqueue(ProtocolTask(ProtocolTaskKind.QUEUE_FRAME, frame=data))
        self.assertEqual(ctx.exception.code, int(ErrorCode.INTERNAL))

        drained = []
        self.assertEqual(queue.drain(queue_frame=drained.append), 1)
        self.assertEqual(drained, [data])


class RuntimeReadLoopFrameClassificationTests(unittest.TestCase):
    def test_classifies_open_metadata_without_counting_metadata_as_app_data(self):
        caps = (
                CAPABILITY_OPEN_METADATA
                | CAPABILITY_PRIORITY_HINTS
                | CAPABILITY_STREAM_GROUPS
        )
        prefix = build_open_metadata_prefix(
            caps, priority=7, group=0, open_info=b"opaque"
        )
        frame = Frame(
            FrameType.DATA,
            1,
            FRAME_FLAG_OPEN_METADATA,
            prefix + b"abc",
        )
        parsed = classify_inbound_frame(frame, capabilities=caps)
        self.assertEqual(parsed.kind, ParsedFrameKind.DATA)
        self.assertEqual(parsed.app_data.tobytes(), b"abc")
        self.assertEqual(parsed.app_data_len, 3)
        self.assertTrue(parsed.metadata_valid)
        self.assertEqual(parsed.metadata.priority, 7)
        self.assertIsNone(parsed.metadata.group)
        self.assertEqual(parsed.metadata.open_info, b"opaque")

    def test_rejects_open_metadata_without_capability(self):
        caps = CAPABILITY_OPEN_METADATA
        prefix = build_open_metadata_prefix(caps, open_info=b"x")
        frame = Frame(FrameType.DATA, 1, FRAME_FLAG_OPEN_METADATA, prefix)
        with self.assertRaises(ProtocolError):
            classify_inbound_frame(frame, capabilities=0)
        with self.assertRaises(FrameSizeError):
            classify_inbound_frame(
                Frame(FrameType.DATA, 1, FRAME_FLAG_OPEN_METADATA, b"\x40"),
                capabilities=0,
            )

    def test_classifies_priority_update_and_invalid_duplicate_as_drop(self):
        caps = (
                CAPABILITY_PRIORITY_UPDATE
                | CAPABILITY_PRIORITY_HINTS
                | CAPABILITY_STREAM_GROUPS
        )
        payload = build_priority_update_payload(
            caps, MetadataUpdate(priority=5, group=0), 4096
        )
        parsed = classify_inbound_frame(
            Frame(FrameType.EXT, 1, 0, payload), capabilities=caps
        )
        self.assertEqual(parsed.kind, ParsedFrameKind.EXT)
        self.assertEqual(parsed.ext_type, 1)
        self.assertTrue(parsed.priority_update_valid)
        self.assertEqual(parsed.priority_update.priority, 5)
        self.assertEqual(parsed.priority_update.group, 0)

        duplicate_priority = bytes((1, 1, 1, 1, 1, 1, 2))
        parsed = classify_inbound_frame(
            Frame(FrameType.EXT, 1, 0, duplicate_priority), capabilities=caps
        )
        self.assertFalse(parsed.priority_update_valid)

    def test_go_away_watermarks_are_directional_local_and_non_increasing(self):
        payload = build_go_away_payload(4, 2, 0, "")
        parsed = classify_inbound_frame(
            Frame(FrameType.GOAWAY, 0, 0, payload),
            local_role=Role.INITIATOR,
            peer_go_away_bidi=4,
            peer_go_away_uni=2,
        )
        self.assertEqual(parsed.go_away.last_accepted_bidi, 4)

        with self.assertRaises(ProtocolError):
            validate_peer_go_away_payload(
                parsed.go_away,
                local_role=Role.RESPONDER,
                peer_go_away_bidi=4,
                peer_go_away_uni=2,
            )
        with self.assertRaises(ProtocolError):
            classify_inbound_frame(
                Frame(FrameType.GOAWAY, 0, 0, build_go_away_payload(8, 2, 0, "")),
                local_role=Role.INITIATOR,
                peer_go_away_bidi=4,
                peer_go_away_uni=2,
            )

    def test_ping_dispatch_queues_pong_and_read_loop_once_uses_frame_codec(self):
        frame = Frame(FrameType.PING, 0, 0, b"12345678")
        dispatcher = ReadLoopFrameDispatcher()
        result = read_loop_once(io.BytesIO(frame.marshal()), dispatcher)
        self.assertEqual(result.parsed.kind, ParsedFrameKind.PING)
        self.assertEqual(result.queued_frames, (Frame(FrameType.PONG, 0, 0, b"12345678"),))

        queue = ReadLoopProtocolQueue()
        dispatcher = ReadLoopFrameDispatcher(protocol_queue=queue)
        result = dispatcher.handle_frame(frame)
        self.assertEqual(result.queued_frames, ())
        self.assertEqual(queue.snapshot().length, 1)

    def test_short_ping_is_frame_size_error(self):
        with self.assertRaises(FrameSizeError):
            classify_inbound_frame(Frame(FrameType.PING, 0, 0, b"short"))

    def test_malformed_payloads_map_to_frame_size_errors_like_go(self):
        malformed = (
            Frame(FrameType.DATA, 1, FRAME_FLAG_OPEN_METADATA, b"\x40"),
            Frame(FrameType.MAX_DATA, 0, 0, b"\x40"),
            Frame(FrameType.BLOCKED, 0, 0, b"\x40"),
            Frame(FrameType.STOP_SENDING, 1, 0, b""),
            Frame(FrameType.RESET, 1, 0, b""),
            Frame(FrameType.ABORT, 1, 0, b""),
            Frame(FrameType.GOAWAY, 0, 0, b""),
            Frame(FrameType.CLOSE, 0, 0, b""),
            Frame(FrameType.EXT, 1, 0, b""),
        )
        for frame in malformed:
            with self.subTest(frame_type=frame.frame_type):
                with self.assertRaises(FrameSizeError):
                    classify_inbound_frame(
                        frame,
                        capabilities=CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_UPDATE,
                    )

        with self.assertRaises(ProtocolError) as ctx:
            classify_inbound_frame(Frame(FrameType.MAX_DATA, 0, 0, b"\x00x"))
        self.assertEqual(ctx.exception.code, int(ErrorCode.PROTOCOL))

    def test_abuse_config_derives_byte_budgets_from_config_settings(self):
        config = Config(
            settings=Settings(
                max_control_payload_bytes=8192,
                max_extension_payload_bytes=1024,
            )
        )
        abuse = ReadLoopAbuseConfig.from_config(config)
        self.assertEqual(abuse.inbound_control_bytes_budget, 8192 * 64)
        self.assertEqual(abuse.inbound_ext_bytes_budget, 256 * 1024)
        self.assertEqual(abuse.inbound_mixed_bytes_budget, 8192 * 64)

    def test_abuse_config_zero_overrides_use_go_defaults(self):
        config = Config(
            settings=Settings(
                max_control_payload_bytes=8192,
                max_extension_payload_bytes=1024,
            ),
            abuse_window=0.0,
            inbound_control_frame_budget=0,
            inbound_control_bytes_budget=0,
            inbound_ext_frame_budget=0,
            inbound_ext_bytes_budget=0,
            inbound_mixed_frame_budget=0,
            inbound_mixed_bytes_budget=0,
            ignored_control_budget=0,
            no_op_zero_data_budget=0,
            inbound_ping_budget=0,
            no_op_max_data_budget=0,
            no_op_blocked_budget=0,
            no_op_priority_update_budget=0,
            group_rebucket_churn_budget=0,
            hidden_abort_churn_window=0.0,
            hidden_abort_churn_threshold=0,
            visible_terminal_churn_window=0.0,
            visible_terminal_churn_threshold=0,
        )
        abuse = ReadLoopAbuseConfig.from_config(config)
        self.assertEqual(abuse.abuse_window, 0.0)
        self.assertEqual(abuse.inbound_control_frame_budget, DEFAULT_INBOUND_CONTROL_FRAME_BUDGET)
        self.assertEqual(abuse.inbound_control_bytes_budget, 8192 * 64)
        self.assertEqual(abuse.inbound_ext_frame_budget, DEFAULT_INBOUND_EXT_FRAME_BUDGET)
        self.assertEqual(abuse.inbound_ext_bytes_budget, 256 * 1024)
        self.assertEqual(abuse.inbound_mixed_frame_budget, DEFAULT_INBOUND_CONTROL_FRAME_BUDGET)
        self.assertEqual(abuse.inbound_mixed_bytes_budget, 8192 * 64)
        self.assertEqual(abuse.ignored_control_budget, DEFAULT_IGNORED_CONTROL_BUDGET)
        self.assertEqual(abuse.no_op_zero_data_budget, DEFAULT_NO_OP_ZERO_DATA_BUDGET)
        self.assertEqual(abuse.inbound_ping_budget, DEFAULT_INBOUND_PING_BUDGET)
        self.assertEqual(abuse.no_op_max_data_budget, DEFAULT_NO_OP_MAX_DATA_BUDGET)
        self.assertEqual(abuse.no_op_blocked_budget, DEFAULT_NO_OP_BLOCKED_BUDGET)
        self.assertEqual(
            abuse.no_op_priority_update_budget,
            DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET,
        )
        self.assertEqual(abuse.group_rebucket_churn_budget, DEFAULT_GROUP_REBUCKET_CHURN_BUDGET)
        self.assertEqual(abuse.hidden_abort_churn_window, 0.0)
        self.assertEqual(abuse.hidden_abort_churn_budget, DEFAULT_HIDDEN_ABORT_CHURN_BUDGET)
        self.assertEqual(abuse.visible_terminal_churn_window, 0.0)
        self.assertEqual(
            abuse.visible_terminal_churn_budget,
            DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET,
        )
        tracker = InboundBudgetTracker(abuse)
        tracker.record_frame(Frame(FrameType.PING, 0, 0, b"12345678"), now=1.0)

    def test_abuse_config_accepts_go_named_no_op_control_threshold(self):
        config = Config(ignored_control_budget=11, no_op_control_flood_threshold=22)

        abuse = ReadLoopAbuseConfig.from_config(config)

        self.assertEqual(abuse.ignored_control_budget, 22)
        self.assertEqual(
            abuse.group_rebucket_churn_budget,
            DEFAULT_GROUP_REBUCKET_CHURN_BUDGET,
        )
        self.assertEqual(
            abuse.hidden_abort_churn_window,
            DEFAULT_HIDDEN_ABORT_CHURN_WINDOW,
        )
        self.assertEqual(
            abuse.hidden_abort_churn_budget,
            DEFAULT_HIDDEN_ABORT_CHURN_BUDGET,
        )
        self.assertEqual(
            abuse.visible_terminal_churn_window,
            DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW,
        )
        self.assertEqual(
            abuse.visible_terminal_churn_budget,
            DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET,
        )


class RuntimeReadLoopBoundaryTests(unittest.TestCase):
    def test_read_loop_helpers_reject_python_invalid_input_shapes(self):
        frame = Frame(FrameType.PING, 0, 0, b"12345678")
        parsed = ParsedInboundFrame(frame, ParsedFrameKind.PING)

        with self.assertRaises(TypeError):
            ParsedInboundFrame(object(), ParsedFrameKind.PING)
        with self.assertRaises(TypeError):
            ParsedInboundFrame(frame, ParsedFrameKind.PING, metadata_valid=1)
        data_frame = Frame(FrameType.DATA, 1, 0, b"abcd")
        self.assertEqual(
            ParsedInboundFrame(
                data_frame,
                ParsedFrameKind.DATA,
                app_data_offset=1,
                app_data_len=2,
            ).app_data.tobytes(),
            b"bc",
        )
        with self.assertRaises(ValueError):
            ParsedInboundFrame(
                data_frame,
                ParsedFrameKind.DATA,
                app_data_offset=5,
            )
        with self.assertRaises(ValueError):
            ParsedInboundFrame(
                data_frame,
                ParsedFrameKind.DATA,
                app_data_offset=3,
                app_data_len=2,
            )
        with self.assertRaises(TypeError):
            ReadLoopDispatchResult(object())
        with self.assertRaises(ValueError):
            WindowedCounter(count=-1)
        with self.assertRaises(TypeError):
            WindowedCounter().record(window=True, budget=1, message="x")
        with self.assertRaises(TypeError):
            WindowedCounter().record(window=1.0, budget=True, message="x")
        with self.assertRaises(TypeError):
            WindowedCounter().record(
                window=1.0,
                budget=1,
                message="x",
                reset_on_equal=1,
            )
        with self.assertRaises(ValueError):
            TrafficBudgetCounter(frames=-1)
        with self.assertRaises(ValueError):
            TrafficBudgetCounter().record(
                payload_len=1,
                window=-1,
                frame_budget=1,
                byte_budget=1,
                message="x",
            )
        with self.assertRaises(ValueError):
            ReadLoopAbuseConfig(abuse_window=-1)
        with self.assertRaises(TypeError):
            ReadLoopAbuseConfig(inbound_control_frame_budget=True)
        with self.assertRaises(ValueError):
            ReceiveWindowState(received=-1)
        with self.assertRaises(TypeError):
            ReplenishDecision(1)
        with self.assertRaises(ValueError):
            LateDataTracker(aggregate_cap=-1)
        with self.assertRaises(TypeError):
            LateDataTracker().record(1, hidden=1)
        with self.assertRaises(TypeError):
            LateDataTracker().record(1, track_per_stream=1)
        with self.assertRaises(TypeError):
            LateDataTracker().record(1, cause=True)
        with self.assertRaises(TypeError):
            ProtocolTask(True)
        with self.assertRaises(ValueError):
            ProtocolTask(ProtocolTaskKind.CLOSE_WRITE, deadline=-1)
        with self.assertRaises(ValueError):
            ProtocolQueueSnapshot(-1, 0)
        with self.assertRaises(TypeError):
            ReadLoopProtocolQueue(max_jobs=True)
        queue = ReadLoopProtocolQueue()
        queue.enqueue(ProtocolTask(ProtocolTaskKind.QUEUE_FRAME, frame=frame))
        with self.assertRaises(TypeError):
            queue.drain(max_tasks=True)
        with self.assertRaises(TypeError):
            ReadLoopFrameDispatcher(capabilities=True)
        with self.assertRaises(TypeError):
            ReadLoopFrameDispatcher(local_role=True)
        with self.assertRaises(ValueError):
            ReadLoopFrameDispatcher(peer_go_away_bidi=-1)
        with self.assertRaises(TypeError):
            ReadLoopFrameDispatcher(budgets=object())
        with self.assertRaises(TypeError):
            ReadLoopFrameDispatcher(protocol_queue=object())
        with self.assertRaises(TypeError):
            validate_go_away_watermark_for_direction(4, 1)
        with self.assertRaises(TypeError):
            stream_id_previously_used(
                True,
                local_role=Role.INITIATOR,
                next_local_bidi=4,
                next_local_uni=2,
                next_peer_bidi=1,
                next_peer_uni=3,
            )

        self.assertIs(parsed.kind, ParsedFrameKind.PING)


if __name__ == "__main__":
    unittest.main()
