import unittest

import zmux
import zmux._runtime as runtime_package
from zmux._runtime import control as runtime
from zmux._runtime.control import (
    AdvisoryHandoffPlan,
    DEFAULT_URGENCY_RANK,
    PendingControlMetrics,
    PendingControlState,
    PendingControlValue,
    PendingPriorityQueueResult,
    PendingPriorityQueueStatus,
    PendingTxFrameCollector,
    PreparedPriorityUpdate,
    PriorityUpdatePlan,
    SessionControlKind,
    StreamControlKind,
    WriteLane,
    WriteRequest,
    append_priority_update_payload,
    build_pending_priority_update_frame,
    build_priority_update_payload,
    frame_buffered_bytes,
    is_urgent_type,
    make_pending_varint_control_frame,
    parse_priority_update_payload,
    pending_stream_control_bytes,
    plan_pending_priority_update,
    plan_priority_advisory_handoff,
    project_tracked_memory_delta,
    session_control_frame_type,
    stream_control_frame_type,
    urgency_rank,
)
from zmux.varint import parse_varint


class RuntimeControlTest(unittest.TestCase):
    def test_runtime_package_keeps_control_helpers_in_explicit_module(self) -> None:
        self.assertEqual(runtime_package.__all__, ())
        self.assertEqual(runtime.DEFAULT_URGENCY_RANK, DEFAULT_URGENCY_RANK)
        self.assertIs(runtime.PriorityUpdatePlan, PriorityUpdatePlan)
        self.assertIs(runtime.AdvisoryHandoffPlan, AdvisoryHandoffPlan)
        self.assertEqual(runtime.urgency_rank(zmux.FrameType.PING), 8)
        self.assertFalse(runtime.is_urgent_type(zmux.FrameType.DATA))
        self.assertTrue(runtime.plan_pending_priority_update(0, 0, 0, 1, 1, 1).accept)
        self.assertIn("project_tracked_memory_delta", runtime.__all__)

    def test_control_go_urgency_and_memory_projection_helpers(self) -> None:
        urgent_order = (
            (zmux.FrameType.CLOSE, 0),
            (zmux.FrameType.GOAWAY, 1),
            (zmux.FrameType.ABORT, 2),
            (zmux.FrameType.RESET, 3),
            (zmux.FrameType.STOP_SENDING, 4),
            (zmux.FrameType.MAX_DATA, 5),
            (zmux.FrameType.BLOCKED, 6),
            (zmux.FrameType.PONG, 7),
            (zmux.FrameType.PING, 8),
        )

        for frame_type, rank in urgent_order:
            self.assertTrue(is_urgent_type(frame_type))
            self.assertEqual(urgency_rank(frame_type), rank)
        self.assertFalse(is_urgent_type(zmux.FrameType.DATA))
        self.assertEqual(urgency_rank(zmux.FrameType.DATA), DEFAULT_URGENCY_RANK)
        self.assertEqual(urgency_rank(int(zmux.FrameType.PING)), 8)

        self.assertEqual(project_tracked_memory_delta(10, 3, 5), 12)
        self.assertEqual(project_tracked_memory_delta(10, 99, 5), 5)
        self.assertEqual(
            project_tracked_memory_delta((1 << 64) - 1, 0, 1),
            (1 << 64) - 1,
        )

        accepted = plan_pending_priority_update(100, 30, 10, 20, 50, 200)
        self.assertEqual(accepted.next_pending_bytes, 40)
        self.assertEqual(accepted.projected_tracked, 110)
        self.assertTrue(accepted.accept)

        over_budget = plan_pending_priority_update(100, 30, 0, 60, 50, 200)
        self.assertEqual(over_budget.next_pending_bytes, 90)
        self.assertFalse(over_budget.accept)

        over_cap = plan_priority_advisory_handoff(100, 10, 50, 120)
        self.assertEqual(over_cap.projected_tracked, 140)
        self.assertFalse(over_cap.accept)

    def test_pending_control_coalesces_and_drains_in_go_order(self) -> None:
        state = PendingControlState(max_write_batch_frames=8)

        self.assertTrue(state.queue_stream_blocked(8, 11))
        self.assertTrue(state.queue_stream_blocked(4, 10))
        self.assertFalse(state.queue_stream_blocked(4, 10))
        self.assertTrue(state.queue_stream_max_data(8, 21))
        self.assertTrue(state.queue_stream_max_data(4, 20))
        self.assertTrue(state.queue_stream_max_data(4, 19))
        self.assertTrue(
            state.queue_pending_session_control(SessionControlKind.BLOCKED, 30)
        )
        self.assertTrue(state.ensure_pending_session_max_data(40))
        self.assertFalse(
            state.queue_pending_session_control(SessionControlKind.MAX_DATA, 39)
        )
        self.assertTrue(state.has_pending_control_work())

        snapshot = state.snapshot()
        self.assertTrue(snapshot.has_session_max_data)
        self.assertTrue(snapshot.has_session_blocked)
        self.assertEqual(snapshot.stream_max_data_count, 2)
        self.assertEqual(snapshot.stream_blocked_count, 2)
        self.assertEqual(state.recompute_control_bytes(), snapshot.control_bytes)

        result = state.take_pending_urgent_control_request()
        self.assertTrue(result.has_request())
        self.assertIsNone(result.error)
        request = result.request
        self.assertEqual(request.lane, WriteLane.URGENT)
        self.assertTrue(request.urgent_reserved)
        self.assertEqual(
            [(frame.frame_type, frame.stream_id) for frame in request.frames],
            [
                (zmux.FrameType.MAX_DATA, 0),
                (zmux.FrameType.MAX_DATA, 4),
                (zmux.FrameType.MAX_DATA, 8),
                (zmux.FrameType.BLOCKED, 0),
                (zmux.FrameType.BLOCKED, 4),
                (zmux.FrameType.BLOCKED, 8),
            ],
        )
        self.assertEqual(
            [parse_varint(frame.payload)[0] for frame in request.frames],
            [40, 20, 21, 30, 10, 11],
        )
        self.assertFalse(state.has_pending_control_work())
        self.assertEqual(state.snapshot().control_bytes, 0)
        self.assertFalse(
            state.queue_pending_session_control(SessionControlKind.BLOCKED, 30)
        )
        state.clear_session_blocked_state()
        self.assertTrue(
            state.queue_pending_session_control(SessionControlKind.BLOCKED, 30)
        )

        dropped = PendingControlState()
        self.assertTrue(
            dropped.queue_pending_session_control(SessionControlKind.BLOCKED, 7)
        )
        self.assertTrue(dropped.drop_pending_session_control(SessionControlKind.BLOCKED))
        self.assertFalse(
            dropped.queue_pending_session_control(SessionControlKind.BLOCKED, 7)
        )
        dropped.clear_session_blocked_state()
        self.assertTrue(
            dropped.queue_pending_session_control(SessionControlKind.BLOCKED, 7)
        )

    def test_pending_control_budget_and_goaway_force_accounting(self) -> None:
        state = PendingControlState(pending_control_budget=1)

        self.assertFalse(state.queue_stream_max_data(4, zmux.MAX_VARINT62))
        self.assertEqual(state.snapshot().stream_max_data_count, 0)

        payload = b"x" * 128
        self.assertTrue(state.set_pending_goaway_payload(payload))
        self.assertEqual(state.snapshot().pending_goaway_bytes, len(payload))
        self.assertEqual(state.snapshot().control_bytes, len(payload))
        state.clear_pending_goaway()
        self.assertEqual(state.snapshot().control_bytes, 0)

    def test_collector_admits_first_frame_and_then_stops_on_limits(self) -> None:
        frame = make_pending_varint_control_frame(zmux.FrameType.MAX_DATA, 0, 1)
        collector = PendingTxFrameCollector(max_frames=1, max_bytes=1)

        self.assertGreater(frame_buffered_bytes(frame), 1)
        self.assertTrue(collector.append(frame))
        self.assertTrue(collector.stopped)
        self.assertFalse(collector.append(frame))
        self.assertEqual(len(collector.as_tuple()), 1)

    def test_priority_update_queue_build_parse_and_drain(self) -> None:
        caps = int(
            zmux.Capability.PRIORITY_UPDATE
            | zmux.Capability.PRIORITY_HINTS
            | zmux.Capability.STREAM_GROUPS
        )
        update = zmux.MetadataUpdate(priority=7, group=9)
        payload = build_priority_update_payload(caps, update, 1024)
        appended = bytearray()

        self.assertEqual(
            append_priority_update_payload(appended, caps, update, 1024),
            payload,
        )
        self.assertEqual(bytes(appended), payload)
        metadata, valid = parse_priority_update_payload(payload)
        self.assertTrue(valid)
        self.assertEqual(metadata.priority, 7)
        self.assertEqual(metadata.group, 9)

        state = PendingControlState(
            pending_priority_budget=len(payload),
            max_write_batch_frames=1,
        )
        result = state.queue_priority_update(4, payload)
        self.assertTrue(result.accepted())
        self.assertEqual(state.snapshot().priority_update_count, 1)

        request_result = state.take_pending_priority_update_request()
        self.assertTrue(request_result.has_request())
        request = request_result.request
        self.assertEqual(request.lane, WriteLane.ADVISORY)
        self.assertTrue(request.advisory_reserved)
        self.assertEqual(len(request.frames), 1)
        self.assertEqual(request.frames[0].frame_type, zmux.FrameType.EXT)
        self.assertEqual(request.frames[0].stream_id, 4)
        self.assertEqual(request.frames[0].payload, payload)
        self.assertEqual(state.snapshot().priority_bytes, 0)

    def test_priority_update_handoff_respects_session_memory_cap(self) -> None:
        state = PendingControlState(
            pending_priority_budget=1024,
            session_memory_hard_cap=1,
        )

        self.assertTrue(state.queue_priority_update(4, b"\x01").accepted())
        self.assertTrue(state.snapshot().priority_update_count)
        result = state.take_pending_priority_update_request()
        self.assertFalse(result.has_request())
        self.assertEqual(state.snapshot().priority_update_count, 0)
        self.assertEqual(state.snapshot().priority_bytes, 0)

        state = PendingControlState(
            pending_priority_budget=1024,
            session_memory_hard_cap=1,
        )
        self.assertTrue(state.queue_priority_update(4, b"\x01").accepted())
        prepared = state.take_pending_priority_update_frame(4)
        self.assertFalse(prepared.has_frame())
        self.assertEqual(state.snapshot().priority_update_count, 0)
        self.assertEqual(state.snapshot().priority_bytes, 0)

    def test_urgent_control_handoff_reports_session_memory_cap_error(self) -> None:
        state = PendingControlState(
            pending_control_budget=1024,
            session_memory_hard_cap=1,
        )

        self.assertTrue(state.ensure_pending_session_max_data(1))
        result = state.take_pending_urgent_control_request()
        self.assertFalse(result.has_request())
        self.assertIsInstance(result.error, zmux.ProtocolError)
        self.assertIn("session memory cap exceeded", str(result.error))
        self.assertEqual(state.snapshot().control_bytes, 0)

    def test_priority_update_rejections_are_structured(self) -> None:
        payload = b"0123456789"

        budgeted = PendingControlState(pending_priority_budget=1)
        budget_result = budgeted.queue_priority_update(4, payload)
        self.assertEqual(
            budget_result.status,
            PendingPriorityQueueStatus.DROPPED_BUDGET,
        )
        self.assertIsInstance(budget_result.structured_error(), zmux.ProtocolError)

        capped = PendingControlState(
            pending_priority_budget=1024,
            session_memory_hard_cap=1,
        )
        memory_result = capped.queue_priority_update(4, payload)
        self.assertEqual(
            memory_result.status,
            PendingPriorityQueueStatus.DROPPED_MEMORY,
        )
        self.assertIsInstance(memory_result.structured_error(), zmux.ProtocolError)

        closed = PendingControlState(allow_non_close_control=False)
        unavailable = closed.queue_priority_update(4, payload)
        self.assertEqual(
            unavailable.status,
            PendingPriorityQueueStatus.DROPPED_UNAVAILABLE,
        )
        self.assertIsInstance(unavailable.structured_error(), zmux.SessionClosed)
        self.assertIsInstance(
            PendingPriorityQueueResult().structured_error(),
            zmux.ProtocolError,
        )

    def test_terminal_frames_clear_when_non_close_control_disallowed(self) -> None:
        state = PendingControlState()
        reset = zmux.Frame(
            zmux.FrameType.RESET,
            4,
            0,
            zmux.build_error_payload(int(zmux.ErrorCode.CANCELLED), "stop"),
        )

        self.assertTrue(
            state.set_pending_terminal_frames(4, (reset,), coalesced=True)
        )
        self.assertEqual(state.snapshot().terminal_count, 1)
        self.assertEqual(state.snapshot().metrics.coalesced_terminal_signals, 1)
        self.assertTrue(state.set_pending_goaway_payload(b"bye"))

        state.allow_non_close_control = False
        self.assertFalse(state.ensure_pending_non_close_control())
        snapshot = state.snapshot()
        self.assertEqual(snapshot.terminal_count, 0)
        self.assertEqual(snapshot.pending_goaway_bytes, 3)
        self.assertEqual(snapshot.control_bytes, 3)

    def test_terminal_frame_bundle_drains_atomically_with_tiny_batch_limit(self) -> None:
        state = PendingControlState(max_write_batch_frames=1)
        stop = zmux.Frame(
            zmux.FrameType.STOP_SENDING,
            4,
            0,
            zmux.build_error_payload(int(zmux.ErrorCode.CANCELLED), ""),
        )
        reset = zmux.Frame(
            zmux.FrameType.RESET,
            4,
            0,
            zmux.build_error_payload(int(zmux.ErrorCode.CANCELLED), ""),
        )

        self.assertTrue(state.set_pending_terminal_frames(4, (stop, reset)))
        first = state.take_pending_urgent_control_request().request
        self.assertEqual(
            [frame.frame_type for frame in first.frames],
            [zmux.FrameType.STOP_SENDING, zmux.FrameType.RESET],
        )
        self.assertEqual(state.snapshot().terminal_count, 0)
        second = state.take_pending_urgent_control_request()
        self.assertFalse(second.has_request())

    def test_prepared_priority_update_can_restore_or_release(self) -> None:
        state = PendingControlState(pending_priority_budget=1024)
        payload = b"\x01"

        self.assertTrue(state.queue_priority_update(4, payload).accepted())
        prepared = state.take_pending_priority_update_frame(4)
        self.assertTrue(prepared.has_frame())
        self.assertEqual(state.snapshot().prepared_priority_bytes, prepared.frame_bytes)
        self.assertEqual(prepared.frame().payload, payload)

        self.assertTrue(state.restore_prepared_priority_update(prepared))
        self.assertEqual(state.snapshot().prepared_priority_bytes, 0)
        self.assertEqual(state.snapshot().priority_update_count, 1)
        self.assertFalse(PreparedPriorityUpdate(4, payload, 0).has_frame())

    def test_pending_stream_control_byte_cost_uses_canonical_varints(self) -> None:
        self.assertEqual(pending_stream_control_bytes(4, 63), 2)
        self.assertEqual(pending_stream_control_bytes(64, 64), 4)
        with self.assertRaises(ValueError):
            make_pending_varint_control_frame(zmux.FrameType.MAX_DATA, 0, -1)
        with self.assertRaises(ValueError):
            PendingControlState().set_pending_stream_control(
                StreamControlKind.MAX_DATA,
                0,
                1,
            )

    def test_control_helpers_reject_python_invalid_input_shapes(self) -> None:
        with self.assertRaises(TypeError):
            PriorityUpdatePlan(0, 0, 1)
        with self.assertRaises(TypeError):
            AdvisoryHandoffPlan(0, 1)
        with self.assertRaises(TypeError):
            PendingControlValue(1, 1)
        with self.assertRaises(ValueError):
            PendingControlMetrics(coalesced_terminal_signals=-1)
        with self.assertRaises(TypeError):
            PendingPriorityQueueResult(True)
        with self.assertRaises(TypeError):
            PreparedPriorityUpdate(4, 1, 1)
        with self.assertRaises(TypeError):
            PreparedPriorityUpdate(True, b"x", 1)
        with self.assertRaises(ValueError):
            PreparedPriorityUpdate(4, b"x", -1)
        with self.assertRaises(TypeError):
            PendingControlState().set_pending_goaway_payload(1)
        with self.assertRaises(TypeError):
            PendingControlState().queue_priority_update(4, 1)
        with self.assertRaises(TypeError):
            build_pending_priority_update_frame(4, 1)
        with self.assertRaises(TypeError):
            parse_priority_update_payload(1)
        with self.assertRaises(TypeError):
            WriteRequest((), 0, clone_frames_before_send=1)
        with self.assertRaises(TypeError):
            WriteRequest((), 0, lane=True)
        with self.assertRaises(TypeError):
            PendingTxFrameCollector(max_frames=True)
        with self.assertRaises(ValueError):
            PendingTxFrameCollector(max_bytes=-1)
        with self.assertRaises(TypeError):
            PendingControlState(max_write_batch_frames=True)
        with self.assertRaises(TypeError):
            PendingControlState(allow_non_close_control=1)
        with self.assertRaises(TypeError):
            PendingControlState().set_pending_terminal_frames(
                4,
                (),
                coalesced=1,
            )
        with self.assertRaises(TypeError):
            session_control_frame_type(True)
        with self.assertRaises(TypeError):
            stream_control_frame_type(True)
        with self.assertRaises(TypeError):
            is_urgent_type(True)

    def test_prepared_priority_release_rejects_negative_counts(self) -> None:
        state = PendingControlState(pending_priority_budget=1024)
        payload = b"\x01"

        self.assertTrue(state.queue_priority_update(4, payload).accepted())
        prepared = state.take_pending_priority_update_frame(4)
        self.assertEqual(state.snapshot().prepared_priority_bytes, prepared.frame_bytes)
        with self.assertRaises(ValueError):
            state.release_prepared_priority_bytes(-1)
        self.assertEqual(state.snapshot().prepared_priority_bytes, prepared.frame_bytes)


if __name__ == "__main__":
    unittest.main()
