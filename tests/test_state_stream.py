import unittest

import zmux
from zmux._runtime.stream import (
    LocalOpenPhase,
    RecvHalfState,
    SendHalfState,
    StreamHalfState,
    TerminalKind,
)
from zmux._state.stream import (
    DataFrameTraits,
    LateDataCause,
    MetadataUpdateRoute,
    PendingStreamControlKind,
    PendingStreamFlag,
    PendingStreamQueueKind,
    PendingStreamState,
    ReceivedMetadataCarriage,
    StreamMetadataState,
    StreamSendAccountingState,
    StreamState,
    StreamTerminalState,
    TerminalAbortSource,
    TerminalResetSource,
    build_merged_priority_update_payload,
    data_frame_from_parts,
    frame_buffered_bytes,
    merge_pending_metadata_update,
    metadata_update_route,
    received_metadata_policy,
    single_part_payload_view,
)

FULL_METADATA_CAPS = int(
    zmux.Capability.OPEN_METADATA
    | zmux.Capability.PRIORITY_HINTS
    | zmux.Capability.STREAM_GROUPS
    | zmux.Capability.PRIORITY_UPDATE
)


class StreamMetadataStateTests(unittest.TestCase):
    def test_open_options_and_open_update_routing_follow_visibility(self):
        state = StreamMetadataState.from_open_options(
            zmux.OpenOptions(initial_priority=7, initial_group=0, open_info=b"hello")
        )
        self.assertEqual(state.metadata.priority, 7)
        self.assertIsNone(state.metadata.group)
        self.assertEqual(state.open_info(), b"hello")

        phase = state.local_open_phase(opened_locally=True)
        self.assertEqual(phase, LocalOpenPhase.NEEDS_COMMIT)
        self.assertEqual(
            metadata_update_route(
                phase,
                FULL_METADATA_CAPS,
                zmux.MetadataUpdate(priority=3),
            ),
            MetadataUpdateRoute.OPEN_METADATA,
        )
        with self.assertRaises(zmux.PriorityUpdateUnavailable):
            metadata_update_route(phase, 0, zmux.MetadataUpdate(priority=3))

        change = state.apply_metadata_update(
            zmux.MetadataUpdate(priority=3, group=9),
            FULL_METADATA_CAPS,
        )
        self.assertTrue(change.changed)
        self.assertTrue(change.group_changed())
        self.assertEqual(state.metadata.priority, 3)
        self.assertEqual(state.metadata.group, 9)

        prefix = state.build_opening_prefix(FULL_METADATA_CAPS)
        parsed = zmux.parse_data_payload(prefix, zmux.FRAME_FLAG_OPEN_METADATA)
        self.assertEqual(parsed.metadata.priority, 3)
        self.assertEqual(parsed.metadata.group, 9)
        self.assertEqual(parsed.open_info, b"hello")

    def test_received_metadata_and_pending_priority_merge_are_lossless(self):
        state = StreamMetadataState()
        ignored = state.apply_received_metadata(
            zmux.StreamMetadata(priority=8, group=4),
            int(zmux.Capability.OPEN_METADATA),
            ReceivedMetadataCarriage.OPEN,
        )
        self.assertFalse(ignored.changed)

        applied = state.apply_received_metadata(
            zmux.StreamMetadata(priority=8, group=4, open_info=b"x"),
            FULL_METADATA_CAPS,
            ReceivedMetadataCarriage.OPEN,
        )
        self.assertTrue(applied.changed)
        self.assertEqual(state.metadata, zmux.StreamMetadata(8, 4, b"x"))
        cleared = state.apply_received_metadata(
            zmux.StreamMetadata(priority=8, group=4, open_info=b""),
            FULL_METADATA_CAPS,
            ReceivedMetadataCarriage.OPEN,
        )
        self.assertTrue(cleared.changed)
        self.assertEqual(state.metadata.open_info, b"")

        state.apply_open_metadata(FULL_METADATA_CAPS, open_info=b"again")
        self.assertEqual(state.metadata.open_info, b"again")
        state.apply_open_metadata(FULL_METADATA_CAPS, open_info=b"")
        self.assertEqual(state.metadata.open_info, b"")

        pending_payload = zmux.build_priority_update_payload(
            FULL_METADATA_CAPS,
            zmux.MetadataUpdate(priority=2, group=6),
        )
        merged = merge_pending_metadata_update(
            zmux.MetadataUpdate(priority=10),
            pending_payload,
        )
        self.assertEqual(merged.priority, 10)
        self.assertEqual(merged.group, 6)

        payload = build_merged_priority_update_payload(
            FULL_METADATA_CAPS,
            zmux.MetadataUpdate(group=12),
            pending_payload,
        )
        parsed, valid = zmux.parse_priority_update_payload(payload)
        self.assertTrue(valid)
        self.assertEqual(parsed.priority, 2)
        self.assertEqual(parsed.group, 12)

    def test_stream_state_update_metadata_routes_and_merges_pending_priority(self):
        state = StreamState(
            stream_id=4,
            id_assigned=True,
            opened_locally=True,
        )

        route = state.update_metadata(
            zmux.MetadataUpdate(priority=3, group=7),
            FULL_METADATA_CAPS,
        )
        self.assertEqual(route, MetadataUpdateRoute.OPEN_METADATA)
        self.assertEqual(state.metadata.priority, 3)
        self.assertEqual(state.metadata.group, 7)
        self.assertFalse(state.pending.has_pending_priority_update())

        state.mark_send_committed()
        state.set_peer_visible()
        route = state.update_metadata(
            zmux.MetadataUpdate(priority=9, group=11),
            FULL_METADATA_CAPS,
        )
        self.assertEqual(route, MetadataUpdateRoute.PRIORITY_FRAME)
        self.assertTrue(state.pending.has_pending_priority_update())
        parsed, valid = zmux.parse_priority_update_payload(state.pending.priority)
        self.assertTrue(valid)
        self.assertEqual(parsed.priority, 9)
        self.assertEqual(parsed.group, 11)
        self.assertEqual(state.metadata.priority, 9)
        self.assertEqual(state.metadata.group, 11)

        state.update_metadata(zmux.MetadataUpdate(priority=10), FULL_METADATA_CAPS)
        parsed, valid = zmux.parse_priority_update_payload(state.pending.priority)
        self.assertTrue(valid)
        self.assertEqual(parsed.priority, 10)
        self.assertEqual(parsed.group, 11)

        with self.assertRaises(zmux.EmptyMetadataUpdate):
            state.update_metadata(zmux.MetadataUpdate(), FULL_METADATA_CAPS)

    def test_stream_state_update_metadata_rejects_unwritable_stream(self):
        recv_only = StreamState(
            stream_id=7,
            id_assigned=True,
            opened_locally=False,
            bidirectional=False,
        )
        with self.assertRaises(zmux.StreamNotWritable):
            recv_only.update_metadata(zmux.MetadataUpdate(priority=1), FULL_METADATA_CAPS)

        closed = StreamState(stream_id=4, id_assigned=True, opened_locally=True)
        closed.set_send_fin()
        with self.assertRaises(zmux.WriteClosed):
            closed.update_metadata(zmux.MetadataUpdate(priority=1), FULL_METADATA_CAPS)

    def test_visibility_gates_peer_visible_and_accept_queue_like_java(self):
        pending_local = StreamState(opened_locally=True)
        self.assertFalse(pending_local.should_mark_peer_visible())
        self.assertFalse(pending_local.awaiting_peer_visibility())

        committed_local = StreamState(
            stream_id=4,
            id_assigned=True,
            opened_locally=True,
        )
        self.assertTrue(committed_local.should_mark_peer_visible())
        self.assertTrue(committed_local.awaiting_peer_visibility())
        committed_local.set_peer_visible()
        self.assertFalse(committed_local.should_mark_peer_visible())
        self.assertFalse(committed_local.awaiting_peer_visibility())

        inbound = StreamState(
            stream_id=8,
            id_assigned=True,
            opened_locally=False,
        )
        self.assertFalse(inbound.lifecycle.application_visible)
        self.assertFalse(inbound.enqueue_accepted())
        inbound.lifecycle.mark_application_visible()
        self.assertTrue(inbound.enqueue_accepted())
        self.assertTrue(inbound.lifecycle.application_visible)
        self.assertTrue(inbound.lifecycle.accept_queued)
        self.assertTrue(inbound.queue.enqueued)
        self.assertFalse(inbound.enqueue_accepted())


class StreamAccountingAndPendingTests(unittest.TestCase):
    def test_send_accounting_saturates_and_clears_blocked_state(self):
        send = StreamSendAccountingState()
        send.initialize_peer_send_limit(10)
        send.reserve_send_bytes(5)
        send.reserve_queued_data_bytes(7)
        send.reserve_inflight_queued_bytes(3)
        send.mark_blocked_queued(10)
        self.assertTrue(send.blocked_queued)

        send.raise_peer_send_limit(11)
        self.assertFalse(send.blocked_queued)
        send.commit_reserved_send_bytes(2)
        self.assertEqual(send.reserved_send_bytes, 3)
        self.assertEqual(send.sent_bytes, 2)
        send.clear_pending_buffered_state()
        self.assertEqual(send.queued_data_bytes, 0)
        self.assertEqual(send.inflight_queued_bytes, 0)

    def test_pending_control_priority_and_terminal_state(self):
        pending = PendingStreamState()
        pending.set_pending_control_value(PendingStreamControlKind.MAX_DATA, 100)
        self.assertTrue(pending.skip_pending_control_queue(PendingStreamControlKind.MAX_DATA, 99))
        self.assertFalse(pending.skip_pending_control_queue(PendingStreamControlKind.MAX_DATA, 101))
        self.assertTrue(pending.in_pending_queue(PendingStreamQueueKind.MAX_DATA))

        pending.set_pending_priority_update(b"priority")
        self.assertTrue(pending.has_pending_priority_update())
        self.assertTrue(pending.in_pending_queue(PendingStreamQueueKind.PRIORITY))
        pending.set_pending_priority_update(b"")
        self.assertFalse(pending.has_pending_priority_update())

        metadata = StreamMetadataState()
        metadata.stage_priority_update(payload=b"")
        self.assertTrue(metadata.has_pending_priority_update())

        stop = zmux.build_error_payload(8, "stop")
        reset = zmux.build_error_payload(9, "reset")
        abort = zmux.build_error_payload(10, "abort")
        self.assertTrue(pending.set_terminal_stop(stop, stream_id=4).changed)
        self.assertTrue(pending.set_terminal_reset(reset, stream_id=4).changed)
        frames = pending.pending_terminal_frames(4)
        self.assertEqual(frame_buffered_bytes(frames[0]), 1 + len(stop))
        self.assertEqual(
            [frame.frame_type for frame in frames],
            [zmux.FrameType.STOP_SENDING, zmux.FrameType.RESET],
        )
        self.assertEqual(
            pending.pending_terminal_control_bytes(),
            sum(frame_buffered_bytes(frame) for frame in frames),
        )
        opener = zmux.Frame(zmux.FrameType.DATA, 4, zmux.FRAME_FLAG_OPEN_METADATA, b"m")
        pending.set_terminal_opener(opener, stream_id=4)
        frames = pending.pending_terminal_frames(4)
        self.assertEqual(frames[0], opener)
        self.assertEqual(
            pending.pending_terminal_control_bytes(),
            sum(frame_buffered_bytes(frame) for frame in frames),
        )

        result = pending.set_terminal_abort(abort, stream_id=4)
        self.assertTrue(result.changed)
        self.assertTrue(result.superseded)
        self.assertTrue(pending.flags & PendingStreamFlag.TERMINAL_ABORT)
        self.assertFalse(pending.flags & PendingStreamFlag.TERMINAL_STOP)
        self.assertEqual(
            [frame.frame_type for frame in pending.pending_terminal_frames(4)],
            [zmux.FrameType.ABORT],
        )


class StreamTerminalStateTests(unittest.TestCase):
    def test_terminal_error_priority_preserves_source_and_kind(self):
        terminal = StreamTerminalState()
        half = StreamHalfState(True, True)
        terminal.record_peer_stop_sending(42, "stop")
        half.mark_send_stop_seen()
        err = terminal.operation_error(half)
        self.assertIsInstance(err, zmux.WriteClosed)
        self.assertEqual(err.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(err.termination_kind, zmux.TerminationKind.STOPPED)

        terminal = StreamTerminalState()
        half = StreamHalfState(True, True)
        terminal.record_peer_reset(43, "reset")
        half.mark_recv_reset()
        err = terminal.operation_error(half)
        self.assertIsInstance(err, zmux.ApplicationError)
        self.assertEqual(err.application_code, 43)
        self.assertEqual(err.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(err.direction, zmux.ErrorDirection.READ)
        self.assertEqual(err.termination_kind, zmux.TerminationKind.RESET)

    def test_session_close_errors_are_directional(self):
        terminal = StreamTerminalState()
        close_error = zmux.ApplicationError(7, "closing")
        close_error.with_source(zmux.ErrorSource.REMOTE)
        terminal.record_session_close(
            close_error,
            close_write_half=True,
            close_read_half=False,
        )
        self.assertIsNotNone(terminal.send_close_error)
        self.assertIsNone(terminal.recv_close_error)
        self.assertEqual(terminal.send_close_error.direction, zmux.ErrorDirection.WRITE)
        self.assertEqual(
            terminal.send_close_error.termination_kind,
            zmux.TerminationKind.SESSION_TERMINATION,
        )

    def test_terminal_state_rejects_non_bool_direction_flags(self):
        terminal = StreamTerminalState()
        close_error = zmux.ApplicationError(7, "closing")
        with self.assertRaises(TypeError):
            terminal.record_session_close(
                close_error,
                close_write_half=1,
                close_read_half=False,
            )
        with self.assertRaises(TypeError):
            terminal.read_error(
                local_receive=1,
                local_read_stop=False,
                recv_half=RecvHalfState.OPEN,
            )


class AggregateStreamStateTests(unittest.TestCase):
    def test_visibility_receive_release_and_compaction(self):
        state = StreamState(
            stream_id=4,
            id_assigned=True,
            opened_locally=True,
            metadata_state=StreamMetadataState.from_open_options(
                zmux.OpenOptions(initial_priority=5, open_info=b"hi")
            ),
        )
        self.assertEqual(state.visibility_phase(), LocalOpenPhase.NEEDS_COMMIT)
        self.assertTrue(state.blocks_graceful_session_close())
        self.assertTrue(state.should_reclaim_unseen_local(0, 99))

        retained = state.append_read_data(b"abcdef")
        self.assertEqual(retained, 6)
        self.assertEqual(state.receive.recv_buffer, 6)
        self.assertEqual(state.receive.recv_pending, 0)
        self.assertEqual(state.read(2), b"ab")
        self.assertEqual(state.receive.recv_buffer, 4)
        self.assertEqual(state.receive.recv_pending, 2)

        state.set_recv_stop_sent(8)
        self.assertEqual(state.late_data_cause(), LateDataCause.CLOSE_READ)
        self.assertEqual(len(state.read_buffer), 0)
        self.assertEqual(state.receive.recv_buffer, 0)
        self.assertEqual(state.receive.recv_pending, 0)

        state.set_aborted_with_source(99, "boom", TerminalAbortSource.LOCAL)
        self.assertTrue(state.fully_terminal())
        self.assertTrue(state.should_compact_terminal(still_tracked=True))
        tombstone = state.tombstone_state()
        self.assertEqual(tombstone.terminal_kind, TerminalKind.ABORTED)
        self.assertTrue(tombstone.has_terminal_code)
        self.assertEqual(tombstone.terminal_code, 99)

        peer_abort = StreamState(stream_id=8, id_assigned=True)
        peer_abort.set_aborted_with_source(77, "peer abort", TerminalAbortSource.PEER)
        tombstone = peer_abort.tombstone_state()
        self.assertEqual(tombstone.terminal_kind, TerminalKind.ABORTED)
        self.assertTrue(tombstone.has_terminal_code)
        self.assertEqual(tombstone.terminal_code, 77)

    def test_half_state_setters_and_data_frame_building(self):
        state = StreamState(
            stream_id=4,
            id_assigned=True,
            opened_locally=True,
            metadata_state=StreamMetadataState.from_open_options(
                zmux.OpenOptions(initial_priority=1, open_info=b"open")
            ),
        )
        frame = state.data_frame(
            b"tail",
            DataFrameTraits.OPEN_METADATA | DataFrameTraits.FIN,
            capabilities=FULL_METADATA_CAPS,
        )
        self.assertEqual(frame.frame_type, zmux.FrameType.DATA)
        self.assertTrue(frame.flags & zmux.FRAME_FLAG_OPEN_METADATA)
        self.assertTrue(frame.flags & zmux.FRAME_FLAG_FIN)
        parsed = zmux.parse_data_payload(frame.payload, frame.flags)
        self.assertEqual(parsed.open_info, b"open")
        self.assertEqual(parsed.app_data, b"tail")

        plain = state.data_frame(b"plain", DataFrameTraits.NONE, capabilities=0)
        self.assertEqual(plain.flags, 0)
        self.assertEqual(plain.payload, b"plain")

        parts = (b"ab", b"cdef", b"gh")
        view, ok = single_part_payload_view(parts, 1, 1, 3)
        self.assertTrue(ok)
        self.assertEqual(view.tobytes(), b"def")
        view, ok = single_part_payload_view(parts, 0, 1, 4)
        self.assertFalse(ok)

        frame = data_frame_from_parts(4, b"", parts, 0, 1, 4, DataFrameTraits.NONE)
        self.assertEqual(frame.payload, b"bcde")

        state.set_send_stop_seen(44, "stop")
        self.assertEqual(state.half.effective_send_half(), SendHalfState.STOP_SEEN)
        state.pending.set_pending_control_value(PendingStreamControlKind.BLOCKED, 12)
        state.pending.set_pending_priority_update(b"priority")
        state.set_send_fin()
        self.assertEqual(state.half.effective_send_half(), SendHalfState.FIN)
        self.assertFalse(state.pending.in_pending_queue(PendingStreamQueueKind.BLOCKED))
        self.assertFalse(state.pending.has_pending_priority_update())
        state.clear_send_fin()
        self.assertEqual(state.half.effective_send_half(), SendHalfState.STOP_SEEN)
        state.pending.set_pending_control_value(PendingStreamControlKind.BLOCKED, 16)
        state.pending.set_pending_priority_update(b"priority")
        state.set_send_reset_with_source(
            45,
            "reset",
            TerminalResetSource.FROM_STOP_SENDING,
        )
        self.assertEqual(state.half.effective_send_half(), SendHalfState.RESET)
        self.assertTrue(state.half.send_reset_from_stop)
        self.assertFalse(state.pending.in_pending_queue(PendingStreamQueueKind.BLOCKED))
        self.assertFalse(state.pending.has_pending_priority_update())
        state.set_send_fin()
        self.assertFalse(state.half.send_reset_from_stop)
        state.set_send_reset_with_source(
            47,
            "reset from stop",
            TerminalResetSource.FROM_STOP_SENDING,
        )
        self.assertTrue(state.half.send_reset_from_stop)
        state.set_send_abort_with_source(48, "abort")
        self.assertFalse(state.half.send_reset_from_stop)
        state.set_recv_reset(46, "peer reset")
        self.assertEqual(state.half.effective_recv_half(), RecvHalfState.RESET)

    def test_stream_state_rejects_non_bool_flags(self):
        with self.assertRaises(TypeError):
            StreamState(id_assigned=1)
        with self.assertRaises(TypeError):
            StreamState(bidirectional=1)
        with self.assertRaises(TypeError):
            StreamState(local_send=1)

        state = StreamState(stream_id=4, id_assigned=True, opened_locally=True)
        with self.assertRaises(TypeError):
            state.should_compact_terminal(still_tracked=1)

    def test_metadata_and_pending_state_reject_non_bool_flags(self):
        metadata = StreamMetadataState()
        with self.assertRaises(TypeError):
            metadata.local_open_phase(1)
        with self.assertRaises(TypeError):
            metadata.should_mark_peer_visible(True, 1)
        with self.assertRaises(TypeError):
            metadata.apply_priority_update(FULL_METADATA_CAPS, zmux.StreamMetadata(), valid=1)
        with self.assertRaises(TypeError):
            metadata.stage_priority_update(group=1, group_present=1)
        with self.assertRaises(TypeError):
            metadata_update_route(True, FULL_METADATA_CAPS, zmux.MetadataUpdate(priority=1))

        with self.assertRaises(TypeError):
            received_metadata_policy(FULL_METADATA_CAPS, True)

        pending = PendingStreamState()
        with self.assertRaises(TypeError):
            pending.pending_control_value(True)
        with self.assertRaises(TypeError):
            pending.set_pending_priority_update(1)
        with self.assertRaises(TypeError):
            pending.set_terminal_stop(1)
        with self.assertRaises(TypeError):
            pending.skip_pending_control_queue(
                PendingStreamControlKind.MAX_DATA,
                1,
                blocked_queued=1,
            )
        with self.assertRaises(TypeError):
            pending.pending_control_flush_state(
                PendingStreamControlKind.MAX_DATA,
                id_assigned=1,
                local_send=True,
                local_receive=True,
                phase=LocalOpenPhase.PEER_VISIBLE,
                read_stopped=False,
                recv_terminal_value=False,
                send_half=SendHalfState.OPEN,
            )

        state = StreamState(stream_id=4, id_assigned=True, opened_locally=True)
        with self.assertRaises(TypeError):
            state.data_frame(b"data", True)
        with self.assertRaises(TypeError):
            data_frame_from_parts(4, 1, (b"ab",), 0, 0, 1, DataFrameTraits.NONE)
        with self.assertRaises(TypeError):
            data_frame_from_parts(4, b"", (b"ab",), 0, 0, 1, True)
        with self.assertRaises(TypeError):
            data_frame_from_parts(4, b"", (b"ab",), True, 0, 1, DataFrameTraits.NONE)
        with self.assertRaises(TypeError):
            single_part_payload_view((b"ab",), 0, 0, True)
        with self.assertRaises(TypeError):
            state.set_send_reset_with_source(1, source=True)
        with self.assertRaises(TypeError):
            state.set_send_abort_with_source(1, source=True)


if __name__ == "__main__":
    unittest.main()
