import array
import unittest

import zmux
from zmux._runtime.stream import (
    LateDataAction,
    LocalAbortAction,
    LocalOpenPhase,
    LocalOpenVisibility,
    LocalRecvAction,
    LocalSendAction,
    PeerDataOutcome,
    PeerStreamControlAction,
    PendingTerminalKind,
    PendingTerminalState,
    RecvHalfState,
    SendHalfState,
    StopSendingOutcome,
    StreamAddr,
    StreamHalfState,
    StreamReadBuffer,
    StreamReceiveReleaseMode,
    StreamReceiveReleaseTraits,
    StreamRuntimeState,
    StreamWaitState,
    TerminalDataIntent,
    TerminalErrorChoice,
    TerminalKind,
    TerminalOpenerPolicy,
    TerminalResetSource,
    TerminalSignalKind,
    advance_parts,
    build_stream_tombstone,
    checked_total_part_len,
    deadline_expired,
    deadline_remaining,
    effective_deadline,
    fully_terminal,
    local_abort_action_for_stream,
    local_close_read_action,
    local_close_write_action,
    merge_pending_priority_update,
    peer_blocked_action,
    peer_data_transition,
    peer_max_data_action,
    plan_peer_abort,
    plan_peer_reset,
    plan_peer_stop_sending,
    read_chunk_overhead_bytes,
    read_error_choice,
    session_close_transition,
    should_advertise_blocked,
    should_advertise_max_data,
    should_flush_priority_update,
    should_flush_stream_blocked,
    should_flush_stream_max_data,
    should_reclaim_unseen_local_stream,
    should_tighten_read_buf_after_consume,
    terminal_error_priority,
    timeout_to_deadline,
)


class StreamHalfStateTests(unittest.TestCase):
    def test_half_state_action_tables_match_go_reference(self):
        self.assertFalse(
            fully_terminal(True, True, SendHalfState.FIN, RecvHalfState.STOP_SENT)
        )
        self.assertTrue(
            fully_terminal(True, True, SendHalfState.RESET, RecvHalfState.FIN)
        )
        self.assertTrue(
            fully_terminal(True, True, SendHalfState.OPEN, RecvHalfState.ABORTED)
        )

        self.assertEqual(
            local_close_write_action(False, SendHalfState.ABSENT),
            LocalSendAction.NOT_WRITABLE,
        )
        self.assertEqual(
            local_close_write_action(True, SendHalfState.OPEN),
            LocalSendAction.APPLY,
        )
        self.assertEqual(
            local_close_write_action(True, SendHalfState.FIN),
            LocalSendAction.CLOSED,
        )
        self.assertEqual(
            local_close_write_action(True, SendHalfState.RESET),
            LocalSendAction.TERMINAL,
        )
        self.assertEqual(
            local_close_read_action(False, RecvHalfState.ABSENT),
            LocalRecvAction.NOT_READABLE,
        )
        self.assertEqual(
            local_close_read_action(True, RecvHalfState.OPEN),
            LocalRecvAction.APPLY,
        )
        self.assertEqual(
            local_close_read_action(True, RecvHalfState.FIN),
            LocalRecvAction.CLOSED,
        )
        self.assertEqual(
            local_abort_action_for_stream(SendHalfState.ABORTED, RecvHalfState.OPEN),
            LocalAbortAction.NO_OP,
        )

    def test_terminal_priority_peer_data_and_peer_control_plans(self):
        self.assertEqual(
            terminal_error_priority(SendHalfState.ABORTED, RecvHalfState.RESET),
            TerminalErrorChoice.SEND_ABORT,
        )
        self.assertEqual(
            terminal_error_priority(SendHalfState.RESET, RecvHalfState.RESET),
            TerminalErrorChoice.SEND_RESET,
        )
        self.assertEqual(
            read_error_choice(True, True, RecvHalfState.RESET),
            TerminalErrorChoice.RECV_CLOSED,
        )
        self.assertEqual(
            peer_data_transition(
                True, False, SendHalfState.OPEN, RecvHalfState.ABSENT, False
            ).outcome,
            PeerDataOutcome.ABORT_STATE,
        )
        stopped = peer_data_transition(
            True, True, SendHalfState.OPEN, RecvHalfState.STOP_SENT, True
        )
        self.assertEqual(stopped.outcome, PeerDataOutcome.IGNORE)
        self.assertTrue(stopped.advance_recv_fin)
        self.assertTrue(stopped.track_late_per_stream)
        half = StreamHalfState(True, True)
        half.mark_local_read_stop()
        half.mark_recv_fin()
        stopped_after_fin = half.peer_data_plan(fin=True)
        self.assertEqual(stopped_after_fin.outcome, PeerDataOutcome.IGNORE)
        self.assertTrue(stopped_after_fin.advance_recv_fin)
        self.assertTrue(stopped_after_fin.track_late_per_stream)

        self.assertEqual(
            peer_max_data_action(False, True, SendHalfState.ABSENT, RecvHalfState.OPEN),
            PeerStreamControlAction.ABORT_STATE,
        )
        self.assertEqual(
            peer_blocked_action(True, False, SendHalfState.OPEN, RecvHalfState.ABSENT),
            PeerStreamControlAction.ABORT_STATE,
        )
        self.assertTrue(should_advertise_max_data(True, RecvHalfState.OPEN))
        self.assertFalse(should_advertise_max_data(True, RecvHalfState.RESET))
        self.assertTrue(should_advertise_blocked(True, SendHalfState.OPEN))
        self.assertFalse(should_advertise_blocked(True, SendHalfState.STOP_SEEN))

        stop = plan_peer_stop_sending(
            True, True, SendHalfState.OPEN, RecvHalfState.OPEN
        )
        self.assertFalse(stop.ignore)
        self.assertEqual(stop.outcome, StopSendingOutcome.FINISH)
        reset = plan_peer_reset(True, True, SendHalfState.OPEN, RecvHalfState.OPEN)
        self.assertTrue(reset.record_reset)
        self.assertTrue(reset.release_receive)
        abort = plan_peer_abort(True, True, SendHalfState.OPEN, RecvHalfState.OPEN)
        self.assertTrue(abort.record_abort)
        self.assertTrue(abort.release_send)

    def test_visibility_flush_and_tombstone_predicates(self):
        phase = LocalOpenVisibility(True, False, False, False).phase()
        self.assertEqual(phase, LocalOpenPhase.NEEDS_COMMIT)
        self.assertTrue(phase.needs_local_opener())
        self.assertEqual(
            should_flush_stream_max_data(True, True, phase, False, False),
            (False, True),
        )
        self.assertEqual(
            should_flush_stream_blocked(True, True, phase, SendHalfState.OPEN),
            (False, True),
        )
        self.assertEqual(
            should_flush_priority_update(phase, SendHalfState.OPEN),
            (False, True),
        )

        visible = LocalOpenVisibility(True, True, True, False).phase()
        self.assertEqual(
            should_flush_stream_max_data(True, True, visible, False, False),
            (True, False),
        )
        self.assertEqual(
            should_flush_priority_update(visible, SendHalfState.STOP_SEEN),
            (False, False),
        )
        self.assertTrue(
            should_reclaim_unseen_local_stream(
                phase,
                True,
                True,
                12,
                8,
                99,
                True,
                True,
                SendHalfState.OPEN,
                RecvHalfState.OPEN,
            )
        )

        plan = session_close_transition(
            True, True, SendHalfState.STOP_SEEN, RecvHalfState.STOP_SENT, False
        )
        self.assertTrue(plan.finish_send)
        self.assertTrue(plan.finish_recv)

        tombstone = build_stream_tombstone(
            True,
            SendHalfState.RESET,
            RecvHalfState.ABORTED,
            send_reset_code=7,
            recv_abort_code=11,
        )
        self.assertEqual(tombstone.terminal_kind, TerminalKind.ABORTED)
        self.assertTrue(tombstone.has_terminal_code)
        self.assertEqual(tombstone.terminal_code, 11)
        self.assertEqual(
            build_stream_tombstone(
                True, SendHalfState.FIN, RecvHalfState.FIN
            ).data_action,
            LateDataAction.ABORT_CLOSED,
        )


class StreamReadBufferTests(unittest.TestCase):
    def test_buffer_reads_across_chunks_and_tracks_retained_storage(self):
        buffer = StreamReadBuffer()
        self.assertEqual(buffer.append(b"ab"), 2)
        self.assertEqual(buffer.append(b"cd"), 2)
        out = bytearray(3)

        read = buffer.readinto(out)
        self.assertEqual(read.bytes_read, 3)
        self.assertEqual(bytes(out), b"abc")
        self.assertEqual(len(buffer), 1)
        self.assertEqual(buffer.read(), b"d")
        self.assertTrue(buffer.is_empty())
        self.assertEqual(buffer.retained_bytes, 0)

    def test_buffer_tightens_large_consumed_tail(self):
        source = b"x" * (512 << 10)
        buffer = StreamReadBuffer()
        buffer.append(memoryview(source))
        self.assertGreaterEqual(buffer.retained_bytes, 512 << 10)

        out = bytearray(len(source) - 1)
        read = buffer.readinto(out)
        self.assertEqual(read.bytes_read, len(source) - 1)
        self.assertEqual(len(buffer), 1)
        self.assertLessEqual(buffer.retained_bytes, 1)
        self.assertTrue(read.released_retained_bytes >= (512 << 10) - 1)

        self.assertEqual(buffer.read(), b"x")
        self.assertTrue(buffer.is_empty())

    def test_typed_buffers_are_counted_and_read_as_bytes(self):
        source = array.array("H", [0x0201, 0x0403])
        buffer = StreamReadBuffer()
        buffer.append(source)
        self.assertEqual(len(buffer), 4)

        out = bytearray(4)
        read = buffer.readinto(out)
        self.assertEqual(read.bytes_read, 4)
        self.assertEqual(bytes(out), source.tobytes())
        self.assertEqual(checked_total_part_len((source,), 8), 4)

    def test_receive_release_modes_clear_budget_and_buffers(self):
        state = StreamRuntimeState(stream_id=4, id_set=True)
        state.append_read_data(b"abcdef")
        self.assertEqual(state.receive.recv_pending, 0)
        self.assertEqual(state.read(2), b"ab")
        self.assertEqual(state.receive.recv_pending, 2)
        state.receive.clear()
        state.read_buffer.clear()
        state.append_read_data(b"abcdef")
        result = state.apply_receive_release(
            StreamReceiveReleaseTraits.BUDGET.release_mode()
        )
        self.assertEqual(result.released_budget_bytes, 6)
        self.assertEqual(len(state.read_buffer), 6)

        result = state.apply_receive_release(
            StreamReceiveReleaseMode.RELEASE_AND_CLEAR_READ_BUF
        )
        self.assertEqual(result.cleared_read_bytes, 6)
        self.assertEqual(len(state.read_buffer), 0)
        self.assertEqual(state.receive.recv_buffer, 0)

    def test_shrink_and_overhead_helpers_match_go_thresholds(self):
        self.assertTrue(should_tighten_read_buf_after_consume(0, 1))
        self.assertFalse(should_tighten_read_buf_after_consume(1, 128))
        self.assertFalse(should_tighten_read_buf_after_consume(128 << 10, 512 << 10))
        self.assertTrue(should_tighten_read_buf_after_consume(1, 512 << 10))
        self.assertEqual(read_chunk_overhead_bytes(10, 7), 3)
        self.assertEqual(read_chunk_overhead_bytes(7, 10), 0)

    def test_buffer_rejects_implicit_python_integer_coercions(self):
        buffer = StreamReadBuffer()
        with self.assertRaises(TypeError):
            buffer.append(b"abc", offset="1")
        with self.assertRaises(ValueError):
            buffer.append(b"abc", offset=-1)
        with self.assertRaises(TypeError):
            buffer.read(True)
        self.assertEqual(buffer.read(-1), b"")


class StreamDeadlineAndWritePlanTests(unittest.TestCase):
    def test_deadlines_use_earliest_bounded_deadline(self):
        self.assertIsNone(effective_deadline(None, None))
        self.assertEqual(effective_deadline(10.0, None), 10.0)
        self.assertEqual(effective_deadline(None, 5.0), 5.0)
        self.assertEqual(effective_deadline(10.0, 5.0), 5.0)
        self.assertEqual(effective_deadline(2.0, 5.0), 2.0)
        self.assertAlmostEqual(deadline_remaining(11.0, now=10.0), 1.0)
        self.assertTrue(deadline_expired(10.0, now=10.0))

        wait = StreamWaitState()
        wait.set_read_deadline(10.0)
        self.assertAlmostEqual(wait.remaining_read(now=9.5), 0.5)
        wait.set_read_timeout(-1.0, now=20.0)
        self.assertTrue(deadline_expired(wait.read_deadline, now=20.0))
        self.assertIsNone(timeout_to_deadline(float("inf"), now=20.0))

    def test_checked_total_and_part_advance(self):
        parts = (b"ab", b"", b"cde")
        with self.assertRaises(zmux.FrameSizeError):
            checked_total_part_len((b"abc", b"de"), 4)
        self.assertEqual(
            (
                checked_total_part_len(parts, 8),
                advance_parts(parts, 0, 0, 3),
                advance_parts(parts, 2, 1, 9),
            ),
            (5, (2, 1), (3, 0)),
        )


class StreamTerminalPlanTests(unittest.TestCase):
    def read_closed_error(self, state):
        return state.terminal.read_error(
            local_receive=state.local_receive,
            local_read_stop=state.half.local_read_stop,
            recv_half=state.half.effective_recv_half(),
        )

    def test_unidirectional_sides_derive_from_opener_and_direction(self):
        local_uni = StreamRuntimeState(
            stream_id=2,
            id_set=True,
            opened_locally=True,
            bidirectional=False,
        )
        self.assertTrue(local_uni.local_send)
        self.assertFalse(local_uni.local_receive)
        self.assertTrue(local_uni.read_closed())
        self.assertFalse(local_uni.write_closed())

        peer_uni = StreamRuntimeState(
            stream_id=3,
            id_set=True,
            opened_locally=False,
            bidirectional=False,
        )
        self.assertFalse(peer_uni.local_send)
        self.assertTrue(peer_uni.local_receive)
        self.assertFalse(peer_uni.read_closed())
        self.assertTrue(peer_uni.write_closed())

    def test_close_write_on_unseen_local_open_emits_open_metadata_fin(self):
        state = StreamRuntimeState(
            stream_id=4,
            id_set=True,
            opened_locally=True,
            metadata=zmux.StreamMetadata(priority=7, open_info=b"hello"),
        )
        plan = state.prepare_close_write_plan(
            capabilities=int(
                zmux.Capability.OPEN_METADATA | zmux.Capability.PRIORITY_HINTS
            )
        )
        self.assertFalse(plan.should_retry())
        self.assertEqual(len(plan.frames), 1)
        frame = plan.frames[0]
        self.assertEqual(frame.frame_type, zmux.FrameType.DATA)
        self.assertTrue(frame.flags & zmux.FRAME_FLAG_FIN)
        self.assertTrue(frame.flags & zmux.FRAME_FLAG_OPEN_METADATA)
        self.assertTrue(state.peer_visible)
        self.assertTrue(state.write_closed())

    def test_close_write_flushes_pending_priority_before_fin_when_peer_visible(self):
        state = StreamRuntimeState(
            stream_id=4,
            id_set=True,
            opened_locally=True,
            send_committed=True,
            peer_visible=True,
        )
        caps = int(
            zmux.Capability.PRIORITY_UPDATE
            | zmux.Capability.PRIORITY_HINTS
            | zmux.Capability.STREAM_GROUPS
        )
        pending = state.stage_priority_update(
            zmux.MetadataUpdate(priority=9, group=3),
            capabilities=caps,
        )

        plan = state.prepare_close_write_plan(capabilities=caps)

        self.assertEqual(
            [frame.frame_type for frame in plan.frames],
            [zmux.FrameType.EXT, zmux.FrameType.DATA],
        )
        self.assertEqual(plan.frames[0].payload, pending)
        metadata, valid = zmux.parse_priority_update_payload(plan.frames[0].payload)
        self.assertTrue(valid)
        self.assertEqual(metadata.priority, 9)
        self.assertEqual(metadata.group, 3)
        self.assertTrue(plan.frames[1].flags & zmux.FRAME_FLAG_FIN)
        self.assertFalse(state.has_pending_priority_update())
        self.assertTrue(state.write_closed())

    def test_failed_opener_metadata_build_does_not_commit_visibility(self):
        state = StreamRuntimeState(
            stream_id=4,
            id_set=True,
            opened_locally=True,
            metadata=zmux.StreamMetadata(open_info=b"hello"),
        )
        pending = state.stage_priority_update(
            zmux.MetadataUpdate(priority=5),
            capabilities=int(
                zmux.Capability.PRIORITY_UPDATE | zmux.Capability.PRIORITY_HINTS
            ),
        )
        with self.assertRaises(zmux.ProtocolError) as ctx:
            state.prepare_close_write_plan(capabilities=0)
        self.assertTrue(zmux.open_info_unavailable(ctx.exception))
        self.assertFalse(state.send_committed)
        self.assertFalse(state.peer_visible)
        self.assertFalse(state.write_closed())
        self.assertTrue(state.has_pending_priority_update())
        self.assertEqual(state.pending_priority_update_payload, pending)

    def test_close_read_prepares_opener_and_stop_sending(self):
        state = StreamRuntimeState(
            stream_id=4,
            id_set=True,
            opened_locally=True,
            metadata=zmux.StreamMetadata(priority=5),
        )
        plan = state.prepare_close_read_plan(
            capabilities=int(
                zmux.Capability.OPEN_METADATA | zmux.Capability.PRIORITY_HINTS
            )
        )
        frames = plan.frames()
        self.assertEqual(
            [frame.frame_type for frame in frames],
            [zmux.FrameType.DATA, zmux.FrameType.STOP_SENDING],
        )
        self.assertFalse(frames[0].flags & zmux.FRAME_FLAG_FIN)
        self.assertTrue(state.read_closed())
        self.assertEqual(len(state.read_buffer), 0)
        self.assertTrue(state.pending_terminal.flags & PendingTerminalKind.STOP)

    def test_close_read_on_visible_stream_only_sends_stop_sending(self):
        state = StreamRuntimeState(
            stream_id=4,
            id_set=True,
            opened_locally=True,
            send_committed=True,
            peer_visible=True,
        )

        plan = state.prepare_close_read_plan()
        frames = plan.frames()

        self.assertEqual([frame.frame_type for frame in frames], [zmux.FrameType.STOP_SENDING])
        self.assertTrue(state.read_closed())

    def test_priority_update_staging_merges_pending_payload_and_metadata(self):
        caps = int(
            zmux.Capability.PRIORITY_UPDATE
            | zmux.Capability.PRIORITY_HINTS
            | zmux.Capability.STREAM_GROUPS
        )
        state = StreamRuntimeState(
            stream_id=4,
            id_set=True,
            metadata=zmux.StreamMetadata(priority=1, group=2, open_info=b"open"),
        )

        first = state.stage_priority_update(
            zmux.MetadataUpdate(priority=5),
            capabilities=caps,
        )
        second = state.stage_priority_update(
            zmux.MetadataUpdate(group=7),
            capabilities=caps,
        )
        merged = merge_pending_priority_update(
            zmux.MetadataUpdate(group=8),
            first,
        )
        parsed, valid = zmux.parse_priority_update_payload(second)

        self.assertEqual(merged.priority, 5)
        self.assertEqual(merged.group, 8)
        self.assertTrue(valid)
        self.assertEqual(parsed.priority, 5)
        self.assertEqual(parsed.group, 7)
        self.assertEqual(state.metadata.priority, 5)
        self.assertEqual(state.metadata.group, 7)
        self.assertEqual(state.metadata.open_info, b"open")

    def test_peer_stop_sending_surfaces_remote_stopped_write_error(self):
        state = StreamRuntimeState(stream_id=4, id_set=True)
        pending = state.stage_priority_update(
            zmux.MetadataUpdate(priority=5),
            capabilities=int(
                zmux.Capability.PRIORITY_UPDATE | zmux.Capability.PRIORITY_HINTS
            ),
        )

        self.assertTrue(pending)
        self.assertTrue(state.apply_peer_stop_sending(42, "stop"))
        self.assertFalse(state.has_pending_priority_update())
        self.assertTrue(state.write_closed())

        error = state.terminal.operation_error(state.half)
        self.assertIsInstance(error, zmux.WriteClosed)
        self.assertEqual(error.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(error.termination_kind, zmux.TerminationKind.STOPPED)

        previous = state.conclude_stop_sending_with_reset()
        self.assertEqual(previous, SendHalfState.STOP_SEEN)
        reset_error = state.terminal.operation_error(state.half)
        self.assertIsInstance(reset_error, zmux.WriteClosed)
        self.assertEqual(reset_error.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(reset_error.termination_kind, zmux.TerminationKind.STOPPED)

    def test_peer_stop_sending_ignores_terminal_or_absent_send_half(self):
        finished = StreamRuntimeState(stream_id=4, id_set=True)
        finished.half.mark_send_fin()

        self.assertFalse(finished.apply_peer_stop_sending(42, "late"))
        self.assertIsNone(finished.terminal.send_stop_error)

        recv_only = StreamRuntimeState(
            stream_id=7,
            id_set=True,
            opened_locally=False,
            bidirectional=False,
        )
        with self.assertRaises(zmux.StreamNotWritable):
            recv_only.apply_peer_stop_sending(42)

    def test_close_write_after_stop_reset_is_idempotent_noop(self):
        state = StreamRuntimeState(stream_id=4, id_set=True)
        state.apply_peer_stop_sending(42, "stop")
        state.conclude_stop_sending_with_reset()

        plan = state.prepare_close_write_plan()

        self.assertEqual(plan.frames, ())

    def test_reset_from_stop_without_peer_stop_keeps_local_reset_error(self):
        state = StreamRuntimeState(stream_id=4, id_set=True)
        state.execute_terminal_signal(
            TerminalSignalKind.RESET,
            42,
            reset_source=TerminalResetSource.FROM_STOP_SENDING,
        )

        error = state.terminal.operation_error(state.half)
        self.assertIsInstance(error, zmux.ApplicationError)
        self.assertEqual(error.source, zmux.ErrorSource.LOCAL)
        self.assertEqual(error.direction, zmux.ErrorDirection.WRITE)
        self.assertEqual(error.termination_kind, zmux.TerminationKind.RESET)

    def test_read_closed_error_source_matches_terminal_cause(self):
        stopped = StreamRuntimeState(stream_id=4, id_set=True)
        stopped.commit_local_read_stop(42)
        stop_error = self.read_closed_error(stopped)
        self.assertIsInstance(stop_error, zmux.ReadClosed)
        self.assertEqual(stop_error.source, zmux.ErrorSource.LOCAL)
        self.assertEqual(stop_error.termination_kind, zmux.TerminationKind.STOPPED)

        finished = StreamRuntimeState(stream_id=4, id_set=True)
        finished.half.mark_recv_fin()
        fin_error = self.read_closed_error(finished)
        self.assertIsInstance(fin_error, zmux.ReadClosed)
        self.assertEqual(fin_error.source, zmux.ErrorSource.REMOTE)
        self.assertEqual(fin_error.termination_kind, zmux.TerminationKind.GRACEFUL)

    def test_reset_for_unseen_committed_local_stream_promotes_to_abort(self):
        state = StreamRuntimeState(stream_id=4, id_set=True, opened_locally=True)
        plan = state.execute_terminal_signal(
            TerminalSignalKind.RESET,
            int(zmux.ErrorCode.CANCELLED),
            opener_policy=TerminalOpenerPolicy.REJECT_UNOPENED,
            reset_source=TerminalResetSource.DIRECT,
        )
        self.assertEqual(plan.frame_type, zmux.FrameType.ABORT)
        self.assertTrue(state.pending_terminal.flags & PendingTerminalKind.ABORT)
        self.assertTrue(state.read_closed())
        self.assertTrue(state.write_closed())

    def test_pending_terminal_coalesces_and_abort_supersedes(self):
        state = StreamRuntimeState(stream_id=4, id_set=True)
        reset = state.execute_terminal_signal(
            TerminalSignalKind.RESET,
            int(zmux.ErrorCode.CANCELLED),
        )
        again = state.enqueue_terminal_signal(reset)
        self.assertTrue(again.coalesced)

        abort = state.execute_terminal_signal(TerminalSignalKind.ABORT, 99, "boom")
        self.assertEqual(abort.frame_type, zmux.FrameType.ABORT)
        self.assertTrue(state.pending_terminal.flags & PendingTerminalKind.ABORT)
        self.assertFalse(state.pending_terminal.flags & PendingTerminalKind.RESET)

    def test_stream_runtime_rejects_implicit_python_coercions(self):
        with self.assertRaises(TypeError):
            StreamRuntimeState(stream_id=4, id_set=1)
        with self.assertRaises(ValueError):
            StreamRuntimeState(id_set=True)
        with self.assertRaises(ValueError):
            StreamAddr("peer", stream_id_set=True)
        with self.assertRaises(TypeError):
            StreamRuntimeState(stream_id=4, id_set=True, local_send=1)
        with self.assertRaises(TypeError):
            StreamHalfState(True, True).mark_send_reset(from_stop=1)
        with self.assertRaises(TypeError):
            PendingTerminalState().set_stop(4)

        state = StreamRuntimeState(stream_id=4, id_set=True)
        with self.assertRaises(TypeError):
            state.apply_receive_release(True)
        with self.assertRaises(TypeError):
            state.prepare_data_frame_plan(True)
        with self.assertRaises(TypeError):
            state.prepare_data_frame_plan(TerminalDataIntent.CLOSE_WRITE, capabilities=True)


if __name__ == "__main__":
    unittest.main()
