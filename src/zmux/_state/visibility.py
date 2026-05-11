"""Local-open visibility and delayed-control predicates.

This module mirrors Go's ``internal/state/visibility.go``.  It keeps local
opener visibility decisions independent from concrete stream/session runtime
objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .half import (
    RecvHalfState,
    SendHalfState,
    _coerce_enum,
    _require_bool,
    fully_terminal,
    send_terminal,
)


class LocalOpenPhase(IntEnum):
    NONE = 0
    NEEDS_COMMIT = 1
    NEEDS_EMIT = 2
    QUEUED = 3
    PEER_VISIBLE = 4

    def is_local(self) -> bool:
        return self is not LocalOpenPhase.NONE

    def needs_local_opener(self) -> bool:
        return self is LocalOpenPhase.NEEDS_COMMIT

    def awaiting_peer_visibility(self) -> bool:
        return self in _AWAITING_PEER_VISIBILITY_PHASES

    def should_emit_opener_frame(self) -> bool:
        return self in _OPENER_FRAME_PHASES

    def should_mark_peer_visible(self) -> bool:
        return self.is_local() and self is not LocalOpenPhase.PEER_VISIBLE

    def can_take_pending_priority_update(self) -> bool:
        return not self.awaiting_peer_visibility()

    def should_queue_stream_blocked(self, available_stream: int) -> bool:
        available_stream = _nonnegative_int(available_stream, "available_stream")
        return available_stream == 0 and self is LocalOpenPhase.PEER_VISIBLE


_AWAITING_PEER_VISIBILITY_PHASES = (
    LocalOpenPhase.NEEDS_COMMIT,
    LocalOpenPhase.NEEDS_EMIT,
    LocalOpenPhase.QUEUED,
)
_OPENER_FRAME_PHASES = (
    LocalOpenPhase.NEEDS_COMMIT,
    LocalOpenPhase.NEEDS_EMIT,
)


@dataclass(frozen=True)
class LocalOpenVisibility:
    local_opened: bool = False
    send_committed: bool = False
    peer_visible: bool = False
    opener_queued: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "local_opened",
            _require_bool(self.local_opened, "local_opened"),
        )
        object.__setattr__(
            self,
            "send_committed",
            _require_bool(self.send_committed, "send_committed"),
        )
        object.__setattr__(
            self,
            "peer_visible",
            _require_bool(self.peer_visible, "peer_visible"),
        )
        object.__setattr__(
            self,
            "opener_queued",
            _require_bool(self.opener_queued, "opener_queued"),
        )

    def phase(self) -> LocalOpenPhase:
        if not self.local_opened:
            return LocalOpenPhase.NONE
        if self.peer_visible:
            return LocalOpenPhase.PEER_VISIBLE
        if not self.send_committed:
            return LocalOpenPhase.NEEDS_COMMIT
        if self.opener_queued:
            return LocalOpenPhase.QUEUED
        return LocalOpenPhase.NEEDS_EMIT


def should_enqueue_accepted(application_visible: bool, accepted: bool, enqueued: bool) -> bool:
    application_visible = _require_bool(application_visible, "application_visible")
    accepted = _require_bool(accepted, "accepted")
    enqueued = _require_bool(enqueued, "enqueued")
    return application_visible and not accepted and not enqueued


def should_flush_stream_max_data(
        id_set: bool,
        local_receive: bool,
        phase: LocalOpenPhase,
        read_stopped_value: bool,
        recv_terminal_value: bool,
) -> tuple[bool, bool]:
    id_set = _require_bool(id_set, "id_set")
    local_receive = _require_bool(local_receive, "local_receive")
    phase = _coerce_enum(phase, LocalOpenPhase, "phase")
    read_stopped_value = _require_bool(read_stopped_value, "read_stopped_value")
    recv_terminal_value = _require_bool(recv_terminal_value, "recv_terminal_value")
    if not id_set or not local_receive:
        return False, False
    if read_stopped_value or recv_terminal_value:
        return False, False
    if phase.awaiting_peer_visibility():
        return False, True
    return True, False


def should_flush_stream_blocked(
        id_set: bool,
        local_send: bool,
        phase: LocalOpenPhase,
        send_half: SendHalfState,
) -> tuple[bool, bool]:
    id_set = _require_bool(id_set, "id_set")
    local_send = _require_bool(local_send, "local_send")
    phase = _coerce_enum(phase, LocalOpenPhase, "phase")
    send_half = _coerce_enum(send_half, SendHalfState, "send_half")
    if not id_set or not local_send:
        return False, False
    if send_half is not SendHalfState.OPEN:
        return False, False
    if phase.awaiting_peer_visibility():
        return False, True
    return True, False


def should_flush_priority_update(
        phase: LocalOpenPhase, send_half: SendHalfState
) -> tuple[bool, bool]:
    phase = _coerce_enum(phase, LocalOpenPhase, "phase")
    send_half = _coerce_enum(send_half, SendHalfState, "send_half")
    if send_half is SendHalfState.STOP_SEEN or send_terminal(send_half):
        return False, False
    if not phase.can_take_pending_priority_update():
        return False, True
    return True, False


def should_reclaim_unseen_local_stream(
        phase: LocalOpenPhase,
        id_assigned: bool,
        bidi: bool,
        stream_id: int,
        peer_go_away_bidi: int,
        peer_go_away_uni: int,
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    phase = _coerce_enum(phase, LocalOpenPhase, "phase")
    id_assigned = _require_bool(id_assigned, "id_assigned")
    bidi = _require_bool(bidi, "bidi")
    stream_id = _nonnegative_int(stream_id, "stream_id")
    peer_go_away_bidi = _nonnegative_int(peer_go_away_bidi, "peer_go_away_bidi")
    peer_go_away_uni = _nonnegative_int(peer_go_away_uni, "peer_go_away_uni")
    if (
            not id_assigned
            or not phase.awaiting_peer_visibility()
            or fully_terminal(local_send, local_receive, send_half, recv_half)
    ):
        return False
    return stream_id > (peer_go_away_bidi if bidi else peer_go_away_uni)


def should_finalize_peer_active(
        active_counted: bool,
        local_opened: bool,
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    active_counted = _require_bool(active_counted, "active_counted")
    local_opened = _require_bool(local_opened, "local_opened")
    return (
            active_counted
            and not local_opened
            and fully_terminal(local_send, local_receive, send_half, recv_half)
    )


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


__all__ = (
    "LocalOpenPhase",
    "LocalOpenVisibility",
    "should_enqueue_accepted",
    "should_finalize_peer_active",
    "should_flush_priority_update",
    "should_flush_stream_blocked",
    "should_flush_stream_max_data",
    "should_reclaim_unseen_local_stream",
)
