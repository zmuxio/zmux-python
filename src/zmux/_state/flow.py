"""Stream flow-control admission predicates.

The Go state package keeps these helpers near the half-state model so reader
and writer code can distinguish valid peer control from late terminal noise
and structurally impossible stream-scope control.
"""

from __future__ import annotations

from enum import IntEnum

from .half import (
    RecvHalfState,
    SendHalfState,
    _coerce_enum,
    _require_bool,
    fully_terminal,
)


class PeerStreamControlAction(IntEnum):
    """Disposition for peer stream-scope MAX_DATA/BLOCKED control."""

    APPLY = 0
    IGNORE = 1
    ABORT_STATE = 2


def ignore_late_non_opening_control(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    """Return whether late stream control can be ignored as terminal noise."""

    local_send = _require_bool(local_send, "local_send")
    local_receive = _require_bool(local_receive, "local_receive")
    return fully_terminal(local_send, local_receive, send_half, recv_half)


def peer_max_data_action(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> PeerStreamControlAction:
    """Classify inbound MAX_DATA for this stream shape and terminal state."""

    if ignore_late_non_opening_control(local_send, local_receive, send_half, recv_half):
        return PeerStreamControlAction.IGNORE
    if not local_send:
        return PeerStreamControlAction.ABORT_STATE
    return PeerStreamControlAction.APPLY


def peer_blocked_action(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> PeerStreamControlAction:
    """Classify inbound BLOCKED for this stream shape and terminal state."""

    if ignore_late_non_opening_control(local_send, local_receive, send_half, recv_half):
        return PeerStreamControlAction.IGNORE
    if not local_receive:
        return PeerStreamControlAction.ABORT_STATE
    return PeerStreamControlAction.APPLY


def should_advertise_max_data(local_receive: bool, recv_half: RecvHalfState) -> bool:
    """Return whether this endpoint can still advertise receive credit."""

    local_receive = _require_bool(local_receive, "local_receive")
    recv_half = _coerce_enum(recv_half, RecvHalfState, "recv_half")
    return local_receive and recv_half is RecvHalfState.OPEN


def should_advertise_blocked(local_send: bool, send_half: SendHalfState) -> bool:
    """Return whether this endpoint can still advertise send-side blockage."""

    local_send = _require_bool(local_send, "local_send")
    send_half = _coerce_enum(send_half, SendHalfState, "send_half")
    return local_send and send_half is SendHalfState.OPEN


__all__ = (
    "PeerStreamControlAction",
    "ignore_late_non_opening_control",
    "peer_blocked_action",
    "peer_max_data_action",
    "should_advertise_blocked",
    "should_advertise_max_data",
)
