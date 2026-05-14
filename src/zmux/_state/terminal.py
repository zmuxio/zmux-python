"""Terminal stream-state transitions.

This module mirrors Go's ``internal/state/terminal.go``.  It owns the small
action tables that decide how local terminal operations, peer terminal frames,
and late peer DATA interact with stream half states.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Type

from .flow import ignore_late_non_opening_control
from .half import (
    RecvHalfState,
    SendHalfState,
    coerce_enum,
    require_bool,
    fully_terminal,
    recv_terminal,
    send_terminal,
)


class TerminalErrorChoice(IntEnum):
    NONE = 0
    SEND_ABORT = 1
    RECV_ABORT = 2
    SEND_RESET = 3
    RECV_RESET = 4
    SEND_CLOSED = 5
    RECV_CLOSED = 6


class LocalSendAction(IntEnum):
    APPLY = 0
    NOT_WRITABLE = 1
    CLOSED = 2
    TERMINAL = 3


class LocalRecvAction(IntEnum):
    APPLY = 0
    NOT_READABLE = 1
    CLOSED = 2
    TERMINAL = 3


class LocalAbortAction(IntEnum):
    APPLY = 0
    NO_OP = 1


class StopSendingOutcome(IntEnum):
    IGNORE = 0
    FINISH = 1
    RESET = 2


class PeerDataOutcome(IntEnum):
    ACCEPT = 0
    IGNORE = 1
    ABORT_CLOSED = 2
    ABORT_STATE = 3


_SEND_CLOSED_CHOICES = (SendHalfState.FIN, SendHalfState.STOP_SEEN)
_RECV_CLOSED_CHOICES = (RecvHalfState.STOP_SENT, RecvHalfState.FIN)
_SEND_TERMINAL_FAILURES = (SendHalfState.RESET, SendHalfState.ABORTED)
_RECV_TERMINAL_FAILURES = (RecvHalfState.RESET, RecvHalfState.ABORTED)
_PEER_STOP_IGNORED_SEND_STATES = (
    SendHalfState.STOP_SEEN,
    SendHalfState.FIN,
    SendHalfState.RESET,
    SendHalfState.ABORTED,
)
_PEER_RESET_IGNORED_RECV_STATES = (
    RecvHalfState.FIN,
    RecvHalfState.RESET,
    RecvHalfState.ABORTED,
)


@dataclass(frozen=True)
class PeerDataPlan:
    outcome: PeerDataOutcome
    advance_recv_fin: bool = False
    track_late_per_stream: bool = False

    def __post_init__(self) -> None:
        _set_enum_field(self, "outcome", PeerDataOutcome)
        _set_bool_field(self, "advance_recv_fin")
        _set_bool_field(self, "track_late_per_stream")


@dataclass(frozen=True)
class SessionClosePlan:
    finish_send: bool = False
    finish_recv: bool = False
    abort_send: bool = False
    abort_recv: bool = False

    def __post_init__(self) -> None:
        _set_bool_field(self, "finish_send")
        _set_bool_field(self, "finish_recv")
        _set_bool_field(self, "abort_send")
        _set_bool_field(self, "abort_recv")


@dataclass(frozen=True)
class PeerStopSendingPlan:
    ignore: bool = False
    record_stop: bool = False
    outcome: StopSendingOutcome = StopSendingOutcome.IGNORE

    def __post_init__(self) -> None:
        _set_bool_field(self, "ignore")
        _set_bool_field(self, "record_stop")
        _set_enum_field(self, "outcome", StopSendingOutcome)


@dataclass(frozen=True)
class PeerResetPlan:
    ignore: bool = False
    record_reset: bool = False
    release_receive: bool = False
    clear_read_buf: bool = False

    def __post_init__(self) -> None:
        _set_bool_field(self, "ignore")
        _set_bool_field(self, "record_reset")
        _set_bool_field(self, "release_receive")
        _set_bool_field(self, "clear_read_buf")


@dataclass(frozen=True)
class PeerAbortPlan:
    ignore: bool = False
    record_abort: bool = False
    release_send: bool = False
    release_receive: bool = False
    clear_read_buf: bool = False

    def __post_init__(self) -> None:
        _set_bool_field(self, "ignore")
        _set_bool_field(self, "record_abort")
        _set_bool_field(self, "release_send")
        _set_bool_field(self, "release_receive")
        _set_bool_field(self, "clear_read_buf")


def read_error_choice(
        local_receive: bool, local_read_stop: bool, recv_half: RecvHalfState
) -> TerminalErrorChoice:
    local_receive = require_bool(local_receive, "local_receive")
    local_read_stop = require_bool(local_read_stop, "local_read_stop")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if not local_receive:
        return TerminalErrorChoice.NONE
    if local_read_stop:
        return TerminalErrorChoice.RECV_CLOSED
    if recv_half is RecvHalfState.ABORTED:
        return TerminalErrorChoice.RECV_ABORT
    if recv_half is RecvHalfState.STOP_SENT:
        return TerminalErrorChoice.RECV_CLOSED
    if recv_half is RecvHalfState.RESET:
        return TerminalErrorChoice.RECV_RESET
    if recv_half is RecvHalfState.FIN:
        return TerminalErrorChoice.RECV_CLOSED
    return TerminalErrorChoice.NONE


def terminal_error_priority(
        send_half: SendHalfState, recv_half: RecvHalfState
) -> TerminalErrorChoice:
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if send_half is SendHalfState.ABORTED:
        return TerminalErrorChoice.SEND_ABORT
    if recv_half is RecvHalfState.ABORTED:
        return TerminalErrorChoice.RECV_ABORT
    if send_half is SendHalfState.RESET:
        return TerminalErrorChoice.SEND_RESET
    if recv_half is RecvHalfState.RESET:
        return TerminalErrorChoice.RECV_RESET
    if send_half in _SEND_CLOSED_CHOICES:
        return TerminalErrorChoice.SEND_CLOSED
    if recv_half in _RECV_CLOSED_CHOICES:
        return TerminalErrorChoice.RECV_CLOSED
    return TerminalErrorChoice.NONE


def local_close_write_action(local_send: bool, send_half: SendHalfState) -> LocalSendAction:
    local_send = require_bool(local_send, "local_send")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    if not local_send:
        return LocalSendAction.NOT_WRITABLE
    if send_half is SendHalfState.FIN:
        return LocalSendAction.CLOSED
    if send_half in _SEND_TERMINAL_FAILURES:
        return LocalSendAction.TERMINAL
    return LocalSendAction.APPLY


def local_reset_action(local_send: bool, send_half: SendHalfState) -> LocalSendAction:
    return local_close_write_action(local_send, send_half)


def local_close_read_action(local_receive: bool, recv_half: RecvHalfState) -> LocalRecvAction:
    local_receive = require_bool(local_receive, "local_receive")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if not local_receive:
        return LocalRecvAction.NOT_READABLE
    if recv_half in _RECV_CLOSED_CHOICES:
        return LocalRecvAction.CLOSED
    if recv_half in _RECV_TERMINAL_FAILURES:
        return LocalRecvAction.TERMINAL
    return LocalRecvAction.APPLY


def local_abort_action_for_stream(
        send_half: SendHalfState, recv_half: RecvHalfState
) -> LocalAbortAction:
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if send_half is SendHalfState.ABORTED or recv_half is RecvHalfState.ABORTED:
        return LocalAbortAction.NO_OP
    return LocalAbortAction.APPLY


def session_close_transition(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
        abortive: bool,
) -> SessionClosePlan:
    local_send = require_bool(local_send, "local_send")
    local_receive = require_bool(local_receive, "local_receive")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    abortive = require_bool(abortive, "abortive")
    if abortive:
        return SessionClosePlan(
            abort_send=local_send and not send_terminal(send_half),
            abort_recv=local_receive and not recv_terminal(recv_half),
        )
    return SessionClosePlan(
        finish_send=local_send and not send_terminal(send_half),
        finish_recv=local_receive and not recv_terminal(recv_half),
    )


def ignore_peer_stop_sending(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    return _ignore_late_peer_control(
        local_send,
        local_receive,
        send_half,
        recv_half,
        send_terminal_states=_PEER_STOP_IGNORED_SEND_STATES,
    )


def ignore_peer_reset(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    return _ignore_late_peer_control(
        local_send,
        local_receive,
        send_half,
        recv_half,
        recv_terminal_states=_PEER_RESET_IGNORED_RECV_STATES,
    )


def _ignore_late_peer_control(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
        *,
        send_terminal_states=frozenset(),
        recv_terminal_states=frozenset(),
) -> bool:
    local_send = require_bool(local_send, "local_send")
    local_receive = require_bool(local_receive, "local_receive")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if ignore_late_non_opening_control(local_send, local_receive, send_half, recv_half):
        return True
    return send_half in send_terminal_states or recv_half in recv_terminal_states


def ignore_peer_abort(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    local_send = require_bool(local_send, "local_send")
    local_receive = require_bool(local_receive, "local_receive")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if ignore_late_non_opening_control(local_send, local_receive, send_half, recv_half):
        return True
    return send_half is SendHalfState.ABORTED or recv_half is RecvHalfState.ABORTED


def peer_data_transition(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
        fin: bool,
) -> PeerDataPlan:
    local_send = require_bool(local_send, "local_send")
    local_receive = require_bool(local_receive, "local_receive")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    fin = require_bool(fin, "fin")
    if not local_receive:
        if fully_terminal(local_send, local_receive, send_half, recv_half):
            return PeerDataPlan(PeerDataOutcome.IGNORE)
        return PeerDataPlan(PeerDataOutcome.ABORT_STATE)
    if recv_half in _RECV_TERMINAL_FAILURES:
        return PeerDataPlan(PeerDataOutcome.IGNORE, track_late_per_stream=True)
    if recv_half is RecvHalfState.STOP_SENT:
        return PeerDataPlan(
            PeerDataOutcome.IGNORE,
            advance_recv_fin=fin,
            track_late_per_stream=True,
        )
    if recv_half is RecvHalfState.FIN:
        if fully_terminal(local_send, local_receive, send_half, recv_half):
            return PeerDataPlan(PeerDataOutcome.IGNORE)
        return PeerDataPlan(PeerDataOutcome.ABORT_CLOSED)
    if fully_terminal(local_send, local_receive, send_half, recv_half):
        return PeerDataPlan(PeerDataOutcome.IGNORE)
    return PeerDataPlan(PeerDataOutcome.ACCEPT)


def _set_bool_field(instance: object, name: str) -> None:
    object.__setattr__(instance, name, require_bool(getattr(instance, name), name))


def _set_enum_field(instance: object, name: str, enum_type: Type[IntEnum]) -> None:
    object.__setattr__(
        instance,
        name,
        coerce_enum(getattr(instance, name), enum_type, name),
    )


def peer_stop_sending_outcome(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> StopSendingOutcome:
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if ignore_peer_stop_sending(local_send, local_receive, send_half, recv_half):
        return StopSendingOutcome.IGNORE
    if recv_half in _RECV_TERMINAL_FAILURES:
        return StopSendingOutcome.RESET
    return StopSendingOutcome.FINISH


def plan_peer_stop_sending(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> PeerStopSendingPlan:
    outcome = peer_stop_sending_outcome(local_send, local_receive, send_half, recv_half)
    return PeerStopSendingPlan(
        ignore=outcome is StopSendingOutcome.IGNORE,
        record_stop=outcome is not StopSendingOutcome.IGNORE,
        outcome=outcome,
    )


def plan_peer_reset(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> PeerResetPlan:
    if ignore_peer_reset(local_send, local_receive, send_half, recv_half):
        return PeerResetPlan(ignore=True)
    return PeerResetPlan(
        record_reset=True,
        release_receive=local_receive,
        clear_read_buf=local_receive,
    )


def plan_peer_abort(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> PeerAbortPlan:
    if ignore_peer_abort(local_send, local_receive, send_half, recv_half):
        return PeerAbortPlan(ignore=True)
    return PeerAbortPlan(
        record_abort=True,
        release_send=local_send,
        release_receive=local_receive,
        clear_read_buf=local_receive,
    )


__all__ = (
    "LocalAbortAction",
    "LocalRecvAction",
    "LocalSendAction",
    "PeerAbortPlan",
    "PeerDataOutcome",
    "PeerDataPlan",
    "PeerResetPlan",
    "PeerStopSendingPlan",
    "SessionClosePlan",
    "StopSendingOutcome",
    "TerminalErrorChoice",
    "ignore_late_non_opening_control",
    "ignore_peer_abort",
    "ignore_peer_reset",
    "ignore_peer_stop_sending",
    "local_abort_action_for_stream",
    "local_close_read_action",
    "local_close_write_action",
    "local_reset_action",
    "peer_data_transition",
    "peer_stop_sending_outcome",
    "plan_peer_abort",
    "plan_peer_reset",
    "plan_peer_stop_sending",
    "read_error_choice",
    "session_close_transition",
    "terminal_error_priority",
)
