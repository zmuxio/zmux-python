"""Stream half-state primitives.

These are the Python equivalents of Go's ``internal/state/half.go``.  They are
kept free of session/runtime imports so higher-level helpers can share one
state model without circular dependencies.
"""

from __future__ import annotations

from enum import IntEnum


class SendHalfState(IntEnum):
    """Local send-half state."""

    UNKNOWN = 0
    ABSENT = 1
    OPEN = 2
    STOP_SEEN = 3
    FIN = 4
    RESET = 5
    ABORTED = 6


class RecvHalfState(IntEnum):
    """Local receive-half state."""

    UNKNOWN = 0
    ABSENT = 1
    OPEN = 2
    FIN = 3
    STOP_SENT = 4
    RESET = 5
    ABORTED = 6


_SEND_TERMINAL_STATES = frozenset(
    (
        SendHalfState.FIN,
        SendHalfState.RESET,
        SendHalfState.ABORTED,
    )
)
_RECV_TERMINAL_STATES = frozenset(
    (
        RecvHalfState.FIN,
        RecvHalfState.RESET,
        RecvHalfState.ABORTED,
    )
)


def base_send_half_state(local_send: bool) -> SendHalfState:
    """Return the initial send-half state for this stream shape."""

    local_send = require_bool(local_send, "local_send")
    return SendHalfState.OPEN if local_send else SendHalfState.ABSENT


def normalize_send_half_state(local_send: bool, send_half: SendHalfState) -> SendHalfState:
    """Resolve ``UNKNOWN`` send-half state from stream shape."""

    local_send = require_bool(local_send, "local_send")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    return base_send_half_state(local_send) if send_half is SendHalfState.UNKNOWN else send_half


def base_recv_half_state(local_receive: bool) -> RecvHalfState:
    """Return the initial receive-half state for this stream shape."""

    local_receive = require_bool(local_receive, "local_receive")
    return RecvHalfState.OPEN if local_receive else RecvHalfState.ABSENT


def normalize_recv_half_state(local_receive: bool, recv_half: RecvHalfState) -> RecvHalfState:
    """Resolve ``UNKNOWN`` receive-half state from stream shape."""

    local_receive = require_bool(local_receive, "local_receive")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    return base_recv_half_state(local_receive) if recv_half is RecvHalfState.UNKNOWN else recv_half


def send_terminal(send_half: SendHalfState) -> bool:
    """Return whether the send half has reached a terminal state."""

    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    return send_half in _SEND_TERMINAL_STATES


def recv_terminal(recv_half: RecvHalfState) -> bool:
    """Return whether the receive half has reached a terminal state."""

    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    return recv_half in _RECV_TERMINAL_STATES


def read_stopped(recv_half: RecvHalfState) -> bool:
    """Return whether local read was explicitly stopped."""

    return coerce_enum(recv_half, RecvHalfState, "recv_half") is RecvHalfState.STOP_SENT


def fully_terminal(
        local_send: bool,
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
) -> bool:
    """Return whether both present halves are terminal, with abort override."""

    local_send = require_bool(local_send, "local_send")
    local_receive = require_bool(local_receive, "local_receive")
    send_half = coerce_enum(send_half, SendHalfState, "send_half")
    recv_half = coerce_enum(recv_half, RecvHalfState, "recv_half")
    if send_half is SendHalfState.ABORTED or recv_half is RecvHalfState.ABORTED:
        return True
    send_done = (not local_send) or send_terminal(send_half)
    recv_done = (not local_receive) or recv_terminal(recv_half)
    return send_done and recv_done


def coerce_enum(value, enum_type, name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be a %s or integer" % (name, enum_type.__name__))
    return enum_type(value)


def require_bool(value: bool, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a bool" % name)
    return value


__all__ = (
    "RecvHalfState",
    "SendHalfState",
    "coerce_enum",
    "require_bool",
    "base_recv_half_state",
    "base_send_half_state",
    "fully_terminal",
    "normalize_recv_half_state",
    "normalize_send_half_state",
    "read_stopped",
    "recv_terminal",
    "send_terminal",
)
