"""Session lifecycle transition plans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from .half import require_bool
from ..errors import SessionClosed, error_code
from ..protocol import ErrorCode
from ..session import SessionState

MAX_ERROR_UNWRAP_DEPTH = 64
_CAN_OPEN_STATES = frozenset((SessionState.READY, SessionState.DRAINING))
_TERMINAL_STATES = frozenset((SessionState.CLOSED, SessionState.FAILED))
_LOCAL_CONTROL_BLOCKED_STATES = frozenset(
    (SessionState.CLOSING, SessionState.CLOSED, SessionState.FAILED)
)
_ORDERLY_TRANSPORT_CLOSE_STATES = frozenset(
    (SessionState.CLOSING, SessionState.CLOSED)
)
_TRANSPORT_CLOSE_TYPES = (
    EOFError,
    BrokenPipeError,
)


class BeginCloseOutcome(str, Enum):
    RETURN_EXISTING = "return_existing"
    WAIT_EXISTING = "wait_existing"
    GRACEFUL = "graceful"
    ABORTIVE = "abortive"


class LocalOpenOutcome(str, Enum):
    ALLOW = "allow"
    RETURN_EXISTING = "return_existing"
    RETURN_CLOSED = "return_closed"


@dataclass(frozen=True)
class BeginClosePlan:
    outcome: BeginCloseOutcome
    next_state: SessionState

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "outcome",
            coerce_enum(self.outcome, BeginCloseOutcome, "outcome"),
        )
        object.__setattr__(
            self,
            "next_state",
            _coerce_session_state(self.next_state),
        )


@dataclass(frozen=True)
class PeerGoAwayPlan:
    ignore: bool = False
    changed: bool = False
    next_state: Optional[SessionState] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ignore", require_bool(self.ignore, "ignore"))
        object.__setattr__(self, "changed", require_bool(self.changed, "changed"))
        if self.next_state is not None:
            object.__setattr__(
                self,
                "next_state",
                _coerce_session_state(self.next_state),
            )


@dataclass(frozen=True)
class PeerClosePlan:
    ignore: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "ignore", require_bool(self.ignore, "ignore"))


def can_open_locally(state: Any) -> bool:
    state = _coerce_session_state(state)
    return state in _CAN_OPEN_STATES


def is_session_finished(state: Any) -> bool:
    return _coerce_session_state(state) in _TERMINAL_STATES


def ignore_peer_non_close_frame(state: Any, close_error_present: bool) -> bool:
    close_error_present = require_bool(close_error_present, "close_error_present")
    if close_error_present:
        return True
    state = _coerce_session_state(state)
    return state is SessionState.CLOSING or state.terminal()


def allow_local_non_close_control(
        state: Any,
        close_error_present: bool = False,
        peer_close_error_present: bool = False,
        close_frame_outstanding: bool = False,
) -> bool:
    close_error_present = require_bool(close_error_present, "close_error_present")
    peer_close_error_present = require_bool(
        peer_close_error_present, "peer_close_error_present"
    )
    close_frame_outstanding = require_bool(
        close_frame_outstanding, "close_frame_outstanding"
    )
    if close_error_present or peer_close_error_present or close_frame_outstanding:
        return False
    state = _coerce_session_state(state)
    return state not in _LOCAL_CONTROL_BLOCKED_STATES


def plan_local_open(
        state: Any,
        graceful_close_active: bool = False,
        close_error_present: bool = False,
) -> LocalOpenOutcome:
    graceful_close_active = require_bool(
        graceful_close_active, "graceful_close_active"
    )
    close_error_present = require_bool(close_error_present, "close_error_present")
    if close_error_present:
        return LocalOpenOutcome.RETURN_EXISTING
    if graceful_close_active:
        return LocalOpenOutcome.RETURN_CLOSED
    if can_open_locally(state):
        return LocalOpenOutcome.ALLOW
    return LocalOpenOutcome.RETURN_CLOSED


def plan_begin_close(
        state: Any,
        graceful_close_active: bool = False,
        close_error_present: bool = False,
        has_open_streams: bool = False,
) -> BeginClosePlan:
    graceful_close_active = require_bool(
        graceful_close_active, "graceful_close_active"
    )
    close_error_present = require_bool(close_error_present, "close_error_present")
    has_open_streams = require_bool(has_open_streams, "has_open_streams")
    state = _coerce_session_state(state)
    if state.terminal():
        return BeginClosePlan(BeginCloseOutcome.RETURN_EXISTING, state)
    if state is SessionState.CLOSING or graceful_close_active:
        return BeginClosePlan(BeginCloseOutcome.WAIT_EXISTING, state)
    if close_error_present:
        return BeginClosePlan(BeginCloseOutcome.RETURN_EXISTING, state)
    if can_open_locally(state) and has_open_streams:
        return BeginClosePlan(BeginCloseOutcome.GRACEFUL, SessionState.DRAINING)
    return BeginClosePlan(BeginCloseOutcome.ABORTIVE, SessionState.CLOSING)


def advance_session_on_go_away(state: Any, changed: bool) -> SessionState:
    changed = require_bool(changed, "changed")
    state = _coerce_session_state(state)
    if changed and state is SessionState.READY:
        return SessionState.DRAINING
    return state


def plan_peer_go_away(
        state: Any,
        close_error_present: bool,
        current_bidi: int,
        current_uni: int,
        next_bidi: int,
        next_uni: int,
) -> PeerGoAwayPlan:
    close_error_present = require_bool(close_error_present, "close_error_present")
    current_bidi = _nonnegative_int(current_bidi, "current_bidi")
    current_uni = _nonnegative_int(current_uni, "current_uni")
    next_bidi = _nonnegative_int(next_bidi, "next_bidi")
    next_uni = _nonnegative_int(next_uni, "next_uni")
    state = _coerce_session_state(state)
    if ignore_peer_non_close_frame(state, close_error_present):
        return PeerGoAwayPlan(ignore=True, next_state=state)
    changed = next_bidi < current_bidi or next_uni < current_uni
    return PeerGoAwayPlan(
        changed=changed,
        next_state=advance_session_on_go_away(state, changed),
    )


def begin_session_closing(state: Any) -> SessionState:
    state = _coerce_session_state(state)
    if state.terminal():
        return state
    return SessionState.CLOSING


def close_session_state(
        state: Any,
        err: Optional[BaseException],
        closed_sentinel: Optional[BaseException] = None,
) -> SessionState:
    state = _coerce_session_state(state)
    if err is None or _is_closed_sentinel(err, closed_sentinel):
        return SessionState.CLOSED
    code_value = error_code(err)
    if code_value is not None:
        if code_value == int(ErrorCode.NO_ERROR):
            return SessionState.CLOSED
        return SessionState.FAILED
    if _is_transport_close(err):
        return SessionState.CLOSED if _is_orderly_transport_close(state) else SessionState.FAILED
    return SessionState.FAILED


def visible_session_error(
        state: Any,
        err: Optional[BaseException],
        closed_sentinel: Optional[BaseException] = None,
) -> Optional[BaseException]:
    state = _coerce_session_state(state)
    sentinel = _closed_sentinel(closed_sentinel)
    if err is None or _is_closed_sentinel(err, closed_sentinel):
        return sentinel
    code_value = error_code(err)
    if code_value == int(ErrorCode.NO_ERROR):
        return sentinel
    if _is_transport_close(err) and _is_orderly_transport_close(state):
        return sentinel
    return err


def is_benign_session_error(
        state: Any,
        err: Optional[BaseException],
        closed_sentinel: Optional[BaseException] = None,
) -> bool:
    visible = visible_session_error(state, err, closed_sentinel)
    return visible is None or _is_closed_sentinel(visible, closed_sentinel)


def ignore_peer_close(
        close_error: Optional[BaseException],
        peer_close_error_present: bool,
        closed_sentinel: Optional[BaseException] = None,
) -> bool:
    peer_close_error_present = require_bool(
        peer_close_error_present, "peer_close_error_present"
    )
    if peer_close_error_present:
        return True
    if close_error is None:
        return False
    if _is_closed_sentinel(close_error, closed_sentinel):
        return True
    if error_code(close_error) is not None:
        return True
    return not _is_transport_close(close_error)


def plan_peer_close(
        close_error: Optional[BaseException],
        peer_close_error_present: bool,
        closed_sentinel: Optional[BaseException] = None,
) -> PeerClosePlan:
    return PeerClosePlan(
        ignore_peer_close(close_error, peer_close_error_present, closed_sentinel)
    )


def _coerce_session_state(value: Any) -> SessionState:
    if isinstance(value, SessionState):
        return value
    if isinstance(value, str):
        return SessionState(value)
    raise TypeError("session state must be a SessionState or string")


def coerce_enum(value: Any, enum_type: type[Enum], name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, bool):
        raise TypeError("%s must be a %s or string" % (name, enum_type.__name__))
    try:
        return enum_type(value)
    except ValueError:
        raise
    except Exception as exc:
        raise TypeError(
            "%s must be a %s or string" % (name, enum_type.__name__)
        ) from exc


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


def _closed_sentinel(closed_sentinel: Optional[BaseException]) -> BaseException:
    return closed_sentinel if closed_sentinel is not None else SessionClosed()


def _is_closed_sentinel(
        err: BaseException,
        closed_sentinel: Optional[BaseException],
) -> bool:
    if closed_sentinel is None:
        return any(isinstance(item, SessionClosed) for item in _walk_error_chain(err))
    return any(_same_error(item, closed_sentinel) for item in _walk_error_chain(err))


def _is_orderly_transport_close(state: SessionState) -> bool:
    return state in _ORDERLY_TRANSPORT_CLOSE_STATES


def _is_transport_close(err: BaseException) -> bool:
    return any(isinstance(item, _TRANSPORT_CLOSE_TYPES) for item in _walk_error_chain(err))


def _same_error(err: BaseException, target: BaseException) -> bool:
    try:
        return err is target or err == target
    except Exception:
        return False


def _walk_error_chain(err: Optional[BaseException]):
    seen = set()
    stack = [(err, 0)]
    while stack:
        item, depth = stack.pop()
        if item is None or depth > MAX_ERROR_UNWRAP_DEPTH:
            continue
        ident = id(item)
        if ident in seen:
            continue
        seen.add(ident)
        yield item
        next_depth = depth + 1
        cause = getattr(item, "__cause__", None)
        if cause is not None:
            stack.append((cause, next_depth))
        context = getattr(item, "__context__", None)
        if context is not None and context is not cause:
            stack.append((context, next_depth))
        try:
            children = iter(getattr(item, "exceptions", ()) or ())
        except TypeError:
            children = ()
        for child in children:
            if isinstance(child, BaseException):
                stack.append((child, next_depth))


__all__ = (
    "BeginCloseOutcome",
    "BeginClosePlan",
    "LocalOpenOutcome",
    "MAX_ERROR_UNWRAP_DEPTH",
    "PeerClosePlan",
    "PeerGoAwayPlan",
    "advance_session_on_go_away",
    "allow_local_non_close_control",
    "begin_session_closing",
    "can_open_locally",
    "close_session_state",
    "ignore_peer_close",
    "ignore_peer_non_close_frame",
    "is_benign_session_error",
    "is_session_finished",
    "plan_begin_close",
    "plan_local_open",
    "plan_peer_close",
    "plan_peer_go_away",
    "visible_session_error",
)
