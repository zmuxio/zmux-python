"""Lifecycle event value types."""

from __future__ import annotations

import math
import time as _time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    TerminationKind,
    ZmuxError,
    as_structured_error,
    code as _error_code,
    direction as _error_direction,
    has_code as _error_has_code,
    interrupted as _error_interrupted,
    operation as _error_operation,
    reason as _error_reason,
    scope as _error_scope,
    source as _error_source,
    termination_kind as _error_termination_kind,
    timeout as _error_timeout,
)
from .payload import StreamMetadata, StreamMetadataView
from .protocol import MAX_VARINT62


class EventType(str, Enum):
    """Repository-default lifecycle event kinds."""

    STREAM_OPENED = "stream_opened"
    STREAM_ACCEPTED = "stream_accepted"
    SESSION_CLOSED = "session_closed"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class StreamEventInfo:
    """Metadata attached to stream lifecycle events."""

    stream_id: int
    metadata: StreamMetadata = field(default_factory=StreamMetadata)
    local: bool = False
    bidirectional: bool = False
    application_visible: bool = False
    local_addr: Optional[object] = None
    remote_addr: Optional[object] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "stream_id", _require_stream_id(self.stream_id, "stream_id")
        )
        object.__setattr__(self, "metadata", _coerce_metadata(self.metadata))
        object.__setattr__(self, "local", _coerce_bool(self.local, "local"))
        object.__setattr__(
            self,
            "bidirectional",
            _coerce_bool(self.bidirectional, "bidirectional"),
        )
        object.__setattr__(
            self,
            "application_visible",
            _coerce_bool(self.application_visible, "application_visible"),
        )

    @property
    def open_info(self) -> bytes:
        """Return the peer-visible open metadata bytes."""

        return self.metadata.open_info

    @property
    def has_open_info(self) -> bool:
        """Return whether the event carries peer-visible open metadata."""

        return bool(self.metadata.open_info)


@dataclass(frozen=True)
class Event:
    """A lightweight stream or session lifecycle notification."""

    event_type: EventType
    session_state: Optional[object] = None
    stream: Optional[StreamEventInfo] = None
    time: float = field(default_factory=_time.time)
    error: Optional[BaseException] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_type", _coerce_event_type(self.event_type))
        object.__setattr__(self, "session_state", _coerce_session_state(self.session_state))
        object.__setattr__(self, "stream", _coerce_stream_event_info(self.stream))
        object.__setattr__(self, "time", _coerce_timestamp(self.time))
        if self.error is not None and not isinstance(self.error, BaseException):
            raise TypeError("error must be an exception or None")

    @property
    def stream_id(self) -> int:
        return 0 if self.stream is None else self.stream.stream_id

    @property
    def local(self) -> bool:
        return False if self.stream is None else self.stream.local

    @property
    def bidirectional(self) -> bool:
        return False if self.stream is None else self.stream.bidirectional

    @property
    def application_visible(self) -> bool:
        return False if self.stream is None else self.stream.application_visible

    @property
    def is_stream_event(self) -> bool:
        return self.stream is not None

    @property
    def error_details(self) -> Optional[ZmuxError]:
        return as_structured_error(self.error)

    @property
    def error_has_code(self) -> bool:
        return _error_has_code(self.error)

    def error_code(self, fallback: Optional[int] = None) -> Optional[int]:
        return _error_code(self.error, fallback)

    @property
    def error_operation(self) -> ErrorOperation:
        return _error_operation(self.error)

    @property
    def error_reason(self) -> str:
        return _error_reason(self.error)

    @property
    def error_scope(self) -> ErrorScope:
        return _error_scope(self.error)

    @property
    def error_source(self) -> ErrorSource:
        return _error_source(self.error)

    @property
    def error_direction(self) -> ErrorDirection:
        return _error_direction(self.error)

    @property
    def error_termination_kind(self) -> TerminationKind:
        return _error_termination_kind(self.error)

    @property
    def error_timeout(self) -> bool:
        return _error_timeout(self.error)

    @property
    def error_interrupted(self) -> bool:
        return _error_interrupted(self.error)


def _coerce_event_type(value: EventType) -> EventType:
    if isinstance(value, EventType):
        return value
    try:
        return EventType(value)
    except ValueError as exc:
        raise ValueError("invalid event type: %r" % (value,)) from exc


def _coerce_session_state(value: Optional[object]) -> Optional[object]:
    if value is None:
        return None
    from .session import SessionState

    if isinstance(value, SessionState):
        return value
    if isinstance(value, str):
        return SessionState(value)
    raise TypeError("session_state must be a SessionState, string, or None")


def _coerce_stream_event_info(
        value: Optional[StreamEventInfo],
) -> Optional[StreamEventInfo]:
    if value is None:
        return None
    if isinstance(value, StreamEventInfo):
        return value
    raise TypeError("stream must be StreamEventInfo or None")


def _coerce_metadata(value: object) -> StreamMetadata:
    if value is None:
        return StreamMetadata()
    if isinstance(value, StreamMetadata):
        return value
    if isinstance(value, StreamMetadataView):
        return value.to_owned()
    raise TypeError("metadata must be StreamMetadata")


def _require_stream_id(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % field_name)
    return int(value)


def _coerce_bool(value: bool, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a bool" % field_name)
    return value


def _coerce_timestamp(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("time must be a number")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("time must be finite")
    return value


__all__ = [
    "Event",
    "EventType",
    "StreamEventInfo",
]
