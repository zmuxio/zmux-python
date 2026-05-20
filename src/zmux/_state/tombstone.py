"""Terminal tombstone and marker-only stream bookkeeping.

The Go implementation keeps compact state for fully terminal streams so late
DATA on a used stream can still be classified after the full stream object is
released.  This module mirrors that behavior as a pure Python state object:
visible tombstones, hidden control-opened tombstones, and marker-only ranges.
"""

from __future__ import annotations

import math
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Type

from .half import RecvHalfState, SendHalfState, coerce_enum, require_bool
from .terminal import TerminalErrorChoice, terminal_error_priority
from ..config import DEFAULT_TOMBSTONE_LIMIT, DEFAULT_USED_MARKER_LIMIT
from ..protocol import MAX_VARINT62

MAX_UINT64 = (1 << 64) - 1
INVALID_TOMBSTONE_INDEX = -1
MAX_TOMBSTONES = DEFAULT_TOMBSTONE_LIMIT
DEFAULT_MARKER_ONLY_USED_STREAM_LIMIT = DEFAULT_USED_MARKER_LIMIT
MARKER_ONLY_RANGE_COMPACT_THRESHOLD = 64
HIDDEN_CONTROL_RETAINED_HARD_CAP = 64
HIDDEN_CONTROL_RETAINED_MAX_AGE = 1.0
DEFAULT_RETAINED_STATE_UNIT = 4 << 10
DEFAULT_COMPACT_TERMINAL_STATE_UNIT = 64


class LateDataAction(IntEnum):
    IGNORE = 1
    ABORT_CLOSED = 2
    ABORT_STATE = 3


class TerminalKind(IntEnum):
    UNKNOWN = 0
    GRACEFUL = 1
    RESET = 2
    ABORTED = 3


class LateDataCause(IntEnum):
    NONE = 0
    CLOSE_READ = 1
    RESET = 2
    ABORT = 3


_TERMINAL_ABORT_CHOICES = (
    TerminalErrorChoice.SEND_ABORT,
    TerminalErrorChoice.RECV_ABORT,
)
_TERMINAL_RESET_CHOICES = (
    TerminalErrorChoice.SEND_RESET,
    TerminalErrorChoice.RECV_RESET,
)
_TERMINAL_GRACEFUL_CHOICES = (
    TerminalErrorChoice.SEND_CLOSED,
    TerminalErrorChoice.RECV_CLOSED,
)


@dataclass(frozen=True)
class StreamTombstone(object):
    data_action: LateDataAction = LateDataAction.IGNORE
    terminal_kind: TerminalKind = TerminalKind.UNKNOWN
    has_terminal_code: bool = False
    terminal_code: int = 0

    def __post_init__(self) -> None:
        _set_enum_field(self, "data_action", LateDataAction)
        _set_enum_field(self, "terminal_kind", TerminalKind)
        _set_bool_field(self, "has_terminal_code")
        _set_u64_field(self, "terminal_code")


def tombstone_late_data_action(local_receive: bool, recv_half: RecvHalfState) -> LateDataAction:
    local_receive = require_bool(local_receive, "local_receive")
    if not local_receive:
        return LateDataAction.IGNORE
    if coerce_enum(recv_half, RecvHalfState, "recv_half") is RecvHalfState.FIN:
        return LateDataAction.ABORT_CLOSED
    return LateDataAction.IGNORE


def tombstone_terminal_kind(
        send_half: SendHalfState, recv_half: RecvHalfState
) -> TerminalKind:
    choice = terminal_error_priority(send_half, recv_half)
    if choice in _TERMINAL_ABORT_CHOICES:
        return TerminalKind.ABORTED
    if choice in _TERMINAL_RESET_CHOICES:
        return TerminalKind.RESET
    if choice in _TERMINAL_GRACEFUL_CHOICES:
        return TerminalKind.GRACEFUL
    return TerminalKind.UNKNOWN


def tombstone_terminal_code(
        send_half: SendHalfState,
        recv_half: RecvHalfState,
        send_reset_code: Optional[int] = None,
        send_abort_code: Optional[int] = None,
        recv_reset_code: Optional[int] = None,
        recv_abort_code: Optional[int] = None,
) -> tuple[int, bool]:
    choice = terminal_error_priority(send_half, recv_half)
    if choice is TerminalErrorChoice.SEND_ABORT and send_abort_code is not None:
        return _require_varint62(send_abort_code, "send_abort_code"), True
    if choice is TerminalErrorChoice.RECV_ABORT and recv_abort_code is not None:
        return _require_varint62(recv_abort_code, "recv_abort_code"), True
    if choice is TerminalErrorChoice.SEND_RESET and send_reset_code is not None:
        return _require_varint62(send_reset_code, "send_reset_code"), True
    if choice is TerminalErrorChoice.RECV_RESET and recv_reset_code is not None:
        return _require_varint62(recv_reset_code, "recv_reset_code"), True
    return 0, False


def build_stream_tombstone(
        local_receive: bool,
        send_half: SendHalfState,
        recv_half: RecvHalfState,
        send_reset_code: Optional[int] = None,
        send_abort_code: Optional[int] = None,
        recv_reset_code: Optional[int] = None,
        recv_abort_code: Optional[int] = None,
) -> StreamTombstone:
    code, has_code = tombstone_terminal_code(
        send_half,
        recv_half,
        send_reset_code,
        send_abort_code,
        recv_reset_code,
        recv_abort_code,
    )
    return StreamTombstone(
        tombstone_late_data_action(local_receive, recv_half),
        tombstone_terminal_kind(send_half, recv_half),
        has_code,
        code,
    )


def should_compact_terminal(
        id_set: bool,
        fully_terminal_value: bool,
        recv_buffer: int,
        read_buf_len: int,
        still_tracked: bool,
) -> bool:
    id_set = require_bool(id_set, "id_set")
    fully_terminal_value = require_bool(fully_terminal_value, "fully_terminal_value")
    recv_buffer = _require_u64(recv_buffer, "recv_buffer")
    read_buf_len = _require_u64(read_buf_len, "read_buf_len")
    still_tracked = require_bool(still_tracked, "still_tracked")
    if not id_set or not fully_terminal_value:
        return False
    if recv_buffer != 0 or read_buf_len != 0:
        return False
    return still_tracked


@dataclass(frozen=True)
class UsedStreamMarker(object):
    action: LateDataAction = LateDataAction.IGNORE
    cause: LateDataCause = LateDataCause.NONE

    def __post_init__(self) -> None:
        _set_enum_field(self, "action", LateDataAction)
        _set_enum_field(self, "cause", LateDataCause)


@dataclass(frozen=True)
class TerminalDataDisposition(object):
    action: LateDataAction = LateDataAction.IGNORE
    cause: LateDataCause = LateDataCause.NONE

    def __post_init__(self) -> None:
        _set_enum_field(self, "action", LateDataAction)
        _set_enum_field(self, "cause", LateDataCause)

    def marker(self) -> UsedStreamMarker:
        return UsedStreamMarker(self.action, self.cause)


@dataclass
class UsedStreamRange(object):
    start: int
    end: int
    marker: UsedStreamMarker = field(default_factory=UsedStreamMarker)

    def __post_init__(self) -> None:
        self.start = _require_u64(self.start, "start")
        self.end = _require_u64(self.end, "end")
        if self.start > self.end:
            raise ValueError("start must be <= end")
        self.marker = _coerce_marker(self.marker)


@dataclass
class StreamTombstoneRecord(object):
    tombstone: StreamTombstone = field(default_factory=StreamTombstone)
    hidden: bool = False
    created_at: float = 0.0
    order_index: int = INVALID_TOMBSTONE_INDEX
    hidden_index: int = INVALID_TOMBSTONE_INDEX
    late_data_cause: LateDataCause = LateDataCause.NONE
    late_data_received: int = 0
    late_data_cap: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.tombstone, StreamTombstone):
            raise TypeError("tombstone must be a StreamTombstone")
        self.hidden = require_bool(self.hidden, "hidden")
        self.created_at = _require_timestamp(self.created_at, "created_at")
        self.order_index = _require_queue_index(self.order_index, "order_index")
        self.hidden_index = _require_queue_index(self.hidden_index, "hidden_index")
        self.late_data_cause = coerce_enum(
            self.late_data_cause, LateDataCause, "late_data_cause"
        )
        self.late_data_received = _require_u64(
            self.late_data_received,
            "late_data_received",
        )
        if self.late_data_cap is not None:
            self.late_data_cap = _require_u64(self.late_data_cap, "late_data_cap")

    def queue_index(self, hidden: bool) -> int:
        hidden = require_bool(hidden, "hidden")
        return self.hidden_index if hidden else self.order_index

    def set_queue_index(self, hidden: bool, index: int) -> None:
        hidden = require_bool(hidden, "hidden")
        index = _require_queue_index(index, "index")
        if hidden:
            self.hidden_index = index
        else:
            self.order_index = index

    def terminal_data_disposition(self) -> TerminalDataDisposition:
        return TerminalDataDisposition(
            self.tombstone.data_action,
            self.late_data_cause,
        )

    def used_stream_marker(self) -> UsedStreamMarker:
        return self.terminal_data_disposition().marker()

    def record_late_data(self, length: int) -> bool:
        length = _require_u64(length, "length")
        if length == 0:
            return False
        self.late_data_received = _saturating_add_u64(
            self.late_data_received,
            length,
        )
        return (
                self.late_data_cap is not None
                and self.late_data_received > self.late_data_cap
        )


@dataclass(frozen=True)
class StreamTombstoneLookup(object):
    tombstone: Optional[StreamTombstoneRecord] = None
    present: bool = False

    def found(self) -> bool:
        return self.present


@dataclass(frozen=True)
class TerminalDataLookup(object):
    disposition: TerminalDataDisposition = field(default_factory=TerminalDataDisposition)
    present: bool = False

    def found(self) -> bool:
        return self.present


@dataclass(frozen=True)
class TerminalLateDataResult(object):
    hidden: bool = False
    cap_exceeded: bool = False

    def __post_init__(self) -> None:
        _set_bool_field(self, "hidden")
        _set_bool_field(self, "cap_exceeded")


@dataclass(frozen=True)
class QueueIndexLookup(object):
    index: int = INVALID_TOMBSTONE_INDEX
    present: bool = False

    def found(self) -> bool:
        return self.present


@dataclass(frozen=True)
class TombstoneOrderLookup(object):
    stream_id: int = 0
    tombstone: Optional[StreamTombstoneRecord] = None
    present: bool = False

    def found(self) -> bool:
        return self.present


@dataclass(frozen=True)
class TombstoneIDLookup(object):
    stream_id: int = 0
    present: bool = False

    def found(self) -> bool:
        return self.present


def same_used_stream_marker(left: UsedStreamMarker, right: UsedStreamMarker) -> bool:
    return left.action == right.action and left.cause == right.cause


def used_stream_range_contains(stream_range: UsedStreamRange, stream_id: int) -> bool:
    stream_id = _require_u64(stream_id, "stream_id")
    return (
            stream_range.start <= stream_id <= stream_range.end
            and (stream_id - stream_range.start) % 4 == 0
    )


def used_stream_range_mergeable(
        left: UsedStreamRange,
        right: UsedStreamRange,
) -> bool:
    return (
            same_used_stream_marker(left.marker, right.marker)
            and left.start % 4 == right.start % 4
            and _range_end_reaches(left.end, right.start)
            and _range_end_reaches(right.end, left.start)
    )


def merge_used_stream_range_around(
        ranges: list[UsedStreamRange],
        index: int,
) -> list[UsedStreamRange]:
    if index < 0 or index >= len(ranges):
        return ranges
    while index > 0 and used_stream_range_mergeable(ranges[index - 1], ranges[index]):
        current = ranges.pop(index)
        previous = ranges[index - 1]
        if current.start < previous.start:
            previous.start = current.start
        if current.end > previous.end:
            previous.end = current.end
        index -= 1
    while index + 1 < len(ranges) and used_stream_range_mergeable(
            ranges[index],
            ranges[index + 1],
    ):
        next_range = ranges.pop(index + 1)
        if next_range.end > ranges[index].end:
            ranges[index].end = next_range.end
    return ranges


def set_contained_used_stream_marker(
        ranges: list[UsedStreamRange],
        index: int,
        stream_id: int,
        marker: UsedStreamMarker,
) -> list[UsedStreamRange]:
    stream_id = _require_u64(stream_id, "stream_id")
    if index < 0 or index >= len(ranges):
        return ranges
    current = ranges[index]
    if not used_stream_range_contains(current, stream_id):
        return ranges
    if same_used_stream_marker(current.marker, marker):
        return ranges

    replacement = []
    inserted_offset = 0
    if current.start < stream_id:
        replacement.append(UsedStreamRange(current.start, stream_id - 4, current.marker))
        inserted_offset = 1
    replacement.append(UsedStreamRange(stream_id, stream_id, marker))
    if stream_id < current.end:
        replacement.append(UsedStreamRange(stream_id + 4, current.end, current.marker))
    ranges[index: index + 1] = replacement
    return merge_used_stream_range_around(ranges, index + inserted_offset)


def upsert_used_stream_range(
        ranges: list[UsedStreamRange],
        stream_id: int,
        marker: UsedStreamMarker,
) -> list[UsedStreamRange]:
    stream_id = _require_u64(stream_id, "stream_id")
    index = _first_range_starting_after(ranges, stream_id)
    if index > 0 and used_stream_range_contains(ranges[index - 1], stream_id):
        return set_contained_used_stream_marker(ranges, index - 1, stream_id, marker)
    ranges.insert(index, UsedStreamRange(stream_id, stream_id, marker))
    return merge_used_stream_range_around(ranges, index)


def used_stream_marker_for(
        used_stream_ranges: Sequence[UsedStreamRange],
        used_stream_data: dict[int, UsedStreamMarker],
        stream_id: int,
) -> tuple[UsedStreamMarker, bool]:
    stream_id = _require_u64(stream_id, "stream_id")
    marker = used_stream_data.get(stream_id)
    if marker is not None:
        return marker, True
    if not used_stream_ranges:
        return UsedStreamMarker(), False
    index = _first_range_starting_after(used_stream_ranges, stream_id)
    if index > 0 and used_stream_range_contains(used_stream_ranges[index - 1], stream_id):
        return used_stream_ranges[index - 1].marker, True
    return UsedStreamMarker(), False


def used_stream_marker_from_tombstone(
        tombstone: StreamTombstone,
        cause: LateDataCause,
) -> UsedStreamMarker:
    if not isinstance(tombstone, StreamTombstone):
        raise TypeError("tombstone must be a StreamTombstone")
    cause = coerce_enum(cause, LateDataCause, "cause")
    return UsedStreamMarker(tombstone.data_action, cause)


@dataclass
class TerminalBookkeepingState(object):
    tombstone_limit: int = MAX_TOMBSTONES
    marker_only_used_stream_limit: Optional[int] = DEFAULT_MARKER_ONLY_USED_STREAM_LIMIT
    hidden_tombstone_limit: int = HIDDEN_CONTROL_RETAINED_HARD_CAP
    hidden_control_retained_max_age: float = HIDDEN_CONTROL_RETAINED_MAX_AGE
    tombstones: dict[int, StreamTombstoneRecord] = field(default_factory=dict)
    tombstone_order: list[Optional[int]] = field(default_factory=list)
    tombstone_head: int = 0
    tombstone_count: int = 0
    tombstones_init: bool = False
    hidden_tombstone_order: list[Optional[int]] = field(default_factory=list)
    hidden_tombstone_head: int = 0
    hidden_tombstone_count_value: int = 0
    hidden_tombstones_init: bool = False
    used_stream_data: dict[int, UsedStreamMarker] = field(default_factory=dict)
    used_stream_ranges: list[UsedStreamRange] = field(default_factory=list)
    used_stream_range_mode: bool = False
    marker_only_limit_exceeded: bool = False

    def __post_init__(self) -> None:
        self.tombstone_limit = _require_u64(self.tombstone_limit, "tombstone_limit")
        if self.marker_only_used_stream_limit is not None:
            self.marker_only_used_stream_limit = _require_u64(
                self.marker_only_used_stream_limit,
                "marker_only_used_stream_limit",
            )
        self.hidden_tombstone_limit = _require_u64(
            self.hidden_tombstone_limit,
            "hidden_tombstone_limit",
        )
        self.hidden_control_retained_max_age = _require_timestamp(
            self.hidden_control_retained_max_age,
            "hidden_control_retained_max_age",
        )
        self.marker_only_limit_exceeded = require_bool(
            self.marker_only_limit_exceeded,
            "marker_only_limit_exceeded",
        )

    def tombstone_for(self, stream_id: int) -> StreamTombstoneLookup:
        stream_id = _require_u64(stream_id, "stream_id")
        tombstone = self.tombstones.get(stream_id)
        return StreamTombstoneLookup(tombstone, tombstone is not None)

    def terminal_data_disposition_for(self, stream_id: int) -> TerminalDataLookup:
        stream_id = _require_u64(stream_id, "stream_id")
        tombstone = self.tombstones.get(stream_id)
        if tombstone is not None:
            return TerminalDataLookup(tombstone.terminal_data_disposition(), True)
        marker, present = self.used_stream_marker_for(stream_id)
        if not present:
            return TerminalDataLookup()
        return TerminalDataLookup(TerminalDataDisposition(marker.action, marker.cause), True)

    def has_terminal_marker(self, stream_id: int) -> bool:
        return self.terminal_data_disposition_for(stream_id).found()

    def record_terminal_late_data(
            self,
            stream_id: int,
            length: int,
    ) -> TerminalLateDataResult:
        stream_id = _require_u64(stream_id, "stream_id")
        length = _require_u64(length, "length")
        if length == 0:
            return TerminalLateDataResult()
        tombstone = self.tombstones.get(stream_id)
        if tombstone is None:
            return TerminalLateDataResult()
        return TerminalLateDataResult(
            tombstone.hidden,
            tombstone.record_late_data(length),
        )

    def record_tombstone(
            self,
            stream_id: int,
            tombstone: StreamTombstoneRecord,
            now: Optional[float] = None,
            enforce: bool = True,
    ) -> list[int]:
        stream_id = _require_u64(stream_id, "stream_id")
        if not isinstance(tombstone, StreamTombstoneRecord):
            raise TypeError("tombstone must be a StreamTombstoneRecord")
        enforce = require_bool(enforce, "enforce")
        now = time.monotonic() if now is None else _require_timestamp(now, "now")
        if tombstone.created_at <= 0:
            tombstone.created_at = now

        self.ensure_tombstone_queue()
        previous = self.tombstones.get(stream_id)
        if previous is not None and previous.hidden and not tombstone.hidden:
            self.remove_hidden_tombstone(stream_id, previous)

        self.mark_used_stream(stream_id, tombstone.used_stream_marker())
        self.tombstones[stream_id] = tombstone
        self.append_tombstone(stream_id)

        if tombstone.hidden:
            if previous is None or not previous.hidden:
                self.append_hidden_tombstone(stream_id)
            elif previous.hidden_index >= 0:
                tombstone.hidden_index = previous.hidden_index
                self.tombstones[stream_id] = tombstone

        removed = []
        if enforce:
            removed.extend(self.reap_excess_tombstones())
            removed.extend(self.enforce_hidden_control_state_budget(now))
        self.maybe_compact_tombstone_queue()
        self.maybe_compact_hidden_tombstone_queue()
        return removed

    def mark_used_stream(self, stream_id: int, marker: UsedStreamMarker) -> None:
        stream_id = _require_u64(stream_id, "stream_id")
        marker = _coerce_marker(marker)
        if self.used_stream_range_mode:
            upsert_used_stream_range(self.used_stream_ranges, stream_id, marker)
            self.drop_used_stream_map_entry(stream_id)
            self.enforce_marker_only_used_stream_limit()
            return
        self.used_stream_data[stream_id] = marker
        self.compact_marker_only_ranges()
        self.enforce_marker_only_used_stream_limit(check_only=True)

    def drop_used_stream_map_entry(self, stream_id: int) -> None:
        stream_id = _require_u64(stream_id, "stream_id")
        self.used_stream_data.pop(stream_id, None)

    def used_stream_marker_for(self, stream_id: int) -> tuple[UsedStreamMarker, bool]:
        return used_stream_marker_for(self.used_stream_ranges, self.used_stream_data, stream_id)

    def compact_marker_only_ranges(self) -> None:
        marker_only_count = self.marker_only_map_count()
        if (
                marker_only_count == 0
                or (
                marker_only_count <= self.marker_only_hard_cap()
                and marker_only_count < MARKER_ONLY_RANGE_COMPACT_THRESHOLD
        )
        ):
            return
        stream_ids = sorted(
            stream_id
            for stream_id in self.used_stream_data
            if stream_id not in self.tombstones
        )
        if not stream_ids:
            return
        for stream_id in stream_ids:
            marker = self.used_stream_data.pop(stream_id, None)
            if marker is not None:
                upsert_used_stream_range(self.used_stream_ranges, stream_id, marker)
        self.used_stream_range_mode = True

    def marker_only_map_count(self) -> int:
        if not self.used_stream_data or not self.tombstones:
            return len(self.used_stream_data)
        return sum(1 for stream_id in self.used_stream_data if stream_id not in self.tombstones)

    def marker_only_range_count(self) -> int:
        return len(self.used_stream_ranges)

    def marker_only_retained(self) -> int:
        return self.marker_only_map_count() + self.marker_only_range_count()

    def marker_only_hard_cap(self) -> int:
        if self.marker_only_used_stream_limit is None:
            return DEFAULT_MARKER_ONLY_USED_STREAM_LIMIT
        return self.marker_only_used_stream_limit

    def enforce_marker_only_used_stream_limit(self, check_only: bool = False) -> bool:
        if not check_only:
            self.compact_marker_only_ranges()
        self.marker_only_limit_exceeded = self.marker_only_retained() > self.marker_only_hard_cap()
        return not self.marker_only_limit_exceeded

    def hidden_control_state_retained(self) -> int:
        return self.hidden_tombstone_count()

    def visible_tombstone_retained(self) -> int:
        return max(0, self.tombstone_count_current() - self.hidden_control_state_retained())

    def hidden_control_state_bytes(
            self,
            retained_state_unit: int = DEFAULT_RETAINED_STATE_UNIT,
    ) -> int:
        retained_state_unit = _require_u64(retained_state_unit, "retained_state_unit")
        return _saturating_mul_u64(
            self.hidden_control_state_retained(),
            retained_state_unit,
        )

    def retained_state_bytes(
            self,
            retained_state_unit: int = DEFAULT_RETAINED_STATE_UNIT,
            compact_terminal_state_unit: int = DEFAULT_COMPACT_TERMINAL_STATE_UNIT,
    ) -> int:
        retained_state_unit = _require_u64(retained_state_unit, "retained_state_unit")
        compact_terminal_state_unit = _require_u64(
            compact_terminal_state_unit,
            "compact_terminal_state_unit",
        )
        hidden = _saturating_mul_u64(
            self.hidden_control_state_retained(),
            retained_state_unit,
        )
        visible = _saturating_mul_u64(
            self.visible_tombstone_retained(),
            compact_terminal_state_unit,
        )
        marker_only = _saturating_mul_u64(
            self.marker_only_retained(),
            compact_terminal_state_unit,
        )
        return _saturating_add_u64(_saturating_add_u64(hidden, visible), marker_only)

    def reap_excess_tombstones(self) -> list[int]:
        removed = []
        limit = self.effective_tombstone_limit()
        while self.tombstone_count_current() > limit:
            head = self.tombstone_head_id()
            if not head.found() or not self.remove_tombstone(head.stream_id):
                return removed
            removed.append(head.stream_id)
        self.maybe_compact_tombstone_queue()
        return removed

    def effective_tombstone_limit(self) -> int:
        return self.tombstone_limit

    def reap_tombstones_for_memory_pressure(
            self,
            tracked_session_memory: int,
            session_memory_hard_cap: int,
            retained_state_unit: int = DEFAULT_RETAINED_STATE_UNIT,
            compact_terminal_state_unit: int = DEFAULT_COMPACT_TERMINAL_STATE_UNIT,
    ) -> list[int]:
        tracked = _require_u64(tracked_session_memory, "tracked_session_memory")
        hard_cap = _require_u64(session_memory_hard_cap, "session_memory_hard_cap")
        retained_state_unit = _require_u64(retained_state_unit, "retained_state_unit")
        compact_terminal_state_unit = _require_u64(
            compact_terminal_state_unit,
            "compact_terminal_state_unit",
        )
        removed = []
        while self.tombstone_count_current() > 0 and tracked > hard_cap:
            head = self.tombstone_head_id()
            if not head.found():
                break
            tombstone = self.tombstones.get(head.stream_id)
            if tombstone is None:
                self.advance_tombstone_head()
                continue
            if not tombstone.hidden and self.visible_tombstone_retained() <= 1:
                break
            released = retained_state_unit if tombstone.hidden else compact_terminal_state_unit
            if not self.remove_tombstone(head.stream_id):
                break
            removed.append(head.stream_id)
            tracked = max(0, tracked - released)
        self.maybe_compact_tombstone_queue()
        return removed

    def enforce_hidden_control_state_budget(
            self,
            now: Optional[float] = None,
            session_memory_hard_cap: int = 0,
            retained_state_unit: int = DEFAULT_RETAINED_STATE_UNIT,
    ) -> list[int]:
        now = time.monotonic() if now is None else _require_timestamp(now, "now")
        removed = self.reap_expired_hidden_control_state(now)
        cap = self.hidden_tombstone_limit
        while self.hidden_control_state_retained() > cap:
            tail = self.hidden_tombstone_tail_id()
            if not tail.found() or not self.remove_tombstone(tail.stream_id):
                return removed
            removed.append(tail.stream_id)
        hard_cap = _require_u64(session_memory_hard_cap, "session_memory_hard_cap")
        retained_state_unit = _require_u64(retained_state_unit, "retained_state_unit")
        if hard_cap > 0:
            while self.hidden_control_state_bytes(retained_state_unit) > hard_cap:
                tail = self.hidden_tombstone_tail_id()
                if not tail.found() or not self.remove_tombstone(tail.stream_id):
                    return removed
                removed.append(tail.stream_id)
        self.maybe_compact_hidden_tombstone_queue()
        return removed

    def reap_expired_hidden_control_state(
            self, now: Optional[float] = None
    ) -> list[int]:
        now = time.monotonic() if now is None else _require_timestamp(now, "now")
        removed = []
        while True:
            head = self.hidden_tombstone_head_id()
            if not head.found():
                return removed
            tombstone = self.tombstones.get(head.stream_id)
            if tombstone is None or not tombstone.hidden:
                self._clear_hidden_head_slot()
                continue
            if (
                    tombstone.created_at <= 0
                    or now - tombstone.created_at <= self.hidden_control_retained_max_age
            ):
                return removed
            if not self.remove_tombstone(head.stream_id):
                return removed
            removed.append(head.stream_id)

    def remove_tombstone(self, stream_id: int) -> bool:
        stream_id = _require_u64(stream_id, "stream_id")
        self.ensure_tombstone_queue()
        tombstone = self.tombstones.get(stream_id)
        if tombstone is None:
            return False
        index = self.tombstone_index(stream_id, tombstone.order_index)
        if not index.found():
            return False
        return self.remove_tombstone_order_slot(index.index)

    def remove_tombstone_order_slot(self, index: int) -> bool:
        self.ensure_tombstone_queue()
        if index < self.tombstone_head:
            return False
        entry = self.tombstone_order_entry(index)
        if not entry.found() or entry.tombstone is None:
            return False
        self.tombstone_order[index] = None
        self.tombstone_count = max(0, self.tombstone_count - 1)
        tombstone = entry.tombstone
        self.mark_used_stream(entry.stream_id, tombstone.used_stream_marker())
        tombstone.order_index = INVALID_TOMBSTONE_INDEX
        self.remove_hidden_tombstone(entry.stream_id, tombstone)
        self.tombstones.pop(entry.stream_id, None)
        if index == self.tombstone_head:
            self.advance_tombstone_head()
        self.maybe_compact_tombstone_queue()
        return True

    def ensure_tombstone_queue(self) -> None:
        if self.tombstones_init:
            return
        self.tombstone_head = 0
        self.tombstone_count = 0
        if not self.tombstones or not self.tombstone_order:
            self.tombstones_init = True
            return
        for index, stream_id in enumerate(self.tombstone_order):
            if stream_id is None:
                continue
            tombstone = self.tombstones.get(stream_id)
            if tombstone is None:
                continue
            tombstone.order_index = index
            self.tombstone_count += 1
        self.tombstones_init = True

    def tombstone_count_current(self) -> int:
        self.ensure_tombstone_queue()
        return self.tombstone_count

    def tombstone_order_entry(self, index: int) -> TombstoneOrderLookup:
        if index < 0 or index >= len(self.tombstone_order):
            return TombstoneOrderLookup()
        stream_id = self.tombstone_order[index]
        if stream_id is None:
            return TombstoneOrderLookup()
        tombstone = self.tombstones.get(stream_id)
        if tombstone is None or tombstone.order_index != index:
            return TombstoneOrderLookup()
        return TombstoneOrderLookup(stream_id, tombstone, True)

    def tombstone_index(
            self,
            stream_id: int,
            hint: int = INVALID_TOMBSTONE_INDEX,
    ) -> QueueIndexLookup:
        stream_id = _require_u64(stream_id, "stream_id")
        if self.tombstone_order_contains(stream_id, hint):
            return QueueIndexLookup(hint, True)
        if stream_id not in self.tombstones:
            return QueueIndexLookup()
        for index in range(self.tombstone_head, len(self.tombstone_order)):
            if self.tombstone_order[index] == stream_id:
                return QueueIndexLookup(index, True)
        return QueueIndexLookup()

    def tombstone_order_contains(self, stream_id: int, index: int) -> bool:
        if index < 0 or index >= len(self.tombstone_order):
            return False
        if self.tombstone_order[index] != stream_id:
            return False
        tombstone = self.tombstones.get(stream_id)
        return tombstone is not None and tombstone.order_index == index

    def advance_tombstone_head(self) -> None:
        while self.tombstone_head < len(self.tombstone_order):
            if self.tombstone_order_entry(self.tombstone_head).found():
                return
            self.tombstone_head += 1

    def tombstone_head_id(self) -> TombstoneIDLookup:
        self.ensure_tombstone_queue()
        self.advance_tombstone_head()
        entry = self.tombstone_order_entry(self.tombstone_head)
        if entry.found():
            return TombstoneIDLookup(entry.stream_id, True)
        return TombstoneIDLookup()

    def tombstone_tail_id(self) -> TombstoneIDLookup:
        self.ensure_tombstone_queue()
        for index in range(len(self.tombstone_order) - 1, self.tombstone_head - 1, -1):
            entry = self.tombstone_order_entry(index)
            if entry.found():
                return TombstoneIDLookup(entry.stream_id, True)
        return TombstoneIDLookup()

    def append_tombstone(self, stream_id: int) -> None:
        self.ensure_tombstone_queue()
        self._append_indexed_tombstone(stream_id, False)

    def maybe_compact_tombstone_queue(self) -> None:
        self.ensure_tombstone_queue()
        self._compact_indexed_tombstone_queue(False)

    def ensure_hidden_tombstones(self) -> None:
        if self.hidden_tombstones_init:
            return
        self.ensure_tombstone_queue()
        self.hidden_tombstone_head = 0
        self.hidden_tombstone_count_value = 0
        self.hidden_tombstone_order = []
        for index in range(self.tombstone_head, len(self.tombstone_order)):
            entry = self.tombstone_order_entry(index)
            if not entry.found() or entry.tombstone is None:
                continue
            if not entry.tombstone.hidden:
                entry.tombstone.hidden_index = INVALID_TOMBSTONE_INDEX
                continue
            entry.tombstone.hidden_index = len(self.hidden_tombstone_order)
            self.hidden_tombstone_order.append(entry.stream_id)
            self.hidden_tombstone_count_value += 1
        self.hidden_tombstones_init = True

    def hidden_tombstone_count(self) -> int:
        self.ensure_hidden_tombstones()
        return self.hidden_tombstone_count_value

    def hidden_tombstone_order_entry(self, index: int) -> TombstoneOrderLookup:
        if index < 0 or index >= len(self.hidden_tombstone_order):
            return TombstoneOrderLookup()
        stream_id = self.hidden_tombstone_order[index]
        if stream_id is None:
            return TombstoneOrderLookup()
        tombstone = self.tombstones.get(stream_id)
        if tombstone is None or not tombstone.hidden or tombstone.hidden_index != index:
            return TombstoneOrderLookup()
        return TombstoneOrderLookup(stream_id, tombstone, True)

    def hidden_tombstone_index(
            self,
            stream_id: int,
            hint: int = INVALID_TOMBSTONE_INDEX,
    ) -> QueueIndexLookup:
        stream_id = _require_u64(stream_id, "stream_id")
        if self.hidden_tombstone_order_contains(stream_id, hint):
            return QueueIndexLookup(hint, True)
        for index, candidate in enumerate(self.hidden_tombstone_order):
            if candidate == stream_id:
                return QueueIndexLookup(index, True)
        return QueueIndexLookup()

    def hidden_tombstone_order_contains(self, stream_id: int, index: int) -> bool:
        if index < 0 or index >= len(self.hidden_tombstone_order):
            return False
        if self.hidden_tombstone_order[index] != stream_id:
            return False
        tombstone = self.tombstones.get(stream_id)
        return tombstone is not None and tombstone.hidden and tombstone.hidden_index == index

    def advance_hidden_tombstone_head(self) -> None:
        while self.hidden_tombstone_head < len(self.hidden_tombstone_order):
            if self.hidden_tombstone_order_entry(self.hidden_tombstone_head).found():
                return
            self.hidden_tombstone_head += 1

    def hidden_tombstone_head_id(self) -> TombstoneIDLookup:
        self.ensure_hidden_tombstones()
        self.advance_hidden_tombstone_head()
        entry = self.hidden_tombstone_order_entry(self.hidden_tombstone_head)
        if entry.found():
            return TombstoneIDLookup(entry.stream_id, True)
        return TombstoneIDLookup()

    def hidden_tombstone_tail_id(self) -> TombstoneIDLookup:
        self.ensure_hidden_tombstones()
        for index in range(
                len(self.hidden_tombstone_order) - 1,
                self.hidden_tombstone_head - 1,
                -1,
        ):
            entry = self.hidden_tombstone_order_entry(index)
            if entry.found():
                return TombstoneIDLookup(entry.stream_id, True)
        return TombstoneIDLookup()

    def append_hidden_tombstone(self, stream_id: int) -> None:
        self.ensure_hidden_tombstones()
        self._append_indexed_tombstone(stream_id, True)

    def remove_hidden_tombstone(
            self,
            stream_id: int,
            tombstone: StreamTombstoneRecord,
    ) -> None:
        stream_id = _require_u64(stream_id, "stream_id")
        if not isinstance(tombstone, StreamTombstoneRecord):
            raise TypeError("tombstone must be a StreamTombstoneRecord")
        if not tombstone.hidden:
            return
        self.ensure_hidden_tombstones()
        index = self.hidden_tombstone_index(stream_id, tombstone.hidden_index)
        if not index.found():
            return
        self.hidden_tombstone_order[index.index] = None
        tombstone.hidden_index = INVALID_TOMBSTONE_INDEX
        self.hidden_tombstone_count_value = max(0, self.hidden_tombstone_count_value - 1)
        if stream_id in self.tombstones:
            self.tombstones[stream_id] = tombstone
        if index.index == self.hidden_tombstone_head:
            self.advance_hidden_tombstone_head()
        self.maybe_compact_hidden_tombstone_queue()

    def maybe_compact_hidden_tombstone_queue(self) -> None:
        self.ensure_hidden_tombstones()
        self._compact_indexed_tombstone_queue(True)

    def tombstone_order_ids(self) -> list[int]:
        self.maybe_compact_tombstone_queue()
        return [
            entry.stream_id
            for index in range(self.tombstone_head, len(self.tombstone_order))
            if (entry := self.tombstone_order_entry(index)).found()
        ]

    def hidden_tombstone_order_ids(self) -> list[int]:
        self.maybe_compact_hidden_tombstone_queue()
        return [
            entry.stream_id
            for index in range(self.hidden_tombstone_head, len(self.hidden_tombstone_order))
            if (entry := self.hidden_tombstone_order_entry(index)).found()
        ]

    def clear(self) -> None:
        self.tombstones.clear()
        self.tombstone_order = []
        self.tombstone_head = 0
        self.tombstone_count = 0
        self.tombstones_init = False
        self.hidden_tombstone_order = []
        self.hidden_tombstone_head = 0
        self.hidden_tombstone_count_value = 0
        self.hidden_tombstones_init = False
        self.used_stream_data.clear()
        self.used_stream_ranges = []
        self.used_stream_range_mode = False
        self.marker_only_limit_exceeded = False

    def _append_indexed_tombstone(self, stream_id: int, hidden: bool) -> None:
        tombstone = self.tombstones.get(stream_id)
        if tombstone is None or (hidden and not tombstone.hidden):
            return
        lookup = (
            self.hidden_tombstone_index(stream_id, tombstone.queue_index(True))
            if hidden
            else self.tombstone_index(stream_id, tombstone.queue_index(False))
        )
        if lookup.found():
            if tombstone.queue_index(hidden) != lookup.index:
                tombstone.set_queue_index(hidden, lookup.index)
            return
        order = self.hidden_tombstone_order if hidden else self.tombstone_order
        tombstone.set_queue_index(hidden, len(order))
        order.append(stream_id)
        if hidden:
            self.hidden_tombstone_count_value += 1
        else:
            self.tombstone_count += 1

    def _compact_indexed_tombstone_queue(self, hidden: bool) -> None:
        order = self.hidden_tombstone_order if hidden else self.tombstone_order
        head = self.hidden_tombstone_head if hidden else self.tombstone_head
        count = self.hidden_tombstone_count_value if hidden else self.tombstone_count
        if count <= 0:
            if hidden:
                self.hidden_tombstone_order = []
                self.hidden_tombstone_head = 0
                self.hidden_tombstone_count_value = 0
                self.hidden_tombstones_init = True
            else:
                self.tombstone_order = []
                self.tombstone_head = 0
                self.tombstone_count = 0
                self.tombstones_init = True
            return
        if head == 0 and len(order) <= 2 * count:
            return

        compacted = []
        for index in range(head, len(order)):
            entry = (
                self.hidden_tombstone_order_entry(index)
                if hidden
                else self.tombstone_order_entry(index)
            )
            if not entry.found() or entry.tombstone is None:
                continue
            entry.tombstone.set_queue_index(hidden, len(compacted))
            compacted.append(entry.stream_id)
        if hidden:
            self.hidden_tombstone_order = compacted
            self.hidden_tombstone_head = 0
            self.hidden_tombstone_count_value = len(compacted)
            self.hidden_tombstones_init = True
        else:
            self.tombstone_order = compacted
            self.tombstone_head = 0
            self.tombstone_count = len(compacted)
            self.tombstones_init = True

    def _clear_hidden_head_slot(self) -> None:
        if self.hidden_tombstone_head < len(self.hidden_tombstone_order):
            self.hidden_tombstone_order[self.hidden_tombstone_head] = None
            self.hidden_tombstone_count_value = max(0, self.hidden_tombstone_count_value - 1)
        self.advance_hidden_tombstone_head()
        self.maybe_compact_hidden_tombstone_queue()


def _first_range_starting_after(ranges: Sequence[UsedStreamRange], stream_id: int) -> int:
    low = 0
    high = len(ranges)
    while low < high:
        mid = (low + high) >> 1
        if ranges[mid].start > stream_id:
            high = mid
        else:
            low = mid + 1
    return low


def _range_end_reaches(end: int, start: int) -> bool:
    return end >= start or (end <= MAX_UINT64 - 4 and end + 4 >= start)


def _saturating_add_u64(left: int, right: int) -> int:
    if left >= MAX_UINT64 or right >= MAX_UINT64 - left:
        return MAX_UINT64
    return left + right


def _saturating_mul_u64(left: int, right: int) -> int:
    if left == 0 or right == 0:
        return 0
    if left >= MAX_UINT64 or right >= MAX_UINT64 or left > MAX_UINT64 // right:
        return MAX_UINT64
    return left * right


def _require_u64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    if value > MAX_UINT64:
        raise ValueError("%s must be <= uint64 max" % name)
    return value


def _require_queue_index(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < INVALID_TOMBSTONE_INDEX:
        raise ValueError("%s must be >= %d" % (name, INVALID_TOMBSTONE_INDEX))
    return value


def _require_timestamp(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a number" % name)
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError("%s must be finite and >= 0" % name)
    return value


def _require_varint62(value: int, name: str) -> int:
    value = _require_u64(value, name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % name)
    return value


def _coerce_marker(value: UsedStreamMarker) -> UsedStreamMarker:
    if not isinstance(value, UsedStreamMarker):
        raise TypeError("marker must be a UsedStreamMarker")
    return value


def _set_bool_field(instance: object, name: str) -> None:
    object.__setattr__(instance, name, require_bool(getattr(instance, name), name))


def _set_enum_field(instance: object, name: str, enum_type: Type[IntEnum]) -> None:
    object.__setattr__(
        instance,
        name,
        coerce_enum(getattr(instance, name), enum_type, name),
    )


def _set_u64_field(instance: object, name: str) -> None:
    object.__setattr__(instance, name, _require_u64(getattr(instance, name), name))


__all__ = (
    "DEFAULT_COMPACT_TERMINAL_STATE_UNIT",
    "DEFAULT_MARKER_ONLY_USED_STREAM_LIMIT",
    "DEFAULT_RETAINED_STATE_UNIT",
    "HIDDEN_CONTROL_RETAINED_HARD_CAP",
    "HIDDEN_CONTROL_RETAINED_MAX_AGE",
    "INVALID_TOMBSTONE_INDEX",
    "LateDataAction",
    "LateDataCause",
    "MARKER_ONLY_RANGE_COMPACT_THRESHOLD",
    "MAX_TOMBSTONES",
    "MAX_UINT64",
    "QueueIndexLookup",
    "StreamTombstoneLookup",
    "StreamTombstoneRecord",
    "TerminalBookkeepingState",
    "TerminalDataDisposition",
    "TerminalDataLookup",
    "TerminalLateDataResult",
    "TerminalKind",
    "TombstoneIDLookup",
    "TombstoneOrderLookup",
    "UsedStreamMarker",
    "UsedStreamRange",
    "StreamTombstone",
    "build_stream_tombstone",
    "merge_used_stream_range_around",
    "same_used_stream_marker",
    "set_contained_used_stream_marker",
    "should_compact_terminal",
    "tombstone_late_data_action",
    "tombstone_terminal_code",
    "tombstone_terminal_kind",
    "upsert_used_stream_range",
    "used_stream_marker_for",
    "used_stream_marker_from_tombstone",
    "used_stream_range_contains",
    "used_stream_range_mergeable",
)
