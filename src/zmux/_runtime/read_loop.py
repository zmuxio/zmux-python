"""Read-loop ingress helpers for the native runtime.

The concrete session object owns locking, stream registries, and condition
variables.  This module keeps the reusable read-loop policy pieces small and
deterministic: stream-id arithmetic, receive-credit replenishment math,
inbound flood budgets, late-data accounting, protocol-loop task admission, and
frame payload classification.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import BinaryIO, Deque, Optional, Protocol

from ._errors import frame_size_error, local_internal_error
from .flow import (
    aggregate_late_data_cap,
    late_data_per_stream_cap,
    min_nonzero,
    negotiated_frame_payload,
    next_credit_limit,
    quarter_threshold,
    receive_window_exceeded,
    replenish_min_pending,
    repo_default_per_stream_data_hwm,
    repo_default_session_data_hwm,
    saturating_add,
    saturating_mul,
    session_emergency_threshold,
    session_standing_growth_allowed,
    session_window_target,
    should_flush_receive_credit,
    should_replenish_pending_window,
    standing_growth_allowed,
    stream_emergency_threshold,
    stream_standing_growth_allowed,
    stream_window_target,
    window_remaining,
)
from .._state.open import (
    expected_next_peer_stream_id,
    initial_receive_window,
    initial_send_window,
)
from .._state.stream_id import (
    first_local_stream_id,
    first_peer_stream_id,
    stream_is_bidi,
    stream_is_local,
    stream_kind_for_local,
    stream_opener,
    validate_local_open_id as _state_validate_local_open_id,
    validate_stream_id_for_role as _state_validate_stream_id_for_role,
)
from .._state.tombstone import LateDataCause
from .._wire.varint import encode_varint, parse_varint
from ..config import (
    DEFAULT_ABUSE_WINDOW,
    DEFAULT_GROUP_REBUCKET_CHURN_BUDGET,
    DEFAULT_HIDDEN_ABORT_CHURN_BUDGET,
    DEFAULT_HIDDEN_ABORT_CHURN_WINDOW,
    DEFAULT_IGNORED_CONTROL_BUDGET,
    DEFAULT_INBOUND_CONTROL_FRAME_BUDGET,
    DEFAULT_INBOUND_EXT_FRAME_BUDGET,
    DEFAULT_INBOUND_PING_BUDGET,
    DEFAULT_NO_OP_BLOCKED_BUDGET,
    DEFAULT_NO_OP_MAX_DATA_BUDGET,
    DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET,
    DEFAULT_NO_OP_ZERO_DATA_BUDGET,
    DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET,
    DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW,
    Config,
    Limits,
    Settings,
    default_settings,
)
from ..errors import (
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FlowControlError,
    FrameSizeError,
    ProtocolError,
)
from ..frame import Frame, read_frame, validate_frame
from ..payload import (
    GoAwayPayload,
    StreamMetadata,
    build_error_payload,
    parse_data_payload_metadata_offset,
    parse_error_payload,
    parse_go_away_payload,
    parse_priority_update_payload,
)
from ..protocol import (
    CAPABILITY_OPEN_METADATA,
    CAPABILITY_PRIORITY_UPDATE,
    ErrorCode,
    EXT_PRIORITY_UPDATE,
    FRAME_FLAG_FIN,
    FRAME_FLAG_OPEN_METADATA,
    FrameType,
    MAX_VARINT62,
    Role,
    capabilities_can_carry_group_in_update,
    capabilities_can_carry_group_on_open,
    capabilities_can_carry_priority_in_update,
    capabilities_can_carry_priority_on_open,
)
from .._validation import (
    require_bool as _require_bool,
    require_nonnegative_duration as _nonnegative_duration,
    require_nonnegative_int as _nonnegative_int,
    require_stream_id as _require_stream_id,
    require_varint62 as _require_varint62,
)

PING_TOKEN_BYTES = 8
MIN_INBOUND_CONTROL_BYTE_BUDGET = 256 << 10
MIN_INBOUND_EXT_BYTE_BUDGET = 256 << 10
MAX_PENDING_READ_LOOP_PROTOCOL_JOBS = 256
MAX_REUSABLE_PENDING_READ_LOOP_PROTOCOL_JOBS_CAP = 1024
_DEFAULT_SETTINGS = default_settings()


def _default_if_zero(value: int, default: int) -> int:
    value = _nonnegative_int(value, "value")
    return default if value == 0 else value


class ProtocolAction(Protocol):
    def __call__(self) -> object:
        ...


class FrameCallback(Protocol):
    def __call__(self, frame: Frame) -> object:
        ...


class PongPayloadFactory(Protocol):
    def __call__(self, payload: bytes) -> bytes:
        ...


class ParsedFrameKind(str, Enum):
    """Normalized read-loop frame class."""

    DATA = "data"
    MAX_DATA = "max_data"
    BLOCKED = "blocked"
    STOP_SENDING = "stop_sending"
    RESET = "reset"
    ABORT = "abort"
    PING = "ping"
    PONG = "pong"
    GO_AWAY = "go_away"
    CLOSE = "close"
    EXT = "ext"


class ProtocolTaskKind(IntEnum):
    """Read-loop protocol-loop task kinds."""

    QUEUE_FRAME = 0
    CLOSE_WRITE = 1


_VARINT_FRAME_KINDS = {
    FrameType.MAX_DATA: ParsedFrameKind.MAX_DATA,
    FrameType.BLOCKED: ParsedFrameKind.BLOCKED,
}
_ERROR_FRAME_KINDS = {
    FrameType.STOP_SENDING: ParsedFrameKind.STOP_SENDING,
    FrameType.RESET: ParsedFrameKind.RESET,
    FrameType.ABORT: ParsedFrameKind.ABORT,
}


@dataclass(frozen=True)
class ParsedInboundFrame(object):
    """One frame after read-loop payload classification."""

    frame: Frame
    kind: ParsedFrameKind
    app_data_offset: int = 0
    app_data_len: int = 0
    metadata: Optional[StreamMetadata] = None
    metadata_valid: bool = True
    value: Optional[int] = None
    error_code: Optional[int] = None
    reason: str = ""
    go_away: Optional[GoAwayPayload] = None
    ext_type: Optional[int] = None
    priority_update: Optional[StreamMetadata] = None
    priority_update_valid: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.frame, Frame):
            raise TypeError("frame must be a Frame")
        object.__setattr__(self, "kind", _coerce_enum(self.kind, ParsedFrameKind, "kind"))
        object.__setattr__(
            self,
            "app_data_offset",
            _nonnegative_int(self.app_data_offset, "app_data_offset"),
        )
        object.__setattr__(
            self,
            "app_data_len",
            _nonnegative_int(self.app_data_len, "app_data_len"),
        )
        payload_len = len(self.frame.payload)
        if self.app_data_offset > payload_len:
            raise ValueError("app_data_offset exceeds payload length")
        if self.app_data_len > payload_len - self.app_data_offset:
            raise ValueError("app_data range exceeds payload length")
        object.__setattr__(
            self,
            "metadata_valid",
            _require_bool(self.metadata_valid, "metadata_valid"),
        )
        object.__setattr__(
            self,
            "priority_update_valid",
            _require_bool(
                self.priority_update_valid,
                "priority_update_valid",
            ),
        )

    @property
    def stream_id(self) -> int:
        return self.frame.stream_id

    @property
    def frame_type(self) -> FrameType:
        return self.frame.frame_type

    @property
    def app_data(self) -> memoryview:
        if self.frame.frame_type != FrameType.DATA:
            return memoryview(b"")
        offset = self.app_data_offset
        return memoryview(self.frame.payload)[offset: offset + self.app_data_len]

    @property
    def has_open_metadata(self) -> bool:
        return bool(self.frame.flags & FRAME_FLAG_OPEN_METADATA)

    @property
    def fin(self) -> bool:
        return bool(self.frame.flags & FRAME_FLAG_FIN)


@dataclass(frozen=True)
class ReadLoopDispatchResult(object):
    """Result from one dispatcher call."""

    parsed: ParsedInboundFrame
    queued_frames: tuple[Frame, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.parsed, ParsedInboundFrame):
            raise TypeError("parsed must be a ParsedInboundFrame")
        object.__setattr__(self, "queued_frames", tuple(self.queued_frames))


@dataclass
class WindowedCounter(object):
    """A saturating count over a monotonic time window."""

    window_start: Optional[float] = None
    count: int = 0

    def __post_init__(self) -> None:
        if self.window_start is not None:
            self.window_start = _monotonic_now(self.window_start)
        self.count = _nonnegative_int(self.count, "count")

    def clear(self) -> None:
        self.window_start = None
        self.count = 0

    def record(
            self,
            *,
            window: float,
            budget: int,
            message: str,
            now: Optional[float] = None,
            reset_on_equal: bool = False,
    ) -> None:
        window = _nonnegative_duration(window, "window")
        budget = _nonnegative_int(budget, "budget")
        reset_on_equal = _require_bool(reset_on_equal, "reset_on_equal")
        now = _monotonic_now(now)
        if self.window_start is None:
            self.window_start = now
            self.count = 0
        else:
            elapsed = max(0.0, now - self.window_start)
            expired = elapsed >= window if reset_on_equal else elapsed > window
            if expired:
                self.window_start = now
                self.count = 0
        self.count = saturating_add(self.count, 1)
        if self.count > budget:
            raise _remote_protocol_error(message)


@dataclass
class TrafficBudgetCounter(object):
    """Frame and payload-byte budget over one monotonic time window."""

    window_start: Optional[float] = None
    frames: int = 0
    bytes: int = 0

    def __post_init__(self) -> None:
        if self.window_start is not None:
            self.window_start = _monotonic_now(self.window_start)
        self.frames = _nonnegative_int(self.frames, "frames")
        self.bytes = _nonnegative_int(self.bytes, "bytes")

    def clear(self) -> None:
        self.window_start = None
        self.frames = 0
        self.bytes = 0

    def record(
            self,
            *,
            payload_len: int,
            window: float,
            frame_budget: int,
            byte_budget: int,
            message: str,
            now: Optional[float] = None,
    ) -> None:
        window = _nonnegative_duration(window, "window")
        frame_budget = _nonnegative_int(frame_budget, "frame_budget")
        byte_budget = _nonnegative_int(byte_budget, "byte_budget")
        now = _monotonic_now(now)
        if self.window_start is None or max(0.0, now - self.window_start) > window:
            self.window_start = now
            self.frames = 0
            self.bytes = 0
        self.frames = saturating_add(self.frames, 1)
        self.bytes = saturating_add(self.bytes, _nonnegative_int(payload_len, "payload_len"))
        frames_ok = self.frames <= frame_budget
        bytes_ok = self.bytes <= byte_budget
        if not frames_ok or not bytes_ok:
            raise _remote_protocol_error(message)


@dataclass(frozen=True)
class ReadLoopAbuseConfig(object):
    """Configured inbound flood and churn thresholds."""

    abuse_window: float = DEFAULT_ABUSE_WINDOW
    inbound_control_frame_budget: int = DEFAULT_INBOUND_CONTROL_FRAME_BUDGET
    inbound_control_bytes_budget: int = MIN_INBOUND_CONTROL_BYTE_BUDGET
    inbound_ext_frame_budget: int = DEFAULT_INBOUND_EXT_FRAME_BUDGET
    inbound_ext_bytes_budget: int = MIN_INBOUND_EXT_BYTE_BUDGET
    inbound_mixed_frame_budget: int = DEFAULT_INBOUND_CONTROL_FRAME_BUDGET
    inbound_mixed_bytes_budget: int = MIN_INBOUND_CONTROL_BYTE_BUDGET
    ignored_control_budget: int = DEFAULT_IGNORED_CONTROL_BUDGET
    no_op_zero_data_budget: int = DEFAULT_NO_OP_ZERO_DATA_BUDGET
    inbound_ping_budget: int = DEFAULT_INBOUND_PING_BUDGET
    no_op_max_data_budget: int = DEFAULT_NO_OP_MAX_DATA_BUDGET
    no_op_blocked_budget: int = DEFAULT_NO_OP_BLOCKED_BUDGET
    no_op_priority_update_budget: int = DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET
    group_rebucket_churn_budget: int = DEFAULT_GROUP_REBUCKET_CHURN_BUDGET
    hidden_abort_churn_window: float = DEFAULT_HIDDEN_ABORT_CHURN_WINDOW
    hidden_abort_churn_budget: int = DEFAULT_HIDDEN_ABORT_CHURN_BUDGET
    visible_terminal_churn_window: float = DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW
    visible_terminal_churn_budget: int = DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET

    def __post_init__(self) -> None:
        for name in (
                "abuse_window",
                "hidden_abort_churn_window",
                "visible_terminal_churn_window",
        ):
            object.__setattr__(
                self,
                name,
                _nonnegative_duration(getattr(self, name), name),
            )
        for name in (
                "inbound_control_frame_budget",
                "inbound_control_bytes_budget",
                "inbound_ext_frame_budget",
                "inbound_ext_bytes_budget",
                "inbound_mixed_frame_budget",
                "inbound_mixed_bytes_budget",
                "ignored_control_budget",
                "no_op_zero_data_budget",
                "inbound_ping_budget",
                "no_op_max_data_budget",
                "no_op_blocked_budget",
                "no_op_priority_update_budget",
                "group_rebucket_churn_budget",
                "hidden_abort_churn_budget",
                "visible_terminal_churn_budget",
        ):
            object.__setattr__(self, name, _nonnegative_int(getattr(self, name), name))

    @classmethod
    def from_config(cls, config: Optional[Config]) -> "ReadLoopAbuseConfig":
        if config is None:
            settings = _DEFAULT_SETTINGS
            abuse_window = DEFAULT_ABUSE_WINDOW
            control_frame_budget = DEFAULT_INBOUND_CONTROL_FRAME_BUDGET
            ext_frame_budget = DEFAULT_INBOUND_EXT_FRAME_BUDGET
            control_bytes_budget = _default_control_byte_budget(settings)
            ext_bytes_budget = _default_ext_byte_budget(settings)
            return cls(
                abuse_window=abuse_window,
                inbound_control_frame_budget=control_frame_budget,
                inbound_control_bytes_budget=control_bytes_budget,
                inbound_ext_frame_budget=ext_frame_budget,
                inbound_ext_bytes_budget=ext_bytes_budget,
                inbound_mixed_frame_budget=max(control_frame_budget, ext_frame_budget),
                inbound_mixed_bytes_budget=max(control_bytes_budget, ext_bytes_budget),
            )

        settings = config.settings
        abuse_window = (
            config.abuse_window
            if config.abuse_window is not None
            else DEFAULT_ABUSE_WINDOW
        )
        control_frame_budget = _default_if_zero(
            config.inbound_control_frame_budget,
            DEFAULT_INBOUND_CONTROL_FRAME_BUDGET,
        )
        ext_frame_budget = _default_if_zero(
            config.inbound_ext_frame_budget,
            DEFAULT_INBOUND_EXT_FRAME_BUDGET,
        )
        control_bytes_budget = (
            config.inbound_control_bytes_budget
            if config.inbound_control_bytes_budget not in (None, 0)
            else _default_control_byte_budget(settings)
        )
        ext_bytes_budget = (
            config.inbound_ext_bytes_budget
            if config.inbound_ext_bytes_budget not in (None, 0)
            else _default_ext_byte_budget(settings)
        )
        mixed_frame_budget = (
            config.inbound_mixed_frame_budget
            if config.inbound_mixed_frame_budget not in (None, 0)
            else max(control_frame_budget, ext_frame_budget)
        )
        mixed_bytes_budget = (
            config.inbound_mixed_bytes_budget
            if config.inbound_mixed_bytes_budget not in (None, 0)
            else max(control_bytes_budget, ext_bytes_budget)
        )
        ignored_control_budget = (
            config.no_op_control_flood_threshold
            if config.no_op_control_flood_threshold != 0
            else _default_if_zero(
                config.ignored_control_budget,
                DEFAULT_IGNORED_CONTROL_BUDGET,
            )
        )
        return cls(
            abuse_window=abuse_window,
            inbound_control_frame_budget=control_frame_budget,
            inbound_control_bytes_budget=control_bytes_budget,
            inbound_ext_frame_budget=ext_frame_budget,
            inbound_ext_bytes_budget=ext_bytes_budget,
            inbound_mixed_frame_budget=mixed_frame_budget,
            inbound_mixed_bytes_budget=mixed_bytes_budget,
            ignored_control_budget=ignored_control_budget,
            no_op_zero_data_budget=_default_if_zero(
                config.no_op_zero_data_budget,
                DEFAULT_NO_OP_ZERO_DATA_BUDGET,
            ),
            inbound_ping_budget=_default_if_zero(
                config.inbound_ping_budget,
                DEFAULT_INBOUND_PING_BUDGET,
            ),
            no_op_max_data_budget=_default_if_zero(
                config.no_op_max_data_budget,
                DEFAULT_NO_OP_MAX_DATA_BUDGET,
            ),
            no_op_blocked_budget=_default_if_zero(
                config.no_op_blocked_budget,
                DEFAULT_NO_OP_BLOCKED_BUDGET,
            ),
            no_op_priority_update_budget=_default_if_zero(
                config.no_op_priority_update_budget,
                DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET,
            ),
            group_rebucket_churn_budget=_default_if_zero(
                config.group_rebucket_churn_budget,
                DEFAULT_GROUP_REBUCKET_CHURN_BUDGET,
            ),
            hidden_abort_churn_window=(
                config.hidden_abort_churn_window
                if config.hidden_abort_churn_window is not None
                else DEFAULT_HIDDEN_ABORT_CHURN_WINDOW
            ),
            hidden_abort_churn_budget=_default_if_zero(
                config.hidden_abort_churn_threshold,
                DEFAULT_HIDDEN_ABORT_CHURN_BUDGET,
            ),
            visible_terminal_churn_window=(
                config.visible_terminal_churn_window
                if config.visible_terminal_churn_window is not None
                else DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW
            ),
            visible_terminal_churn_budget=_default_if_zero(
                config.visible_terminal_churn_threshold,
                DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET,
            ),
        )


@dataclass
class InboundBudgetTracker(object):
    """Stateful inbound flood guard used under the session lock."""

    config: ReadLoopAbuseConfig = field(default_factory=ReadLoopAbuseConfig)
    control: TrafficBudgetCounter = field(default_factory=TrafficBudgetCounter)
    ext: TrafficBudgetCounter = field(default_factory=TrafficBudgetCounter)
    mixed: TrafficBudgetCounter = field(default_factory=TrafficBudgetCounter)
    ignored_control: WindowedCounter = field(default_factory=WindowedCounter)
    no_op_max_data: WindowedCounter = field(default_factory=WindowedCounter)
    no_op_blocked: WindowedCounter = field(default_factory=WindowedCounter)
    no_op_priority_update: WindowedCounter = field(default_factory=WindowedCounter)
    no_op_zero_data: WindowedCounter = field(default_factory=WindowedCounter)
    inbound_ping: WindowedCounter = field(default_factory=WindowedCounter)
    group_rebucket_churn: WindowedCounter = field(default_factory=WindowedCounter)
    hidden_abort_churn: WindowedCounter = field(default_factory=WindowedCounter)
    visible_terminal_churn: WindowedCounter = field(default_factory=WindowedCounter)
    dropped_priority_updates: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.config, ReadLoopAbuseConfig):
            raise TypeError("config must be a ReadLoopAbuseConfig")
        self.dropped_priority_updates = _nonnegative_int(
            self.dropped_priority_updates,
            "dropped_priority_updates",
        )

    @classmethod
    def from_config(cls, config: Optional[Config]) -> "InboundBudgetTracker":
        return cls(ReadLoopAbuseConfig.from_config(config))

    def record_frame(self, frame: Frame, now: Optional[float] = None) -> None:
        payload_len = len(frame.payload)
        if frame.frame_type == FrameType.DATA:
            return
        if frame.frame_type == FrameType.EXT:
            self.record_ext(payload_len, now)
            self.record_mixed(payload_len, now)
            return
        self.record_control(payload_len, now)
        self.record_mixed(payload_len, now)

    def record_control(self, payload_len: int, now: Optional[float] = None) -> None:
        self.control.record(
            payload_len=payload_len,
            window=self.config.abuse_window,
            frame_budget=self.config.inbound_control_frame_budget,
            byte_budget=self.config.inbound_control_bytes_budget,
            message="high-rate inbound control flood exceeded local threshold",
            now=now,
        )

    def record_ext(self, payload_len: int, now: Optional[float] = None) -> None:
        self.ext.record(
            payload_len=payload_len,
            window=self.config.abuse_window,
            frame_budget=self.config.inbound_ext_frame_budget,
            byte_budget=self.config.inbound_ext_bytes_budget,
            message="high-rate inbound EXT flood exceeded local threshold",
            now=now,
        )

    def record_mixed(self, payload_len: int, now: Optional[float] = None) -> None:
        self.mixed.record(
            payload_len=payload_len,
            window=self.config.abuse_window,
            frame_budget=self.config.inbound_mixed_frame_budget,
            byte_budget=self.config.inbound_mixed_bytes_budget,
            message="high-rate inbound mixed control/EXT flood exceeded local threshold",
            now=now,
        )

    def record_ignored_control(self, now: Optional[float] = None) -> None:
        self.ignored_control.record(
            window=self.config.abuse_window,
            budget=self.config.ignored_control_budget,
            message="ignored control budget exceeded",
            now=now,
        )

    def clear_ignored_control(self) -> None:
        self.ignored_control.clear()

    def clear_no_op_control_budgets(self) -> None:
        self.clear_ignored_control()
        self.no_op_max_data.clear()
        self.no_op_blocked.clear()
        self.no_op_priority_update.clear()

    def record_no_op_max_data(self, now: Optional[float] = None) -> None:
        self.record_ignored_control(now)
        self.no_op_max_data.record(
            window=self.config.abuse_window,
            budget=self.config.no_op_max_data_budget,
            message="no-op MAX_DATA budget exceeded",
            now=now,
        )

    def clear_no_op_max_data(self) -> None:
        self.clear_no_op_control_budgets()

    def record_no_op_blocked(self, now: Optional[float] = None) -> None:
        self.record_ignored_control(now)
        self.no_op_blocked.record(
            window=self.config.abuse_window,
            budget=self.config.no_op_blocked_budget,
            message="no-op BLOCKED budget exceeded",
            now=now,
        )

    def clear_no_op_blocked(self) -> None:
        self.clear_no_op_control_budgets()

    def record_no_op_priority_update(self, now: Optional[float] = None) -> None:
        self.record_ignored_control(now)
        self.no_op_priority_update.record(
            window=self.config.abuse_window,
            budget=self.config.no_op_priority_update_budget,
            message="no-op PRIORITY_UPDATE budget exceeded",
            now=now,
        )

    def clear_no_op_priority_update(self) -> None:
        self.clear_no_op_control_budgets()

    def record_no_op_zero_data(self, now: Optional[float] = None) -> None:
        self.no_op_zero_data.record(
            window=self.config.abuse_window,
            budget=self.config.no_op_zero_data_budget,
            message="zero-length DATA budget exceeded",
            now=now,
        )

    def update_no_op_zero_data(
            self,
            *,
            stream_existed: bool,
            app_len: int,
            flags: int,
            now: Optional[float] = None,
    ) -> None:
        stream_existed = _require_bool(stream_existed, "stream_existed")
        app_len = _nonnegative_int(app_len, "app_len")
        flags = _nonnegative_int(flags, "flags")
        data_control_flags = flags & (FRAME_FLAG_FIN | FRAME_FLAG_OPEN_METADATA)
        if stream_existed and app_len == 0 and data_control_flags == 0:
            self.record_no_op_zero_data(now)
        else:
            self.no_op_zero_data.clear()

    def record_inbound_ping(self, now: Optional[float] = None) -> None:
        self.inbound_ping.record(
            window=self.config.abuse_window,
            budget=self.config.inbound_ping_budget,
            message="inbound PING budget exceeded",
            now=now,
        )

    def record_group_rebucket_churn(self, now: Optional[float] = None) -> None:
        self.group_rebucket_churn.record(
            window=self.config.abuse_window,
            budget=self.config.group_rebucket_churn_budget,
            message="high-rate effective stream_group rebucketing churn exceeded local threshold",
            now=now,
        )

    def record_hidden_abort_churn(self, now: Optional[float] = None) -> None:
        self.hidden_abort_churn.record(
            window=self.config.hidden_abort_churn_window,
            budget=self.config.hidden_abort_churn_budget,
            message="rapid hidden open-then-abort churn exceeded local threshold",
            now=now,
        )

    def record_visible_terminal_churn(self, now: Optional[float] = None) -> None:
        self.visible_terminal_churn.record(
            window=self.config.visible_terminal_churn_window,
            budget=self.config.visible_terminal_churn_budget,
            message="rapid open-then-reset/abort churn exceeded local threshold",
            now=now,
        )

    def record_dropped_priority_update(self) -> None:
        self.dropped_priority_updates = saturating_add(self.dropped_priority_updates, 1)


@dataclass
class ReceiveWindowState(object):
    """Receive-side window counters for a session or stream."""

    received: int = 0
    advertised: int = 0
    pending: int = 0
    buffered: int = 0

    def __post_init__(self) -> None:
        self.received = _nonnegative_int(self.received, "received")
        self.advertised = _nonnegative_int(self.advertised, "advertised")
        self.pending = _nonnegative_int(self.pending, "pending")
        self.buffered = _nonnegative_int(self.buffered, "buffered")

    def check_available(self, amount: int) -> None:
        if receive_window_exceeded(self.received, self.advertised, amount):
            raise _flow_control_error("MAX_DATA exceeded")

    def account_received(self, amount: int) -> None:
        amount = _nonnegative_int(amount, "amount")
        self.received = saturating_add(self.received, amount)
        self.buffered = saturating_add(self.buffered, amount)

    def release_buffered(self, amount: int) -> int:
        amount = min(_nonnegative_int(amount, "amount"), self.buffered)
        self.buffered -= amount
        self.pending = saturating_add(self.pending, amount)
        return amount


@dataclass(frozen=True)
class ReplenishDecision(object):
    """Result of a receive-credit flush decision."""

    should_flush: bool
    desired_limit: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "should_flush",
            _require_bool(self.should_flush, "should_flush"),
        )
        object.__setattr__(
            self,
            "desired_limit",
            _nonnegative_int(self.desired_limit, "desired_limit"),
        )


@dataclass
class LateDataTracker(object):
    """Late-data discard caps and counters."""

    aggregate_cap: int = 0
    per_stream_cap: int = 0
    aggregate_received: int = 0
    per_stream_received: int = 0
    after_close_read: int = 0
    after_reset: int = 0
    after_abort: int = 0
    hidden_unread_discarded: int = 0

    def __post_init__(self) -> None:
        for name in (
                "aggregate_cap",
                "per_stream_cap",
                "aggregate_received",
                "per_stream_received",
                "after_close_read",
                "after_reset",
                "after_abort",
                "hidden_unread_discarded",
        ):
            setattr(self, name, _nonnegative_int(getattr(self, name), name))

    def record(
            self,
            amount: int,
            cause: LateDataCause = LateDataCause.NONE,
            *,
            hidden: bool = False,
            track_per_stream: bool = True,
    ) -> None:
        amount = _nonnegative_int(amount, "amount")
        cause = _coerce_enum(cause, LateDataCause, "cause")
        hidden = _require_bool(hidden, "hidden")
        track_per_stream = _require_bool(track_per_stream, "track_per_stream")
        if amount == 0:
            return
        self.aggregate_received = saturating_add(self.aggregate_received, amount)
        if track_per_stream:
            self.per_stream_received = saturating_add(self.per_stream_received, amount)
        if cause == LateDataCause.CLOSE_READ:
            self.after_close_read = saturating_add(self.after_close_read, amount)
        elif cause == LateDataCause.RESET:
            self.after_reset = saturating_add(self.after_reset, amount)
        elif cause == LateDataCause.ABORT:
            self.after_abort = saturating_add(self.after_abort, amount)
        if hidden:
            self.hidden_unread_discarded = saturating_add(
                self.hidden_unread_discarded, amount
            )
        self.check_caps()

    def check_caps(self) -> None:
        if self.aggregate_cap and self.aggregate_received > self.aggregate_cap:
            raise _remote_protocol_error("late-data cap exceeded")
        if self.per_stream_cap and self.per_stream_received > self.per_stream_cap:
            raise _remote_protocol_error("late-data cap exceeded")


@dataclass(frozen=True)
class ProtocolTask(object):
    """A deferred action produced by the read loop."""

    kind: ProtocolTaskKind
    frame: Optional[Frame] = None
    action: Optional[ProtocolAction] = None
    deadline: Optional[float] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kind",
            _coerce_enum(self.kind, ProtocolTaskKind, "kind"),
        )
        if self.deadline is not None:
            object.__setattr__(
                self,
                "deadline",
                _nonnegative_duration(self.deadline, "deadline"),
            )

    def drop_on_overflow(self) -> bool:
        if self.kind is not ProtocolTaskKind.QUEUE_FRAME or self.frame is None:
            return False
        frame_type = self.frame.frame_type
        return frame_type is FrameType.PONG or frame_type is FrameType.ABORT


class ProtocolTaskCallback(Protocol):
    def __call__(self, task: ProtocolTask) -> object:
        ...


@dataclass(frozen=True)
class ProtocolQueueSnapshot(object):
    """Inspection state for the read-loop protocol task queue."""

    length: int
    backlog_blocked: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "length", _nonnegative_int(self.length, "length"))
        object.__setattr__(
            self,
            "backlog_blocked",
            _nonnegative_int(self.backlog_blocked, "backlog_blocked"),
        )


class ReadLoopProtocolQueue(object):
    """Bounded protocol-loop backlog with Go-compatible overflow rules."""

    def __init__(self, max_jobs: int = MAX_PENDING_READ_LOOP_PROTOCOL_JOBS) -> None:
        self.max_jobs = _nonnegative_int(max_jobs, "max_jobs")
        self._tasks: Deque[ProtocolTask] = deque()
        self.backlog_blocked = 0

    def __len__(self) -> int:
        return len(self._tasks)

    def snapshot(self) -> ProtocolQueueSnapshot:
        return ProtocolQueueSnapshot(len(self._tasks), self.backlog_blocked)

    def enqueue(self, task: ProtocolTask) -> bool:
        if len(self._tasks) >= self.max_jobs:
            self.backlog_blocked = saturating_add(self.backlog_blocked, 1)
            if task.drop_on_overflow():
                return False
            raise _local_internal_error("pending read-loop protocol backlog exceeded")
        self._tasks.append(task)
        return True

    def queue_frame(self, frame: Frame) -> bool:
        return self.enqueue(ProtocolTask(ProtocolTaskKind.QUEUE_FRAME, frame=frame))

    def close_write(
            self, action: ProtocolAction, deadline: Optional[float] = None
    ) -> bool:
        return self.enqueue(
            ProtocolTask(
                ProtocolTaskKind.CLOSE_WRITE,
                action=action,
                deadline=deadline,
            )
        )

    def drain(
            self,
            *,
            queue_frame: Optional[FrameCallback] = None,
            close_write: Optional[ProtocolTaskCallback] = None,
            max_tasks: Optional[int] = None,
    ) -> int:
        executed = 0
        limit = (
            len(self._tasks)
            if max_tasks is None
            else _nonnegative_int(max_tasks, "max_tasks")
        )
        while self._tasks and executed < limit:
            task = self._tasks.popleft()
            if task.kind is ProtocolTaskKind.QUEUE_FRAME:
                if queue_frame is not None and task.frame is not None:
                    queue_frame(task.frame)
            elif task.kind is ProtocolTaskKind.CLOSE_WRITE:
                if task.action is not None:
                    task.action()
                elif close_write is not None:
                    close_write(task)
            executed += 1
        return executed

    def clear(self) -> None:
        self._tasks.clear()


class ReadLoopFrameDispatcher(object):
    """Small frame dispatcher for read-loop-owned generic behavior."""

    def __init__(
            self,
            *,
            limits: Optional[Limits] = None,
            capabilities: int = 0,
            local_role: Optional[Role] = None,
            peer_go_away_bidi: Optional[int] = None,
            peer_go_away_uni: Optional[int] = None,
            budgets: Optional[InboundBudgetTracker] = None,
            protocol_queue: Optional[ReadLoopProtocolQueue] = None,
            pong_payload: Optional[PongPayloadFactory] = None,
    ) -> None:
        self.limits = limits
        self.capabilities = _nonnegative_int(capabilities, "capabilities")
        self.local_role = None if local_role is None else _coerce_role(local_role)
        self.peer_go_away_bidi = (
            None
            if peer_go_away_bidi is None
            else _require_varint62(peer_go_away_bidi, "peer_go_away_bidi")
        )
        self.peer_go_away_uni = (
            None
            if peer_go_away_uni is None
            else _require_varint62(peer_go_away_uni, "peer_go_away_uni")
        )
        if budgets is not None and not isinstance(budgets, InboundBudgetTracker):
            raise TypeError("budgets must be an InboundBudgetTracker")
        if protocol_queue is not None and not isinstance(protocol_queue, ReadLoopProtocolQueue):
            raise TypeError("protocol_queue must be a ReadLoopProtocolQueue")
        self.budgets = budgets if budgets is not None else InboundBudgetTracker()
        self.protocol_queue = protocol_queue
        self.pong_payload = pong_payload or default_pong_payload

    def handle_frame(
            self, frame: Frame, now: Optional[float] = None
    ) -> ReadLoopDispatchResult:
        validate_frame(frame, self.limits, inbound=True)
        self.budgets.record_frame(frame, now)
        parsed = classify_inbound_frame(
            frame,
            capabilities=self.capabilities,
            local_role=self.local_role,
            peer_go_away_bidi=self.peer_go_away_bidi,
            peer_go_away_uni=self.peer_go_away_uni,
        )
        queued: tuple[Frame, ...] = ()
        if frame.frame_type == FrameType.PING:
            self.budgets.record_inbound_ping(now)
            pong = Frame(FrameType.PONG, 0, 0, self.pong_payload(frame.payload))
            if self.protocol_queue is not None:
                self.protocol_queue.queue_frame(pong)
            else:
                queued = (pong,)
        return ReadLoopDispatchResult(parsed, queued)


def classify_inbound_frame(
        frame: Frame,
        *,
        capabilities: int = 0,
        local_role: Optional[Role] = None,
        peer_go_away_bidi: Optional[int] = None,
        peer_go_away_uni: Optional[int] = None,
) -> ParsedInboundFrame:
    """Parse frame payload into the shape the session ingress logic consumes."""

    frame_type = frame.frame_type
    if frame_type == FrameType.DATA:
        has_open_metadata = bool(frame.flags & FRAME_FLAG_OPEN_METADATA)
        metadata = StreamMetadata()
        valid = True
        app_offset = 0
        if has_open_metadata:
            try:
                metadata, valid, app_offset = parse_data_payload_metadata_offset(
                    frame.payload,
                    frame.flags,
                )
            except FrameSizeError:
                raise
            except ProtocolError as exc:
                raise _frame_size_error("invalid DATA payload") from exc
            if capabilities & CAPABILITY_OPEN_METADATA == 0:
                raise _remote_protocol_error("DATA|OPEN_METADATA is not negotiated")
            metadata = metadata_with_normalized_group(
                metadata, capabilities=capabilities, on_open=True
            )
        return ParsedInboundFrame(
            frame,
            ParsedFrameKind.DATA,
            app_data_offset=app_offset,
            app_data_len=len(frame.payload) - app_offset,
            metadata=metadata if has_open_metadata else None,
            metadata_valid=valid,
        )
    varint_kind = _VARINT_FRAME_KINDS.get(frame_type)
    if varint_kind is not None:
        value = parse_exact_varint_payload(frame.payload, frame_type)
        return ParsedInboundFrame(frame, varint_kind, value=value)
    error_kind = _ERROR_FRAME_KINDS.get(frame_type)
    if error_kind is not None:
        try:
            code, reason = parse_error_payload(frame.payload)
        except FrameSizeError:
            raise
        except ProtocolError as exc:
            raise _frame_size_error("invalid %s payload" % frame_type) from exc
        return ParsedInboundFrame(
            frame,
            error_kind,
            error_code=code,
            reason=reason,
        )
    if frame_type == FrameType.PING:
        _require_ping_payload(frame.payload, "PING")
        return ParsedInboundFrame(frame, ParsedFrameKind.PING)
    if frame_type == FrameType.PONG:
        _require_ping_payload(frame.payload, "PONG")
        return ParsedInboundFrame(frame, ParsedFrameKind.PONG)
    if frame_type == FrameType.GOAWAY:
        try:
            payload = parse_go_away_payload(frame.payload)
        except FrameSizeError:
            raise
        except ProtocolError as exc:
            raise _frame_size_error("invalid GOAWAY payload") from exc
        if local_role is not None:
            validate_peer_go_away_payload(
                payload,
                local_role=local_role,
                peer_go_away_bidi=peer_go_away_bidi,
                peer_go_away_uni=peer_go_away_uni,
            )
        return ParsedInboundFrame(frame, ParsedFrameKind.GO_AWAY, go_away=payload)
    if frame_type == FrameType.CLOSE:
        try:
            code, reason = parse_error_payload(frame.payload)
        except FrameSizeError:
            raise
        except ProtocolError as exc:
            raise _frame_size_error("invalid CLOSE payload") from exc
        return ParsedInboundFrame(
            frame, ParsedFrameKind.CLOSE, error_code=code, reason=reason
        )
    if frame_type == FrameType.EXT:
        try:
            ext_type, consumed = parse_varint(frame.payload)
        except FrameSizeError:
            raise
        except ProtocolError as exc:
            raise _frame_size_error("invalid EXT payload") from exc
        priority = None
        valid = True
        if ext_type == EXT_PRIORITY_UPDATE and capabilities & CAPABILITY_PRIORITY_UPDATE:
            try:
                priority, valid = parse_priority_update_payload(frame.payload)
            except FrameSizeError:
                raise
            except ProtocolError as exc:
                raise _frame_size_error("invalid PRIORITY_UPDATE payload") from exc
            if valid:
                priority = metadata_with_normalized_group(
                    priority, capabilities=capabilities, on_open=False
                )
        return ParsedInboundFrame(
            frame,
            ParsedFrameKind.EXT,
            ext_type=ext_type,
            priority_update=priority,
            priority_update_valid=valid,
            app_data_offset=consumed,
        )
    raise _remote_protocol_error("invalid frame type")


def read_loop_once(
        reader: BinaryIO,
        dispatcher: ReadLoopFrameDispatcher,
        limits: Optional[Limits] = None,
) -> ReadLoopDispatchResult:
    """Read one frame from ``reader`` and dispatch generic read-loop behavior."""

    frame = read_frame(reader, limits if limits is not None else dispatcher.limits)
    return dispatcher.handle_frame(frame)


def default_pong_payload(request_payload: bytes) -> bytes:
    """Return the default PONG payload for a PING request."""

    return bytes(request_payload)


def build_abort_frame(stream_id: int, code: int = int(ErrorCode.CANCELLED)) -> Frame:
    """Build a read-loop ABORT control frame."""

    return Frame(FrameType.ABORT, _require_stream_id(stream_id), 0, build_error_payload(code))


def build_max_data_frame(stream_id: int, value: int) -> Frame:
    """Build a MAX_DATA frame with a varint payload."""

    return Frame(
        FrameType.MAX_DATA,
        _require_varint62(stream_id, "stream_id"),
        0,
        encode_varint(clamp_varint62(value)),
    )


def parse_exact_varint_payload(payload: bytes, frame_type: FrameType) -> int:
    try:
        value, consumed = parse_varint(payload)
    except FrameSizeError:
        raise
    except ProtocolError as exc:
        raise _frame_size_error("invalid %s payload" % frame_type) from exc
    if consumed != len(payload):
        raise _remote_protocol_error("%s payload has trailing bytes" % frame_type)
    return value


def metadata_with_normalized_group(
        metadata: StreamMetadata,
        *,
        capabilities: int = 0,
        on_open: bool = False,
) -> StreamMetadata:
    """Return metadata after applying negotiated semantic carriage rules."""

    priority = metadata.priority
    group = normalize_stream_group(metadata.group) if on_open else metadata.group
    if on_open:
        if priority is not None and not capabilities_can_carry_priority_on_open(
                capabilities
        ):
            priority = None
        if group is not None and not capabilities_can_carry_group_on_open(capabilities):
            group = None
        open_info = metadata.open_info
    else:
        if priority is not None and not capabilities_can_carry_priority_in_update(
                capabilities
        ):
            priority = None
        if group is not None and not capabilities_can_carry_group_in_update(
                capabilities
        ):
            group = None
        open_info = b""
    return StreamMetadata(priority, group, open_info)


def normalize_stream_group(group: Optional[int]) -> Optional[int]:
    """Normalize stream group ``0`` to the implicit no-group value."""

    return group if group not in (None, 0) else None


def validate_peer_go_away_payload(
        payload: GoAwayPayload,
        *,
        local_role: Role,
        peer_go_away_bidi: Optional[int] = None,
        peer_go_away_uni: Optional[int] = None,
) -> None:
    validate_go_away_watermark_for_direction(payload.last_accepted_bidi, True)
    validate_go_away_watermark_creator(local_role, payload.last_accepted_bidi)
    validate_go_away_watermark_for_direction(payload.last_accepted_uni, False)
    validate_go_away_watermark_creator(local_role, payload.last_accepted_uni)
    if (
            peer_go_away_bidi is not None
            and payload.last_accepted_bidi > peer_go_away_bidi
    ) or (
            peer_go_away_uni is not None and payload.last_accepted_uni > peer_go_away_uni
    ):
        raise _remote_protocol_error("GOAWAY watermarks must be non-increasing")


def validate_go_away_watermark_for_direction(stream_id: int, bidi: bool) -> None:
    stream_id = _nonnegative_int(stream_id, "stream_id")
    bidi = _require_bool(bidi, "bidi")
    if stream_id == 0:
        return
    if stream_id > MAX_VARINT62:
        raise _remote_protocol_error(
            "stream %d exceeds varint62 range for GOAWAY watermark" % stream_id
        )
    if stream_is_bidi(stream_id) != bidi:
        raise _remote_protocol_error(
            "stream %d has wrong direction for GOAWAY watermark" % stream_id
        )


def validate_go_away_watermark_creator(local_role: Role, stream_id: int) -> None:
    stream_id = _nonnegative_int(stream_id, "stream_id")
    if stream_id == 0:
        return
    if not stream_is_local(local_role, stream_id):
        raise _remote_protocol_error(
            "stream %d is not creatable by role %s" % (stream_id, local_role)
        )


def validate_stream_id_for_role(local_role: Role, stream_id: int) -> None:
    try:
        _state_validate_stream_id_for_role(local_role, stream_id)
    except ValueError as exc:
        raise _remote_protocol_error(str(exc)) from None


def validate_local_open_id(local_role: Role, stream_id: int, bidi: bool) -> None:
    try:
        _state_validate_local_open_id(local_role, stream_id, bidi)
    except ValueError as exc:
        raise _remote_protocol_error(str(exc)) from None


def stream_id_previously_used(
        stream_id: int,
        *,
        local_role: Role,
        next_local_bidi: int,
        next_local_uni: int,
        next_peer_bidi: int,
        next_peer_uni: int,
) -> bool:
    stream_id = _require_varint62(stream_id, "stream_id")
    local_role = _coerce_role(local_role)
    next_local_bidi = _require_varint62(next_local_bidi, "next_local_bidi")
    next_local_uni = _require_varint62(next_local_uni, "next_local_uni")
    next_peer_bidi = _require_varint62(next_peer_bidi, "next_peer_bidi")
    next_peer_uni = _require_varint62(next_peer_uni, "next_peer_uni")
    if stream_is_local(local_role, stream_id):
        return stream_id < (next_local_bidi if stream_is_bidi(stream_id) else next_local_uni)
    return stream_id < (next_peer_bidi if stream_is_bidi(stream_id) else next_peer_uni)


def replenish_decision(
        *,
        advertised: int,
        received: int,
        pending: int,
        target: int,
        emergency_threshold: int,
        min_pending: int,
        allow_standing_growth: bool,
        force: bool = False,
) -> ReplenishDecision:
    should_flush = should_flush_receive_credit(
        advertised,
        received,
        pending,
        target,
        emergency_threshold,
        min_pending,
        force,
    )
    if not should_flush:
        return ReplenishDecision(False, advertised)
    return ReplenishDecision(
        True,
        next_credit_limit(
            advertised, pending, received, target, allow_standing_growth
        ),
    )


def clamp_varint62(value: int) -> int:
    return min(_nonnegative_int(value, "value"), MAX_VARINT62)


def _default_control_byte_budget(settings: Settings) -> int:
    max_payload = (
            settings.max_control_payload_bytes or _DEFAULT_SETTINGS.max_control_payload_bytes
    )
    return max(MIN_INBOUND_CONTROL_BYTE_BUDGET, saturating_mul(max_payload, 64))


def _default_ext_byte_budget(settings: Settings) -> int:
    max_payload = (
            settings.max_extension_payload_bytes
            or _DEFAULT_SETTINGS.max_extension_payload_bytes
    )
    return max(MIN_INBOUND_EXT_BYTE_BUDGET, saturating_mul(max_payload, 64))


def _require_ping_payload(payload: bytes, label: str) -> None:
    if len(payload) < PING_TOKEN_BYTES:
        raise FrameSizeError(
            "%s payload too short" % label,
            code=int(ErrorCode.FRAME_SIZE),
            scope=ErrorScope.SESSION,
            operation=ErrorOperation.READ,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.READ,
        )


def _coerce_role(value: Role) -> Role:
    if isinstance(value, Role):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("role must be a Role or integer")
    return Role.from_code(value)


def _coerce_enum(value, enum_type, name: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        return enum_type(value)
    if isinstance(value, bool):
        raise TypeError("%s must be a %s or integer" % (name, enum_type.__name__))
    return enum_type(value)


def _monotonic_now(now: Optional[float]) -> float:
    if now is None:
        return time.monotonic()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise TypeError("now must be a monotonic timestamp")
    now = float(now)
    if now < 0:
        raise ValueError("now must be >= 0")
    return now


def _remote_protocol_error(message: str) -> ProtocolError:
    return ProtocolError(
        message,
        code=int(ErrorCode.PROTOCOL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )


def _flow_control_error(message: str) -> FlowControlError:
    return FlowControlError(
        message,
        code=int(ErrorCode.FLOW_CONTROL),
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.READ,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )


def _frame_size_error(message: str) -> FrameSizeError:
    return frame_size_error(
        message,
        operation=ErrorOperation.READ,
        source=ErrorSource.REMOTE,
        direction=ErrorDirection.READ,
    )


def _local_internal_error(message: str) -> ProtocolError:
    return local_internal_error(
        message,
        operation=ErrorOperation.READ,
        direction=ErrorDirection.READ,
    )


__all__ = (
    "MAX_PENDING_READ_LOOP_PROTOCOL_JOBS",
    "MAX_REUSABLE_PENDING_READ_LOOP_PROTOCOL_JOBS_CAP",
    "MIN_INBOUND_CONTROL_BYTE_BUDGET",
    "MIN_INBOUND_EXT_BYTE_BUDGET",
    "PING_TOKEN_BYTES",
    "ParsedFrameKind",
    "ParsedInboundFrame",
    "ProtocolQueueSnapshot",
    "ProtocolTask",
    "ProtocolTaskKind",
    "ReadLoopAbuseConfig",
    "ReadLoopDispatchResult",
    "ReadLoopFrameDispatcher",
    "ReadLoopProtocolQueue",
    "ReceiveWindowState",
    "ReplenishDecision",
    "InboundBudgetTracker",
    "LateDataCause",
    "LateDataTracker",
    "TrafficBudgetCounter",
    "WindowedCounter",
    "aggregate_late_data_cap",
    "build_abort_frame",
    "build_max_data_frame",
    "classify_inbound_frame",
    "clamp_varint62",
    "default_pong_payload",
    "expected_next_peer_stream_id",
    "first_local_stream_id",
    "first_peer_stream_id",
    "initial_receive_window",
    "initial_send_window",
    "late_data_per_stream_cap",
    "metadata_with_normalized_group",
    "min_nonzero",
    "negotiated_frame_payload",
    "next_credit_limit",
    "normalize_stream_group",
    "parse_exact_varint_payload",
    "quarter_threshold",
    "read_loop_once",
    "receive_window_exceeded",
    "replenish_decision",
    "replenish_min_pending",
    "repo_default_per_stream_data_hwm",
    "repo_default_session_data_hwm",
    "saturating_add",
    "saturating_mul",
    "session_emergency_threshold",
    "session_standing_growth_allowed",
    "session_window_target",
    "should_flush_receive_credit",
    "should_replenish_pending_window",
    "standing_growth_allowed",
    "stream_emergency_threshold",
    "stream_id_previously_used",
    "stream_is_bidi",
    "stream_is_local",
    "stream_kind_for_local",
    "stream_opener",
    "stream_standing_growth_allowed",
    "stream_window_target",
    "validate_go_away_watermark_creator",
    "validate_go_away_watermark_for_direction",
    "validate_local_open_id",
    "validate_peer_go_away_payload",
    "validate_stream_id_for_role",
    "window_remaining",
)
