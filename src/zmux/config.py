"""Configuration value types for zmux sessions."""

from __future__ import annotations

import math
import secrets
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Callable, MutableSequence, Optional

from .protocol import (
    MAX_PREFACE_SETTINGS_BYTES,
    MAX_VARINT62,
    PREFACE_VERSION,
    PROTO_VERSION,
    Capability,
    Role,
    SchedulerHint,
    SETTING_PREFACE_PADDING,
)
from .varint import varint_len

DEFAULT_KEEPALIVE_INTERVAL = 60.0
DEFAULT_KEEPALIVE_MAX_PING_INTERVAL = 5.0 * 60.0
DEFAULT_PREFACE_PADDING_MIN_BYTES = 16
DEFAULT_PREFACE_PADDING_MAX_BYTES = 256
DEFAULT_PING_PADDING_MIN_BYTES = 16
DEFAULT_PING_PADDING_MAX_BYTES = 64
DEFAULT_CAPABILITIES = int(
    Capability.OPEN_METADATA
    | Capability.PRIORITY_HINTS
    | Capability.STREAM_GROUPS
    | Capability.PRIORITY_UPDATE
)
DEFAULT_WRITE_QUEUE_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_WRITE_BATCH_MAX_FRAMES = 32
DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR = 64 * 1024
DEFAULT_PENDING_CONTROL_BYTES_BUDGET_FLOOR = 64 * 1024
DEFAULT_PENDING_PRIORITY_BYTES_BUDGET_FLOOR = 64 * 1024
DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR = 256 * 1024
DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR = 4 * 1024 * 1024
DEFAULT_MAX_PROVISIONAL_STREAMS_BIDI = 64
DEFAULT_MAX_PROVISIONAL_STREAMS_UNI = 64
DEFAULT_TOMBSTONE_LIMIT = 4096
DEFAULT_USED_MARKER_LIMIT = 16384
DEFAULT_LATE_DATA_AGGREGATE_CAP_FLOOR = 64 * 1024
DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR = 1024
DEFAULT_IGNORED_CONTROL_BUDGET = 128
DEFAULT_NO_OP_ZERO_DATA_BUDGET = 128
DEFAULT_INBOUND_PING_BUDGET = 128
DEFAULT_NO_OP_MAX_DATA_BUDGET = 128
DEFAULT_NO_OP_BLOCKED_BUDGET = 128
DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET = 128
DEFAULT_ABUSE_WINDOW = 5.0
DEFAULT_INBOUND_CONTROL_FRAME_BUDGET = 2048
DEFAULT_INBOUND_EXT_FRAME_BUDGET = 1024
DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR = 256 * 1024
DEFAULT_INBOUND_EXT_BYTES_BUDGET_FLOOR = 256 * 1024
DEFAULT_GROUP_REBUCKET_CHURN_BUDGET = 256
DEFAULT_HIDDEN_ABORT_CHURN_WINDOW = 1.0
DEFAULT_HIDDEN_ABORT_CHURN_BUDGET = 128
DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW = 1.0
DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET = 128
DEFAULT_CLOSE_DRAIN_TIMEOUT = 0.5
DEFAULT_GO_AWAY_DRAIN_INTERVAL = 0.01
DEFAULT_ACCEPT_BACKLOG_LIMIT = 128
DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR = 4 * 1024 * 1024
DEFAULT_ACCEPT_BACKLOG_PER_STREAM_BYTES_FLOOR = 256 * 1024
DEFAULT_ACCEPT_BACKLOG_PER_STREAM_FRAMES = 16
DEFAULT_ACCEPT_BACKLOG_SESSION_FACTOR = 4
DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET = 64 * 1024
DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET = 64 * 1024
DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW = 0.1
DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX = 2.0
DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR = 8 * 1024 * 1024

_SETTING_VARINT_FIELDS = (
    "initial_max_stream_data_bidi_locally_opened",
    "initial_max_stream_data_bidi_peer_opened",
    "initial_max_stream_data_uni",
    "initial_max_data",
    "max_incoming_streams_bidi",
    "max_incoming_streams_uni",
    "max_frame_payload",
    "max_control_payload_bytes",
    "max_extension_payload_bytes",
    "ping_padding_key",
)

EventHandler = Callable[[Any], None]


@dataclass(frozen=True)
class Limits:
    """Negotiated inbound frame payload limits."""

    max_frame_payload: int = 16384
    max_control_payload_bytes: int = 4096
    max_extension_payload_bytes: int = 4096

    def __post_init__(self) -> None:
        _require_varint62(self.max_frame_payload, "limits max_frame_payload")
        _require_varint62(
            self.max_control_payload_bytes, "limits max_control_payload_bytes"
        )
        _require_varint62(
            self.max_extension_payload_bytes, "limits max_extension_payload_bytes"
        )


@dataclass(frozen=True)
class Settings:
    """Unilateral receive-side settings advertised in a session preface."""

    initial_max_stream_data_bidi_locally_opened: int = 65536
    initial_max_stream_data_bidi_peer_opened: int = 65536
    initial_max_stream_data_uni: int = 65536
    initial_max_data: int = 262144
    max_incoming_streams_bidi: int = 256
    max_incoming_streams_uni: int = 256
    max_frame_payload: int = 16384
    max_control_payload_bytes: int = 4096
    max_extension_payload_bytes: int = 4096
    scheduler_hints: SchedulerHint = SchedulerHint.UNSPECIFIED_OR_BALANCED
    ping_padding_key: int = 0
    _limits_cache: Optional[Limits] = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        for field_name in _SETTING_VARINT_FIELDS:
            _require_varint62(getattr(self, field_name), "settings " + field_name)
        object.__setattr__(
            self, "scheduler_hints", _coerce_scheduler_hint(self.scheduler_hints)
        )

    def limits(self) -> Limits:
        """Return the receive-side frame payload limits carried by settings."""

        cached = self._limits_cache
        if cached is None:
            cached = Limits(
                max_frame_payload=self.max_frame_payload,
                max_control_payload_bytes=self.max_control_payload_bytes,
                max_extension_payload_bytes=self.max_extension_payload_bytes,
            )
            object.__setattr__(self, "_limits_cache", cached)
        return cached

    def is_zero(self) -> bool:
        """Return whether all numeric settings are zero/default-unspecified."""

        return (
                self.initial_max_stream_data_bidi_locally_opened == 0
                and self.initial_max_stream_data_bidi_peer_opened == 0
                and self.initial_max_stream_data_uni == 0
                and self.initial_max_data == 0
                and self.max_incoming_streams_bidi == 0
                and self.max_incoming_streams_uni == 0
                and self.max_frame_payload == 0
                and self.max_control_payload_bytes == 0
                and self.max_extension_payload_bytes == 0
                and self.scheduler_hints == SchedulerHint.UNSPECIFIED_OR_BALANCED
                and self.ping_padding_key == 0
        )

    def with_payload_limits_from_defaults(self) -> "Settings":
        """Fill zero frame payload limit fields from repository defaults."""

        if (
                self.max_frame_payload != 0
                and self.max_control_payload_bytes != 0
                and self.max_extension_payload_bytes != 0
        ):
            return self
        defaults = default_settings()
        return replace(
            self,
            max_frame_payload=(
                defaults.max_frame_payload
                if self.max_frame_payload == 0
                else self.max_frame_payload
            ),
            max_control_payload_bytes=(
                defaults.max_control_payload_bytes
                if self.max_control_payload_bytes == 0
                else self.max_control_payload_bytes
            ),
            max_extension_payload_bytes=(
                defaults.max_extension_payload_bytes
                if self.max_extension_payload_bytes == 0
                else self.max_extension_payload_bytes
            ),
        )

    def encoded_tlv_len(self) -> int:
        """Return the encoded TLV byte length for non-default settings."""

        from ._wire.settings import settings_tlv_len

        return settings_tlv_len(self)

    def to_tlv(self) -> bytes:
        """Return settings encoded as preface TLVs."""

        from ._wire.settings import marshal_settings_tlv

        return marshal_settings_tlv(self)

    def append_tlv_to(self, dst: MutableSequence[int]) -> None:
        """Append this settings TLV encoding to ``dst``."""

        from ._wire.settings import append_settings_tlv

        append_settings_tlv(dst, self)


@dataclass(frozen=True)
class Config:
    """Session establishment and runtime configuration."""

    role: Role = Role.AUTO
    tie_breaker_nonce: int = 0
    min_proto: int = PROTO_VERSION
    max_proto: int = PROTO_VERSION
    capabilities: int = 0
    disable_capabilities: bool = False
    settings: Settings = field(default_factory=Settings)
    nonce_source: Optional[Any] = None
    preface_padding: bool = True
    preface_padding_min_bytes: int = DEFAULT_PREFACE_PADDING_MIN_BYTES
    preface_padding_max_bytes: int = DEFAULT_PREFACE_PADDING_MAX_BYTES
    ping_padding: bool = True
    ping_padding_min_bytes: int = DEFAULT_PING_PADDING_MIN_BYTES
    ping_padding_max_bytes: int = DEFAULT_PING_PADDING_MAX_BYTES
    keepalive_interval: Optional[float] = DEFAULT_KEEPALIVE_INTERVAL
    keepalive_max_ping_interval: Optional[float] = DEFAULT_KEEPALIVE_MAX_PING_INTERVAL
    keepalive_timeout: Optional[float] = None
    write_queue_max_bytes: int = DEFAULT_WRITE_QUEUE_MAX_BYTES
    write_batch_max_frames: int = DEFAULT_WRITE_BATCH_MAX_FRAMES
    session_memory_cap: Optional[int] = None
    per_stream_queued_data_hwm: Optional[int] = None
    session_queued_data_hwm: Optional[int] = None
    urgent_queued_bytes_cap: Optional[int] = None
    pending_control_bytes_budget: Optional[int] = None
    pending_priority_bytes_budget: Optional[int] = None
    max_provisional_streams_bidi: int = DEFAULT_MAX_PROVISIONAL_STREAMS_BIDI
    max_provisional_streams_uni: int = DEFAULT_MAX_PROVISIONAL_STREAMS_UNI
    accept_backlog_limit: Optional[int] = None
    accept_backlog_bytes_limit: Optional[int] = None
    tombstone_limit: int = DEFAULT_TOMBSTONE_LIMIT
    marker_only_used_stream_limit: Optional[int] = None
    used_marker_limit: int = DEFAULT_USED_MARKER_LIMIT
    retained_open_info_bytes_budget: Optional[int] = None
    retained_peer_reason_bytes_budget: Optional[int] = None
    late_data_per_stream_cap: Optional[int] = None
    aggregate_late_data_cap: Optional[int] = None
    ignored_control_budget: int = DEFAULT_IGNORED_CONTROL_BUDGET
    no_op_zero_data_budget: int = DEFAULT_NO_OP_ZERO_DATA_BUDGET
    inbound_ping_budget: int = DEFAULT_INBOUND_PING_BUDGET
    no_op_max_data_budget: int = DEFAULT_NO_OP_MAX_DATA_BUDGET
    no_op_blocked_budget: int = DEFAULT_NO_OP_BLOCKED_BUDGET
    no_op_priority_update_budget: int = DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET
    abuse_window: Optional[float] = DEFAULT_ABUSE_WINDOW
    inbound_control_frame_budget: int = DEFAULT_INBOUND_CONTROL_FRAME_BUDGET
    inbound_control_bytes_budget: Optional[int] = None
    inbound_ext_frame_budget: int = DEFAULT_INBOUND_EXT_FRAME_BUDGET
    inbound_ext_bytes_budget: Optional[int] = None
    inbound_mixed_frame_budget: Optional[int] = None
    inbound_mixed_bytes_budget: Optional[int] = None
    group_rebucket_churn_budget: int = DEFAULT_GROUP_REBUCKET_CHURN_BUDGET
    hidden_abort_churn_window: Optional[float] = DEFAULT_HIDDEN_ABORT_CHURN_WINDOW
    hidden_abort_churn_threshold: int = DEFAULT_HIDDEN_ABORT_CHURN_BUDGET
    visible_terminal_churn_window: Optional[float] = DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW
    visible_terminal_churn_threshold: int = DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET
    stop_sending_graceful_drain_window: Optional[float] = None
    stop_sending_graceful_tail_cap: Optional[int] = None
    graceful_close_drain_timeout: Optional[float] = DEFAULT_CLOSE_DRAIN_TIMEOUT
    go_away_drain_interval: Optional[float] = DEFAULT_GO_AWAY_DRAIN_INTERVAL
    event_handler: Optional[EventHandler] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _coerce_role(self.role))
        _require_varint62(self.tie_breaker_nonce, "config tie_breaker_nonce")
        if self.role in (Role.INITIATOR, Role.RESPONDER) and self.tie_breaker_nonce != 0:
            object.__setattr__(self, "tie_breaker_nonce", 0)
        min_proto = PROTO_VERSION if self.min_proto == 0 else self.min_proto
        max_proto = PROTO_VERSION if self.max_proto == 0 else self.max_proto
        _require_varint62(min_proto, "config min_proto")
        _require_varint62(max_proto, "config max_proto")
        if min_proto > max_proto:
            raise ValueError("config min_proto must be <= max_proto")
        object.__setattr__(self, "min_proto", min_proto)
        object.__setattr__(self, "max_proto", max_proto)
        _require_bool(self.disable_capabilities, "config disable_capabilities")
        _require_varint62(self.capabilities, "config capabilities")
        capabilities = 0 if self.disable_capabilities else self.capabilities
        if capabilities == 0 and not self.disable_capabilities:
            capabilities = DEFAULT_CAPABILITIES
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "settings", _normalize_config_settings(self.settings))
        _validate_nonce_source(self.nonce_source)

        for name in ("preface_padding", "ping_padding"):
            _require_bool(getattr(self, name), "config " + name)
        for name in (
                "preface_padding_min_bytes",
                "preface_padding_max_bytes",
                "ping_padding_min_bytes",
                "ping_padding_max_bytes",
                "write_queue_max_bytes",
                "write_batch_max_frames",
                "max_provisional_streams_bidi",
                "max_provisional_streams_uni",
                "tombstone_limit",
                "used_marker_limit",
                "ignored_control_budget",
                "no_op_zero_data_budget",
                "inbound_ping_budget",
                "no_op_max_data_budget",
                "no_op_blocked_budget",
                "no_op_priority_update_budget",
                "inbound_control_frame_budget",
                "inbound_ext_frame_budget",
                "group_rebucket_churn_budget",
                "hidden_abort_churn_threshold",
                "visible_terminal_churn_threshold",
        ):
            _require_nonnegative_int(getattr(self, name), "config " + name)
        for name in (
                "session_memory_cap",
                "per_stream_queued_data_hwm",
                "session_queued_data_hwm",
                "urgent_queued_bytes_cap",
                "pending_control_bytes_budget",
                "pending_priority_bytes_budget",
                "accept_backlog_limit",
                "accept_backlog_bytes_limit",
                "marker_only_used_stream_limit",
                "retained_open_info_bytes_budget",
                "retained_peer_reason_bytes_budget",
                "late_data_per_stream_cap",
                "aggregate_late_data_cap",
                "inbound_control_bytes_budget",
                "inbound_ext_bytes_budget",
                "inbound_mixed_frame_budget",
                "inbound_mixed_bytes_budget",
                "stop_sending_graceful_tail_cap",
        ):
            _require_optional_nonnegative_int(getattr(self, name), "config " + name)
        for name in (
                "keepalive_interval",
                "keepalive_max_ping_interval",
                "keepalive_timeout",
                "abuse_window",
                "hidden_abort_churn_window",
                "visible_terminal_churn_window",
                "stop_sending_graceful_drain_window",
                "graceful_close_drain_timeout",
                "go_away_drain_interval",
        ):
            object.__setattr__(
                self,
                name,
                _normalize_optional_duration(getattr(self, name), "config " + name),
            )
        if self.event_handler is not None and not callable(self.event_handler):
            raise TypeError("config event_handler must be callable or None")

    def normalized(self) -> "Config":
        """Return this configuration after constructor normalization."""

        return self

    def local_preface(self):
        """Build the local session preface for this configuration."""

        from .preface import Preface

        role = self.role
        nonce = self.tie_breaker_nonce
        if role in (Role.INITIATOR, Role.RESPONDER):
            nonce = 0
        elif nonce == 0:
            nonce = random_varint62(self.nonce_source)

        settings = self.settings
        if self.ping_padding:
            if settings.ping_padding_key == 0:
                settings = replace(settings, ping_padding_key=random_varint62(self.nonce_source))
        elif settings.ping_padding_key != 0:
            settings = replace(settings, ping_padding_key=0)

        return Preface(
            preface_version=PREFACE_VERSION,
            role=role,
            tie_breaker_nonce=nonce,
            min_proto=self.min_proto,
            max_proto=self.max_proto,
            capabilities=self.capabilities,
            settings=settings,
        )

    def local_preface_payload(self, preface=None) -> bytes:
        """Encode a local preface, adding random settings padding if enabled."""

        preface = self.local_preface() if preface is None else preface
        if not self.preface_padding:
            return preface.marshal()

        padding = random_preface_padding(
            preface.settings,
            self.preface_padding_min_bytes,
            self.preface_padding_max_bytes,
            self.nonce_source,
        )
        if not padding:
            return preface.marshal()
        return preface.marshal_with_settings_padding(padding)


@dataclass(frozen=True)
class OpenOptions:
    """Open-time metadata and advisory inputs for a new stream."""

    initial_priority: Optional[int] = None
    initial_group: Optional[int] = None
    open_info: bytes = b""

    def __post_init__(self) -> None:
        if self.initial_priority is not None:
            _require_varint62(self.initial_priority, "open options initial_priority")
        if self.initial_group is not None:
            _require_varint62(self.initial_group, "open options initial_group")
        object.__setattr__(
            self, "open_info", b"" if self.open_info is None else _coerce_open_info(self.open_info)
        )

    def __repr__(self) -> str:
        return (
                "OpenOptions(initial_priority=%r, initial_group=%r, open_info_len=%d)"
                % (self.initial_priority, self.initial_group, len(self.open_info))
        )

    def is_empty(self) -> bool:
        """Return whether this carries no open metadata hints."""

        return (
                self.initial_priority is None
                and self.initial_group is None
                and not self.open_info
        )


_default_config_lock = threading.Lock()
_default_config_template: Optional[Config] = None

ConfigUpdater = Callable[[Config], Optional[Config]]


def default_settings() -> Settings:
    """Return the repository-default settings."""

    return _DEFAULT_SETTINGS


def default_config() -> Config:
    """Return a copy of the process-wide default configuration template."""

    global _default_config_template
    with _default_config_lock:
        if _default_config_template is None:
            _default_config_template = _builtin_default_config()
        template = _default_config_template
    return replace(template)


def configure_default_config(update: ConfigUpdater) -> None:
    """Mutate the process-wide default configuration template.

    ``update`` receives the current immutable template and should return a new
    ``Config``. Returning ``None`` leaves the template unchanged.
    """

    if update is None:
        return
    global _default_config_template
    with _default_config_lock:
        if _default_config_template is None:
            _default_config_template = _builtin_default_config()
        current = replace(_default_config_template)

    next_config = update(current)
    if next_config is not None:
        sanitized = _sanitize_default_config_template(next_config)
        with _default_config_lock:
            _default_config_template = sanitized


def reset_default_config() -> None:
    """Restore the built-in process-wide default configuration template."""

    global _default_config_template
    with _default_config_lock:
        _default_config_template = _builtin_default_config()


def clone_config(config: Optional[Config]) -> Config:
    """Return ``config`` normalized, or the current default when ``None``."""

    return default_config() if config is None else replace(config)


def random_varint62(nonce_source: Optional[Any] = None) -> int:
    """Return a non-zero random varint62 value."""

    for _ in range(1024):
        raw = _random_bytes(nonce_source, 8)
        value = _varint62_from_random_bytes(raw)
        if value != 0:
            return value
    raise RuntimeError("nonce source produced only zero varint62 values")


def random_preface_padding(
        settings: Settings,
        configured_min: int = 0,
        configured_max: int = 0,
        nonce_source: Optional[Any] = None,
) -> bytes:
    """Return random preface padding bytes within the remaining TLV budget."""

    _require_nonnegative_int(configured_min, "configured_min")
    _require_nonnegative_int(configured_max, "configured_max")
    settings = _normalize_config_settings(settings)
    max_payload = _max_preface_padding_payload_bytes(settings, configured_max)
    if max_payload <= 0:
        return b""
    low = min(max(0, configured_min or DEFAULT_PREFACE_PADDING_MIN_BYTES), max_payload)
    return _random_bytes(nonce_source, _random_len(low, max_payload, nonce_source))


def _max_preface_padding_payload_bytes(settings: Settings, configured_max: int) -> int:
    _require_nonnegative_int(configured_max, "configured_max")
    current_len = settings.encoded_tlv_len()
    if current_len >= MAX_PREFACE_SETTINGS_BYTES:
        return 0

    remaining = MAX_PREFACE_SETTINGS_BYTES - current_len
    high = configured_max or DEFAULT_PREFACE_PADDING_MAX_BYTES
    high = min(max(0, high), remaining)
    type_len = varint_len(SETTING_PREFACE_PADDING)
    low = 0
    while low < high:
        candidate = low + (high - low + 1) // 2
        overhead = type_len + varint_len(candidate)
        if overhead <= remaining and candidate <= remaining - overhead:
            low = candidate
        else:
            high = candidate - 1
    return low


def random_ping_padding_len(
        configured_min: int = 0,
        configured_max: int = 0,
        max_payload: int = 4096,
) -> int:
    """Return a random PING/PONG padding length clamped to payload limits."""

    _require_nonnegative_int(configured_min, "configured_min")
    _require_nonnegative_int(configured_max, "configured_max")
    _require_nonnegative_int(max_payload, "max_payload")
    low = configured_min or DEFAULT_PING_PADDING_MIN_BYTES
    high = configured_max or DEFAULT_PING_PADDING_MAX_BYTES
    low = min(max(0, low), max_payload)
    high = min(max(0, high), max_payload)
    if low > high:
        low = high
    return _random_len(low, high)


def default_accept_backlog_bytes_limit(max_frame_payload: int) -> int:
    """Return the derived default accept backlog byte cap."""

    _require_nonnegative_int(max_frame_payload, "max_frame_payload")
    per_stream = max(
        max_frame_payload * DEFAULT_ACCEPT_BACKLOG_PER_STREAM_FRAMES,
        DEFAULT_ACCEPT_BACKLOG_PER_STREAM_BYTES_FLOOR,
    )
    return max(
        per_stream * DEFAULT_ACCEPT_BACKLOG_SESSION_FACTOR,
        DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR,
    )


def default_late_data_aggregate_cap(max_frame_payload: int) -> int:
    """Return the derived aggregate late-data cap."""

    _require_nonnegative_int(max_frame_payload, "max_frame_payload")
    return max(DEFAULT_LATE_DATA_AGGREGATE_CAP_FLOOR, max_frame_payload * 4)


def _builtin_default_config() -> Config:
    return Config()


def _sanitize_default_config_template(config: Config) -> Config:
    if not isinstance(config, Config):
        raise TypeError("default config update must return a Config or None")
    settings = replace(config.settings, ping_padding_key=0)
    return replace(config, tie_breaker_nonce=0, settings=settings)


def _normalize_config_settings(value: Optional[Settings]) -> Settings:
    if value is None:
        return default_settings()
    if not isinstance(value, Settings):
        raise TypeError("config settings must be a Settings instance")
    if value.is_zero():
        return default_settings()
    return value.with_payload_limits_from_defaults()


def _require_varint62(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % field_name)


def _require_nonnegative_int(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)


def _require_optional_nonnegative_int(value: Optional[int], field_name: str) -> None:
    if value is None:
        return
    _require_nonnegative_int(value, field_name)


def _normalize_optional_duration(value: Optional[float], field_name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("%s must be a number of seconds" % field_name)
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError("%s must be a finite value >= 0" % field_name)
    return value


def _validate_nonce_source(source: Optional[Any]) -> None:
    if source is None:
        return
    if callable(source):
        return
    if callable(getattr(source, "read", None)):
        return
    raise TypeError("config nonce_source must be callable, file-like, or None")


def _require_bool(value: bool, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError("%s must be a bool" % field_name)


def _coerce_scheduler_hint(value: SchedulerHint) -> SchedulerHint:
    if value is None:
        return SchedulerHint.UNSPECIFIED_OR_BALANCED
    if isinstance(value, SchedulerHint):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("settings scheduler_hints must be a SchedulerHint or integer")
    return SchedulerHint.from_code(value)


def _coerce_role(value: Role) -> Role:
    if value is None:
        return Role.AUTO
    if isinstance(value, Role):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("config role must be a Role or integer")
    return Role.from_code(value)


def _coerce_open_info(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return _coerce_bytes_like(value, "open options open_info")


def _random_len(low: int, high: int, source: Optional[Any] = None) -> int:
    if high <= low:
        return low
    return low + _random_uint64n(source, high - low + 1)


def _random_bytes(source: Optional[Any], n: int) -> bytes:
    _require_nonnegative_int(n, "random byte count")
    if source is None:
        return secrets.token_bytes(n)
    if callable(source):
        data = source(n)
        data = _coerce_bytes_like(data, "nonce source result")
        if len(data) != n:
            raise ValueError("nonce source returned %d bytes, expected %d" % (len(data), n))
        return data
    else:
        return _read_random_bytes(source, n)


def _read_random_bytes(source: Any, n: int) -> bytes:
    chunks = None
    remaining = n
    while remaining:
        data = source.read(remaining)
        data = _coerce_bytes_like(data, "nonce source result")
        if not data:
            raise ValueError("nonce source returned %d bytes, expected %d" % (n - remaining, n))
        if len(data) > remaining:
            raise ValueError("nonce source returned more bytes than requested")
        if len(data) == remaining and chunks is None:
            return data
        if chunks is None:
            chunks = [data]
        else:
            chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks or ())


def _coerce_bytes_like(value: Any, field_name: str) -> bytes:
    if isinstance(value, bool) or isinstance(value, int):
        raise TypeError("%s must be bytes-like" % field_name)
    try:
        view = memoryview(value)
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % field_name) from exc
    return view.tobytes()


def _random_uint64n(source: Optional[Any], n: int) -> int:
    _require_nonnegative_int(n, "random range")
    if n <= 0:
        raise ValueError("random range must be > 0")
    if source is None:
        return secrets.randbelow(n)
    if n > (1 << 62):
        raise ValueError("random range exceeds varint62 random source capacity")
    limit = (1 << 62) - ((1 << 62) % n)
    for _ in range(1024):
        raw = _random_bytes(source, 8)
        value = _varint62_from_random_bytes(raw)
        if value < limit:
            return value % n
    raise RuntimeError("nonce source produced only rejected random values")


def _varint62_from_random_bytes(raw: bytes) -> int:
    if len(raw) != 8:
        raise ValueError("random varint62 source must be exactly 8 bytes")
    return (
            ((raw[0] & 0x3F) << 56)
            | (raw[1] << 48)
            | (raw[2] << 40)
            | (raw[3] << 32)
            | (raw[4] << 24)
            | (raw[5] << 16)
            | (raw[6] << 8)
            | raw[7]
    )


_DEFAULT_SETTINGS = Settings()
__all__ = [
    "Config",
    "DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR",
    "DEFAULT_ACCEPT_BACKLOG_LIMIT",
    "DEFAULT_ACCEPT_BACKLOG_PER_STREAM_BYTES_FLOOR",
    "DEFAULT_ACCEPT_BACKLOG_PER_STREAM_FRAMES",
    "DEFAULT_ACCEPT_BACKLOG_SESSION_FACTOR",
    "DEFAULT_ABUSE_WINDOW",
    "DEFAULT_CAPABILITIES",
    "DEFAULT_CLOSE_DRAIN_TIMEOUT",
    "DEFAULT_GO_AWAY_DRAIN_INTERVAL",
    "DEFAULT_GROUP_REBUCKET_CHURN_BUDGET",
    "DEFAULT_HIDDEN_ABORT_CHURN_BUDGET",
    "DEFAULT_HIDDEN_ABORT_CHURN_WINDOW",
    "DEFAULT_IGNORED_CONTROL_BUDGET",
    "DEFAULT_INBOUND_CONTROL_FRAME_BUDGET",
    "DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR",
    "DEFAULT_INBOUND_EXT_FRAME_BUDGET",
    "DEFAULT_INBOUND_EXT_BYTES_BUDGET_FLOOR",
    "DEFAULT_INBOUND_PING_BUDGET",
    "DEFAULT_KEEPALIVE_INTERVAL",
    "DEFAULT_KEEPALIVE_MAX_PING_INTERVAL",
    "DEFAULT_LATE_DATA_AGGREGATE_CAP_FLOOR",
    "DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR",
    "DEFAULT_MAX_PROVISIONAL_STREAMS_BIDI",
    "DEFAULT_MAX_PROVISIONAL_STREAMS_UNI",
    "DEFAULT_NO_OP_BLOCKED_BUDGET",
    "DEFAULT_NO_OP_MAX_DATA_BUDGET",
    "DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET",
    "DEFAULT_NO_OP_ZERO_DATA_BUDGET",
    "DEFAULT_PENDING_CONTROL_BYTES_BUDGET_FLOOR",
    "DEFAULT_PENDING_PRIORITY_BYTES_BUDGET_FLOOR",
    "DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR",
    "DEFAULT_PING_PADDING_MAX_BYTES",
    "DEFAULT_PING_PADDING_MIN_BYTES",
    "DEFAULT_PREFACE_PADDING_MAX_BYTES",
    "DEFAULT_PREFACE_PADDING_MIN_BYTES",
    "DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET",
    "DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET",
    "DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR",
    "DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR",
    "DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW",
    "DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX",
    "DEFAULT_TOMBSTONE_LIMIT",
    "DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR",
    "DEFAULT_USED_MARKER_LIMIT",
    "DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET",
    "DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW",
    "DEFAULT_WRITE_BATCH_MAX_FRAMES",
    "DEFAULT_WRITE_QUEUE_MAX_BYTES",
    "Limits",
    "OpenOptions",
    "Settings",
    "clone_config",
    "configure_default_config",
    "default_accept_backlog_bytes_limit",
    "default_config",
    "default_late_data_aggregate_cap",
    "default_settings",
    "random_ping_padding_len",
    "random_preface_padding",
    "random_varint62",
    "reset_default_config",
]
