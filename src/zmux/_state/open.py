"""Local and peer stream-open admission policy."""

from __future__ import annotations

import sys
import time
from typing import Optional, Tuple

from .half import require_bool
from .stream_id import stream_is_bidi, stream_is_local
from ..config import Settings
from ..protocol import MAX_VARINT62, Role

DEFAULT_ADMISSION_SOFT_CAP = 32
DEFAULT_ADMISSION_HARD_CAP = 64
DEFAULT_PROVISIONAL_OPEN_HARD_CAP = DEFAULT_ADMISSION_HARD_CAP
PROVISIONAL_OPEN_MAX_AGE = 5.0
_MAX_INT = sys.maxsize


def local_open_refused_by_goaway(
        stream_id: int,
        bidi: bool,
        peer_goaway_bidi: int,
        peer_goaway_uni: int,
) -> bool:
    stream_id = _nonnegative_int(stream_id, "stream_id")
    bidi = require_bool(bidi, "bidi")
    peer_goaway_bidi = _nonnegative_int(peer_goaway_bidi, "peer_goaway_bidi")
    peer_goaway_uni = _nonnegative_int(peer_goaway_uni, "peer_goaway_uni")
    return stream_id > (peer_goaway_bidi if bidi else peer_goaway_uni)


def max_stream_id_for_class(next_id: int) -> int:
    next_id = _nonnegative_int(next_id, "next_id")
    if next_id == 0 or next_id > MAX_VARINT62:
        return 0
    return next_id + ((MAX_VARINT62 - next_id) // 4) * 4


def projected_local_open_id(next_id: int, queue_len: int) -> int:
    next_id = _nonnegative_int(next_id, "next_id")
    queue_len = _nonnegative_int(queue_len, "queue_len")
    if queue_len <= 0 or next_id == 0 or next_id > MAX_VARINT62:
        return next_id
    remaining = (MAX_VARINT62 - next_id) // 4
    if queue_len > remaining:
        return MAX_VARINT62 + 1
    return next_id + queue_len * 4


def admission_soft_cap(pending_limit: int) -> int:
    pending_limit = _nonnegative_int(pending_limit, "pending_limit")
    if pending_limit <= 0:
        return DEFAULT_ADMISSION_SOFT_CAP
    return max(16, pending_limit // 4)


def admission_hard_cap(pending_limit: int) -> int:
    pending_limit = _nonnegative_int(pending_limit, "pending_limit")
    if pending_limit <= 0:
        return DEFAULT_ADMISSION_HARD_CAP
    return max(32, pending_limit // 2)


def provisional_soft_cap(bidi: bool, pending_limit: int) -> int:
    require_bool(bidi, "bidi")
    return admission_soft_cap(pending_limit)


def provisional_hard_cap(bidi: bool, pending_limit: int) -> int:
    require_bool(bidi, "bidi")
    return admission_hard_cap(pending_limit)


def provisional_open_soft_cap(pending_limit: int, bidi: bool = False) -> int:
    return provisional_soft_cap(bidi, pending_limit)


def provisional_open_hard_cap(pending_limit: int, bidi: bool = False) -> int:
    return provisional_hard_cap(bidi, pending_limit)


def provisional_expired(
        id_set: bool,
        created_at: Optional[float],
        now: Optional[float] = None,
        max_age: float = PROVISIONAL_OPEN_MAX_AGE,
) -> bool:
    id_set = require_bool(id_set, "id_set")
    if id_set or created_at is None or max_age <= 0:
        return False
    now_value = time.monotonic() if now is None else float(now)
    return now_value - float(created_at) > max_age


def provisional_available_count(next_id: int, max_id: int) -> int:
    next_id = _nonnegative_int(next_id, "next_id")
    max_id = _nonnegative_int(max_id, "max_id")
    if next_id > max_id:
        return 0
    return min(_MAX_INT, ((max_id - next_id) // 4) + 1)


def peer_open_refused_by_goaway(
        stream_id: int,
        local_goaway_bidi: int,
        local_goaway_uni: int,
) -> bool:
    stream_id = _nonnegative_int(stream_id, "stream_id")
    local_goaway_bidi = _nonnegative_int(local_goaway_bidi, "local_goaway_bidi")
    local_goaway_uni = _nonnegative_int(local_goaway_uni, "local_goaway_uni")
    return stream_id > (
        local_goaway_bidi if stream_is_bidi(stream_id) else local_goaway_uni
    )


def expected_next_peer_stream_id(
        stream_id: int,
        next_peer_bidi: int,
        next_peer_uni: int,
) -> int:
    return next_peer_bidi if stream_is_bidi(stream_id) else next_peer_uni


def active_stream_within_limit(
        bidi: bool,
        active_bidi: int,
        active_uni: int,
        max_incoming_bidi: int,
        max_incoming_uni: int,
) -> bool:
    bidi = require_bool(bidi, "bidi")
    active_bidi = _nonnegative_int(active_bidi, "active_bidi")
    active_uni = _nonnegative_int(active_uni, "active_uni")
    max_incoming_bidi = _nonnegative_int(max_incoming_bidi, "max_incoming_bidi")
    max_incoming_uni = _nonnegative_int(max_incoming_uni, "max_incoming_uni")
    return active_bidi < max_incoming_bidi if bidi else active_uni < max_incoming_uni


def peer_stream_within_limit(
        bidi: bool,
        active_peer_bidi: int,
        active_peer_uni: int,
        max_incoming_bidi: int,
        max_incoming_uni: int,
) -> bool:
    return active_stream_within_limit(
        bidi,
        active_peer_bidi,
        active_peer_uni,
        max_incoming_bidi,
        max_incoming_uni,
    )


def decrement_active_stream_count(
        bidi: bool,
        active_bidi: int,
        active_uni: int,
) -> Tuple[int, int]:
    bidi = require_bool(bidi, "bidi")
    active_bidi = _nonnegative_int(active_bidi, "active_bidi")
    active_uni = _nonnegative_int(active_uni, "active_uni")
    if bidi:
        return max(0, active_bidi - 1), active_uni
    return active_bidi, max(0, active_uni - 1)


def decrement_active_peer_count(
        bidi: bool,
        active_peer_bidi: int,
        active_peer_uni: int,
) -> Tuple[int, int]:
    return decrement_active_stream_count(bidi, active_peer_bidi, active_peer_uni)


def initial_send_window(local_role: Role, peer: Settings, stream_id: int) -> int:
    bidi = stream_is_bidi(stream_id)
    local_opened = stream_is_local(local_role, stream_id)
    if not bidi:
        if local_opened:
            return peer.initial_max_stream_data_uni
        return 0
    if local_opened:
        return peer.initial_max_stream_data_bidi_peer_opened
    return peer.initial_max_stream_data_bidi_locally_opened


def initial_local_opened_send_window(peer: Settings, bidi: bool) -> int:
    bidi = require_bool(bidi, "bidi")
    if bidi:
        return peer.initial_max_stream_data_bidi_peer_opened
    return peer.initial_max_stream_data_uni


def initial_receive_window(local_role: Role, local: Settings, stream_id: int) -> int:
    bidi = stream_is_bidi(stream_id)
    local_opened = stream_is_local(local_role, stream_id)
    if not bidi:
        if local_opened:
            return 0
        return local.initial_max_stream_data_uni
    if local_opened:
        return local.initial_max_stream_data_bidi_locally_opened
    return local.initial_max_stream_data_bidi_peer_opened


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


__all__ = (
    "DEFAULT_ADMISSION_HARD_CAP",
    "DEFAULT_ADMISSION_SOFT_CAP",
    "DEFAULT_PROVISIONAL_OPEN_HARD_CAP",
    "PROVISIONAL_OPEN_MAX_AGE",
    "active_stream_within_limit",
    "admission_hard_cap",
    "admission_soft_cap",
    "decrement_active_peer_count",
    "decrement_active_stream_count",
    "expected_next_peer_stream_id",
    "initial_local_opened_send_window",
    "initial_receive_window",
    "initial_send_window",
    "local_open_refused_by_goaway",
    "max_stream_id_for_class",
    "peer_open_refused_by_goaway",
    "peer_stream_within_limit",
    "projected_local_open_id",
    "provisional_available_count",
    "provisional_expired",
    "provisional_hard_cap",
    "provisional_open_hard_cap",
    "provisional_open_soft_cap",
    "provisional_soft_cap",
)
