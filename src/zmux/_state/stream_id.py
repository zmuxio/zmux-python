"""Stream-id arithmetic and ownership predicates."""

from __future__ import annotations

from .half import require_bool
from ..protocol import MAX_VARINT62, Role

_OPENER_BIT = 0x1
_BIDI_BIT = 0x2


def first_local_stream_id(role: Role, bidi: bool) -> int:
    role = _coerce_role(role)
    bidi = require_bool(bidi, "bidi")
    if role is Role.INITIATOR:
        return 4 if bidi else 2
    if role is Role.RESPONDER:
        return 1 if bidi else 3
    return 0


def first_peer_stream_id(local_role: Role, bidi: bool) -> int:
    local_role = _coerce_role(local_role)
    bidi = require_bool(bidi, "bidi")
    if local_role is Role.INITIATOR:
        return 1 if bidi else 3
    if local_role is Role.RESPONDER:
        return 4 if bidi else 2
    return 0


def stream_is_bidi(stream_id: int) -> bool:
    return _nonnegative_int(stream_id, "stream_id") & _BIDI_BIT == 0


def stream_opener(stream_id: int) -> Role:
    stream_id = _nonnegative_int(stream_id, "stream_id")
    return Role.INITIATOR if stream_id & _OPENER_BIT == 0 else Role.RESPONDER


def stream_is_local(local_role: Role, stream_id: int) -> bool:
    return stream_opener(stream_id) is _coerce_role(local_role)


def stream_kind_for_local(local_role: Role, stream_id: int) -> tuple[bool, bool]:
    bidi = stream_is_bidi(stream_id)
    local_opened = stream_is_local(local_role, stream_id)
    if bidi:
        return True, True
    if local_opened:
        return True, False
    return False, True


def validate_stream_id_for_role(local_role: Role, stream_id: int) -> None:
    _ = _coerce_role(local_role)
    stream_id = _nonnegative_int(stream_id, "stream_id")
    if stream_id == 0:
        raise ValueError("stream_id = 0 is session-scoped")
    if stream_id > MAX_VARINT62:
        raise ValueError("stream_id %d exceeds varint62 range" % stream_id)


def validate_local_open_id(local_role: Role, stream_id: int, bidi: bool) -> None:
    validate_stream_id_for_role(local_role, stream_id)
    bidi = require_bool(bidi, "bidi")
    if not stream_is_local(local_role, stream_id):
        raise ValueError(
            "stream_id %d is not locally owned for role %s" % (stream_id, local_role)
        )
    if stream_is_bidi(stream_id) != bidi:
        want = "bidirectional" if bidi else "unidirectional"
        raise ValueError("stream_id %d is not %s" % (stream_id, want))


def _coerce_role(value: Role) -> Role:
    if isinstance(value, Role):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("role must be a Role or integer")
    return Role(value)


def _nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be >= 0" % name)
    return value


__all__ = (
    "first_local_stream_id",
    "first_peer_stream_id",
    "stream_is_bidi",
    "stream_is_local",
    "stream_kind_for_local",
    "stream_opener",
    "validate_local_open_id",
    "validate_stream_id_for_role",
)
