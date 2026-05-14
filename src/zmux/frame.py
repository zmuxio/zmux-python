"""Public frame codec value types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Optional, Tuple

from .config import Limits
from .errors import ErrorDirection, ErrorOperation, ErrorScope, TransportError
from .protocol import FRAME_FLAG_MASK, MAX_VARINT62, FrameType


@dataclass(frozen=True)
class Frame:
    """One decoded zmux frame."""

    frame_type: FrameType
    stream_id: int
    flags: int
    payload: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "frame_type", _coerce_frame_type(self.frame_type))
        object.__setattr__(self, "stream_id", _require_varint62(self.stream_id, "stream_id"))
        object.__setattr__(self, "flags", _require_flags(self.flags))
        object.__setattr__(self, "payload", _coerce_payload_bytes(self.payload))

    def __repr__(self) -> str:
        return (
                "%s(frame_type=%r, stream_id=%r, flags=%r, payload_length=%r)"
                % (
                    self.__class__.__name__,
                    self.frame_type,
                    self.stream_id,
                    self.flags,
                    len(self.payload),
                )
        )

    def code(self) -> int:
        """Return the one-byte frame code."""

        return int(self.frame_type) | self.flags

    def as_view(self) -> "FrameView":
        """Return a borrowed view over this frame payload."""

        return FrameView(self.frame_type, self.stream_id, self.flags, self.payload)

    def encoded_len(self) -> int:
        """Return the number of bytes needed to encode this frame."""

        from ._wire.frame import frame_length_for_payload
        from .varint import varint_len

        body_len = frame_length_for_payload(varint_len(self.stream_id), len(self.payload))
        return varint_len(body_len) + body_len

    def marshal(self) -> bytes:
        """Encode this frame into bytes."""

        from ._wire.frame import marshal_frame

        return marshal_frame(self)

    def append_to(self, dst) -> None:
        """Append this frame encoding to ``dst``."""

        from ._wire.frame import append_frame

        append_frame(dst, self)

    def validate(self, limits: Optional[Limits] = None, inbound: bool = False) -> None:
        """Validate this frame envelope and payload."""

        from ._wire.frame import validate_frame

        validate_frame(self, limits, inbound)

    @classmethod
    def parse(cls, src: bytes, limits: Optional[Limits] = None) -> Tuple["Frame", int]:
        """Parse and copy one frame from ``src``."""

        from ._wire.frame import parse_frame

        return parse_frame(src, limits)


@dataclass(frozen=True)
class FrameView:
    """Borrowed decoded frame view."""

    frame_type: FrameType
    stream_id: int
    flags: int
    payload: memoryview

    def __post_init__(self) -> None:
        object.__setattr__(self, "frame_type", _coerce_frame_type(self.frame_type))
        object.__setattr__(self, "stream_id", _require_varint62(self.stream_id, "stream_id"))
        object.__setattr__(self, "flags", _require_flags(self.flags))
        object.__setattr__(self, "payload", _coerce_payload_view(self.payload))

    def __repr__(self) -> str:
        return (
                "%s(frame_type=%r, stream_id=%r, flags=%r, payload_length=%r)"
                % (
                    self.__class__.__name__,
                    self.frame_type,
                    self.stream_id,
                    self.flags,
                    len(self.payload),
                )
        )

    def code(self) -> int:
        """Return the one-byte frame code."""

        return int(self.frame_type) | self.flags

    def to_owned(self) -> Frame:
        """Copy this frame view into an owned frame."""

        return Frame(self.frame_type, self.stream_id, self.flags, self.payload.tobytes())

    def encoded_len(self) -> int:
        """Return the number of bytes needed to encode this frame view."""

        from ._wire.frame import frame_length_for_payload
        from .varint import varint_len

        body_len = frame_length_for_payload(varint_len(self.stream_id), len(self.payload))
        return varint_len(body_len) + body_len

    def validate(self, limits: Optional[Limits] = None, inbound: bool = False) -> None:
        """Validate this borrowed frame."""

        from ._wire.frame import validate_frame_view

        validate_frame_view(self, limits, inbound)


def parse_frame(src: bytes, limits: Optional[Limits] = None) -> Tuple[Frame, int]:
    """Parse and copy one complete frame from ``src``."""

    from ._wire.frame import parse_frame as _parse_frame

    return _parse_frame(src, limits)


def parse_frame_view(
        src: bytes, limits: Optional[Limits] = None
) -> Tuple[FrameView, int]:
    """Parse one frame and borrow its payload."""

    from ._wire.frame import parse_frame_view as _parse_frame_view

    return _parse_frame_view(src, limits)


def read_frame(reader: BinaryIO, limits: Optional[Limits] = None) -> Frame:
    """Read and parse one frame from ``reader``."""

    from ._wire.frame import read_frame as _read_frame

    return _read_frame(reader, limits)


def write_frame(
        writer: BinaryIO, frame: Frame, limits: Optional[Limits] = None
) -> None:
    """Validate and write one complete frame to a binary stream."""

    from ._wire.frame import (
        append_frame_header_trusted,
        inbound_payload_limit,
        normalize_limits,
        validate_frame,
    )
    from ._wire.errors import ERR_PAYLOAD_TOO_LARGE, frame_size_error

    if not isinstance(frame, Frame):
        raise TypeError("frame must be a Frame")
    if writer is None or not callable(getattr(writer, "write", None)):
        raise TypeError("writer must provide write(bytes)")

    limits = normalize_limits(limits)
    validate_frame(frame, limits, False)
    if len(frame.payload) > inbound_payload_limit(frame.frame_type, limits):
        raise frame_size_error(ERR_PAYLOAD_TOO_LARGE, ErrorOperation.WRITE)
    header = bytearray()
    append_frame_header_trusted(header, frame.code(), frame.stream_id, len(frame.payload))
    _write_all(writer, header)
    if frame.payload:
        _write_all(writer, frame.payload)


def marshal_frame(frame: Frame) -> bytes:
    """Encode one frame into bytes."""

    from ._wire.frame import marshal_frame as _marshal_frame

    return _marshal_frame(frame)


def validate_frame(
        frame: Frame, limits: Optional[Limits] = None, inbound: bool = False
) -> None:
    """Validate one frame."""

    from ._wire.frame import validate_frame as _validate_frame

    _validate_frame(frame, limits, inbound)


def normalize_limits(limits: Optional[Limits]) -> Limits:
    """Replace zero limit fields with defaults."""

    from ._wire.frame import normalize_limits as _normalize_limits

    return _normalize_limits(limits)


def inbound_payload_limit(frame_type: FrameType, limits: Limits) -> int:
    """Return the inbound payload limit for ``frame_type``."""

    from ._wire.frame import inbound_payload_limit as _inbound_payload_limit

    return _inbound_payload_limit(frame_type, limits)


def _coerce_frame_type(value: FrameType) -> FrameType:
    if isinstance(value, FrameType):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("frame_type must be a FrameType or integer")
    return FrameType.from_code(value)


def _require_varint62(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % field_name)
    return int(value)


def _require_flags(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("flags must be an integer")
    if value < 0 or value > 0xFF:
        raise ValueError("flags must fit in one byte")
    if value & ~FRAME_FLAG_MASK:
        raise ValueError("flags must use only frame flag bits")
    return int(value)


def _coerce_payload_bytes(value) -> bytes:
    if value is None:
        return b""
    return bytes(_coerce_payload_view(value))


def _coerce_payload_view(value) -> memoryview:
    if value is None:
        return memoryview(b"")
    view = memoryview(value)
    if view.itemsize == 1 and view.ndim == 1 and view.format == "B":
        return view
    try:
        return view.cast("B")
    except TypeError:
        return memoryview(view.tobytes())


def _write_all(writer: BinaryIO, data) -> None:
    view = memoryview(data)
    while view:
        try:
            written = writer.write(view)
        except OSError as exc:
            raise _transport_write_error(exc) from exc
        if written is None:
            raise _transport_write_error(
                BlockingIOError("frame writer returned no progress")
            )
        if isinstance(written, bool) or not isinstance(written, int):
            raise _transport_write_error(
                OSError("zmux: frame writer reported invalid progress")
            )
        if written <= 0 or written > len(view):
            raise _transport_write_error(
                OSError("zmux: frame writer reported invalid progress")
            )
        view = view[written:]


def _transport_write_error(error: OSError) -> TransportError:
    return TransportError(
        error,
        scope=ErrorScope.SESSION,
        operation=ErrorOperation.WRITE,
        direction=ErrorDirection.WRITE,
    )


__all__ = [
    "Frame",
    "FrameView",
    "Limits",
    "inbound_payload_limit",
    "marshal_frame",
    "normalize_limits",
    "parse_frame",
    "parse_frame_view",
    "read_frame",
    "write_frame",
    "validate_frame",
]
