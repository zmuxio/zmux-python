"""Public payload and metadata value types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional, Tuple

from .protocol import MAX_VARINT62


@dataclass(frozen=True)
class StreamMetadata:
    """Peer-visible stream metadata known locally."""

    priority: Optional[int] = None
    group: Optional[int] = None
    open_info: bytes = b""

    def __post_init__(self) -> None:
        if self.priority is not None:
            _require_optional_varint62(self.priority, "priority")
        if self.group is not None:
            _require_optional_varint62(self.group, "group")
        object.__setattr__(self, "open_info", _coerce_bytes(self.open_info))

    def __repr__(self) -> str:
        return (
                "%s(priority=%r, group=%r, open_info_length=%r)"
                % (
                    self.__class__.__name__,
                    self.priority,
                    self.group,
                    len(self.open_info),
                )
        )

    def as_view(self) -> "StreamMetadataView":
        """Return a borrowed view over this metadata."""

        return StreamMetadataView(self.priority, self.group, self.open_info)

    def is_empty(self) -> bool:
        """Return whether no metadata fields are present."""

        return self.priority is None and self.group is None and not self.open_info

    @property
    def has_open_info(self) -> bool:
        """Return whether opaque open metadata is present."""

        return bool(self.open_info)


@dataclass(frozen=True)
class StreamMetadataView:
    """Borrowed peer-visible stream metadata."""

    priority: Optional[int] = None
    group: Optional[int] = None
    open_info: memoryview = field(default_factory=lambda: memoryview(b""))

    def __post_init__(self) -> None:
        if self.priority is not None:
            _require_optional_varint62(self.priority, "priority")
        if self.group is not None:
            _require_optional_varint62(self.group, "group")
        object.__setattr__(self, "open_info", _coerce_byte_view(self.open_info))

    def __repr__(self) -> str:
        return (
                "%s(priority=%r, group=%r, open_info_length=%r)"
                % (
                    self.__class__.__name__,
                    self.priority,
                    self.group,
                    len(self.open_info),
                )
        )

    def is_empty(self) -> bool:
        return self.priority is None and self.group is None and not self.open_info

    @property
    def has_open_info(self) -> bool:
        """Return whether opaque open metadata is present."""

        return bool(self.open_info)

    def to_owned(self) -> StreamMetadata:
        return StreamMetadata(self.priority, self.group, self.open_info.tobytes())


@dataclass(frozen=True)
class MetadataUpdate:
    """Post-open advisory metadata update request."""

    priority: Optional[int] = None
    group: Optional[int] = None

    def __post_init__(self) -> None:
        if self.priority is not None:
            _require_optional_varint62(self.priority, "priority")
        if self.group is not None:
            _require_optional_varint62(self.group, "group")

    def is_empty(self) -> bool:
        """Return whether this update carries no fields."""

        return self.priority is None and self.group is None


@dataclass(frozen=True)
class DataPayload:
    """Parsed DATA payload split into metadata and application bytes."""

    metadata_tlvs: Tuple[object, ...] = ()
    has_metadata: bool = False
    metadata: StreamMetadata = field(default_factory=StreamMetadata)
    open_info: bytes = b""
    app_data: bytes = b""
    metadata_valid: bool = False

    def __post_init__(self) -> None:
        metadata = _coerce_owned_metadata(self.metadata)
        open_info = _coerce_bytes(self.open_info)
        metadata_tlvs = tuple(self.metadata_tlvs or ())
        has_metadata = _coerce_bool(self.has_metadata, "has_metadata")
        metadata_valid = _coerce_bool(self.metadata_valid, "metadata_valid")
        if not has_metadata and (metadata_tlvs or not metadata.is_empty() or open_info):
            has_metadata = True
        if not has_metadata:
            metadata = StreamMetadata()
            open_info = b""
            metadata_valid = False
            metadata_tlvs = ()
        elif metadata_valid:
            if metadata.open_info and not open_info:
                open_info = metadata.open_info
            elif open_info and not metadata.open_info:
                metadata = StreamMetadata(metadata.priority, metadata.group, open_info)
        else:
            metadata = StreamMetadata()
            open_info = b""
            metadata_tlvs = ()
        object.__setattr__(self, "metadata_tlvs", metadata_tlvs)
        object.__setattr__(self, "has_metadata", has_metadata)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "open_info", open_info)
        object.__setattr__(self, "app_data", _coerce_bytes(self.app_data))
        object.__setattr__(self, "metadata_valid", metadata_valid)

    def __repr__(self) -> str:
        return (
                "%s(has_metadata=%r, metadata_valid=%r, metadata=%r, "
                "metadata_tlv_count=%r, app_data_length=%r)"
                % (
                    self.__class__.__name__,
                    self.has_metadata,
                    self.metadata_valid,
                    self.metadata,
                    len(self.metadata_tlvs),
                    len(self.app_data),
                )
        )

    def as_view(self) -> "DataPayloadView":
        """Return a borrowed view over this parsed payload."""

        metadata = self.metadata.as_view() if self.metadata_valid else StreamMetadataView()
        return DataPayloadView(metadata, self.app_data, self.has_metadata, self.metadata_valid)


@dataclass(frozen=True)
class DataPayloadView:
    """Parsed DATA payload view split into metadata and application bytes."""

    metadata: StreamMetadataView = field(default_factory=StreamMetadataView)
    app_data: memoryview = field(default_factory=lambda: memoryview(b""))
    has_metadata: bool = False
    metadata_valid: bool = False

    def __post_init__(self) -> None:
        has_metadata = _coerce_bool(self.has_metadata, "has_metadata")
        metadata_valid = _coerce_bool(self.metadata_valid, "metadata_valid")
        metadata = _coerce_metadata_view(self.metadata)
        if not has_metadata and not metadata.is_empty():
            has_metadata = True
        if not has_metadata:
            metadata = StreamMetadataView()
            metadata_valid = False
        elif not metadata_valid:
            metadata = StreamMetadataView()
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "app_data", _coerce_byte_view(self.app_data))
        object.__setattr__(self, "has_metadata", has_metadata)
        object.__setattr__(self, "metadata_valid", metadata_valid)

    def __repr__(self) -> str:
        return (
                "%s(has_metadata=%r, metadata_valid=%r, metadata=%r, app_data_length=%r)"
                % (
                    self.__class__.__name__,
                    self.has_metadata,
                    self.metadata_valid,
                    self.metadata,
                    len(self.app_data),
                )
        )

    @property
    def open_info(self) -> memoryview:
        return self.metadata.open_info

    def to_owned(self) -> DataPayload:
        metadata = self.metadata.to_owned() if self.metadata_valid else StreamMetadata()
        return DataPayload(
            has_metadata=self.has_metadata,
            metadata=metadata,
            open_info=metadata.open_info,
            app_data=self.app_data.tobytes(),
            metadata_valid=self.metadata_valid,
        )


@dataclass(frozen=True)
class GoAwayPayload:
    """Parsed GOAWAY payload."""

    last_accepted_bidi: int
    last_accepted_uni: int
    code: int
    reason: str = ""

    def __post_init__(self) -> None:
        _require_optional_varint62(self.last_accepted_bidi, "last_accepted_bidi")
        _require_optional_varint62(self.last_accepted_uni, "last_accepted_uni")
        _require_optional_varint62(self.code, "code")
        object.__setattr__(self, "reason", _coerce_reason(self.reason))


def build_open_metadata_prefix(
        capabilities: int,
        priority: Optional[int] = None,
        group: Optional[int] = None,
        open_info: bytes = b"",
        max_frame_payload: int = 16384,
) -> bytes:
    from ._wire.payload import build_open_metadata_prefix as _build

    return _build(capabilities, priority, group, open_info, max_frame_payload)


def build_priority_update_payload(
        capabilities: int, update: MetadataUpdate, max_payload: int = 4096
) -> bytes:
    from ._wire.payload import build_priority_update_payload as _build

    return _build(capabilities, update, max_payload)


def parse_priority_update_payload(payload: bytes) -> Tuple[StreamMetadata, bool]:
    from ._wire.payload import parse_priority_update_payload as _parse

    return _parse(payload)


def parse_data_payload(payload: bytes, flags: int) -> DataPayload:
    from ._wire.payload import parse_data_payload as _parse

    return _parse(payload, flags)


def parse_data_payload_view(payload: bytes, flags: int) -> DataPayloadView:
    from ._wire.payload import parse_data_payload_view as _parse

    return _parse(payload, flags)


def parse_data_payload_metadata_offset(
        payload: bytes, flags: int
) -> Tuple[StreamMetadata, bool, int]:
    from ._wire.payload import parse_data_payload_metadata_offset as _parse

    return _parse(payload, flags)


def parse_stream_metadata_tlvs(
        tlvs: Iterable[object],
) -> Tuple[StreamMetadata, bool]:
    from ._wire.payload import parse_stream_metadata_tlvs as _parse

    return _parse(tlvs)


def parse_stream_metadata_tlvs_view(
        tlvs: Iterable[object],
) -> Tuple[StreamMetadataView, bool]:
    from ._wire.payload import parse_stream_metadata_tlvs_view as _parse

    return _parse(tlvs)


def parse_stream_metadata_bytes_view(payload: bytes) -> Tuple[StreamMetadataView, bool]:
    from ._wire.payload import parse_stream_metadata_bytes_view as _parse

    return _parse(payload)


def build_go_away_payload(
        last_accepted_bidi: int,
        last_accepted_uni: int,
        code: int,
        reason: str = "",
        max_payload: Optional[int] = None,
) -> bytes:
    from ._wire.payload import (
        build_go_away_payload as _build,
        build_go_away_payload_capped as _build_capped,
    )

    if max_payload is not None:
        return _build_capped(
            last_accepted_bidi,
            last_accepted_uni,
            code,
            reason,
            max_payload,
        )
    return _build(last_accepted_bidi, last_accepted_uni, code, reason)


def parse_go_away_payload(payload: bytes) -> GoAwayPayload:
    from ._wire.payload import parse_go_away_payload as _parse

    return _parse(payload)


def build_error_payload(code: int, reason: str = "", max_payload: int = 4096) -> bytes:
    from ._wire.payload import build_error_payload as _build

    return _build(code, reason, max_payload)


def parse_error_payload(payload: bytes) -> Tuple[int, str]:
    from ._wire.payload import parse_error_payload as _parse

    return _parse(payload)


def parse_diag_reason(payload: bytes) -> str:
    from ._wire.payload import parse_diag_reason as _parse

    return _parse(payload)


def _require_optional_varint62(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % field_name)
    if value < 0:
        raise ValueError("%s must be >= 0" % field_name)
    if value > MAX_VARINT62:
        raise ValueError("%s must be within varint62 range" % field_name)


def _coerce_bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bool, int)):
        raise TypeError("bytes value must be bytes-like")
    return bytes(value)


def _coerce_byte_view(value) -> memoryview:
    if value is None:
        return memoryview(b"")
    if isinstance(value, (bool, int)):
        raise TypeError("bytes value must be bytes-like")
    view = memoryview(value)
    if view.itemsize == 1 and view.ndim == 1 and view.format == "B":
        return view
    try:
        return view.cast("B")
    except TypeError:
        return memoryview(view.tobytes())


def _coerce_owned_metadata(value) -> StreamMetadata:
    if value is None:
        return StreamMetadata()
    if isinstance(value, StreamMetadata):
        return value
    if isinstance(value, StreamMetadataView):
        return value.to_owned()
    raise TypeError("metadata must be StreamMetadata")


def _coerce_metadata_view(value) -> StreamMetadataView:
    if value is None:
        return StreamMetadataView()
    if isinstance(value, StreamMetadataView):
        return value
    if isinstance(value, StreamMetadata):
        return value.as_view()
    raise TypeError("metadata must be StreamMetadataView")


def _coerce_bool(value: bool, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError("%s must be a bool" % field_name)
    return value


def _coerce_reason(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TypeError("reason must be a string")
    return value


__all__ = [
    "DataPayload",
    "DataPayloadView",
    "GoAwayPayload",
    "MetadataUpdate",
    "StreamMetadata",
    "StreamMetadataView",
    "build_error_payload",
    "build_go_away_payload",
    "build_open_metadata_prefix",
    "build_priority_update_payload",
    "parse_data_payload",
    "parse_data_payload_metadata_offset",
    "parse_data_payload_view",
    "parse_diag_reason",
    "parse_error_payload",
    "parse_go_away_payload",
    "parse_priority_update_payload",
    "parse_stream_metadata_bytes_view",
    "parse_stream_metadata_tlvs",
    "parse_stream_metadata_tlvs_view",
]
