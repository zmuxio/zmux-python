"""Stream splicing, limiters, packet streams and duplicate session resolution."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any, TypedDict, Unpack

from ._errors import SpliceCommandError
from ._types import (
    DatagramSendOptions,
    DuplicateRule,
    Limiter,
    Packet,
    PacketStats,
    Resolved,
    SendPolicy,
    Sent,
    SpliceDirection,
    SpliceDisposition,
    SpliceDrops,
    SpliceDropReason,
    SpliceEvent,
    SpliceHandoffStats,
    SpliceEnd,
    SpliceHook,
    SpliceHooks,
    SpliceKind,
    SpliceLimits,
    SpliceMeta,
    SpliceResult,
    SpliceRoute,
    SpliceSample,
)
from ._zmux import (
    DEFAULT_MAX_PACKET,
    PacketReceiver,
    PacketSender,
    PacketStream,
    RecvStream,
    SendStream,
    SpliceAbort,
    SpliceControl,
    SpliceController,
    SpliceDecision,
    SpliceHandoffs,
    SpliceMirror,
    SplicePause,
    SpliceReceipt,
    SpliceSignal,
    SpliceUnit,
    _splice_start,
    resolve_duplicate,
)

__all__ = [
    "DEFAULT_MAX_PACKET",
    "DuplicateRule",
    "Limiter",
    "Packet",
    "PacketReceiver",
    "PacketSender",
    "PacketStats",
    "PacketStream",
    "Resolved",
    "SendPolicy",
    "Sent",
    "SpliceAbort",
    "SpliceCommandError",
    "SpliceControl",
    "SpliceController",
    "SpliceDecision",
    "SpliceDirection",
    "SpliceDisposition",
    "SpliceDropReason",
    "SpliceDrops",
    "SpliceEnd",
    "SpliceEvent",
    "SpliceHandoffStats",
    "SpliceHandoffs",
    "SpliceHook",
    "SpliceHooks",
    "SpliceKind",
    "SpliceLimits",
    "SpliceMeta",
    "SpliceMirror",
    "SplicePause",
    "SpliceReceipt",
    "SpliceResult",
    "SpliceRoute",
    "SpliceSample",
    "SpliceSignal",
    "SpliceUnit",
    "controlled_splice",
    "controlled_splice_packets",
    "resolve_duplicate",
    "splice",
    "splice_packets",
]


_Stream = tuple[SendStream, RecvStream]


class _Options(TypedDict, total=False):
    chunk: int | None
    a_to_b: Limiter | None
    b_to_a: Limiter | None
    abort: SpliceAbort | None
    a_to_b_datagrams: DatagramSendOptions | None
    b_to_a_datagrams: DatagramSendOptions | None
    max_packet_payload: int | None
    max_opaque_value: int | None


class _ControlledOptions(_Options, total=False):
    on_event: Callable[[SpliceEvent], None] | None
    a_to_b_hooks: SpliceHooks | None
    b_to_a_hooks: SpliceHooks | None
    a_to_b_label: str
    b_to_a_label: str
    a_to_b_mirror: SpliceMirror | None
    b_to_a_mirror: SpliceMirror | None
    limits: SpliceLimits | None


def splice(
    a: _Stream, b: _Stream, **options: Unpack[_Options]
) -> Coroutine[Any, Any, SpliceResult]:
    """Relay two bidirectional streams as independent half-close directions.

    This consumes the given handles. Cancelling the returned coroutine stops
    the relay and ends both streams. A prefix may already have been forwarded.
    Set `a_to_b` and `b_to_a` to limit outgoing bytes. `chunk` is the
    maximum byte block (65536 by default). `abort` can end several relays.
    """
    _, run = _splice_start(a, b, packets=False, controlled=False, **options)
    return run


def splice_packets(
    a: _Stream, b: _Stream, **options: Unpack[_Options]
) -> Coroutine[Any, Any, SpliceResult]:
    """Relay packet streams while preserving reliable capsule boundaries.

    Eligible
    datagrams can become DATAGRAM capsules when the target cannot accept
    their native representation. Reliable capsules remain reliable. Options,
    stream ownership and cancellation otherwise follow `splice`.
    """
    _, run = _splice_start(a, b, packets=True, controlled=False, **options)
    return run


def _controlled(
    a: _Stream, b: _Stream, *, packets: bool, **options: Unpack[_ControlledOptions]
) -> tuple[SpliceController, Coroutine[Any, Any, SpliceResult]]:
    control, run = _splice_start(a, b, packets=packets, controlled=True, **options)
    assert control is not None
    return control, run


def controlled_splice(
    a: _Stream, b: _Stream, **options: Unpack[_ControlledOptions]
) -> tuple[SpliceController, Coroutine[Any, Any, SpliceResult]]:
    """Create a byte splice with two control handles and a driving coroutine.

    Run the coroutine on the creating loop while interacting with the
    controls. The coroutine owns the streams and ends them on cancellation.
    A prefix may already have been forwarded. Initial hooks can transform
    each direction. A synchronous `on_event` observes committed events on
    the driving loop.
    """
    return _controlled(a, b, packets=False, **options)


def controlled_splice_packets(
    a: _Stream, b: _Stream, **options: Unpack[_ControlledOptions]
) -> tuple[SpliceController, Coroutine[Any, Any, SpliceResult]]:
    """Create a controlled packet splice, with the options of `splice_packets`."""
    return _controlled(a, b, packets=True, **options)
