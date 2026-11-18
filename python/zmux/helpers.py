"""Helpers above the public API (they drive only its operations): the pipe
pool that keeps pipes up, the splice of two streams, rate limiters and the
resolution of duplicate sessions, and packet streams with their relay."""

from __future__ import annotations

from ._types import (
    DuplicateRule,
    Limiter,
    Packet,
    PacketStats,
    PoolDecision,
    PoolEvaluation,
    PoolMember,
    PoolPolicy,
    PoolView,
    Resolved,
    SendPolicy,
    Sent,
    SpliceDirection,
    SpliceEnd,
    SpliceResult,
)
from ._zmux import (
    MIN_RECHECK,
    MachinePoolPolicy,
    MaintainHandle,
    PacketReceiver,
    PacketSender,
    PacketStream,
    PipePool,
    SpliceAbort,
    resolve_duplicate,
    splice,
    splice_packets,
)

DEFAULT_MAX_PACKET = 65535
"""The default bound of a packet's payload (`max_packet`)."""

__all__ = [
    "DEFAULT_MAX_PACKET",
    "MIN_RECHECK",
    "DuplicateRule",
    "Limiter",
    "MachinePoolPolicy",
    "MaintainHandle",
    "Packet",
    "PacketReceiver",
    "PacketSender",
    "PacketStats",
    "PacketStream",
    "PipePool",
    "PoolDecision",
    "PoolEvaluation",
    "PoolMember",
    "PoolPolicy",
    "PoolView",
    "Resolved",
    "SendPolicy",
    "Sent",
    "SpliceAbort",
    "SpliceDirection",
    "SpliceEnd",
    "SpliceResult",
    "resolve_duplicate",
    "splice",
    "splice_packets",
]
