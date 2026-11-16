"""Helpers above the public API (they drive only its operations): the pipe
pool that keeps pipes up, the splice of two streams, rate limiters and the
resolution of duplicate sessions, and packet streams with their relay."""

from __future__ import annotations

from ._types import (
    DuplicateRule,
    Forwarded,
    Limiter,
    Packet,
    PacketStats,
    Resolved,
    SendPolicy,
    Sent,
    Spliced,
    SpliceEnd,
)
from ._zmux import (
    MIN_RECHECK,
    MaintainHandle,
    PacketReceiver,
    PacketSender,
    PacketStream,
    PipePool,
    PoolPolicy,
    PoolPolicyDecision,
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
    "Forwarded",
    "Limiter",
    "MaintainHandle",
    "Packet",
    "PacketReceiver",
    "PacketSender",
    "PacketStats",
    "PacketStream",
    "PipePool",
    "PoolPolicy",
    "PoolPolicyDecision",
    "Resolved",
    "SendPolicy",
    "Sent",
    "SpliceAbort",
    "SpliceEnd",
    "Spliced",
    "resolve_duplicate",
    "splice",
    "splice_packets",
]
