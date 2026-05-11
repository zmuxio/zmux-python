"""Zero-value protocol state helpers for adapter snapshots."""

from __future__ import annotations

from zmux.config import Settings
from zmux.preface import Negotiated, Preface
from zmux.protocol import Role

MAX_UINT64 = (1 << 64) - 1


def _empty_preface() -> Preface:
    return Preface(0, Role.AUTO, 0, 0, 0, 0, Settings())


def _empty_negotiated() -> Negotiated:
    return Negotiated(0, 0, Role.INITIATOR, Role.RESPONDER, Settings())


def _sat_add(a: int, b: int) -> int:
    total = int(a) + int(b)
    return min(total, MAX_UINT64)
