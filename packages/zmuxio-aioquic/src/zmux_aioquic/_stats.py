"""Internal stats counters for aioquic-backed sessions."""

from __future__ import annotations

from typing import Tuple

from zmux.session import ActiveStreamStats
from ._constants import MAX_REASON_STATS_CODES
from ._state import _sat_add


class _ActiveKind(object):
    LOCAL_BIDI = "local_bidi"
    LOCAL_UNI = "local_uni"
    PEER_BIDI = "peer_bidi"
    PEER_UNI = "peer_uni"


class _ActiveCounters(object):
    def __init__(self) -> None:
        self.local_bidi = 0
        self.local_uni = 0
        self.peer_bidi = 0
        self.peer_uni = 0

    def add(self, kind: _ActiveKind) -> None:
        if kind == _ActiveKind.LOCAL_BIDI:
            self.local_bidi = _sat_add(self.local_bidi, 1)
        elif kind == _ActiveKind.LOCAL_UNI:
            self.local_uni = _sat_add(self.local_uni, 1)
        elif kind == _ActiveKind.PEER_BIDI:
            self.peer_bidi = _sat_add(self.peer_bidi, 1)
        elif kind == _ActiveKind.PEER_UNI:
            self.peer_uni = _sat_add(self.peer_uni, 1)

    def done(self, kind: _ActiveKind) -> None:
        if kind == _ActiveKind.LOCAL_BIDI and self.local_bidi:
            self.local_bidi -= 1
        elif kind == _ActiveKind.LOCAL_UNI and self.local_uni:
            self.local_uni -= 1
        elif kind == _ActiveKind.PEER_BIDI and self.peer_bidi:
            self.peer_bidi -= 1
        elif kind == _ActiveKind.PEER_UNI and self.peer_uni:
            self.peer_uni -= 1

    def snapshot(self) -> ActiveStreamStats:
        return ActiveStreamStats(
            local_bidi=self.local_bidi,
            local_uni=self.local_uni,
            peer_bidi=self.peer_bidi,
            peer_uni=self.peer_uni,
        )


class _ReasonCounter(object):
    def __init__(self) -> None:
        self.counts = {}
        self.overflow = 0

    def note(self, code: int) -> None:
        if code in self.counts:
            self.counts[code] = _sat_add(self.counts[code], 1)
        elif len(self.counts) < MAX_REASON_STATS_CODES:
            self.counts[code] = 1
        else:
            self.overflow = _sat_add(self.overflow, 1)

    def snapshot(self) -> Tuple[dict, int]:
        return dict(self.counts), self.overflow
