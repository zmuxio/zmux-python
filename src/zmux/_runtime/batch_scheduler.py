"""Stateful batch scheduler facade."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Dict

from ._containers import pop_attrs
from .sched_core import (
    FALLBACK_GROUP_BUCKET,
    MAX_EXPLICIT_GROUPS,
    MAX_UINT64,
    BatchConfig,
    BatchItem,
    BatchState,
    GroupKey,
    StreamGroupBinding,
    coerce_batch_config,
    normalize_batch_state,
    order_batch_indices,
    release_idle_batch_state_storage,
    require_bool,
    scrub_idle_retained_batch_state,
    uint64,
    varint62,
)

_GROUP_BATCH_STATE_ATTRS = (
    "group_virtual_time",
    "group_finish_tag",
    "group_last_service",
    "group_lag",
    "preferred_stream_head",
)
_STREAM_BATCH_STATE_ATTRS = (
    "stream_finish_tag",
    "stream_last_service",
    "stream_lag",
    "stream_class",
    "stream_last_seen_batch",
    "small_burst_disarmed",
)


class BatchScheduler(object):
    """Stateful retained batch scheduler facade."""

    def __init__(self) -> None:
        self.state = BatchState()
        self.active_group_refs: Dict[int, int] = {}
        self.stream_groups: Dict[int, StreamGroupBinding] = {}

    @property
    def stream_finish_tag(self) -> Dict[int, int]:
        return self.state.stream_finish_tag

    @property
    def group_finish_tag(self) -> Dict[GroupKey, int]:
        return self.state.group_finish_tag

    def ensure_state(self) -> None:
        normalize_batch_state(self.state)

    def order(self, cfg: BatchConfig, items: Sequence[BatchItem]) -> tuple[int, ...]:
        return order_batch_indices(coerce_batch_config(cfg), self.state, items)

    def tracked_explicit_group_count(self) -> int:
        return sum(
            1
            for group_id in self.active_group_refs
            if group_id != 0 and group_id != FALLBACK_GROUP_BUCKET
        )

    def track_explicit_group(self, group_id: int) -> None:
        group_id = uint64(group_id, "group_id")
        if group_id == 0:
            return
        self.active_group_refs[group_id] = min(
            MAX_UINT64, self.active_group_refs.get(group_id, 0) + 1
        )

    def untrack_explicit_group(self, group_id: int) -> None:
        group_id = uint64(group_id, "group_id")
        if group_id == 0:
            return
        refs = self.active_group_refs.get(group_id, 0)
        if refs > 1:
            self.active_group_refs[group_id] = refs - 1
            return
        self.active_group_refs.pop(group_id, None)
        self._drop_group_state(GroupKey.explicit(group_id))
        self.maybe_clear_idle_head_state()

    def group_key_for_stream(
            self, stream_id: int, group: int = 0, group_fair: bool = False
    ) -> GroupKey:
        stream_id = uint64(stream_id, "stream_id")
        group = varint62(group, "group")
        group_fair = require_bool(group_fair, "group_fair")
        if stream_id == 0 or not group_fair or group == 0:
            self.drop_stream_group(stream_id)
            return GroupKey.stream(stream_id)
        current = self.stream_groups.get(stream_id)
        if current is not None and current.group == group and current.bucket != 0:
            return GroupKey.explicit(current.bucket)
        bucket = group
        if (
                bucket not in self.active_group_refs
                and self.tracked_explicit_group_count() >= MAX_EXPLICIT_GROUPS
        ):
            bucket = FALLBACK_GROUP_BUCKET
        self.drop_stream_group(stream_id)
        self.stream_groups[stream_id] = StreamGroupBinding(group, bucket)
        self.track_explicit_group(bucket)
        self._drop_group_state(GroupKey.stream(stream_id))
        return GroupKey.explicit(bucket)

    def drop_stream_group(self, stream_id: int) -> None:
        stream_id = uint64(stream_id, "stream_id")
        binding = self.stream_groups.pop(stream_id, None)
        if binding is not None and binding.bucket:
            self.untrack_explicit_group(binding.bucket)

    def drop_stream(self, stream_id: int) -> None:
        stream_id = uint64(stream_id, "stream_id")
        if stream_id == 0:
            return
        binding = self.stream_groups.pop(stream_id, None)
        if binding is not None and binding.bucket:
            self.untrack_explicit_group(binding.bucket)
        pop_attrs(self.state, _STREAM_BATCH_STATE_ATTRS, stream_id)
        self._drop_group_state(GroupKey.stream(stream_id))
        self.maybe_clear_idle_head_state()

    def clear(self) -> None:
        self.state = BatchState()
        self.active_group_refs.clear()
        self.stream_groups.clear()

    def maybe_clear_idle_head_state(self) -> None:
        if (
                self.state.has_any_retained_state()
                or self.active_group_refs
                or self.stream_groups
        ):
            return
        scrub_idle_retained_batch_state(self.state)
        release_idle_batch_state_storage(self.state)

    def _drop_group_state(self, group_key: GroupKey) -> None:
        pop_attrs(self.state, _GROUP_BATCH_STATE_ATTRS, group_key)
        if (
                self.state.has_preferred_group_head
                and self.state.preferred_group_head == group_key
        ):
            self.state.preferred_group_head = GroupKey()
            self.state.has_preferred_group_head = False


def new_batch_scheduler() -> BatchScheduler:
    return BatchScheduler()


__all__ = ("BatchScheduler", "new_batch_scheduler")
