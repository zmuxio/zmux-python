"""Blocking writer queue with lane admission and byte-pressure accounting."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable, MutableSequence
from typing import Deque, Optional, Tuple

from . import tx as _tx
from .tx import *
from .tx import (
    complete_job_error,
    jobs_have_removable_stream_frame,
    merge_coalesced_priority_update,
    remove_stream_frames,
    replacement_would_exceed_limit,
)
from ..errors import ProtocolError, SessionClosed

_POLL_WAIT_CAP_SECONDS = _tx._POLL_WAIT_CAP_SECONDS
_internal_queue_error = _tx._internal_queue_error
_nonnegative_duration = _tx._nonnegative_duration
_order_urgent_jobs_in_place = _tx._order_urgent_jobs_in_place
_saturating_add = _tx._saturating_add
_WRITE_QUEUE_LANES = (QueueLane.URGENT, QueueLane.ORDINARY)


class WriteQueue:
    """Thread-safe writer lane queue with Go/Rust-compatible accounting."""

    def __init__(self, limits: Optional[WriteQueueLimits] = None, **kwargs: int) -> None:
        if limits is None:
            limits = WriteQueueLimits(**kwargs)
        elif kwargs:
            raise TypeError("pass either limits or keyword limits, not both")
        self.limits = limits
        self._urgent = deque()
        self._ordinary = deque()
        self._queued_bytes = 0
        self._urgent_queued_bytes = 0
        self._data_queued_bytes = 0
        self._data_queued_by_stream = {}
        self._pending_control_bytes = 0
        self._pending_priority_bytes = 0
        self._closed = False
        self._cond = threading.Condition()

    def data_burst_max_bytes(self) -> int:
        return max(
            1,
            min(
                self.limits.max_bytes,
                self.limits.session_data_max_bytes,
                self.limits.per_stream_data_max_bytes,
            ),
        )

    def max_batch_frames(self) -> int:
        return self.limits.max_batch_frames

    def try_push(self, job: WriteJob) -> None:
        self._push(job, block=False, force=False, deadline=None)

    def force_push(self, job: WriteJob) -> None:
        self._push(job, block=False, force=True, deadline=None)

    def push(self, job: WriteJob, timeout: Optional[float] = None) -> None:
        deadline = None if timeout is None else time.monotonic() + _nonnegative_duration(timeout, "timeout")
        self._push(job, block=True, force=False, deadline=deadline)

    def push_until(
            self,
            job: WriteJob,
            deadline: Optional[float],
            check: Optional[Callable[[], None]] = None,
            operation: str = "write",
    ) -> None:
        del operation
        pending = job
        while True:
            if check is not None:
                check()
            try:
                self._push(pending, block=False, force=False, deadline=None)
                return
            except ProtocolError as exc:
                if self._is_intrinsic_push_error(pending, exc):
                    raise
                if str(exc) not in (
                        WRITER_QUEUE_FULL_MESSAGE,
                        URGENT_WRITER_QUEUE_FULL_MESSAGE,
                        PENDING_CONTROL_BUDGET_MESSAGE,
                        PENDING_PRIORITY_BUDGET_MESSAGE,
                        QUEUED_DATA_HWM_MESSAGE,
                ):
                    raise
            with self._cond:
                self._wait_not_full_locked(deadline)

    def shutdown(self) -> None:
        with self._cond:
            self._clear_locked(SessionClosed())
            self._closed = True
            self._cond.notify_all()

    def shutdown_after_close(self, frame: Frame) -> None:
        with self._cond:
            self._clear_locked(SessionClosed())
            job = WriteJob.frame_job(frame)
            cost = job.cost_bytes()
            accounting = queue_cost_for(QueueLane.URGENT, job, cost)
            self._apply_cost_add(accounting)
            self._urgent.append(job)
            self._urgent.append(WriteJob.shutdown())
            self._closed = True
            self._cond.notify_all()

    def close_after_draining(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def stats(self) -> WriterQueueStats:
        with self._cond:
            return WriterQueueStats(
                urgent_jobs=len(self._urgent),
                advisory_jobs=0,
                ordinary_jobs=len(self._ordinary),
                queued_bytes=self._queued_bytes,
                max_bytes=self.limits.max_bytes,
                urgent_queued_bytes=self._urgent_queued_bytes,
                urgent_max_bytes=self.limits.urgent_max_bytes,
                advisory_queued_bytes=0,
                data_queued_bytes=self._data_queued_bytes,
                session_data_high_watermark=self.limits.session_data_max_bytes,
                per_stream_data_high_watermark=self.limits.per_stream_data_max_bytes,
                pending_control_bytes=self._pending_control_bytes,
                pending_control_bytes_budget=self.limits.pending_control_max_bytes,
                pending_priority_bytes=self._pending_priority_bytes,
                pending_priority_bytes_budget=self.limits.pending_priority_max_bytes,
                max_batch_frames=self.limits.max_batch_frames,
            )

    def data_queued_bytes_for_stream(self, stream_id: int) -> int:
        with self._cond:
            return self._data_queued_by_stream.get(stream_id, 0)

    def terminal_control_queued_for_stream(self, stream_id: int) -> bool:
        with self._cond:
            return (
                    jobs_have_terminal_control_for_stream(self._urgent, stream_id)
                    or jobs_have_terminal_control_for_stream(self._ordinary, stream_id)
            )

    def discard_stream(self, stream_id: int) -> StreamDiscardStats:
        return self._discard_stream(stream_id, frame_belongs_to_stream)

    def discard_stream_send_tail(self, stream_id: int) -> StreamDiscardStats:
        return self._discard_stream(stream_id, frame_is_send_tail_for_stream)

    def discard_priority_update(self, stream_id: int) -> bool:
        if stream_id == 0:
            return False
        return self._discard_coalesced(CoalesceKey(CoalesceKind.PRIORITY_UPDATE, stream_id))

    def discard_stream_max_data(self, stream_id: int) -> bool:
        if stream_id == 0:
            return False
        return self._discard_coalesced(CoalesceKey(CoalesceKind.MAX_DATA, stream_id))

    def cancel_tracked_write(self, completion: WriteCompletion) -> Optional[TrackedWriteJob]:
        with self._cond:
            found = self._find_tracked_completion_locked(completion)
            if found is None:
                return None
            lane, index = found
            job = self._remove_lane_job(lane, index)
            if job is None:
                return None
            queued = job.cost_bytes()
            self._apply_cost_remove(queue_cost_for(lane, job, queued))
            self._cond.notify_all()
            return job.tracked if job.kind is WriteJobKind.TRACKED_FRAMES else None

    def pop_batch(self, timeout: Optional[float] = None) -> Optional[Tuple[WriteJob, ...]]:
        batch = []
        status = self.pop_batch_into(batch, timeout)
        if status is WriteQueuePopStatus.BATCH:
            return tuple(batch)
        return None

    def pop_batch_into(
            self, batch: MutableSequence[WriteJob], timeout: Optional[float] = None
    ) -> WriteQueuePopStatus:
        batch.clear()
        deadline = None if timeout is None else time.monotonic() + _nonnegative_duration(timeout, "timeout")
        with self._cond:
            while self._is_empty_locked() and not self._closed:
                if deadline is None:
                    self._cond.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    return WriteQueuePopStatus.TIMED_OUT
                self._cond.wait(min(remaining, _POLL_WAIT_CAP_SECONDS))
            if self._is_empty_locked():
                return WriteQueuePopStatus.CLOSED

            if self._urgent:
                for _ in range(max(1, self.limits.max_batch_frames)):
                    if not self._urgent:
                        break
                    job = self._urgent.popleft()
                    cost = job.cost_bytes()
                    self._apply_cost_remove(queue_cost_for(QueueLane.URGENT, job, cost))
                    batch.append(job)
                    if job.kind is WriteJobKind.SHUTDOWN:
                        break
                _order_urgent_jobs_in_place(batch)
                self._cond.notify_all()
                return WriteQueuePopStatus.BATCH

            saw_nonurgent = False
            nonurgent_batch_bytes = 0
            for _ in range(max(1, self.limits.max_batch_frames)):
                if not self._ordinary:
                    break
                lane = QueueLane.ORDINARY
                job = self._ordinary.popleft()
                cost = job.cost_bytes()
                would_exceed = (
                        _saturating_add(nonurgent_batch_bytes, cost)
                        > self.limits.max_batch_bytes
                )
                if saw_nonurgent and would_exceed:
                    self._ordinary.appendleft(job)
                    break
                saw_nonurgent = True
                nonurgent_batch_bytes = _saturating_add(nonurgent_batch_bytes, cost)
                self._apply_cost_remove(queue_cost_for(lane, job, cost))
                batch.append(job)
                if job.kind in (WriteJobKind.SHUTDOWN, WriteJobKind.DRAIN_SHUTDOWN):
                    break
            self._cond.notify_all()
            return WriteQueuePopStatus.BATCH

    def _push(
            self,
            job: WriteJob,
            *,
            block: bool,
            force: bool,
            deadline: Optional[float],
    ) -> None:
        pending = job
        with self._cond:
            while True:
                if self._closed:
                    raise SessionClosed()
                coalesce_key = pending.coalesce_key()
                bypass_capacity = (
                        force
                        or pending.bypasses_capacity()
                        or (
                                coalesce_key is not None
                                and coalesce_key.kind is CoalesceKind.PRIORITY_UPDATE
                        )
                )
                bypass_urgent_capacity = force or pending.bypasses_urgent_capacity()
                found = self._find_coalesced_locked(coalesce_key)
                if found is not None:
                    lane, index = found
                    current = self._lane(lane)[index]
                    pending = merge_coalesced_priority_update(current, pending)
                    cost = pending.cost_bytes()
                    old_cost = current.cost_bytes()
                    old_accounting = queue_cost_for(lane, current, old_cost)
                    new_accounting = queue_cost_for(lane, pending, cost)
                    if not force:
                        self._raise_intrinsic_cost_errors(new_accounting)
                    blocked = (
                            (
                                    not bypass_capacity
                                    and self._replacement_would_exceed_capacity(old_cost, cost)
                            )
                            or (
                                    not bypass_urgent_capacity
                                    and self._replacement_would_exceed_urgent_capacity(
                                old_accounting.urgent, new_accounting.urgent
                            )
                            )
                            or (
                                    not force
                                    and self._replacement_would_exceed_pending_capacity(
                                old_accounting, new_accounting
                            )
                            )
                            or (
                                    not force
                                    and self._replacement_would_exceed_data_capacity(
                                old_accounting, new_accounting
                            )
                            )
                    )
                    if blocked:
                        if not block:
                            self._raise_capacity_error(
                                old_accounting,
                                new_accounting,
                                replacement=True,
                                urgent_block=(
                                        not bypass_urgent_capacity
                                        and self._replacement_would_exceed_urgent_capacity(
                                    old_accounting.urgent, new_accounting.urgent
                                )
                                ),
                                queue_block=(
                                        not bypass_capacity
                                        and self._replacement_would_exceed_capacity(old_cost, cost)
                                ),
                            )
                        self._wait_not_full_locked(deadline)
                        continue
                    self._lane(lane)[index] = pending
                    self._apply_cost_remove(old_accounting)
                    self._apply_cost_add(new_accounting)
                    self._cond.notify_all()
                    return

                lane = self._lane_for_locked(pending)
                cost = pending.cost_bytes()
                accounting = queue_cost_for(lane, pending, cost)
                if not force:
                    self._raise_intrinsic_cost_errors(accounting)
                queue_block = not bypass_capacity and self._would_exceed_capacity(cost)
                urgent_block = (
                        not bypass_urgent_capacity
                        and self._would_exceed_urgent_capacity(accounting.urgent)
                )
                blocked = (
                        queue_block
                        or urgent_block
                        or (not force and self._would_exceed_pending_capacity(accounting))
                        or (not force and self._would_exceed_data_capacity(accounting))
                )
                if blocked:
                    if not block:
                        self._raise_capacity_error(
                            None,
                            accounting,
                            replacement=False,
                            urgent_block=urgent_block,
                            queue_block=queue_block,
                        )
                    self._wait_not_full_locked(deadline)
                    continue
                self._apply_cost_add(accounting)
                self._lane(lane).append(pending)
                self._cond.notify_all()
                return

    def _is_intrinsic_push_error(self, job: WriteJob, error: ProtocolError) -> bool:
        with self._cond:
            pending = job
            found = self._find_coalesced_locked(pending.coalesce_key())
            if found is not None:
                lane, index = found
                pending = merge_coalesced_priority_update(self._lane(lane)[index], pending)
            lane = self._lane_for_locked(pending)
            cost = queue_cost_for(lane, pending, pending.cost_bytes())
            return self._intrinsic_capacity_message(cost) == str(error)

    def _wait_not_full_locked(self, deadline: Optional[float]) -> None:
        if deadline is None:
            self._cond.wait()
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise WriteTimeout()
        self._cond.wait(min(remaining, _POLL_WAIT_CAP_SECONDS))

    def _discard_stream(
            self,
            stream_id: int,
            remove: Callable[[Frame, int], bool],
    ) -> StreamDiscardStats:
        if stream_id == 0:
            return StreamDiscardStats()
        with self._cond:
            stats = StreamDiscardStats()
            for lane in _WRITE_QUEUE_LANES:
                stats = stats.add(self._discard_stream_from_lane_locked(lane, stream_id, remove))
            if stats.removed_any():
                self._cond.notify_all()
            return stats

    def _discard_coalesced(self, key: CoalesceKey) -> bool:
        with self._cond:
            removed = False
            while True:
                found = self._find_coalesced_locked(key)
                if found is None:
                    break
                lane, index = found
                job = self._remove_lane_job(lane, index)
                if job is None:
                    break
                self._apply_cost_remove(queue_cost_for(lane, job, job.cost_bytes()))
                removed = True
            if removed:
                self._cond.notify_all()
            return removed

    def _discard_stream_from_lane_locked(
            self,
            lane: QueueLane,
            stream_id: int,
            remove: Callable[[Frame, int], bool],
    ) -> StreamDiscardStats:
        lane_jobs = self._lane(lane)
        if not jobs_have_removable_stream_frame(lane_jobs, stream_id, remove):
            return StreamDiscardStats()
        kept = deque()
        stats = StreamDiscardStats()
        while lane_jobs:
            job = lane_jobs.popleft()
            old_cost = queue_cost_for(lane, job, job.cost_bytes())
            next_job, removed = remove_stream_frames(job, stream_id, remove)
            if removed.removed_any():
                stats = stats.add(removed)
                self._apply_cost_remove(old_cost)
                if next_job is not None:
                    self._apply_cost_add(queue_cost_for(lane, next_job, next_job.cost_bytes()))
                    kept.append(next_job)
            elif next_job is not None:
                kept.append(next_job)
        lane_jobs.extend(kept)
        return stats

    def _clear_locked(self, error: BaseException) -> None:
        for lane in (self._urgent, self._ordinary):
            while lane:
                complete_job_error(lane.popleft(), error)
        self._queued_bytes = 0
        self._urgent_queued_bytes = 0
        self._data_queued_bytes = 0
        self._data_queued_by_stream.clear()
        self._pending_control_bytes = 0
        self._pending_priority_bytes = 0

    def _is_empty_locked(self) -> bool:
        return not self._urgent and not self._ordinary

    def _lane(self, lane: QueueLane) -> Deque[WriteJob]:
        if lane is QueueLane.URGENT:
            return self._urgent
        return self._ordinary

    def _lane_for_locked(self, job: WriteJob) -> QueueLane:
        key = job.coalesce_key()
        if key is not None and key.kind is CoalesceKind.PRIORITY_UPDATE:
            return QueueLane.ORDINARY
        stream_id = job.urgent_stream_id()
        if stream_id is None:
            return QueueLane.URGENT if job.is_urgent() else QueueLane.ORDINARY
        return (
            QueueLane.ORDINARY
            if self._has_queued_data_for_stream_locked(stream_id)
            else QueueLane.URGENT
        )

    def _has_queued_data_for_stream_locked(self, stream_id: int) -> bool:
        return self._data_queued_by_stream.get(stream_id, 0) != 0

    def _find_coalesced_locked(
            self, key: Optional[CoalesceKey]
    ) -> Optional[Tuple[QueueLane, int]]:
        if key is None:
            return None
        for lane in _WRITE_QUEUE_LANES:
            jobs = self._lane(lane)
            for index in range(len(jobs) - 1, -1, -1):
                if jobs[index].coalesce_key() == key:
                    return lane, index
        return None

    def _find_tracked_completion_locked(
            self, completion: WriteCompletion
    ) -> Optional[Tuple[QueueLane, int]]:
        for lane in _WRITE_QUEUE_LANES:
            jobs = self._lane(lane)
            for index, job in enumerate(jobs):
                if job.tracks_completion(completion):
                    return lane, index
        return None

    def _remove_lane_job(self, lane: QueueLane, index: int) -> Optional[WriteJob]:
        jobs = self._lane(lane)
        if index < 0 or index >= len(jobs):
            return None
        job = jobs[index]
        del jobs[index]
        return job

    def _would_exceed_capacity(self, cost: int) -> bool:
        return cost > max(0, self.limits.max_bytes - self._queued_bytes)

    def _replacement_would_exceed_capacity(self, old_cost: int, new_cost: int) -> bool:
        return replacement_would_exceed_limit(
            self._queued_bytes, old_cost, new_cost, self.limits.max_bytes
        )

    def _would_exceed_urgent_capacity(self, cost: int) -> bool:
        return cost > max(0, self.limits.urgent_max_bytes - self._urgent_queued_bytes)

    def _replacement_would_exceed_urgent_capacity(
            self, old_cost: int, new_cost: int
    ) -> bool:
        return replacement_would_exceed_limit(
            self._urgent_queued_bytes,
            old_cost,
            new_cost,
            self.limits.urgent_max_bytes,
        )

    def _would_exceed_pending_capacity(self, cost: QueueCost) -> bool:
        return self._pending_capacity_error(cost) is not None

    def _replacement_would_exceed_pending_capacity(
            self, old: QueueCost, new: QueueCost
    ) -> bool:
        return self._replacement_pending_capacity_error(old, new) is not None

    def _would_exceed_data_capacity(self, cost: QueueCost) -> bool:
        if cost.data.is_empty():
            return False
        if self._intrinsic_data_capacity_error(cost):
            return True
        if cost.data.total > max(0, self.limits.session_data_max_bytes - self._data_queued_bytes):
            return True
        for stream_id, count in cost.data.items():
            queued = self._data_queued_by_stream.get(stream_id, 0)
            if count > max(0, self.limits.per_stream_data_max_bytes - queued):
                return True
        return False

    def _replacement_would_exceed_data_capacity(
            self, old: QueueCost, new: QueueCost
    ) -> bool:
        if new.data.is_empty():
            return False
        if replacement_would_exceed_limit(
                self._data_queued_bytes,
                old.data.total,
                new.data.total,
                self.limits.session_data_max_bytes,
        ):
            return True
        for stream_id, new_bytes in new.data.items():
            old_bytes = old.data.get(stream_id)
            if replacement_would_exceed_limit(
                    self._data_queued_by_stream.get(stream_id, 0),
                    old_bytes,
                    new_bytes,
                    self.limits.per_stream_data_max_bytes,
            ):
                return True
        return False

    def _intrinsic_data_capacity_error(self, cost: QueueCost) -> bool:
        if cost.data.is_empty():
            return False
        if cost.data.total > self.limits.session_data_max_bytes:
            return True
        for _, count in cost.data.items():
            if count > self.limits.per_stream_data_max_bytes:
                return True
        return False

    def _raise_intrinsic_cost_errors(self, cost: QueueCost) -> None:
        message = self._intrinsic_capacity_message(cost)
        if message is not None:
            raise _internal_queue_error(message)

    def _intrinsic_capacity_message(self, cost: QueueCost) -> Optional[str]:
        if cost.pending_control > self.limits.pending_control_max_bytes:
            return PENDING_CONTROL_BUDGET_MESSAGE
        if cost.pending_priority > self.limits.pending_priority_max_bytes:
            return PENDING_PRIORITY_BUDGET_MESSAGE
        if self._intrinsic_data_capacity_error(cost):
            return QUEUED_DATA_HWM_MESSAGE
        return None

    def _pending_capacity_error(self, cost: QueueCost) -> Optional[str]:
        if cost.pending_control > max(
                0, self.limits.pending_control_max_bytes - self._pending_control_bytes
        ):
            return PENDING_CONTROL_BUDGET_MESSAGE
        if cost.pending_priority > max(
                0, self.limits.pending_priority_max_bytes - self._pending_priority_bytes
        ):
            return PENDING_PRIORITY_BUDGET_MESSAGE
        return None

    def _replacement_pending_capacity_error(
            self, old: QueueCost, new: QueueCost
    ) -> Optional[str]:
        if replacement_would_exceed_limit(
                self._pending_control_bytes,
                old.pending_control,
                new.pending_control,
                self.limits.pending_control_max_bytes,
        ):
            return PENDING_CONTROL_BUDGET_MESSAGE
        if replacement_would_exceed_limit(
                self._pending_priority_bytes,
                old.pending_priority,
                new.pending_priority,
                self.limits.pending_priority_max_bytes,
        ):
            return PENDING_PRIORITY_BUDGET_MESSAGE
        return None

    def _raise_capacity_error(
            self,
            old: Optional[QueueCost],
            new: QueueCost,
            *,
            replacement: bool,
            urgent_block: bool,
            queue_block: bool,
    ) -> None:
        if queue_block:
            raise _internal_queue_error(WRITER_QUEUE_FULL_MESSAGE)
        if urgent_block:
            raise _internal_queue_error(URGENT_WRITER_QUEUE_FULL_MESSAGE)
        pending = (
            self._replacement_pending_capacity_error(old or QueueCost(), new)
            if replacement
            else self._pending_capacity_error(new)
        )
        if pending is not None:
            raise _internal_queue_error(pending)
        raise _internal_queue_error(QUEUED_DATA_HWM_MESSAGE)

    def _apply_cost_add(self, cost: QueueCost) -> None:
        self._queued_bytes = _saturating_add(self._queued_bytes, cost.queued)
        self._urgent_queued_bytes = _saturating_add(
            self._urgent_queued_bytes, cost.urgent
        )
        self._pending_control_bytes = _saturating_add(
            self._pending_control_bytes, cost.pending_control
        )
        self._pending_priority_bytes = _saturating_add(
            self._pending_priority_bytes, cost.pending_priority
        )
        self._data_queued_bytes = _saturating_add(
            self._data_queued_bytes, cost.data.total
        )
        for stream_id, count in cost.data.items():
            self._data_queued_by_stream[stream_id] = _saturating_add(
                self._data_queued_by_stream.get(stream_id, 0), count
            )

    def _apply_cost_remove(self, cost: QueueCost) -> None:
        self._queued_bytes = max(0, self._queued_bytes - cost.queued)
        self._urgent_queued_bytes = max(0, self._urgent_queued_bytes - cost.urgent)
        self._pending_control_bytes = max(0, self._pending_control_bytes - cost.pending_control)
        self._pending_priority_bytes = max(0, self._pending_priority_bytes - cost.pending_priority)
        self._data_queued_bytes = max(0, self._data_queued_bytes - cost.data.total)
        for stream_id, count in cost.data.items():
            remaining = max(0, self._data_queued_by_stream.get(stream_id, 0) - count)
            if remaining:
                self._data_queued_by_stream[stream_id] = remaining
            else:
                self._data_queued_by_stream.pop(stream_id, None)


__all__ = ("WriteQueue",)
