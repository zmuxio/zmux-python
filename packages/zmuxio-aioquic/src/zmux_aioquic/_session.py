"""Session wrapper for aioquic-like connection objects."""

from __future__ import annotations

import asyncio
import threading
import time
import weakref
from typing import Optional, Set, Tuple
from zmux.config import OpenOptions
from zmux.conformance import SUITE_STREAM_ADAPTER_PROFILE
from zmux.errors import (
    AcceptTimeout,
    AdapterUnsupported,
    ApplicationError,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    OpenTimeout,
    SessionClosed,
    SessionWaitTimeout,
    TerminationKind,
)
from zmux.preface import Negotiated, Preface
from zmux.protocol import CLAIM_STREAM_ADAPTER_PROFILE_V1, ErrorCode
from zmux.session import (
    AsyncSession,
    ReasonStats,
    SessionState,
    SessionStats,
    as_async_session,
)
from zmux.streams import ReadableBuffer

from ._constants import ACCEPTED_PRELUDE_RESULT_QUEUE_CAP
from ._errors import (
    _accepted_prelude_rejectable,
    _is_stream_limit_error,
    _translate_wait_error,
    translate_error,
    translate_open_error,
)
from ._io import (
    _acquire_lock,
    _addr,
    _await_with_timeout,
    _best_effort,
    _close_connection,
    _connection_closed,
    _connection_stream_reader,
    _connection_stream_readers,
    _cancel_write,
    _consume_task_exception,
    _discard_accepted_stream,
    _discard_local_open_stream,
    _fail_reader,
    _first_callable,
    _first_callable_result,
    _maybe_await,
    _queue_wait,
    _reader_saw_fin,
    _remaining_timeout,
    _reserve_local_stream_id,
    _retire_writer,
    _split_stream_result,
    _stream_id,
    _stream_id_or_none,
)
from ._options import (
    SessionOptions,
    normalize_accepted_prelude_max_concurrent,
    normalize_accepted_prelude_read_timeout,
)
from ._prelude import build_stream_prelude, read_stream_prelude
from ._state import _empty_negotiated, _empty_preface, _sat_add
from ._stats import _ActiveCounters, _ActiveKind, _ReasonCounter
from ._stream import AioquicRecvStream, AioquicSendStream, AioquicStream
from ._validation import (
    _normalize_open_options,
    _reason_text,
    _require_application_code,
    _wait_timeout,
)


def wrap_session(
        connection: Optional[object], options: Optional[SessionOptions] = None
) -> AsyncSession:
    """Wrap an aioquic-like connection behind the zmux async session API."""

    if connection is None:
        return as_async_session(None)
    return AioquicSession(connection, options)


def target_claims() -> Tuple[str, ...]:
    return (CLAIM_STREAM_ADAPTER_PROFILE_V1,)


def target_implementation_profiles() -> Tuple[str, ...]:
    return ()


def target_suites() -> Tuple[str, ...]:
    return (SUITE_STREAM_ADAPTER_PROFILE,)


def _quic_stream_is_bidirectional(stream_id: int) -> bool:
    # RFC 9000 2.1: bit 0x2 of a QUIC stream ID marks a unidirectional stream.
    return not stream_id & 0x2


def _open_error_cleanup_code(error: BaseException) -> int:
    code = getattr(error, "numeric_code", None)
    if code is None:
        return int(ErrorCode.CANCELLED)
    try:
        return _require_application_code(code)
    except (TypeError, ValueError):
        return int(ErrorCode.CANCELLED)


class AioquicSession(object):
    """Async zmux session facade for an aioquic-like connection."""

    def __init__(
            self, connection: object, options: Optional[SessionOptions] = None
    ) -> None:
        self._connection = connection
        self._options = options or SessionOptions()
        self._accepted_timeout = normalize_accepted_prelude_read_timeout(
            self._options.accepted_prelude_read_timeout
        )
        self._prepare_sem = asyncio.Semaphore(
            normalize_accepted_prelude_max_concurrent(
                self._options.accepted_prelude_max_concurrent
            )
        )
        self._bidi_queue: asyncio.Queue[object] = asyncio.Queue(
            ACCEPTED_PRELUDE_RESULT_QUEUE_CAP
        )
        self._uni_queue: asyncio.Queue[object] = asyncio.Queue(
            ACCEPTED_PRELUDE_RESULT_QUEUE_CAP
        )
        self._closed_event = asyncio.Event()
        self._lock = threading.RLock()
        self._state = SessionState.READY
        self._close_error: Optional[BaseException] = None
        self._open_streams = 0
        self._accepted_streams = 0
        self._sent_data_bytes = 0
        self._received_data_bytes = 0
        self._active = _ActiveCounters()
        self._reset_reasons = _ReasonCounter()
        self._abort_reasons = _ReasonCounter()
        self._direct_bidi_accept_started = False
        self._direct_uni_accept_started = False
        self._accept_tasks: Set["asyncio.Task[None]"] = set()
        self._prepare_tasks: Set["asyncio.Task[None]"] = set()
        self._create_lock = asyncio.Lock()
        self._peer_closed = False
        self._streams_by_id: "weakref.WeakValueDictionary[int, object]" = (
            weakref.WeakValueDictionary()
        )
        self._event_hook_installed = self._install_quic_event_hook()

    async def __aenter__(self) -> "AioquicSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def accept_stream(self, timeout: Optional[float] = None) -> "AioquicStream":
        self._check_open(ErrorOperation.ACCEPT)
        self._ensure_direct_accept_loop(True)
        return await self._accept_from_queue(  # type: ignore[return-value]
            self._bidi_queue, timeout
        )

    async def accept_uni_stream(
            self, timeout: Optional[float] = None
    ) -> "AioquicRecvStream":
        self._check_open(ErrorOperation.ACCEPT)
        self._ensure_direct_accept_loop(False)
        return await self._accept_from_queue(  # type: ignore[return-value]
            self._uni_queue, timeout
        )

    async def open_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> "AioquicStream":
        self._check_open(ErrorOperation.OPEN)
        options = _normalize_open_options(options)
        # Validate open metadata before any QUIC stream becomes peer-visible.
        prelude = build_stream_prelude(options)
        start = time.monotonic()
        reader, writer = await self._create_stream(True, timeout)
        stream_id = _stream_id(writer, reader)
        stream = AioquicStream.local(self, reader, writer, stream_id, options, prelude)
        self._register_stream(stream)
        try:
            await stream.send_open_prelude_on_open(
                timeout=_remaining_timeout(start, timeout)
            )
        except asyncio.CancelledError:
            await _discard_local_open_stream(
                self._connection, reader, writer, stream_id, True
            )
            raise
        except Exception:
            await _discard_local_open_stream(
                self._connection, reader, writer, stream_id, True
            )
            raise
        self._note_open(True)
        return stream

    async def open_uni_stream(
            self, options: Optional[OpenOptions] = None, *, timeout: Optional[float] = None
    ) -> "AioquicSendStream":
        self._check_open(ErrorOperation.OPEN)
        options = _normalize_open_options(options)
        # Validate open metadata before any QUIC stream becomes peer-visible.
        prelude = build_stream_prelude(options)
        start = time.monotonic()
        reader, writer = await self._create_stream(False, timeout)
        stream_id = _stream_id(writer, reader)
        stream = AioquicSendStream.local(self, writer, stream_id, options, prelude)
        self._register_stream(stream)
        try:
            await stream.send_open_prelude_on_open(
                timeout=_remaining_timeout(start, timeout)
            )
        except asyncio.CancelledError:
            await _discard_local_open_stream(
                self._connection, reader, writer, stream_id, False
            )
            raise
        except Exception:
            await _discard_local_open_stream(
                self._connection, reader, writer, stream_id, False
            )
            raise
        self._note_open(False)
        return stream

    async def open_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> "AioquicStream":
        start = time.monotonic()
        stream = await self.open_stream(options, timeout=timeout)
        try:
            remaining = _remaining_timeout(start, timeout)
            await stream.write_all(data, timeout=remaining)
        except asyncio.CancelledError:
            await _best_effort(
                stream.close_with_error(ErrorCode.CANCELLED, "open payload cancelled")
            )
            raise
        except Exception as exc:
            code = _open_error_cleanup_code(exc)
            await _best_effort(
                stream.close_with_error(
                    code, "open_and_send failed"
                )
            )
            await _best_effort(
                _cancel_write(self._connection, stream._writer, stream.stream_id, code)
            )
            raise
        return stream

    async def open_uni_and_send(
            self,
            data: ReadableBuffer,
            options: Optional[OpenOptions] = None,
            *,
            timeout: Optional[float] = None,
    ) -> "AioquicSendStream":
        start = time.monotonic()
        stream = await self.open_uni_stream(options, timeout=timeout)
        try:
            remaining = _remaining_timeout(start, timeout)
            await stream.write_final(data, timeout=remaining)
        except asyncio.CancelledError:
            await _best_effort(
                stream.close_with_error(ErrorCode.CANCELLED, "open payload cancelled")
            )
            raise
        except Exception as exc:
            code = _open_error_cleanup_code(exc)
            await _best_effort(
                stream.close_with_error(
                    code, "open_uni_and_send failed"
                )
            )
            await _best_effort(
                _cancel_write(self._connection, stream._writer, stream.stream_id, code)
            )
            raise
        return stream

    async def add_incoming_stream(
            self,
            reader: object,
            writer: Optional[object] = None,
            stream_id: Optional[int] = None,
            bidirectional: Optional[bool] = None,
    ) -> None:
        """Prepare and enqueue an incoming QUIC stream.

        This is useful with aioquic stream-handler callbacks. The method reads
        the adapter prelude under the session's concurrency bound before making
        the stream visible to ``accept_*`` callers.

        ``stream_id`` defaults to the writer's or reader's backend stream ID
        (aioquic: ``writer.get_extra_info("stream_id")``) and ``bidirectional``
        defaults to the QUIC stream type encoded in that ID. aioquic hands a
        writer to the callback even for peer unidirectional streams; that
        writer is never used.
        """

        if stream_id is None:
            stream_id = _stream_id_or_none(writer, reader)
        known_id = (
            stream_id
            if isinstance(stream_id, int) and not isinstance(stream_id, bool)
            else None
        )
        id_bidirectional = (
            None if known_id is None else _quic_stream_is_bidirectional(known_id)
        )
        if id_bidirectional is False:
            # The send half of a peer unidirectional stream does not exist.
            _retire_writer(writer)
        if bidirectional is None:
            bidirectional = (
                bool(writer is not None) if id_bidirectional is None else id_bidirectional
            )
        elif id_bidirectional is not None and bool(bidirectional) != id_bidirectional:
            raise AdapterUnsupported(
                "zmux: QUIC stream %d is not %s"
                % (known_id, "bidirectional" if bidirectional else "unidirectional")
            )
        if not bidirectional:
            _retire_writer(writer)
            writer = None
        self._check_open(ErrorOperation.ACCEPT)
        async with self._prepare_sem:
            prepared = False
            try:
                stream = await self._prepare_accepted_stream(
                    reader, writer, stream_id, bidirectional
                )
                prepared = True
                if self._closed_event.is_set():
                    raise SessionClosed(
                        operation=ErrorOperation.ACCEPT, source=ErrorSource.LOCAL
                    )
                queue = self._bidi_queue if bidirectional else self._uni_queue
                if not await self._put_accept_item(queue, stream):
                    raise SessionClosed(
                        operation=ErrorOperation.ACCEPT, source=ErrorSource.LOCAL
                    )
                self._note_accepted(bidirectional)
            except asyncio.CancelledError:
                await self._discard_accepted(
                    reader, writer, known_id, bidirectional, ErrorCode.CANCELLED
                )
                raise
            except Exception:
                code = ErrorCode.CANCELLED if prepared else ErrorCode.PROTOCOL
                await self._discard_accepted(
                    reader, writer, known_id, bidirectional, code
                )
                raise

    def queue_incoming_stream(
            self,
            reader: object,
            writer: Optional[object] = None,
            stream_id: Optional[int] = None,
            bidirectional: Optional[bool] = None,
    ) -> "asyncio.Task[None]":
        loop = asyncio.get_running_loop()
        task = loop.create_task(
            self.add_incoming_stream(reader, writer, stream_id, bidirectional)
        )
        self._track_prepare_task(task)
        return task

    async def ping(self, echo: bytes = b"", *, timeout: Optional[float] = None) -> float:
        raise AdapterUnsupported("zmux: aioquic adapter does not expose native zmux ping")

    async def go_away(
            self,
            last_accepted_bidi: int,
            last_accepted_uni: int,
            code: int = 0,
            reason: str = "",
    ) -> None:
        raise AdapterUnsupported("zmux: aioquic adapter does not expose native zmux go_away")

    async def close(self) -> None:
        await self.close_with_error(0, "")

    async def close_with_error(self, code: int, reason: str = "") -> None:
        code = _require_application_code(code)
        reason = _reason_text(reason)
        already_closed = False
        with self._lock:
            if self._state.terminal():
                already_closed = True
            else:
                self._state = SessionState.CLOSED if code == 0 else SessionState.FAILED
                self._close_error = None if code == 0 else ApplicationError(code, reason)
                if code != 0:
                    self._abort_reasons.note(code)
        if already_closed:
            self._cancel_background_tasks()
            await self._drain_background_tasks()
            return
        self._closed_event.set()
        self._cancel_background_tasks()
        await _close_connection(self._connection, code, reason)
        self._fail_unfinished_streams(self._terminated_error(ErrorOperation.READ))
        await self._drain_background_tasks()

    async def wait(self, timeout: Optional[float] = None) -> None:
        timeout = _wait_timeout(timeout)
        waitable = _first_callable_result(self._connection, ("wait_closed", "wait"))
        if waitable is not None:
            try:
                await _await_with_timeout(waitable, timeout)
                self._mark_closed_after_wait()
                await self._drain_background_tasks()
            except asyncio.TimeoutError:
                raise SessionWaitTimeout()
            except Exception as exc:
                translated = _translate_wait_error(exc)
                if translated is None:
                    self._mark_closed_after_wait()
                    await self._drain_background_tasks()
                    return
                with self._lock:
                    if not self._state.terminal():
                        # Not closed locally: the backend saw a peer or
                        # transport close.
                        self._peer_closed = True
                self._fail(translated)
                await self._drain_background_tasks()
                raise translated
        else:
            await _queue_wait(
                self._closed_event.wait(),
                timeout,
                SessionWaitTimeout(),
            )
            self._cancel_background_tasks()
            await self._drain_background_tasks()
        self._raise_wait_error_if_failed()

    async def wait_timeout(self, timeout: Optional[float] = None) -> bool:
        try:
            await self.wait(timeout)
        except SessionWaitTimeout:
            return False
        return True

    @property
    def closed(self) -> bool:
        return self._state.terminal() or _connection_closed(self._connection)

    @property
    def local_addr(self) -> Optional[object]:
        return self._options.local_addr or _addr(
            self._connection, ("local_addr", "local_address")
        )

    @property
    def remote_addr(self) -> Optional[object]:
        return self._options.remote_addr or _addr(
            self._connection, ("remote_addr", "remote_address", "peer_addr")
        )

    @property
    def peer_addr(self) -> Optional[object]:
        return self.remote_addr

    @property
    def close_error(self) -> Optional[BaseException]:
        return self._close_error

    @property
    def state(self) -> SessionState:
        if self._state.terminal():
            return self._state
        return SessionState.CLOSED if _connection_closed(self._connection) else self._state

    @property
    def stats(self) -> SessionStats:
        with self._lock:
            reset_reasons, reset_overflow = self._reset_reasons.snapshot()
            abort_reasons, abort_overflow = self._abort_reasons.snapshot()
            state = self.state
            sent_data_bytes = self._sent_data_bytes
            received_data_bytes = self._received_data_bytes
            open_streams = self._open_streams
            accepted_streams = self._accepted_streams
            active_streams = self._active.snapshot()
        return SessionStats(
            state=state,
            sent_data_bytes=sent_data_bytes,
            received_data_bytes=received_data_bytes,
            open_streams=open_streams,
            accepted_streams=accepted_streams,
            active_streams=active_streams,
            reasons=ReasonStats(
                reset=reset_reasons,
                reset_overflow=reset_overflow,
                abort=abort_reasons,
                abort_overflow=abort_overflow,
            )
        )

    @property
    def peer_go_away_error(self) -> Optional[ApplicationError]:
        return None

    @property
    def peer_close_error(self) -> Optional[ApplicationError]:
        if not self._peer_closed:
            return None
        err = self._close_error
        return err if isinstance(err, ApplicationError) else None

    @staticmethod
    def local_preface() -> Preface:
        return _empty_preface()

    @staticmethod
    def peer_preface() -> Preface:
        return _empty_preface()

    @staticmethod
    def negotiated() -> Negotiated:
        return _empty_negotiated()

    @property
    def connection(self) -> object:
        return self._connection

    def finish_stream(self, kind: "_ActiveKind") -> None:
        self._finish_stream(kind)

    def note_sent(self, size: int) -> None:
        self._note_sent(size)

    def note_received(self, size: int) -> None:
        self._note_received(size)

    def note_reset(self, code: int) -> None:
        self._note_reset(code)

    def note_abort(self, code: int) -> None:
        self._note_abort(code)

    async def _create_stream(
            self, bidirectional: bool, timeout: Optional[float]
    ) -> Tuple[Optional[object], object]:
        timeout = _wait_timeout(timeout)
        method = _first_callable(
            self._connection,
            (
                "create_stream",
                "open_stream",
                "create_bidirectional_stream" if bidirectional else "create_unidirectional_stream",
                "open_bidirectional_stream" if bidirectional else "open_unidirectional_stream",
            ),
        )
        if method is None:
            raise AdapterUnsupported("zmux: aioquic connection cannot create streams")
        start = time.monotonic()
        # Stream creation and local ID reservation are serialized so concurrent
        # opens can never be handed the same not-yet-used aioquic stream ID.
        await _acquire_lock(self._create_lock, timeout, OpenTimeout)
        try:
            if method.__name__ in ("create_stream", "open_stream"):
                result = method(is_unidirectional=not bidirectional)
            else:
                result = method()
            result = await _await_with_timeout(
                result, _remaining_timeout(start, timeout)
            )
            reader, writer = _split_stream_result(result, bidirectional)
            _reserve_local_stream_id(
                self._connection, _stream_id_or_none(writer, reader)
            )
            return reader, writer
        except asyncio.TimeoutError:
            raise OpenTimeout()
        except Exception as exc:
            raise translate_open_error(exc)
        finally:
            self._create_lock.release()

    async def _accept_from_queue(
            self, queue: "asyncio.Queue[object]", timeout: Optional[float]
    ) -> object:
        start = time.monotonic()
        while True:
            self._check_open(ErrorOperation.ACCEPT)
            item = await self._queue_get_or_closed(
                queue, _remaining_timeout(start, timeout)
            )
            if isinstance(item, BaseException):
                if _accepted_prelude_rejectable(item):
                    continue
                raise item
            return item

    async def _queue_get_or_closed(
            self, queue: "asyncio.Queue[object]", timeout: Optional[float]
    ) -> object:
        get_task = asyncio.create_task(queue.get())
        close_task = asyncio.create_task(self._closed_event.wait())
        tasks = {get_task, close_task}
        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=_wait_timeout(timeout),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise AcceptTimeout()
            if get_task in done:
                return get_task.result()
            raise SessionClosed(operation=ErrorOperation.ACCEPT, source=ErrorSource.LOCAL)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def _direct_accept_method(self, bidirectional: bool) -> Optional[object]:
        method = _first_callable(
            self._connection,
            (
                "accept_stream" if bidirectional else "accept_uni_stream",
                "accept_bidirectional_stream"
                if bidirectional
                else "accept_unidirectional_stream",
            ),
        )
        return method

    def _ensure_direct_accept_loop(self, bidirectional: bool) -> None:
        if (
                self._direct_accept_method(bidirectional) is None
                or self._closed_event.is_set()
        ):
            return
        with self._lock:
            if bidirectional:
                if self._direct_bidi_accept_started:
                    return
                self._direct_bidi_accept_started = True
            else:
                if self._direct_uni_accept_started:
                    return
                self._direct_uni_accept_started = True
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._direct_accept_loop(bidirectional))
        self._track_accept_task(task)

    async def _direct_accept_loop(self, bidirectional: bool) -> None:
        queue = self._bidi_queue if bidirectional else self._uni_queue
        method = self._direct_accept_method(bidirectional)
        if method is None:
            return
        try:
            while not self._closed_event.is_set():
                try:
                    result = await _maybe_await(method())
                    reader, writer = _split_stream_result(result, bidirectional)
                    stream_id = _stream_id(writer, reader)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    translated = (
                        translate_open_error(exc)
                        if _is_stream_limit_error(exc)
                        else translate_error(exc)
                    )
                    await self._publish_accept_error(queue, translated)
                    return

                try:
                    await self._prepare_sem.acquire()
                except asyncio.CancelledError:
                    await self._discard_accepted(
                        reader, writer, stream_id, bidirectional
                    )
                    raise
                if self._closed_event.is_set():
                    self._prepare_sem.release()
                    await self._discard_accepted(
                        reader, writer, stream_id, bidirectional
                    )
                    return

                loop = asyncio.get_running_loop()
                task = loop.create_task(
                    self._prepare_direct_accepted_stream(
                        queue, reader, writer, stream_id, bidirectional
                    )
                )
                self._track_prepare_task(task)
        finally:
            with self._lock:
                if bidirectional:
                    self._direct_bidi_accept_started = False
                else:
                    self._direct_uni_accept_started = False

    async def _prepare_direct_accepted_stream(
            self,
            queue: "asyncio.Queue[object]",
            reader: object,
            writer: Optional[object],
            stream_id: int,
            bidirectional: bool,
    ) -> None:
        try:
            stream = await self._prepare_accepted_stream(
                reader, writer, stream_id, bidirectional
            )
            if self._closed_event.is_set():
                await self._discard_accepted(reader, writer, stream_id, bidirectional)
                return
            if not await self._put_accept_item(queue, stream):
                await self._discard_accepted(reader, writer, stream_id, bidirectional)
                return
            self._note_accepted(bidirectional)
        except asyncio.CancelledError:
            await self._discard_accepted(reader, writer, stream_id, bidirectional)
            raise
        except Exception as exc:
            await self._discard_accepted(
                reader, writer, stream_id, bidirectional, ErrorCode.PROTOCOL
            )
            if not _accepted_prelude_rejectable(exc):
                await self._publish_accept_error(queue, translate_error(exc))
        finally:
            self._prepare_sem.release()

    async def _prepare_accepted_stream(
            self,
            reader: object,
            writer: Optional[object],
            stream_id: Optional[int],
            bidirectional: bool,
    ) -> object:
        meta = await read_stream_prelude(reader, self._accepted_timeout)
        if bidirectional:
            stream = AioquicStream.accepted(self, reader, writer, stream_id, meta)
        else:
            stream = AioquicRecvStream.accepted(self, reader, stream_id, meta)
        self._register_stream(stream)
        return stream

    async def _discard_accepted(
            self,
            reader: object,
            writer: Optional[object],
            stream_id: Optional[int],
            bidirectional: bool,
            code: int = ErrorCode.CANCELLED,
    ) -> None:
        await _discard_accepted_stream(
            reader,
            writer,
            code,
            connection=self._connection,
            stream_id=stream_id,
            bidirectional=bidirectional,
        )

    async def _publish_accept_error(
            self, queue: "asyncio.Queue[object]", error: BaseException
    ) -> None:
        await self._put_accept_item(queue, error)

    async def _put_accept_item(
            self, queue: "asyncio.Queue[object]", item: object
    ) -> bool:
        if self._closed_event.is_set():
            return False
        put_task = asyncio.create_task(queue.put(item))
        close_task = asyncio.create_task(self._closed_event.wait())
        tasks = {put_task, close_task}
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if put_task in done:
                return True
            return False
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def _track_accept_task(self, task: "asyncio.Task[None]") -> None:
        self._accept_tasks.add(task)

        def done(done_task: "asyncio.Task[None]") -> None:
            self._accept_tasks.discard(done_task)
            _consume_task_exception(done_task)

        task.add_done_callback(done)

    def _track_prepare_task(self, task: "asyncio.Task[None]") -> None:
        self._prepare_tasks.add(task)

        def done(done_task: "asyncio.Task[None]") -> None:
            self._prepare_tasks.discard(done_task)
            _consume_task_exception(done_task)

        task.add_done_callback(done)

    def _cancel_background_tasks(self) -> None:
        current = asyncio.current_task()
        for task in tuple(self._accept_tasks) + tuple(self._prepare_tasks):
            if task is not current:
                task.cancel()

    async def _drain_background_tasks(self) -> None:
        current = asyncio.current_task()
        tasks = [
            task
            for task in tuple(self._accept_tasks) + tuple(self._prepare_tasks)
            if task is not current
        ]
        if not tasks:
            return
        await asyncio.gather(*tasks, return_exceptions=True)

    def _mark_closed_after_wait(self) -> None:
        with self._lock:
            if not self._state.terminal():
                self._state = SessionState.CLOSED
        self._closed_event.set()
        self._cancel_background_tasks()

    def _check_open(self, operation: ErrorOperation) -> None:
        if self.closed:
            raise SessionClosed(operation=operation, source=ErrorSource.LOCAL)

    def _note_open(self, bidirectional: bool) -> None:
        with self._lock:
            self._open_streams = _sat_add(self._open_streams, 1)
            self._active.add(_ActiveKind.LOCAL_BIDI if bidirectional else _ActiveKind.LOCAL_UNI)

    def _note_accepted(self, bidirectional: bool) -> None:
        with self._lock:
            self._accepted_streams = _sat_add(self._accepted_streams, 1)
            self._active.add(_ActiveKind.PEER_BIDI if bidirectional else _ActiveKind.PEER_UNI)

    def _finish_stream(self, kind: "_ActiveKind") -> None:
        with self._lock:
            self._active.done(kind)

    def _note_sent(self, size: int) -> None:
        with self._lock:
            self._sent_data_bytes = _sat_add(self._sent_data_bytes, size)

    def _note_received(self, size: int) -> None:
        with self._lock:
            self._received_data_bytes = _sat_add(self._received_data_bytes, size)

    def _note_reset(self, code: int) -> None:
        with self._lock:
            self._reset_reasons.note(code)

    def _note_abort(self, code: int) -> None:
        with self._lock:
            self._abort_reasons.note(code)

    def _fail(self, error: BaseException) -> None:
        with self._lock:
            self._state = SessionState.FAILED
            self._close_error = error
        self._closed_event.set()
        self._cancel_background_tasks()

    def _raise_wait_error_if_failed(self) -> None:
        with self._lock:
            failed = self._state == SessionState.FAILED
            error = self._close_error
        if failed and error is not None:
            raise error

    def _terminated_error(self, operation: ErrorOperation) -> Optional[BaseException]:
        """Return the error stream I/O reports after session termination."""

        if not self.closed:
            return None
        with self._lock:
            error = self._close_error
            peer_closed = self._peer_closed
        if isinstance(error, ApplicationError):
            error = error.clone()
            error.with_operation(operation)
            return error
        if isinstance(error, SessionClosed):
            return SessionClosed(
                str(error),
                operation=operation,
                source=error.source,
                termination_kind=TerminationKind.SESSION_TERMINATION,
            )
        return SessionClosed(
            operation=operation,
            source=ErrorSource.REMOTE if peer_closed else ErrorSource.LOCAL,
            termination_kind=TerminationKind.SESSION_TERMINATION,
        )

    def _register_stream(self, stream: object) -> None:
        if self._event_hook_installed:
            self._streams_by_id[stream.stream_id] = stream  # type: ignore[attr-defined]

    def _install_quic_event_hook(self) -> bool:
        """Observe aioquic stream and connection terminal events.

        aioquic's stock QuicConnectionProtocol ignores StreamReset and
        StopSendingReceived and only feeds EOF to stream readers when the
        connection terminates, so peer codes would otherwise be lost and
        truncated streams would look complete. ``_process_events`` dispatches
        through ``self.quic_event_received``, so a per-instance wrapper sees
        every event before the original handler runs.
        """

        connection = self._connection
        original = getattr(connection, "quic_event_received", None)
        if not callable(original) or getattr(connection, "_quic", None) is None:
            return False
        session_ref = weakref.ref(self)

        def quic_event_received(event: object) -> object:
            session = session_ref()
            if session is not None:
                session._observe_quic_event(event)
            return original(event)

        try:
            connection.quic_event_received = quic_event_received  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            return False
        return True

    def _observe_quic_event(self, event: object) -> None:
        try:
            self._handle_quic_event(event)
        except Exception:
            # Never break the backend's event processing loop.
            return

    def _handle_quic_event(self, event: object) -> None:
        name = event.__class__.__name__
        if name == "StreamReset":
            self._on_peer_stream_reset(
                int(event.stream_id), int(event.error_code)  # type: ignore[attr-defined]
            )
        elif name == "StopSendingReceived":
            self._on_peer_stop_sending(
                int(event.stream_id), int(event.error_code)  # type: ignore[attr-defined]
            )
        elif name == "ConnectionTerminated":
            self._on_connection_terminated(
                int(getattr(event, "error_code", 0) or 0),
                getattr(event, "frame_type", None),
                str(getattr(event, "reason_phrase", "") or ""),
            )

    def _on_peer_stream_reset(self, stream_id: int, code: int) -> None:
        reader = _connection_stream_reader(self._connection, stream_id)
        if reader is None:
            return
        _fail_reader(
            reader,
            ApplicationError(
                code,
                scope=ErrorScope.STREAM,
                operation=ErrorOperation.READ,
                source=ErrorSource.REMOTE,
                direction=ErrorDirection.READ,
                termination_kind=TerminationKind.RESET,
            ),
        )

    def _on_peer_stop_sending(self, stream_id: int, code: int) -> None:
        stream = self._streams_by_id.get(stream_id)
        if stream is not None:
            stream._note_peer_stop_sending(code)  # type: ignore[attr-defined]

    def _on_connection_terminated(
            self, code: int, frame_type: Optional[int], reason: str
    ) -> None:
        with self._lock:
            already_terminal = self._state.terminal()
            if not already_terminal and frame_type is None:
                # An application CONNECTION_CLOSE the session did not send.
                self._peer_closed = True
        if not already_terminal:
            if frame_type is None and code == 0 and not reason:
                with self._lock:
                    self._state = SessionState.CLOSED
                self._closed_event.set()
                self._cancel_background_tasks()
            elif frame_type is None:
                self._fail(
                    ApplicationError(
                        code,
                        reason,
                        scope=ErrorScope.SESSION,
                        operation=ErrorOperation.CLOSE,
                        source=ErrorSource.REMOTE,
                        termination_kind=TerminationKind.SESSION_TERMINATION,
                    )
                )
            else:
                detail = reason or "transport error"
                self._fail(
                    SessionClosed(
                        "zmux: QUIC connection terminated: %s (0x%x)" % (detail, code),
                        scope=ErrorScope.SESSION,
                        operation=ErrorOperation.CLOSE,
                        source=ErrorSource.TRANSPORT,
                        termination_kind=TerminationKind.SESSION_TERMINATION,
                    )
                )
        self._fail_unfinished_streams(self._terminated_error(ErrorOperation.READ))

    def _fail_unfinished_streams(self, error: Optional[BaseException]) -> None:
        # Receive halves without a peer FIN must not report graceful EOF when
        # the connection ends; aioquic itself only feeds EOF to every reader.
        if error is None:
            return
        for reader in _connection_stream_readers(self._connection):
            if not _reader_saw_fin(reader):
                _fail_reader(reader, error)
        # No FIN can follow a closed connection; keep writers from trying.
        for stream in tuple(self._streams_by_id.values()):
            _retire_writer(getattr(stream, "_writer", None))
