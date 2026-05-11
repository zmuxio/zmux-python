"""Async stream wrappers for aioquic-like streams."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from types import TracebackType
from typing import Optional, Tuple

from zmux.config import OpenOptions
from zmux.errors import (
    AdapterUnsupported,
    ApplicationError,
    EmptyMetadataUpdate,
    ErrorSource,
    PriorityUpdateUnavailable,
    ReadClosed,
    ReadTimeout,
    StreamNotReadable,
    StreamNotWritable,
    TerminationKind,
    WriteClosed,
    WriteTimeout,
)
from zmux.payload import MetadataUpdate, StreamMetadata
from zmux.protocol import ErrorCode
from ._constants import WRITEV_COALESCE_MAX_BYTES, _EMPTY_STREAM_PRELUDE
from ._errors import translate_read_error, translate_write_error
from ._io import (
    _await_with_timeout,
    _cancel_read,
    _cancel_write,
    _finish_writer,
    _operation_timeout,
    _read_some,
    _remaining_timeout,
    _write_all,
)
from ._prelude import AcceptedStreamMetadata, build_stream_prelude
from ._stats import _ActiveKind
from ._validation import (
    _deadline_from_timeout,
    _deadline_seconds,
    _memoryview,
    _memoryviews,
    _nonnegative_int,
    _normalize_open_options,
    _read_size,
    _remaining_deadline,
    _reason_text,
    _require_application_code,
    _require_bool,
    _stream_id_value,
    _writable_memoryview,
)


class _StreamBase:
    def __init__(
            self,
            session: AioquicSession,
            reader: Optional[object],
            writer: Optional[object],
            stream_id: Optional[int],
            opened_locally: bool,
            bidirectional: bool,
            active_kind: "_ActiveKind",
            options: Optional[OpenOptions] = None,
            accepted_metadata: Optional[AcceptedStreamMetadata] = None,
    ) -> None:
        self._session = session
        self._reader = reader
        self._writer = writer
        self._stream_id = _stream_id_value(stream_id)
        self._opened_locally = _require_bool(opened_locally, "opened_locally")
        self._bidirectional = _require_bool(bidirectional, "bidirectional")
        self._active_kind = active_kind
        self._active_finished = False
        self._lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._write_operation_lock = asyncio.Lock()
        self._read_closed = reader is None
        self._write_closed = writer is None
        self._read_error: Optional[BaseException] = None
        self._write_error: Optional[BaseException] = None
        self._prelude_sent = not opened_locally
        self._prelude: Optional[bytes] = None
        self._prelude_offset = 0
        self._prelude_frozen = False
        self._deadline: Optional[float] = None
        self._read_deadline: Optional[float] = None
        self._write_deadline: Optional[float] = None
        if opened_locally:
            options = _normalize_open_options(options)
            self._options = options
            self._metadata = StreamMetadata(
                options.initial_priority, options.initial_group, options.open_info
            )
            self._metadata_valid = True
        else:
            meta = accepted_metadata or AcceptedStreamMetadata()
            self._options = OpenOptions()
            self._metadata = meta.metadata
            self._metadata_valid = meta.metadata_valid

    async def __aenter__(self) -> "_StreamBase":
        return self

    async def __aexit__(
            self,
            exc_type: Optional[type[BaseException]],
            exc: Optional[BaseException],
            tb: Optional[TracebackType],
    ) -> None:
        await self.close()

    @property
    def stream_id(self) -> int:
        return self._stream_id

    @property
    def opened_locally(self) -> bool:
        return self._opened_locally

    @property
    def bidirectional(self) -> bool:
        return self._bidirectional

    @property
    def open_info(self) -> bytes:
        return self._metadata.open_info

    @property
    def metadata(self) -> StreamMetadata:
        return StreamMetadata(
            self._metadata.priority, self._metadata.group, self._metadata.open_info
        )

    @property
    def local_addr(self) -> Optional[object]:
        return self._session.local_addr

    @property
    def remote_addr(self) -> Optional[object]:
        return self._session.remote_addr

    def set_deadline(self, deadline: Optional[float]) -> None:
        self._deadline = _deadline_seconds(deadline, "deadline")

    def set_timeout(self, timeout: Optional[float]) -> None:
        self._deadline = _deadline_from_timeout(timeout, "timeout")

    def set_read_deadline(self, deadline: Optional[float]) -> None:
        self._read_deadline = _deadline_seconds(deadline, "read deadline")

    def set_read_timeout(self, timeout: Optional[float]) -> None:
        self._read_deadline = _deadline_from_timeout(timeout, "read timeout")

    def set_write_deadline(self, deadline: Optional[float]) -> None:
        self._write_deadline = _deadline_seconds(deadline, "write deadline")

    def set_write_timeout(self, timeout: Optional[float]) -> None:
        self._write_deadline = _deadline_from_timeout(timeout, "write timeout")

    async def close(self) -> None:
        error: Optional[BaseException] = None
        if self._writer is not None and not self._write_closed:
            try:
                await self.close_write()
            except Exception as exc:
                error = exc
        if self._reader is not None and not self._read_closed:
            try:
                await self.close_read()
            except Exception as exc:
                if error is None:
                    error = exc
        self._maybe_finish_active()
        if error is not None:
            raise error

    async def close_with_error(self, code: int, reason: str = "") -> None:
        code = _require_application_code(code)
        reason = _reason_text(reason)
        error = ApplicationError(code, reason)
        cancel_read = False
        cancel_write = False
        async with self._lock:
            if (self._reader is None or self._read_closed) and (
                    self._writer is None or self._write_closed
            ):
                return
            if self._reader is not None and not self._read_closed:
                self._read_closed = True
                self._read_error = error
                cancel_read = True
            if self._writer is not None and not self._write_closed:
                self._write_closed = True
                self._write_error = error
                cancel_write = True
        if cancel_read:
            await _cancel_read(
                self._session._connection,
                self._reader,
                self._writer,
                self._stream_id,
                code,
            )
        if cancel_write:
            await _cancel_write(
                self._session._connection, self._writer, self._stream_id, code
            )
        if cancel_read or cancel_write:
            self._session._note_abort(code)
        self._maybe_finish_active()

    @property
    def read_closed(self) -> bool:
        return self._read_closed

    @property
    def write_closed(self) -> bool:
        return self._write_closed

    async def read(
            self, max_bytes: int = -1, *, timeout: Optional[float] = None
    ) -> bytes:
        self._require_readable()
        max_bytes = _read_size(max_bytes)
        start = time.monotonic()
        timeout = _operation_timeout(
            start, timeout, _remaining_deadline(self._read_deadline, self._deadline)
        )
        try:
            data = await _read_some(self._reader, max_bytes, timeout)
        except asyncio.TimeoutError:
            raise ReadTimeout()
        except Exception as exc:
            translated = translate_read_error(exc)
            self._read_error = translated
            raise translated
        if data == b"":
            self._read_closed = True
            self._read_error = ReadClosed(
                source=ErrorSource.REMOTE,
                termination_kind=TerminationKind.GRACEFUL,
            )
            self._maybe_finish_active()
        else:
            self._session._note_received(len(data))
        return data

    async def readinto(
            self, buffer: object, *, timeout: Optional[float] = None
    ) -> int:
        view = _writable_memoryview(buffer)
        if len(view) == 0:
            return 0
        data = await self.read(len(view), timeout=timeout)
        size = len(data)
        if size:
            view[:size] = data
        return size

    async def read_exact(
            self, n: int, *, timeout: Optional[float] = None
    ) -> bytes:
        self._require_readable()
        n = _nonnegative_int(n, "read_exact length")
        chunks = bytearray()
        start = time.monotonic()
        while len(chunks) < n:
            remaining_timeout = _operation_timeout(
                start,
                timeout,
                _remaining_deadline(self._read_deadline, self._deadline),
            )
            try:
                chunk = await _read_some(
                    self._reader, n - len(chunks), remaining_timeout
                )
            except asyncio.TimeoutError:
                raise ReadTimeout()
            except Exception as exc:
                translated = translate_read_error(exc)
                self._read_error = translated
                raise translated
            if not chunk:
                self._read_closed = True
                self._maybe_finish_active()
                error = ReadClosed(
                    source=ErrorSource.REMOTE,
                    termination_kind=TerminationKind.GRACEFUL,
                )
                self._read_error = error
                raise error
            chunks.extend(chunk)
        self._session._note_received(len(chunks))
        return bytes(chunks)

    async def close_read(self) -> None:
        await self.cancel_read(ErrorCode.CANCELLED)

    async def cancel_read(self, code: int) -> None:
        self._require_readable()
        code = _require_application_code(code)
        if self._opened_locally and self._bidirectional:
            await self._ensure_open_prelude()
        async with self._lock:
            if self._read_closed:
                raise self._read_error or ReadClosed()
            self._read_closed = True
            self._read_error = ApplicationError(code)
        await _cancel_read(
            self._session._connection,
            self._reader,
            self._writer,
            self._stream_id,
            code,
        )
        self._maybe_finish_active()

    async def write(
            self, data: object, *, timeout: Optional[float] = None
    ) -> int:
        view = _memoryview(data)
        start = time.monotonic()
        await self._acquire_write_operation(start, timeout)
        try:
            return await self._write_unlocked(view, start, timeout)
        finally:
            self._write_operation_lock.release()

    async def _write_unlocked(
            self, view: memoryview, start: float, timeout: Optional[float]
    ) -> int:
        self._require_writable()
        if len(view) == 0:
            return 0
        await self._ensure_open_prelude(timeout=self._remaining_write_timeout(start, timeout))
        self._require_writable()
        await self._write_view(view, timeout=_remaining_timeout(start, timeout))
        self._session._note_sent(len(view))
        return len(view)

    async def write_all(
            self, data: object, *, timeout: Optional[float] = None
    ) -> None:
        await self.write(data, timeout=timeout)

    async def write_vectored(
            self, parts: Iterable[object], *, timeout: Optional[float] = None
    ) -> int:
        views, total = _memoryviews(parts)
        start = time.monotonic()
        await self._acquire_write_operation(start, timeout)
        try:
            return await self._write_vectored_unlocked(views, total, start, timeout)
        finally:
            self._write_operation_lock.release()

    async def _write_vectored_unlocked(
            self,
            views: Tuple[memoryview, ...],
            total: int,
            start: float,
            timeout: Optional[float],
    ) -> int:
        self._require_writable()
        if total == 0:
            return 0
        await self._ensure_open_prelude(timeout=self._remaining_write_timeout(start, timeout))
        self._require_writable()
        if total <= WRITEV_COALESCE_MAX_BYTES:
            payload = b"".join(views)
            await self._write_bytes(payload, timeout=_remaining_timeout(start, timeout))
        else:
            await self._write_views(views, timeout=_remaining_timeout(start, timeout))
        self._session._note_sent(total)
        return total

    async def write_final(
            self, data: object = b"", *, timeout: Optional[float] = None
    ) -> int:
        view = _memoryview(data)
        start = time.monotonic()
        await self._acquire_write_operation(start, timeout)
        try:
            return await self._write_final_unlocked(view, start, timeout)
        finally:
            self._write_operation_lock.release()

    async def _write_final_unlocked(
            self, view: memoryview, start: float, timeout: Optional[float]
    ) -> int:
        self._require_writable()
        await self._ensure_open_prelude(timeout=self._remaining_write_timeout(start, timeout))
        self._require_writable()
        written = 0
        if view:
            await self._write_view(view, timeout=_remaining_timeout(start, timeout))
            written = len(view)
            self._session._note_sent(written)
        await self._close_write_unlocked(start, timeout)
        return written

    async def write_vectored_final(
            self, parts: Iterable[object], *, timeout: Optional[float] = None
    ) -> int:
        views, total = _memoryviews(parts)
        start = time.monotonic()
        await self._acquire_write_operation(start, timeout)
        try:
            return await self._write_vectored_final_unlocked(views, total, start, timeout)
        finally:
            self._write_operation_lock.release()

    async def _write_vectored_final_unlocked(
            self,
            views: Tuple[memoryview, ...],
            total: int,
            start: float,
            timeout: Optional[float],
    ) -> int:
        self._require_writable()
        await self._ensure_open_prelude(timeout=self._remaining_write_timeout(start, timeout))
        self._require_writable()
        if total <= WRITEV_COALESCE_MAX_BYTES:
            payload = b"".join(views)
            if payload:
                await self._write_bytes(payload, timeout=_remaining_timeout(start, timeout))
        else:
            await self._write_views(views, timeout=_remaining_timeout(start, timeout))
        if total:
            self._session._note_sent(total)
        await self._close_write_unlocked(start, timeout)
        return total

    async def close_write(self, *, timeout: Optional[float] = None) -> None:
        start = time.monotonic()
        await self._acquire_write_operation(start, timeout)
        try:
            await self._close_write_unlocked(start, timeout)
        finally:
            self._write_operation_lock.release()

    async def _close_write_unlocked(
            self, start: float, timeout: Optional[float]
    ) -> None:
        self._require_writable()
        await self._ensure_open_prelude(timeout=self._remaining_write_timeout(start, timeout))
        async with self._lock:
            if self._write_closed:
                raise WriteClosed()
            self._write_closed = True
        try:
            timeout = _operation_timeout(
                start,
                timeout,
                _remaining_deadline(self._write_deadline, self._deadline),
            )
            await _finish_writer(self._writer, timeout)
        except Exception as exc:
            translated = translate_write_error(exc)
            self._write_error = translated
            raise translated
        self._maybe_finish_active()

    async def cancel_write(self, code: int) -> None:
        code = _require_application_code(code)
        await self._write_operation_lock.acquire()
        try:
            await self._cancel_write_unlocked(code)
        finally:
            self._write_operation_lock.release()

    async def _cancel_write_unlocked(self, code: int) -> None:
        self._require_writable()
        async with self._lock:
            if self._write_closed:
                raise self._write_error or WriteClosed()
            self._write_closed = True
            self._write_error = ApplicationError(code)
        await _cancel_write(self._session._connection, self._writer, self._stream_id, code)
        self._session._note_reset(code)
        self._maybe_finish_active()

    async def update_metadata(self, update: MetadataUpdate) -> None:
        start = time.monotonic()
        await self._acquire_write_operation(start, None)
        try:
            await self._update_metadata_unlocked(update, start)
        finally:
            self._write_operation_lock.release()

    async def _update_metadata_unlocked(
            self, update: MetadataUpdate, start: float
    ) -> None:
        async with self._lock:
            if self._write_closed:
                raise WriteClosed()
            if update is None or update.is_empty():
                raise EmptyMetadataUpdate()
            if not self._opened_locally or self._prelude_sent:
                raise PriorityUpdateUnavailable()
            priority = self._metadata.priority if update.priority is None else update.priority
            group = self._metadata.group if update.group is None else update.group
            self._metadata = StreamMetadata(priority, group, self._metadata.open_info)
            self._options = OpenOptions(priority, group, self._metadata.open_info)
        await self._ensure_open_prelude(timeout=self._remaining_write_timeout(start, None))

    async def _acquire_write_operation(
            self, start: float, timeout: Optional[float]
    ) -> None:
        try:
            await _await_with_timeout(
                self._write_operation_lock.acquire(),
                _operation_timeout(
                    start,
                    timeout,
                    _remaining_deadline(self._write_deadline, self._deadline),
                ),
            )
        except asyncio.TimeoutError:
            raise WriteTimeout()

    def _remaining_write_timeout(
            self, start: float, timeout: Optional[float]
    ) -> Optional[float]:
        return _operation_timeout(
            start,
            timeout,
            _remaining_deadline(self._write_deadline, self._deadline),
        )

    async def send_open_prelude_on_open(
            self, *, timeout: Optional[float] = None
    ) -> None:
        if self._opened_locally and self._has_peer_visible_open_metadata():
            await self._ensure_open_prelude(timeout=timeout)

    def _has_peer_visible_open_metadata(self) -> bool:
        return (
                self._metadata.priority is not None
                or self._metadata.group is not None
                or bool(self._metadata.open_info)
        )

    async def _ensure_open_prelude(self, *, timeout: Optional[float] = None) -> None:
        if self._prelude_sent or not self._opened_locally:
            return
        async with self._write_lock:
            async with self._lock:
                if self._prelude_sent:
                    return
                if not self._prelude_frozen:
                    self._prelude = build_stream_prelude(self._options)
                    self._prelude_frozen = True
                prelude = self._prelude or _EMPTY_STREAM_PRELUDE
                offset = self._prelude_offset
            if offset < len(prelude):
                view = memoryview(prelude)[offset:]

                def advance(n: int) -> None:
                    self._prelude_offset += n

                try:
                    await _write_all(
                        self._writer,
                        view,
                        timeout,
                        progress=advance,
                    )
                except asyncio.TimeoutError:
                    raise WriteTimeout()
                except Exception as exc:
                    translated = translate_write_error(exc)
                    self._write_error = translated
                    raise translated
            async with self._lock:
                if self._prelude_offset >= len(prelude):
                    self._prelude_sent = True
                    self._prelude = None

    async def _write_view(
            self, view: memoryview, *, timeout: Optional[float] = None
    ) -> None:
        if len(view) != 0:
            await self._write_views((view,), timeout=timeout)

    async def _write_bytes(
            self, data: object, *, timeout: Optional[float] = None
    ) -> None:
        view = _memoryview(data)
        if len(view) == 0:
            return
        await self._write_views((view,), timeout=timeout)

    async def _write_views(
            self, views: Tuple[memoryview, ...], *, timeout: Optional[float] = None
    ) -> None:
        start = time.monotonic()
        try:
            async with self._write_lock:
                for view in views:
                    remaining = _operation_timeout(
                        start,
                        timeout,
                        _remaining_deadline(self._write_deadline, self._deadline),
                    )
                    await _write_all(self._writer, view, remaining)
        except asyncio.TimeoutError:
            raise WriteTimeout()
        except Exception as exc:
            translated = translate_write_error(exc)
            self._write_error = translated
            raise translated

    def _require_readable(self) -> None:
        if self._reader is None:
            raise StreamNotReadable()
        if self._read_closed:
            raise self._read_error or ReadClosed()

    def _require_writable(self) -> None:
        if self._writer is None:
            raise StreamNotWritable()
        if self._write_closed:
            raise self._write_error or WriteClosed()

    def _maybe_finish_active(self) -> None:
        if self._active_finished:
            return
        if (self._reader is None or self._read_closed) and (
                self._writer is None or self._write_closed
        ):
            self._active_finished = True
            self._session._finish_stream(self._active_kind)


class AioquicStream(_StreamBase):
    @classmethod
    def local(
            cls,
            session: AioquicSession,
            reader: object,
            writer: object,
            stream_id: Optional[int],
            options: Optional[OpenOptions],
    ) -> "AioquicStream":
        return cls(
            session,
            reader,
            writer,
            stream_id,
            True,
            True,
            _ActiveKind.LOCAL_BIDI,
            options=options,
        )

    @classmethod
    def accepted(
            cls,
            session: AioquicSession,
            reader: object,
            writer: Optional[object],
            stream_id: Optional[int],
            metadata: AcceptedStreamMetadata,
    ) -> "AioquicStream":
        if writer is None:
            raise AdapterUnsupported("zmux: bidirectional accepted stream has no writer")
        return cls(
            session,
            reader,
            writer,
            stream_id,
            False,
            True,
            _ActiveKind.PEER_BIDI,
            accepted_metadata=metadata,
        )


class AioquicSendStream(_StreamBase):
    @classmethod
    def local(
            cls,
            session: AioquicSession,
            writer: object,
            stream_id: Optional[int],
            options: Optional[OpenOptions],
    ) -> "AioquicSendStream":
        return cls(
            session,
            None,
            writer,
            stream_id,
            True,
            False,
            _ActiveKind.LOCAL_UNI,
            options=options,
        )


class AioquicRecvStream(_StreamBase):
    @classmethod
    def accepted(
            cls,
            session: AioquicSession,
            reader: object,
            stream_id: Optional[int],
            metadata: AcceptedStreamMetadata,
    ) -> "AioquicRecvStream":
        return cls(
            session,
            reader,
            None,
            stream_id,
            False,
            False,
            _ActiveKind.PEER_UNI,
            accepted_metadata=metadata,
        )
