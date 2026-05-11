"""Duck-typed async I/O helpers used by the aioquic adapter."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Iterable
from typing import Callable, Optional, Tuple

from zmux.errors import AdapterUnsupported, ReadClosed, ReadTimeout, WriteClosed
from zmux.protocol import ErrorCode
from ._errors import _protocol_prelude_error
from ._validation import (
    _memoryview,
    _nonnegative_int,
    _read_size,
    _require_application_code,
    _timeout_seconds,
    _wait_timeout,
)


async def _read_exactly(
        reader: object, n: int, timeout: Optional[float], operation: str
) -> bytes:
    try:
        return await _await_with_timeout(_read_exact_no_timeout(reader, n), timeout)
    except asyncio.TimeoutError:
        raise ReadTimeout("zmux: %s timed out" % operation)
    except EOFError:
        raise _protocol_prelude_error(operation, EOFError("unexpected EOF"))


async def _read_exact_no_timeout(reader: object, n: int) -> bytes:
    n = _nonnegative_int(n, "n")
    if n == 0:
        return b""
    method = _first_callable(reader, ("readexactly", "read_exact"))
    if method is not None:
        data = bytes(await _maybe_await(method(n)))
        if len(data) != n:
            raise EOFError("unexpected EOF")
        return data
    chunks = bytearray()
    while len(chunks) < n:
        chunk = await _read_some(reader, n - len(chunks), None)
        if not chunk:
            raise EOFError("unexpected EOF")
        chunks.extend(chunk)
    return bytes(chunks)


async def _read_some(
        reader: object, max_bytes: int, timeout: Optional[float]
) -> bytes:
    if reader is None:
        raise ReadClosed()
    method = _first_callable(reader, ("read",))
    if method is None:
        raise AdapterUnsupported("zmux: aioquic reader has no read method")
    max_bytes = _read_size(max_bytes)
    result = method(max_bytes)
    return bytes(await _await_with_timeout(result, timeout))


async def _write_all(
        writer: object,
        data: object,
        timeout: Optional[float],
        *,
        progress: Optional[Callable[[int], None]] = None,
) -> None:
    if writer is None:
        raise WriteClosed()
    method = _first_callable(writer, ("write",))
    if method is None:
        raise AdapterUnsupported("zmux: aioquic writer has no write method")
    drain = _first_callable(writer, ("drain", "flush"))
    view = _memoryview(data)
    if len(view) == 0:
        return
    start = time.monotonic()
    offset = 0
    while offset < len(view):
        chunk = view[offset:]
        result = await _await_with_timeout(
            _maybe_await(method(chunk)), _remaining_timeout(start, timeout)
        )
        if result is None:
            written = len(chunk)
        elif isinstance(result, int) and not isinstance(result, bool):
            if result < 0 or result > len(chunk):
                raise OSError("zmux: aioquic writer reported invalid progress")
            if result == 0:
                raise OSError("zmux: aioquic writer made no progress")
            written = result
        else:
            raise OSError("zmux: aioquic writer returned a non-integer byte count")
        offset += written
        if progress is not None and written:
            progress(written)
        if drain is not None:
            await _await_with_timeout(
                _maybe_await(drain()), _remaining_timeout(start, timeout)
            )


async def _finish_writer(writer: object, timeout: Optional[float]) -> None:
    if writer is None:
        return
    start = time.monotonic()
    for name in ("write_eof", "finish", "close", "aclose"):
        method = _first_callable(writer, (name,))
        if method is None:
            continue
        await _await_with_timeout(
            _maybe_await(method()), _remaining_timeout(start, timeout)
        )
        break
    wait_closed = _first_callable(writer, ("wait_closed",))
    if wait_closed is not None:
        await _await_with_timeout(
            _maybe_await(wait_closed()), _remaining_timeout(start, timeout)
        )
    drain = _first_callable(writer, ("drain", "flush"))
    if drain is not None:
        await _await_with_timeout(
            _maybe_await(drain()), _remaining_timeout(start, timeout)
        )


async def _cancel_read(
        connection: object,
        reader: Optional[object],
        writer: Optional[object],
        stream_id: int,
        code: int,
) -> None:
    if await _call_first(
            (reader, writer, connection),
            ("cancel_read", "stop_sending", "stop_stream"),
            stream_id,
            code,
    ):
        return
    quic = getattr(connection, "_quic", None)
    if quic is not None:
        await _call_first((quic,), ("stop_stream",), stream_id, code)


async def _cancel_write(
        connection: object, writer: Optional[object], stream_id: int, code: int
) -> None:
    if await _call_first(
            (writer, connection),
            ("cancel_write", "reset", "reset_stream"),
            stream_id,
            code,
    ):
        return
    quic = getattr(connection, "_quic", None)
    if quic is not None:
        await _call_first((quic,), ("reset_stream",), stream_id, code)


async def _close_connection(connection: object, code: int, reason: str) -> None:
    for args in (
            {"error_code": code, "reason_phrase": reason},
            {"error_code": code, "reason": reason},
            {},
    ):
        method = _first_callable(connection, ("close", "aclose"))
        if method is None:
            return
        try:
            await _maybe_await(method(**args))
            return
        except TypeError:
            continue


async def _call_first(
        targets: Iterable[Optional[object]], names: Tuple[str, ...], *args: object
) -> bool:
    for target in targets:
        if target is None:
            continue
        for name in names:
            method = _first_callable(target, (name,))
            if method is None:
                continue
            try:
                await _maybe_await(method(*args))
            except TypeError:
                try:
                    await _maybe_await(method(args[-1]))
                except TypeError:
                    try:
                        await _maybe_await(method())
                    except TypeError:
                        continue
            return True
    return False


async def _discard_accepted_stream(
        reader: Optional[object],
        writer: Optional[object],
        code: int = int(ErrorCode.CANCELLED),
) -> None:
    code = _require_application_code(code)
    await _call_first((reader,), ("cancel_read", "close", "aclose"), code)
    await _call_first(
        (writer,),
        ("cancel_write", "reset", "close", "aclose"),
        code,
    )


async def _discard_local_open_stream(
        connection: object,
        reader: Optional[object],
        writer: Optional[object],
        stream_id: int,
        bidirectional: bool,
) -> None:
    code = int(ErrorCode.INTERNAL)
    if bidirectional:
        await _best_effort(_cancel_read(connection, reader, writer, stream_id, code))
    await _best_effort(_cancel_write(connection, writer, stream_id, code))
    await _best_effort(_finish_writer(writer, None))


async def _queue_get(
        queue: "asyncio.Queue[object]", timeout: Optional[float], timeout_error: BaseException
) -> object:
    try:
        return await _await_with_timeout(queue.get(), timeout)
    except asyncio.TimeoutError:
        raise timeout_error


async def _queue_wait(
        awaitable: Awaitable[object], timeout: Optional[float], timeout_error: BaseException
) -> object:
    try:
        return await _await_with_timeout(awaitable, timeout)
    except asyncio.TimeoutError:
        raise timeout_error


async def _await_with_timeout(awaitable: object, timeout: Optional[float]) -> object:
    if inspect.isawaitable(awaitable):
        timeout = _wait_timeout(timeout)
        if timeout is None:
            return await awaitable  # type: ignore[misc]
        return await asyncio.wait_for(awaitable, timeout)  # type: ignore[arg-type]
    return awaitable


def _remaining_timeout(start: float, timeout: Optional[float]) -> Optional[float]:
    if timeout is None:
        return None
    value = _timeout_seconds(timeout, "timeout")
    if value == float("inf"):
        return None
    return max(0.0, value - max(0.0, time.monotonic() - start))


def _operation_timeout(
        start: float,
        timeout: Optional[float],
        deadline_timeout: Optional[float],
) -> Optional[float]:
    remaining = _remaining_timeout(start, timeout)
    if remaining is None:
        return deadline_timeout
    if deadline_timeout is None:
        return remaining
    return min(remaining, deadline_timeout)


async def _maybe_await(value: object) -> object:
    if inspect.isawaitable(value):
        return await value  # type: ignore[misc]
    return value


async def _best_effort(awaitable: object) -> None:
    try:
        await _maybe_await(awaitable)
    except Exception:
        return


def _consume_task_exception(task: "asyncio.Task[object]") -> None:
    try:
        task.exception()
    except asyncio.CancelledError:
        return
    except Exception:
        return


def _first_callable(target: object, names: Tuple[str, ...]) -> Optional[Callable[..., object]]:
    for name in names:
        if not name:
            continue
        candidate = getattr(target, name, None)
        if callable(candidate):
            return candidate
    return None


def _first_callable_result(target: object, names: Tuple[str, ...]) -> Optional[object]:
    method = _first_callable(target, names)
    return None if method is None else method()


def _split_stream_result(result: object, bidirectional: bool) -> Tuple[Optional[object], object]:
    if isinstance(result, tuple):
        if len(result) == 2:
            reader, writer = result
            if bidirectional and (reader is None or writer is None):
                raise AdapterUnsupported("zmux: bidirectional stream requires reader and writer")
            return reader, writer
        if len(result) == 1:
            return (None, result[0]) if not bidirectional else (result[0], result[0])
    if bidirectional:
        return result, result
    return None, result


def _stream_id(*objects: Optional[object]) -> int:
    for obj in objects:
        if obj is None:
            continue
        for name in ("stream_id", "id"):
            value = getattr(obj, name, None)
            if callable(value):
                value = value()
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
        get_extra_info = getattr(obj, "get_extra_info", None)
        if callable(get_extra_info):
            value = get_extra_info("stream_id")
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
    return 0


def _addr(target: object, names: Tuple[str, ...]) -> Optional[object]:
    for name in names:
        value = getattr(target, name, None)
        if callable(value):
            value = value()
        if value is not None:
            return value
    return None


def _connection_closed(connection: object) -> bool:
    for name in ("closed", "is_closed", "closed_event"):
        value = getattr(connection, name, None)
        if callable(value):
            value = value()
        if isinstance(value, bool):
            return value
        if isinstance(value, asyncio.Event):
            return value.is_set()
    return False
