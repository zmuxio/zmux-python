"""Duck-typed async I/O helpers used by the aioquic adapter."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Iterable
from typing import Optional, Tuple
from zmux.errors import (
    AdapterUnsupported,
    ErrorDirection,
    ReadClosed,
    ReadTimeout,
    WriteClosed,
    ZmuxError,
)
from zmux.protocol import ErrorCode

from ._constants import FINISH_WRITER_WAIT_TIMEOUT
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
        progress: Optional[object] = None,
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
            if not callable(progress):
                raise TypeError("progress must be callable")
            progress(written)
        if drain is not None:
            await _drain_writer(drain, _remaining_timeout(start, timeout))


async def _drain_writer(drain: object, timeout: Optional[float]) -> None:
    try:
        await _await_with_timeout(_maybe_await(drain()), timeout)  # type: ignore[operator]
    except ZmuxError as exc:
        # asyncio.StreamWriter.drain() re-raises its paired reader's exception.
        # A peer RESET recorded on the receive half must not fail the send half.
        if exc.direction == ErrorDirection.READ:
            return
        raise


async def _finish_writer(writer: object, timeout: Optional[float]) -> None:
    """Submit a graceful send-half close (FIN) and return once it is queued.

    A half-close never waits for ``wait_closed()``: aioquic's per-stream
    ``StreamWriter`` only resolves it on ``connection_lost()``, which aioquic
    never delivers. Waits after the FIN or close is submitted are bounded and
    best-effort, so they cannot turn a submitted FIN into a failure.
    """

    if writer is None:
        return
    start = time.monotonic()
    full_close = False
    for name in ("write_eof", "finish", "close", "aclose"):
        method = _first_callable(writer, (name,))
        if method is None:
            continue
        await _await_with_timeout(
            _maybe_await(method()), _remaining_timeout(start, timeout)
        )
        full_close = name in ("close", "aclose")
        break
    wait = _bounded_wait_timeout(_remaining_timeout(start, timeout))
    drain = _first_callable(writer, ("drain", "flush"))
    if drain is not None:
        await _best_effort(_drain_writer(drain, wait))
    if full_close:
        wait_closed = _first_callable(writer, ("wait_closed",))
        if wait_closed is not None:
            await _best_effort(
                _await_with_timeout(_maybe_await(wait_closed()), wait)
            )


def _bounded_wait_timeout(remaining: Optional[float]) -> float:
    if remaining is None:
        return FINISH_WRITER_WAIT_TIMEOUT
    return min(remaining, FINISH_WRITER_WAIT_TIMEOUT)


async def _cancel_read(
        connection: object,
        reader: Optional[object],
        writer: Optional[object],
        stream_id: int,
        code: int,
) -> bool:
    """Stop the receive half; return whether an abortive path was available."""

    if await _call_first(
            (reader, writer, connection),
            ("cancel_read", "stop_sending", "stop_stream"),
            stream_id,
            code,
    ):
        return True
    quic = getattr(connection, "_quic", None)
    if quic is None:
        return False
    if not _quic_stream_known(quic, stream_id):
        # Already discarded by aioquic: both halves are finished.
        return True
    try:
        if not await _call_first((quic,), ("stop_stream",), stream_id, code):
            return False
    except ValueError:
        # aioquic rejects unknown and send-only streams; nothing to stop.
        return True
    _flush_connection(connection)
    return True


async def _cancel_write(
        connection: object, writer: Optional[object], stream_id: int, code: int
) -> bool:
    """Reset the send half; return whether an abortive path was available."""

    if await _call_first(
            (writer, connection),
            ("cancel_write", "reset", "reset_stream"),
            stream_id,
            code,
    ):
        _retire_writer(writer)
        return True
    quic = getattr(connection, "_quic", None)
    if quic is None:
        return False
    if not _quic_stream_known(quic, stream_id):
        # Re-creating send state for a discarded stream would rewind aioquic's
        # local stream-id allocator, so a finished stream is left alone.
        _retire_writer(writer)
        return True
    if not await _call_first((quic,), ("reset_stream",), stream_id, code):
        return False
    _retire_writer(writer)
    _flush_connection(connection)
    return True


def _quic_stream_known(quic: object, stream_id: int) -> bool:
    streams = getattr(quic, "_streams", None)
    if isinstance(streams, dict):
        return stream_id in streams
    return True


def _flush_connection(connection: object) -> None:
    """Send control frames queued directly on aioquic's QuicConnection.

    ``QuicConnection.stop_stream`` and ``reset_stream`` only queue state; the
    protocol object must be told to transmit after direct QuicConnection calls.
    """

    method = _first_callable(connection, ("transmit", "_transmit_soon"))
    if method is None:
        return
    try:
        method()  # type: ignore[operator]
    except Exception:
        return


def _retire_writer(writer: Optional[object]) -> None:
    """Keep an aioquic stream writer from emitting a late FIN.

    ``asyncio.StreamWriter.__del__`` and ``close()`` send FIN through aioquic's
    ``QuicStreamAdapter`` unless the transport reports closing. After a reset,
    or for a peer-opened unidirectional stream, that FIN is invalid and aioquic
    raises from the garbage collector.
    """

    transport = getattr(writer, "transport", None)
    if transport is None or not hasattr(transport, "_closing"):
        return
    try:
        if not transport.is_closing():
            transport._closing = True
    except Exception:
        return


def _reserve_local_stream_id(connection: object, stream_id: Optional[int]) -> None:
    """Make aioquic allocate a freshly created local stream ID immediately.

    aioquic only advances its next local stream ID once data is queued on the
    stream, so two ``create_stream()`` calls without writes would share one QUIC
    stream. An empty, non-final write creates the send state without putting a
    frame on the wire.
    """

    if stream_id is None:
        return
    quic = getattr(connection, "_quic", None)
    if quic is None:
        return
    send = _first_callable(quic, ("send_stream_data",))
    if send is None:
        return
    streams = getattr(quic, "_streams", None)
    if isinstance(streams, dict) and stream_id in streams:
        return
    try:
        send(stream_id, b"")  # type: ignore[operator]
    except Exception:
        return


def _connection_stream_readers(connection: object) -> Tuple[object, ...]:
    readers = getattr(connection, "_stream_readers", None)
    if not isinstance(readers, dict):
        return ()
    return tuple(readers.values())


def _connection_stream_reader(connection: object, stream_id: int) -> Optional[object]:
    readers = getattr(connection, "_stream_readers", None)
    if not isinstance(readers, dict):
        return None
    return readers.get(stream_id)


def _reader_saw_fin(reader: object) -> bool:
    # asyncio.StreamReader records feed_eof(); aioquic feeds EOF only for a
    # peer FIN until the connection terminates.
    return getattr(reader, "_eof", False) is True


def _fail_reader(reader: object, error: BaseException) -> None:
    """Wake a blocked asyncio-style reader with a terminal error."""

    exception = _first_callable(reader, ("exception",))
    try:
        if exception is not None and exception() is not None:
            return
    except Exception:
        return
    set_exception = _first_callable(reader, ("set_exception",))
    if set_exception is None:
        return
    try:
        set_exception(error)  # type: ignore[operator]
    except Exception:
        return


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
        connection: Optional[object] = None,
        stream_id: Optional[int] = None,
        bidirectional: bool = True,
) -> None:
    """Abortively reject a peer-opened stream that is not handed to accept.

    The receive half gets STOP_SENDING(code) and, for bidirectional streams,
    the send half gets RESET(code). A graceful close is only a last resort when
    the backend exposes no abortive path, and a receive-only stream never gets
    a FIN. Cleanup failures never replace the caller's original error.
    """

    code = _require_application_code(code)
    if stream_id is None:
        stream_id = _stream_id_or_none(writer, reader)
    send_writer = writer if bidirectional else None
    stopped = False
    if connection is not None and stream_id is not None:
        stopped = await _best_effort_result(
            _cancel_read(connection, reader, send_writer, stream_id, code)
        )
    if not stopped:
        await _best_effort(
            _call_first((reader,), ("cancel_read", "close", "aclose"), code)
        )
    if send_writer is None:
        _retire_writer(writer)
        return
    reset = False
    if connection is not None and stream_id is not None:
        reset = await _best_effort_result(
            _cancel_write(connection, send_writer, stream_id, code)
        )
    if not reset:
        await _best_effort(
            _call_first(
                (send_writer,),
                ("cancel_write", "reset", "close", "aclose"),
                code,
            )
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
    if not await _best_effort_result(
            _cancel_write(connection, writer, stream_id, code)
    ):
        await _best_effort(_finish_writer(writer, None))


async def _acquire_lock(
        lock: asyncio.Lock, timeout: Optional[float], timeout_error: type
) -> None:
    """Acquire ``lock`` within ``timeout`` without ever leaking it.

    ``asyncio.wait_for`` on Python < 3.12 can drop an acquisition that races
    the timeout, which would leave the lock held forever.
    """

    timeout = _wait_timeout(timeout)
    if timeout is None or not lock.locked():
        await lock.acquire()
        return

    def release_if_acquired(task: "asyncio.Future[bool]") -> None:
        if not task.cancelled() and task.exception() is None:
            lock.release()

    task = asyncio.ensure_future(lock.acquire())
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout)
    except BaseException:
        task.cancel()
        task.add_done_callback(release_if_acquired)
        raise
    if task not in done:
        task.cancel()
        task.add_done_callback(release_if_acquired)
        raise timeout_error()


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


async def _best_effort_result(awaitable: object) -> bool:
    try:
        return bool(await _maybe_await(awaitable))
    except Exception:
        return False


def _consume_task_exception(task: "asyncio.Task[object]") -> None:
    try:
        task.exception()
    except asyncio.CancelledError:
        return
    except Exception:
        return


def _first_callable(target: object, names: Tuple[str, ...]) -> Optional[object]:
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
    stream_id = _stream_id_or_none(*objects)
    return 0 if stream_id is None else stream_id


def _stream_id_or_none(*objects: Optional[object]) -> Optional[int]:
    """Return the backend stream ID, or ``None`` when no object exposes one.

    Zero is a valid QUIC stream ID, so "unknown" must stay distinguishable.
    """

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
    return None


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
    # aioquic's QuicConnectionProtocol only keeps a private termination event.
    value = getattr(connection, "_closed", None)
    if isinstance(value, asyncio.Event):
        return value.is_set()
    return False
