"""Repository-default adapter session contract.

The checks mirror ``internal/adaptertest/session_contract.go`` from the Go
implementation while using Python's async-first adapter API.  The runner only
requires the stable public session and stream method names, so adapter packages
can supply native sessions, wrappers, or lightweight in-memory test pairs.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import math
import time
from collections.abc import Awaitable, Callable
from numbers import Real
from typing import Any, Optional, Tuple

import zmux

DEFAULT_TIMEOUT = 5.0
_READ_CHUNK = 64 * 1024
_MAX_READ_ALL_BYTES = 16 * 1024 * 1024
_POLL_INTERVAL = 0.01

SessionPairFactory = Callable[[], Any]


def run_session_contract(
        pair_factory: SessionPairFactory, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Run the default adapter contract from synchronous test code.

    Use :func:`run_async_session_contract` when the caller is already inside an
    event loop, for example from ``unittest.IsolatedAsyncioTestCase`` or pytest
    async tests.
    """

    _require_pair_factory(pair_factory)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(run_async_session_contract(pair_factory, timeout))
        return
    raise RuntimeError(
        "run_session_contract cannot be called from a running event loop; "
        "await run_async_session_contract instead"
    )


async def run_async_session_contract(
        pair_factory: SessionPairFactory, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Run the default adapter contract against fresh connected session pairs."""

    _require_pair_factory(pair_factory)
    timeout = _normalize_timeout(timeout)
    await _run_case("bidi", pair_factory, timeout, _run_bidi_contract)
    await _run_case("uni", pair_factory, timeout, _run_uni_contract)
    await _run_case(
        "stream_abortive_close",
        pair_factory,
        timeout,
        _run_stream_abortive_close_contract,
    )
    await _run_case("read_stop", pair_factory, timeout, _run_read_stop_contract)
    await _run_case("close", pair_factory, timeout, _run_close_contract)
    await _run_case("abort", pair_factory, timeout, _run_abort_contract)


async def _run_case(
        name: str,
        pair_factory: SessionPairFactory,
        timeout: float,
        body: Callable[[Any, Any, float], Awaitable[None]],
) -> None:
    pair = await _maybe_await(pair_factory())
    client, server = _coerce_pair(pair, name)
    try:
        if await _closed(client):
            raise AssertionError("%s: client session unexpectedly closed before use" % name)
        if await _closed(server):
            raise AssertionError("%s: server session unexpectedly closed before use" % name)
        await body(client, server, timeout)
    except AssertionError as exc:
        if str(exc).startswith(name + ":"):
            raise
        raise AssertionError("%s: %s" % (name, exc)) from exc
    finally:
        await _best_effort(_close_session(client, timeout))
        await _best_effort(_close_session(server, timeout))


async def _run_bidi_contract(client: Any, server: Any, timeout: float) -> None:
    accept_task = asyncio.create_task(_accept_stream(server, timeout))
    client_stream = None
    accepted = None
    try:
        client_stream = await _open_stream(client, timeout)
        payload = b"adapter-contract-bidi"
        written = await _write(client_stream, payload, timeout)
        if written != len(payload):
            raise AssertionError(
                "Write returned %d, want %d" % (written, len(payload))
            )
        await _close_write(client_stream, timeout)

        accepted = await _await_task(accept_task, timeout)
        got = await _read_all(accepted, timeout)
        if got != payload:
            raise AssertionError("ReadAll returned %r, want %r" % (got, payload))
    finally:
        if accepted is not None:
            await _best_effort(_close_stream(accepted, timeout))
        if client_stream is not None:
            await _best_effort(_close_stream(client_stream, timeout))
        await _cancel_task(accept_task, timeout)


async def _run_uni_contract(client: Any, server: Any, timeout: float) -> None:
    accept_task = asyncio.create_task(_accept_uni_stream(server, timeout))
    send = None
    accepted = None
    try:
        send = await _open_uni_stream(client, timeout)
        payload = b"adapter-contract-uni"
        written = await _write(send, payload, timeout)
        if written != len(payload):
            raise AssertionError(
                "Write returned %d, want %d" % (written, len(payload))
            )

        accepted = await _await_task(accept_task, timeout)
        await _close_write(send, timeout)
        got = await _read_all(accepted, timeout)
        if got != payload:
            raise AssertionError("ReadAll returned %r, want %r" % (got, payload))
    finally:
        if accepted is not None:
            await _best_effort(_close_stream(accepted, timeout))
        if send is not None:
            await _best_effort(_close_stream(send, timeout))
        await _cancel_task(accept_task, timeout)


async def _run_stream_abortive_close_contract(
        client: Any, server: Any, timeout: float
) -> None:
    accept_task = asyncio.create_task(_accept_stream(server, timeout))
    client_stream = None
    accepted = None
    try:
        client_stream = await _open_stream(client, timeout)
        written = await _write(client_stream, b"x", timeout)
        if written != 1:
            raise AssertionError("initial Write returned %d, want 1" % written)
        accepted = await _await_task(accept_task, timeout)
        if await _read_exact(accepted, 1, timeout) != b"x":
            raise AssertionError("peer did not read initial byte")

        abort_code = 55
        abort_reason = "adapter-contract-abort"
        await _close_stream_with_error(client_stream, abort_code, abort_reason, timeout)

        local_read = await _capture_error(_read_some(client_stream, 1, timeout))
        if not _matches_application_error(local_read, abort_code, abort_reason):
            raise AssertionError(
                "local Read error %r, want ApplicationError(%d, %r)"
                % (local_read, abort_code, abort_reason)
            )
        local_write = await _capture_error(_write(client_stream, b"y", timeout))
        if not _matches_application_error(local_write, abort_code, abort_reason):
            raise AssertionError(
                "local Write error %r, want ApplicationError(%d, %r)"
                % (local_write, abort_code, abort_reason)
            )

        peer_read = await _capture_error(_read_some(accepted, 1, timeout))
        if peer_read is None:
            raise AssertionError("peer Read succeeded after abortive stream close")
    finally:
        if client_stream is not None:
            await _best_effort(_close_stream(client_stream, timeout))
        if accepted is not None:
            await _best_effort(_close_stream(accepted, timeout))
        await _cancel_task(accept_task, timeout)


async def _run_read_stop_contract(client: Any, server: Any, timeout: float) -> None:
    accept_task = asyncio.create_task(_accept_stream(server, timeout))
    client_stream = None
    accepted = None
    try:
        client_stream = await _open_stream(client, timeout)
        written = await _write(client_stream, b"p", timeout)
        if written != 1:
            raise AssertionError("initial Write returned %d, want 1" % written)
        accepted = await _await_task(accept_task, timeout)
        if await _read_exact(accepted, 1, timeout) != b"p":
            raise AssertionError("peer did not read initial byte")

        stop_code = 77
        await _cancel_read(accepted, stop_code, timeout)
        stopped_read = await _capture_error(_read_some(accepted, 1, timeout))
        if not _matches_read_closed(stopped_read):
            raise AssertionError(
                "post-stop Read error %r, want ReadClosed" % (stopped_read,)
            )

        await _set_write_timeout(client_stream, timeout)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            err = await _capture_error(_write(client_stream, b"x", timeout))
            if err is None:
                await asyncio.sleep(_POLL_INTERVAL)
                continue
            if _matches_application_error_code(err, stop_code) or _matches_write_closed(
                    err
            ):
                return
            raise AssertionError(
                "Write error %r, want ApplicationError(%d) or WriteClosed"
                % (err, stop_code)
            )
        raise AssertionError(
            "Write did not observe stop code %d before timeout" % stop_code
        )
    finally:
        if client_stream is not None:
            await _best_effort(_close_stream(client_stream, timeout))
        if accepted is not None:
            await _best_effort(_close_stream(accepted, timeout))
        await _cancel_task(accept_task, timeout)


async def _run_close_contract(client: Any, server: Any, timeout: float) -> None:
    await _close_session(client, timeout)
    await _wait_for_closed(client, timeout)
    await _wait_for_closed(server, timeout)

    err = await _capture_error(_open_stream(client, timeout))
    if err is None:
        raise AssertionError("OpenStream after Close succeeded")
    if not (
            _matches_session_closed(err)
            or _matches_application_error_code(err, int(zmux.ErrorCode.SESSION_CLOSING))
    ):
        raise AssertionError(
            "OpenStream after Close error %r, want SessionClosed or "
            "session-closing application error"
            % (err,)
        )


async def _run_abort_contract(client: Any, server: Any, timeout: float) -> None:
    abort_code = 91
    abort_reason = "adapter-contract-session-abort"
    await _close_session_with_error(client, abort_code, abort_reason, timeout)

    client_wait = await _wait_for_closed(client, timeout)
    if client_wait is not None and not (
            _matches_session_closed(client_wait)
            or _matches_application_error(client_wait, abort_code, abort_reason)
    ):
        raise AssertionError("client Wait after CloseWithError error %r" % client_wait)

    server_wait = await _wait_for_closed(server, timeout)
    if server_wait is not None and not (
            _matches_session_closed(server_wait)
            or _matches_application_error_code(server_wait, abort_code)
    ):
        raise AssertionError("server Wait after peer CloseWithError error %r" % server_wait)

    err = await _capture_error(_open_stream(client, timeout))
    if err is None:
        raise AssertionError("OpenStream after Abort succeeded")
    if not (
            _matches_session_closed(err)
            or _matches_application_error_code(err, abort_code)
    ):
        raise AssertionError(
            "OpenStream after Abort error %r, want SessionClosed or ApplicationError(%d)"
            % (err, abort_code)
        )


async def _open_stream(session: Any, timeout: float) -> Any:
    return await _call_timed_with_optional_timeout(
        session,
        "open_stream",
        timeout,
        positional_timeout=False,
    )


async def _open_uni_stream(session: Any, timeout: float) -> Any:
    return await _call_timed_with_optional_timeout(
        session,
        "open_uni_stream",
        timeout,
        positional_timeout=False,
    )


async def _accept_stream(session: Any, timeout: float) -> Any:
    return await _call_timed_with_optional_timeout(session, "accept_stream", timeout)


async def _accept_uni_stream(session: Any, timeout: float) -> Any:
    return await _call_timed_with_optional_timeout(
        session, "accept_uni_stream", timeout
    )


async def _write(stream: Any, data: bytes, timeout: float) -> int:
    data = _bytes_like(data, "write payload")
    method = _first_callable(stream, ("write",))
    if method is None:
        method = _first_callable(stream, ("write_all",))
        if method is None:
            raise AssertionError("stream has no write method")
        await _call_with_optional_timeout(method, data, timeout)
        return len(data)
    result = await _call_with_optional_timeout(method, data, timeout)
    return len(data) if result is None else _write_progress(result, len(data))


async def _read_some(stream: Any, max_bytes: int, timeout: float) -> bytes:
    max_bytes = _nonnegative_int(max_bytes, "read size")
    method = _first_callable(stream, ("read",))
    if method is None:
        raise AssertionError("stream has no read method")
    result = await _call_with_optional_timeout(method, max_bytes, timeout)
    data = _bytes_result(result, "read")
    if len(data) > max_bytes:
        raise AssertionError(
            "read returned %d bytes for %d byte request" % (len(data), max_bytes)
        )
    return data


async def _read_exact(stream: Any, size: int, timeout: float) -> bytes:
    size = _nonnegative_int(size, "read_exact size")
    method = _first_callable(stream, ("read_exact",))
    if method is not None:
        result = await _call_with_optional_timeout(method, size, timeout)
        data = _bytes_result(result, "read_exact")
        if len(data) != size:
            raise AssertionError(
                "read_exact returned %d bytes, want %d" % (len(data), size)
            )
        return data

    chunks = bytearray()
    while len(chunks) < size:
        chunk = await _read_some(stream, size - len(chunks), timeout)
        if not chunk:
            raise EOFError("unexpected EOF while reading contract payload")
        chunks.extend(chunk)
    return bytes(chunks)


async def _read_all(
        stream: Any, timeout: float, *, limit: int = _MAX_READ_ALL_BYTES
) -> bytes:
    timeout = _normalize_timeout(timeout)
    limit = _nonnegative_int(limit, "read_all limit")
    deadline = time.monotonic() + timeout
    chunks = bytearray()
    while True:
        capacity = limit - len(chunks)
        max_bytes = min(_READ_CHUNK, capacity if capacity > 0 else 1)
        chunk = await _read_some(
            stream,
            max_bytes,
            _remaining_timeout(deadline, "read_all"),
        )
        if not chunk:
            return bytes(chunks)
        if len(chunks) > limit - len(chunk):
            raise AssertionError("read_all exceeded %d byte contract limit" % limit)
        chunks.extend(chunk)


async def _close_write(stream: Any, timeout: float) -> None:
    await _call_timed(stream, "close_write", timeout)


async def _cancel_read(stream: Any, code: int, timeout: float) -> None:
    await _call_timed(stream, "cancel_read", timeout, code)


async def _close_stream(stream: Any, timeout: float = DEFAULT_TIMEOUT) -> None:
    method = _first_callable(stream, ("close",))
    if method is not None:
        await _await_with_timeout(_invoke(method), timeout)


async def _close_stream_with_error(
        stream: Any, code: int, reason: str, timeout: float
) -> None:
    await _call_timed(stream, "close_with_error", timeout, code, reason)


async def _close_session(session: Any, timeout: float = DEFAULT_TIMEOUT) -> None:
    method = _first_callable(session, ("close",))
    if method is not None:
        await _await_with_timeout(_invoke(method), timeout)


async def _close_session_with_error(
        session: Any, code: int, reason: str, timeout: float
) -> None:
    await _call_timed(session, "close_with_error", timeout, code, reason)


async def _wait_for_closed(session: Any, timeout: float) -> Optional[BaseException]:
    wait_error = None
    try:
        method = _first_callable(session, ("wait",))
        if method is not None:
            await _call_timed_with_optional_timeout(session, "wait", timeout)
    except Exception as exc:
        wait_error = exc
    if not await _closed(session):
        raise AssertionError("session did not report closed after wait")
    if wait_error is not None:
        if _matches_session_closed(wait_error) or isinstance(
                zmux.find_error(wait_error, zmux.ApplicationError),
                zmux.ApplicationError,
        ):
            return wait_error
        raise wait_error
    return None


async def _set_write_timeout(stream: Any, timeout: float) -> None:
    method = _first_callable(stream, ("set_write_timeout",))
    if method is None:
        return
    await _await_with_timeout(_invoke(method, timeout), timeout)


async def _closed(session: Any) -> bool:
    value = getattr(session, "closed", False)
    if callable(value):
        value = value()
    return bool(await _maybe_await(value))


async def _call_timed(obj: Any, name: str, timeout: float, *args: Any) -> Any:
    timeout = _normalize_timeout(timeout)
    method = _first_callable(obj, (name,))
    if method is None:
        raise AssertionError("%r has no %s method" % (obj, name))
    return await _await_with_timeout(_invoke(method, *args), timeout)


async def _call_timed_with_optional_timeout(
        obj: Any,
        name: str,
        timeout: float,
        *,
        positional_timeout: bool = True,
) -> Any:
    timeout = _normalize_timeout(timeout)
    method = _first_callable(obj, (name,))
    if method is None:
        raise AssertionError("%r has no %s method" % (obj, name))
    if _supports_keyword(method, "timeout"):
        return await _await_with_timeout(_invoke(method, timeout=timeout), timeout)
    if positional_timeout and _supports_positional_count(method, 1):
        return await _await_with_timeout(_invoke(method, timeout), timeout)
    return await _await_with_timeout(_invoke(method), timeout)


async def _call_with_optional_timeout(method: Callable[..., Any], *args: Any) -> Any:
    if len(args) < 2:
        return await _invoke(method, *args)
    value_args = args[:-1]
    timeout = _normalize_timeout(args[-1])
    if _supports_keyword(method, "timeout"):
        return await _await_with_timeout(
            _invoke(method, *value_args, timeout=timeout),
            timeout,
        )
    if _supports_positional_count(method, len(args)):
        return await _await_with_timeout(_invoke(method, *args), timeout)
    return await _await_with_timeout(_invoke(method, *value_args), timeout)


def _supports_keyword(method: Callable[..., Any], name: str) -> bool:
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == name and parameter.kind in (
                inspect.Parameter.KEYWORD_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            return True
    return False


def _supports_positional_count(method: Callable[..., Any], count: int) -> bool:
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return True
    positional = 0
    for parameter in signature.parameters.values():
        if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
            return True
        if parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional += 1
    return positional >= count


async def _await_task(task: "asyncio.Task[Any]", timeout: float) -> Any:
    timeout = _normalize_timeout(timeout)
    return await asyncio.wait_for(task, timeout)


async def _await_with_timeout(value: Any, timeout: float) -> Any:
    timeout = _normalize_timeout(timeout)
    if inspect.isawaitable(value):
        return await asyncio.wait_for(value, timeout)
    return value


async def _invoke(method: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    if inspect.iscoroutinefunction(method):
        return await method(*args, **kwargs)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, functools.partial(method, *args, **kwargs))
    if inspect.isawaitable(result):
        return await result
    return result


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _capture_error(awaitable: Awaitable[Any]) -> Optional[BaseException]:
    try:
        await awaitable
    except Exception as exc:
        return exc
    return None


async def _best_effort(awaitable: Awaitable[Any]) -> None:
    try:
        await awaitable
    except Exception:
        return


async def _cancel_task(
        task: "asyncio.Task[Any]", timeout: float = DEFAULT_TIMEOUT
) -> None:
    if task.done():
        try:
            task.exception()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        return
    task.cancel()
    try:
        await asyncio.wait_for(task, _normalize_timeout(timeout))
    except asyncio.CancelledError:
        return
    except asyncio.TimeoutError:
        return
    except Exception:
        return


def _first_callable(obj: Any, names: Tuple[str, ...]) -> Optional[Callable[..., Any]]:
    for name in names:
        candidate = getattr(obj, name, None)
        if callable(candidate):
            return candidate
    return None


def _coerce_pair(pair: Any, case_name: str) -> Tuple[Any, Any]:
    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
        raise AssertionError("%s: session factory must return (client, server)" % case_name)
    client, server = pair
    if client is None or server is None:
        raise AssertionError("%s: session factory returned None session" % case_name)
    return client, server


def _require_pair_factory(pair_factory: Any) -> None:
    if not callable(pair_factory):
        raise TypeError("session pair factory must be callable")


def _matches_application_error(
        error: Optional[BaseException], code: int, reason: str
) -> bool:
    if error is None:
        return False
    app_error = zmux.find_error(error, zmux.ApplicationError)
    return (
            isinstance(app_error, zmux.ApplicationError)
            and app_error.code == code
            and app_error.reason == reason
    )


def _matches_application_error_code(
        error: Optional[BaseException], code: int
) -> bool:
    if error is None:
        return False
    app_error = zmux.find_error(error, zmux.ApplicationError)
    return isinstance(app_error, zmux.ApplicationError) and app_error.code == code


def _matches_session_closed(error: Optional[BaseException]) -> bool:
    if error is None:
        return False
    return isinstance(zmux.find_error(error, zmux.SessionClosed), zmux.SessionClosed)


def _matches_read_closed(error: Optional[BaseException]) -> bool:
    return error is not None and zmux.read_closed(error)


def _matches_write_closed(error: Optional[BaseException]) -> bool:
    return error is not None and zmux.write_closed(error)


def _bytes_like(value: Any, name: str) -> bytes:
    if isinstance(value, int):
        raise TypeError("%s must be bytes-like, not int" % name)
    if isinstance(value, bytes):
        return value
    try:
        return memoryview(value).tobytes()
    except TypeError as exc:
        raise TypeError("%s must be bytes-like" % name) from exc


def _bytes_result(value: Any, operation: str) -> bytes:
    if value is None:
        raise AssertionError("%s returned None, want bytes-like data" % operation)
    try:
        return _bytes_like(value, "%s result" % operation)
    except TypeError as exc:
        raise AssertionError("%s returned non-bytes result %r" % (operation, value)) from exc


def _write_progress(value: Any, requested: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AssertionError("write returned invalid progress %r" % (value,))
    if value < 0 or value > requested:
        raise AssertionError(
            "write returned invalid progress %d for %d bytes" % (value, requested)
        )
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("%s must be an integer" % name)
    if value < 0:
        raise ValueError("%s must be non-negative" % name)
    return value


def _normalize_timeout(timeout: Any) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, Real):
        raise TypeError("session contract timeout must be a real number")
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0.0:
        raise ValueError("session contract timeout must be a positive finite number")
    return timeout


def _remaining_timeout(deadline: float, operation: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise AssertionError("%s timed out" % operation)
    return remaining


__all__ = (
    "DEFAULT_TIMEOUT",
    "SessionPairFactory",
    "run_async_session_contract",
    "run_session_contract",
)
