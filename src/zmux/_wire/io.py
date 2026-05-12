"""Shared binary reader helpers for wire codecs."""

from __future__ import annotations

from typing import BinaryIO, Callable

TruncatedErrorFactory = Callable[[], BaseException]
TransportErrorFactory = Callable[[OSError], BaseException]

__all__ = ("read_chunk_view", "read_exact_bytes")


def read_exact_bytes(
        reader: BinaryIO,
        size: int,
        truncated_error: TruncatedErrorFactory,
        transport_error: TransportErrorFactory,
) -> bytes:
    if size <= 0:
        return b""

    chunks = None
    remaining = size
    while remaining:
        try:
            chunk = reader.read(remaining)
        except InterruptedError:
            continue
        except OSError as exc:
            raise transport_error(exc) from exc
        if chunk is None:
            exc = BlockingIOError("non-blocking reader returned no data")
            raise transport_error(exc) from exc
        view = read_chunk_view(chunk, transport_error)
        chunk_len = len(view)
        if chunk_len == 0:
            raise truncated_error()
        if chunk_len > remaining:
            exc = OSError("reader returned more bytes than requested")
            raise transport_error(exc) from exc
        if chunk_len == remaining and chunks is None and isinstance(chunk, bytes):
            return chunk
        chunk_bytes = view.tobytes()
        if chunk_len == remaining and chunks is None:
            return chunk_bytes
        if chunks is None:
            chunks = [chunk_bytes]
        else:
            chunks.append(chunk_bytes)
        remaining -= chunk_len
    return b"".join(chunks or ())


def read_chunk_view(
        chunk: object, transport_error: TransportErrorFactory
) -> memoryview:
    if isinstance(chunk, (bool, int, str)):
        exc = OSError("reader returned non-bytes data")
        raise transport_error(exc) from exc
    try:
        view = memoryview(chunk)
    except TypeError as exc:
        error = OSError("reader returned non-bytes data")
        raise transport_error(error) from exc
    if (
            view.ndim == 1
            and view.itemsize == 1
            and view.format in ("B", "b", "c")
            and view.contiguous
    ):
        return view
    try:
        return view.cast("B")
    except (TypeError, ValueError) as exc:
        error = OSError("reader returned non-byte data")
        raise transport_error(error) from exc
