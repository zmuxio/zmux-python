# zmuxio-aioquic

`zmuxio-aioquic` wraps an established aioquic connection behind the stable
`zmux.AsyncSession` API.

It is an adapter over QUIC streams. It does not create QUIC connections and it
does not expose native ZMux wire-session controls such as `ping`, `go_away`,
prefaces, or negotiated native settings.

## Installation

```bash
pip install zmuxio-aioquic
```

The adapter depends on `zmuxio` and `aioquic`. The core package alone does not
install aioquic or cryptography:

```bash
pip install zmuxio
```

## Usage

```python
import zmux
import zmux_aioquic


async def run(connection) -> None:
    session = zmux_aioquic.wrap_session(connection)

    stream = await session.open_stream()
    await stream.write_final(b"hello")
    await session.close()
```

Use `SessionOptions` when the adapter needs prelude timeout or concurrency
tuning:

```python
options = zmux_aioquic.SessionOptions(
    accepted_prelude_read_timeout=2.0,
    accepted_prelude_max_concurrent=16,
)

session = zmux_aioquic.wrap_session(connection, options)
```

Incoming streams can be accepted directly when the wrapped connection exposes
`accept_stream(...)` / `accept_uni_stream(...)`. aioquic instead hands every
peer-opened stream, unidirectional ones included, to the protocol's
synchronous `stream_handler(reader, writer)` callback. Wrap the protocol when it
is created and enqueue streams from that callback:

```python
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol


class ZmuxProtocol(QuicConnectionProtocol):
    def __init__(self, quic, stream_handler=None):
        super().__init__(quic, stream_handler=self._handle_stream)
        self.session = zmux_aioquic.wrap_session(self)

    def _handle_stream(self, reader, writer) -> None:
        self.session.queue_incoming_stream(reader, writer)


async with connect(host, port, configuration=configuration,
                   create_protocol=ZmuxProtocol) as protocol:
    stream = await protocol.session.accept_stream()
```

`queue_incoming_stream(reader, writer)` takes the QUIC stream ID from
`writer.get_extra_info("stream_id")` and the stream direction from that ID, so
peer unidirectional streams are delivered by `accept_uni_stream(...)`. Pass
`stream_id` / `bidirectional` explicitly only for backends that cannot report
them; a direction that contradicts the QUIC stream ID is rejected with
`zmux.AdapterUnsupported`.

When the wrapped object is an aioquic `QuicConnectionProtocol`, the session
installs a per-instance `quic_event_received` wrapper so it can observe
`StreamReset`, `StopSendingReceived`, and `ConnectionTerminated` events before
aioquic's default handling.

## Stable API Coverage

Wrapped sessions implement `zmux.AsyncSession`:

- `accept_stream(...)` / `accept_uni_stream(...)`
- `open_stream(...)` / `open_uni_stream(...)`
- `open_and_send(...)` / `open_uni_and_send(...)`
- `close()`, `close_with_error(...)`, `wait(...)`, `closed`, `state`, and
  `stats`

Wrapped streams implement `zmux.AsyncStream`, `zmux.AsyncSendStream`, and
`zmux.AsyncRecvStream`:

- `stream_id`, `open_info`, `metadata`, and `update_metadata(...)`
- `read(...)`, `readinto(...)`, and `read_exact(...)`
- `write(...)`, `write_all(...)`, `write_vectored(...)`, and
  `write_final(...)`
- `close_read()`, `cancel_read(...)`, `close_write()`, `cancel_write(...)`,
  and `close_with_error(...)`
- read and write timeout helpers

Direction errors use the same core exception types as native ZMux:
`zmux.StreamNotReadable` for reads from send-only streams and
`zmux.StreamNotWritable` for writes to receive-only streams. Use
`zmux.AdapterUnsupported` only for adapter-only gaps such as native ZMux
session controls that QUIC streams cannot expose.

## Options

`accepted_prelude_read_timeout`:

- `0`: use `DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT`
- `None` or a negative value: disable the adapter-managed timeout
- positive number: timeout in seconds

Accepted QUIC streams whose adapter prelude does not arrive in time are
discarded instead of blocking later ready streams.

`accepted_prelude_max_concurrent`:

- `None` or `0`: use `default_accepted_prelude_max_concurrent()`
- positive number: per-session bound for concurrently parsing accepted stream
  preludes
- values above `MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT` are clamped

Set the process-wide default during startup when many sessions should share the
same value:

```python
zmux_aioquic.set_default_accepted_prelude_max_concurrent(16)
```

## Mapping

- `open_stream(...)` and `accept_stream(...)` map to QUIC bidirectional
  streams.
- `open_uni_stream(...)` and `accept_uni_stream(...)` map to QUIC
  unidirectional streams.
- Open-time ZMux metadata is carried in an adapter prelude:
  `varint(metadata_len)` followed by stream metadata TLVs.
- `OpenOptions` supports binary open info, initial priority, and initial group.
- `open_info` and `metadata` expose decoded opener metadata on accepted
  streams.
- Open-time metadata is validated before the QUIC stream is created, so an
  oversized `open_info` fails with `zmux.OpenMetadataTooLarge` without using a
  QUIC stream ID.
- `update_metadata(...)` works only before the local stream prelude is emitted.
  Later updates fail with `PriorityUpdateUnavailable`.
- `close_read()` maps to QUIC read-side cancellation (STOP_SENDING) with
  `ErrorCode.CANCELLED`.
- `cancel_read(code)` maps to QUIC read-side cancellation with that code.
- `close_write()` maps to QUIC send-side graceful close and returns once the
  FIN is queued.
- `cancel_write(code)` maps to QUIC send-side reset (RESET_STREAM) with that
  code.
- `close_with_error(code, reason)` is best-effort at stream scope.
- Stream resets and stops issued through aioquic's `QuicConnection` are
  followed by `transmit()`, so they reach the peer without waiting for other
  traffic.
- An accepted stream whose adapter prelude is malformed, oversized, or not
  received in time is never exposed; it is rejected with STOP_SENDING and, for
  bidirectional streams, RESET_STREAM carrying `ErrorCode.PROTOCOL`.
- After the peer FIN has been consumed, `read(...)` keeps returning `b""`.
  Ordinary zero-length writes return `0` without observing write-side state.
- Writes either hand all of their bytes to the QUIC stream or raise. When an
  error (such as `zmux.WriteTimeout`) comes after part of the data was already
  handed to the QUIC stream, the error carries that count as
  `characters_written`, like native sessions and `BlockingIOError`, so a retry
  can resume after those bytes.

Fresh write-side reset or abort visibility is not a portable adapter guarantee
because QUIC can discard previously written but unacknowledged stream data,
including a just-submitted metadata prelude.

## Errors

- A peer RESET_STREAM (code) fails reads on that stream with
  `zmux.ApplicationError(code)` (remote, reset). The local send half is not
  affected.
- A peer STOP_SENDING (code) fails later writes on that stream with
  `zmux.ApplicationError(code)` (remote, stopped). aioquic itself answers the
  stop with RESET_STREAM carrying `NO_ERROR`, not the peer's code.
- A peer QUIC application close with a nonzero code or a reason fails the
  session with `zmux.ApplicationError(code, reason)`, reported by `wait()`,
  `close_error`, and `peer_close_error`. A peer close with code 0 and no reason
  is a graceful close. Transport errors and idle timeouts fail the session
  with `zmux.SessionClosed`.
- When the connection ends, blocked accepts fail with `zmux.SessionClosed`,
  reads on streams without a peer FIN fail with the session error instead of
  returning EOF, and writes fail with the session error.
- QUIC stream-limit failures are normalized to `zmux.OpenLimited`.

Use helpers such as `zmux.error_code(...)`, `zmux.open_limited(...)`,
`zmux.adapter_unsupported(...)`, `zmux.priority_update_unavailable(...)`,
`zmux.session_closed(...)`, `zmux.stream_not_readable(...)`,
`zmux.stream_not_writable(...)`, `zmux.read_closed(...)`,
`zmux.write_closed(...)`, and `zmux.timeout(...)` instead of depending on
aioquic exception classes.

## Reduced Behavior

- No native ZMux `ping`, `go_away`, peer-close diagnostics, prefaces, or
  negotiated settings.
- No post-open native advisory frames such as native `PRIORITY_UPDATE`.
- No QUIC datagram, packet acknowledgement, RTT, or loss-state API.
- `stats` reports adapter-visible counters, not native ZMux runtime internals.

## Conformance

`target_claims()`, `target_implementation_profiles()`, and `target_suites()`
provide adapter conformance metadata for tests that exercise the stable async
session contract over aioquic.
