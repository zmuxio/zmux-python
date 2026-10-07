# zmuxio

Python package for the ZMux v1 single-link stream multiplexing protocol.

The PyPI distribution is `zmuxio`; the import package is `zmux`.

## Installation

```bash
pip install zmuxio
```

```python
import zmux
```

`zmuxio` keeps the core package free of QUIC dependencies. Install the aioquic
adapter only when your application already uses aioquic:

```bash
pip install zmuxio-aioquic
```

## Native ZMux

The core package contains the native ZMux implementation. It does not need
aioquic or any other adapter dependency.

Use `zmux.open(...)` when both peers can auto-negotiate roles, or
`zmux.client(...)` / `zmux.server(...)` when an outer protocol already assigns
the initiator and responder:

```python
import socket
import zmux

sock = socket.create_connection(("example.com", 443))

with zmux.client(sock) as session:
    stream = session.open_stream(zmux.OpenOptions(open_info=b"rpc"))
    stream.write_final(b"hello")
    response = stream.read(4096)
```

`zmux.open(...)`, `zmux.client(...)`, and `zmux.server(...)` return
`zmux.Conn`, the native synchronous implementation. `Conn` implements the
stable `zmux.Session` protocol, so application code can type against the common
interface while still using the native implementation directly.

## API Overview

Application code should depend on the stable session and stream protocols when
it wants to accept either the native implementation or an adapter:

- `zmux.Session` / `zmux.AsyncSession`
- `zmux.Stream` / `zmux.AsyncStream`
- `zmux.SendStream` / `zmux.AsyncSendStream`
- `zmux.RecvStream` / `zmux.AsyncRecvStream`

The native implementation is the primary implementation. Adapters such as
`zmuxio-aioquic` are optional integrations that implement the same stable API
shape and reuse the same public value and error types for other transports.

```python
import zmux
from zmux.session import Session


def echo_once(session: Session) -> None:
    stream = session.accept_stream()
    with stream:
        request = stream.read(65536)
        stream.write_final(request)
```

Open and use native streams:

```python
stream = session.open_stream()
stream.write_all(b"request")
stream.close_write()
response = stream.read(4096)

send = session.open_uni_and_send(b"event")
recv = session.accept_uni_stream()
```

Open and send the first payload in one call:

```python
stream = session.open_and_send(b"hello")
send = session.open_uni_and_send(b"hello")
```

`open_and_send(...)` leaves a bidirectional stream open. `open_uni_and_send(...)`
writes the final payload and closes the send side.

## Metadata And Priority

Use `OpenOptions` to attach opener metadata:

```python
options = zmux.OpenOptions(
    initial_priority=7,
    initial_group=2,
    open_info=b"rpc",
)

stream = session.open_stream(options)
```

The receiving side reads opener metadata from `stream.open_info` or
`stream.metadata`.

Before the stream metadata is emitted, implementations may also accept a
metadata update:

```python
stream.update_metadata(zmux.MetadataUpdate(priority=3))
```

If metadata cannot be represented by the current backend, implementations raise
`zmux.PriorityUpdateUnavailable` or `zmux.AdapterUnsupported`. Opener metadata
the session cannot carry (`open_info` without negotiated open metadata, or a
prefix larger than the peer's `max_frame_payload`) makes `open_stream()` raise
`zmux.OpenInfoUnavailable` or `zmux.OpenMetadataTooLarge` without using a
stream ID. An update made while the stream's first write is in progress waits
for that write (bounded by the write deadline) and then goes out as a priority
update. Stream group `0` means "no explicit group" and is reported as `None`.

## Transports

ZMux runs over one reliable, ordered byte stream. The core package exposes small
transport protocols and helpers for custom integrations:

```python
class SyncByteStream(object):
    def read(self, max_bytes: int = 16384) -> bytes: ...

    def write_all(self, data: bytes) -> None: ...

    def close(self) -> None: ...
```

A transport passed to `zmux.client()`/`zmux.server()` without `write_all()` or
`sendall()` is driven through `write()`, which must return the number of bytes
written, as `io.RawIOBase.write()` does; short writes are retried. `None` means
nothing was written (a non-blocking raw stream) and fails the session with
`zmux.TransportError` rather than being taken as a full write.

When a transport exposes read and write halves separately, join them:

```python
duplex = zmux.join(read_half, write_half)
```

The joined transport forwards addresses, deadlines, vectored writes, pause
handles, and close operations when the supplied halves expose compatible
methods.

## Closing And Errors

Stream close operations follow the same stable shape across implementations:

```python
stream.close_write()  # graceful send-half close
stream.close_read()  # cancel local interest in reads
stream.close_with_error(0x100, "bye")  # stream application error

session.close()
session.close_with_error(0x100, "bye")
session.wait()
```

`stream.close()` sends DATA|FIN if the send half is still open (falling back to
`RESET(CANCELLED)` when the FIN cannot be queued before the write deadline) and
STOP_SENDING if the read half is still open; halves the peer already finished
or reset are not an error. A repeated `close_with_error()` is a no-op, while
`close_write()` on a finished, reset or aborted send half raises. Once a peer
RESET or ABORT, a local abort, or session termination is visible, unread bytes
are dropped and reads raise that error with its code. DATA the peer already
had in flight when `close_read()` or `close_with_error()` took effect is
discarded with its session credit returned, up to the stream credit that was
still outstanding, and never fails the session; a stopped read half that gets
more than that is aborted with `FLOW_CONTROL`. A read returns EOF only
after the peer's FIN: when a session ends (even with `NO_ERROR`) before the peer
finished a stream, its reads raise the session error instead.

`session.close()` stops admitting local opens at once (they raise
`SessionClosed`), fails opened-but-never-written streams with
`REFUSED_STREAM`, and then waits only for streams with local send work still
outstanding; unaccepted or unread peer streams do not delay it.

On native sessions, `session.go_away(bidi, uni)` never lets the advertised
watermarks increase: a request an earlier GOAWAY already covers returns
without sending, and watermarks that are invalid or would increase raise a
local `ProtocolError`. `session.peer_go_away_error` reports the latest peer
GOAWAY cause, including code 0 with its reason. At most one locally originated
PING is outstanding; `ping()` waits (within its timeout) while another PING is
in flight, and an echo that does not fit both sides' control-payload limits
raises `FrameSizeError`.

Native stream writes either queue all of their bytes or raise. When an error (such as `WriteTimeout`) comes after part
of the data was already queued,
those bytes are still sent and the error carries their count as
`characters_written`, like `BlockingIOError`, so a retry can resume after them.
`zmuxio-aioquic` streams report partial writes the same way.

Use error helpers instead of matching exception text:

```python
def write_or_code(stream, payload):
    try:
        stream.write_all(payload)
    except Exception as exc:
        if zmux.session_closed(exc):
            return None
        if zmux.timeout(exc):
            raise
        return zmux.error_code(exc)
```

Common helpers include `session_closed`, `read_closed`, `write_closed`,
`stream_not_readable`, `stream_not_writable`, `open_limited`, `open_expired`,
`priority_update_unavailable`, `adapter_unsupported`, `timeout`,
`interrupted`, `error_code`, and `error_reason`.

## Configuration And Codec Helpers

`zmux.Config`, `zmux.Settings`, and `zmux.OpenOptions` are dataclasses. Start
from `zmux.default_config()` when an implementation accepts a config object.
Use `zmux.configure_default_config(...)` during process startup to adjust the
process-wide default template.

`Config.establishment_timeout` bounds session establishment: the local preface
is written while the peer preface is read, and both must finish within the
bound. It defaults to `zmux.DEFAULT_ESTABLISHMENT_TIMEOUT` (10 seconds); `None`
or `0` select the default and `math.inf` disables it. A stalled establishment
fails with an `INTERNAL`-coded error.

Native sessions hand every outbound frame to one writer thread, so stream
write timeouts, `ping(timeout=...)`, `close()` and keepalive stay bounded even
when the peer stops reading. A stream write that times out may already have
queued part of its data; that part is still delivered in order.

The public codec helpers are available for diagnostics, proxies, and
conformance tests:

```python
raw = zmux.encode_varint(64)
value, used = zmux.parse_varint(raw)

frame = zmux.parse_frame(packet)
payload = zmux.parse_data_payload(frame.payload, frame.flags)
```

## aioquic Adapter

`zmuxio-aioquic` wraps an established aioquic connection behind
`zmux.AsyncSession`:

```python
import zmux
import zmux_aioquic


async def run(connection) -> None:
    session = zmux_aioquic.wrap_session(connection)
    stream = await session.open_stream()
    await stream.write_final(b"hello")
```

See the adapter package README for aioquic-specific options and behavior.
