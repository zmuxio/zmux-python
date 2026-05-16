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
`zmux.PriorityUpdateUnavailable` or `zmux.AdapterUnsupported`.

## Transports

ZMux runs over one reliable, ordered byte stream. The core package exposes small
transport protocols and helpers for custom integrations:

```python
class SyncByteStream(object):
    def read(self, max_bytes: int = 16384) -> bytes: ...
    def write_all(self, data: bytes) -> None: ...
    def close(self) -> None: ...
```

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
stream.close_write()                  # graceful send-half close
stream.close_read()                   # cancel local interest in reads
stream.close_with_error(0x100, "bye") # stream application error

session.close()
session.close_with_error(0x100, "bye")
session.wait()
```

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
