# zmuxio

[![CI](https://github.com/zmuxio/zmux-python/actions/workflows/ci.yml/badge.svg)](https://github.com/zmuxio/zmux-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zmuxio.svg)](https://pypi.org/project/zmuxio/)
[![Python versions](https://img.shields.io/pypi/pyversions/zmuxio.svg)](https://pypi.org/project/zmuxio/)
[![License](https://img.shields.io/pypi/l/zmuxio.svg)](LICENSE)

Python bindings for zmux: multiplexed streams and datagrams over one or many
reliable byte pipes, wire-compatible with QMux (draft-ietf-quic-qmux). With a
plain QMux peer a session is a single-pipe QMux session; between two zmux
endpoints it adds multipath, resumption, stream preambles, priorities and
datagram flows.

The protocol and all I/O run in the Rust implementation on a runtime managed
by the extension; Python awaits the results on its asyncio loop.

```
pip install zmuxio      # import zmux; Python 3.12+, also free-threaded 3.14t
```

Prebuilt wheels: Linux (manylinux) x86_64, aarch64, armv7, i686, ppc64le,
s390x and riscv64; Linux (musllinux) x86_64, aarch64, armv7 and i686; macOS
x86_64 and arm64; Windows x86_64 and x86. Other platforms (Windows on arm64,
for example) install from the sdist, which needs a Rust toolchain.

```python
import asyncio, zmux

async def main():
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")

        async def serve():
            async for session in listener:
                async for send, recv in session:
                    await send.write(await recv.read_to_end())
                    await send.finish()

        server = asyncio.create_task(serve())
        async with await zmux.connect_tcp(addr) as session:
            send, recv = await session.open_bi(info=b"echo")
            await send.write(b"hello")
            await send.finish()
            print(await recv.read_to_end())
        server.cancel()

asyncio.run(main())
```

Carriers: TCP, TLS (`TlsConfig` from PEM paths or bytes; clients default to
the bundled web roots), QUIC (with lanes), WebSocket, HTTP/1.1, HTTP/2
(`Http2Connection` opens several pipes on one connection), HTTP/3 and
WebTransport. `dial_x(target, *, ...)` gives a `PipeIo`,
`connect_x(target, *, tls=None, config=None, ...)` a `Session`, and
`Listener.serve_x(addr, *, ...)` accepts. `pipe_from_streams(reader, writer)`
runs a session over any asyncio stream pair (slower: bytes pass through
Python).

```python
session = await zmux.connect_quic("example.net:443", config=zmux.Config(idle_timeout=30))
async with session:
    send, recv = await session.open_bi(info=b"route", priority=zmux.Priority(1))
    async with send:                      # finish on exit, reset on error
        await send.write(b"request")
    async for chunk in recv:              # until the end of the stream
        ...
```

Streams: `finish()` ends the sending half, `reset(code)` abandons it,
`recv.stop(code)` asks the peer to stop sending. Every coroutine is
cancellation-safe; use `asyncio.timeout()` for deadlines (durations are
seconds). `open_connection(session)` returns an asyncio-style
`(reader, StreamWriter)` pair whose `drain()` applies backpressure.

Events and statistics:

```python
async for event in session.events():
    match event:
        case zmux.PipeStateChanged(pipe=p, state=zmux.PipeState.FAILED, failure=why):
            log.warning("pipe %d failed: %s", p, why)
        case zmux.Suspended() | zmux.Resumed():
            log.info("%s", event.kind)
print(session.stats().bytes_sent, [s.smoothed_rtt for s in session.pipe_stats()])
```

Multipath: give both ends `Config(psk=...)` (or `tls_auth=True` over
TLS/QUIC), then
`session.add_pipe(await zmux.dial_tcp(addr), policy=zmux.PipePolicy(priority=1))`.
For an out-of-band join, `r = session.reserve_pipe()`, send `r.header` as the
`Zmux-Pipe-Join` request header
(`dial_websocket(url, headers={"Zmux-Pipe-Join": r.header})`), then
`r.attach(pipe)`. Resumption: `Config(resume_timeout=..., dead_timeout=...)`,
and `session.revalidate_pipes()` after a network change.

Early data: `Config(early_data=True)` toward a zmux peer sends the first
streams before the peer's parameters arrive. QUIC 0-RTT: keep one
`QuicClient(tls, zero_rtt=True)` with `Config(carrier_early_data=True)` at
both ends and `serve_quic(..., zero_rtt=True)`; `session.zero_rtt` reports
what happened. Early data can be replayed, so servers should refuse
non-idempotent requests on replayable streams:

```python
async for send, recv in session:
    if recv.is_replayable and not idempotent(recv.preamble.info):
        await recv.stop(1)
        await send.reset(1)
        continue
    ...
```

On `EarlyDataRejected` (`retryable` is true) open the streams again on a new
session without early data, and `QuicClient.forget(server_name)`.

Errors derive from `zmux.ZmuxError` with `kind` (`ErrorKind`), `retryable`
and `code`; `SessionClosed` adds `reason` and `remote`.

License: Apache-2.0.
