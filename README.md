# zmuxio

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

Carriers: TCP, TLS (`TlsConfig` from PEM paths or bytes), QUIC (with lanes),
WebSocket (`ws://`, and `wss://` with a `TlsConfig`), HTTP/1.1, HTTP/2
(prior knowledge or TLS; `Http2Connection` opens several pipes on one
connection), HTTP/3 and WebTransport — `dial_*` gives a `PipeIo`,
`connect_*` a `Session`, `Listener.serve_*` accepts. `pipe_from_streams(reader, writer)`
runs a session over any asyncio stream pair; its bytes pass through Python,
so it is slower than the built-in carriers.

Multipath: give both ends `Config(psk=...)` (or `tls_auth=True` over TLS/QUIC),
then `session.add_pipe(await zmux.dial_tcp(addr), priority=1, standby=False)`.
For an out-of-band join, `r = session.reserve_pipe()` and send `r.header` as
the `Zmux-Pipe-Join` request header (for example
`dial_websocket(url, headers=[("Zmux-Pipe-Join", r.header)])`), then
`r.attach(pipe)`. Resumption: `Config(resume_timeout=..., dead_timeout=...,
suspect_floor=..., probation=...)`, `session.revalidate_pipes()` after a
network change.

Early data: `Config(early_data=True)` toward a zmux peer sends the first
streams, with their preamble and `peer_priority`, before the peer's
parameters arrive. QUIC 0-RTT: keep one `QuicClient(tls, zero_rtt=True)`;
with `Config(carrier_early_data=True)` at both ends and
`serve_quic(..., zero_rtt=True)`, later connections to a server send their
first records as 0-RTT data (`client.connect` returns the session and a
`ZeroRtt` report). 0-RTT data can be replayed: use it only for requests
whose effect may happen twice.
Errors derive from `zmux.ZmuxError` and carry `kind`, `retryable` and `code`;
`EarlyDataRejected` means retry on a new session without early data.

License: Apache-2.0.
