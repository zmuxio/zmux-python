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

Prebuilt wheels: Linux (manylinux) x86_64, aarch64, armv7, ppc64le,
s390x and riscv64; Linux (musllinux) x86_64, aarch64, armv7 and i686; macOS
x86_64 and arm64; Windows x86_64 and x86. Other platforms (Windows on arm64,
for example) install from the sdist, which needs a Rust toolchain.

## A first session

This program runs as it is: an echo server and a client in one process.

```python
import asyncio

import zmux


async def main() -> None:
    async with zmux.Listener() as listener:
        host, port = await listener.serve_tcp("127.0.0.1", 0)

        async def serve() -> None:
            async for session in listener:
                async with session:
                    async for send, recv in session:
                        await send.write(await recv.read_to_end())
                        await send.finish()

        server = asyncio.create_task(serve())
        async with await zmux.connect_tcp(host, port) as session:
            send, recv = await session.open_bi(info=b"echo")
            await send.write(b"hello")
            await send.finish()
            print(await recv.read_to_end())
        server.cancel()


asyncio.run(main())
```

The other examples below are fragments: they assume a running event loop and
the names they use.

The root namespace holds what an application uses: sessions, listeners, pipes
and streams, their configuration, options, events, statistics and errors, and
the dial and serve entries. The rest has a namespace of its own: `zmux.adapter`
(what only the author of a carrier adapter or of an accept loop needs),
`zmux.sched` (the scheduler and redundancy settings), `zmux.shaping` and
`zmux.helpers` (pipe pools, `splice`, limiters, duplicate sessions, packet streams).

## Terms

A **carrier** is one underlying connection that moves bytes or messages: a
TCP or TLS connection, a QUIC connection, an HTTP request, a WebSocket, a
stream of another session. A **pipe input** (`PipeIo`) is a carrier, or the
pair of carriers of a split, not yet given to a session. A **pipe** is one
path of a session between the two endpoints, carried by a carrier and named
by a `PipeId`. A **stream** belongs to the session, not to a pipe.

## Carriers

`dial_x(host, port, *, ...)` (a URL for the WebSocket, HTTP/3 and WebTransport
carriers) opens a carrier and returns a `PipeIo`; `connect_x` takes the same
arguments and a `config=`, dials, and returns a `Session`;
`Listener.serve_x(host, port, *, ...)` accepts and returns the bound
`(host, port)`. A host you pass, alone or in a `(host, port)` address, is a
`str` (a name or an IP literal) or an `ipaddress.IPv4Address` /
`IPv6Address`. An address reported to you (a peer, a source) is a `(host,
port)` tuple of `str` and `int`. `Session.connect(pipe, config=...)`,
`Session.accept(pipe, config=...)` and `Session.symmetric(pipe, config=...)`
(roles negotiated) start a session on a pipe input of your own.

| Carrier kind (`CarrierKind`) | Dial | Connect | Serve | `Candidate` |
|---|---|---|---|---|
| (none) | `dial_tcp` | `connect_tcp` | `serve_tcp` | |
| (none) | `dial_tls` | `connect_tls` | `serve_tls` | |
| `QUIC` | `dial_quic`, `QuicClient.dial` | `connect_quic`, `QuicClient.connect` | `serve_quic` | `Candidate.quic` |
| `WEBSOCKET` | `dial_websocket` | `connect_websocket` | `serve_websocket`, `serve_http(websocket=True)` | `Candidate.websocket` |
| `STREAMING` | `dial_streaming`, `dial_http2`, `Http2Connection.dial` then `open_pipe()` | `connect_streaming`, `connect_http2` | `serve_http` | `Candidate.streaming` |
| `SPLIT` | `dial_split`, `Http2Connection.open_split()` | `connect_split` | `serve_http` | `Candidate.split` |
| `EXCHANGE` | `dial_exchange` | `connect_exchange` | `serve_http(exchange=...)` | `Candidate.exchange` |
| `HTTP3` | `dial_http3` | `connect_http3` | `serve_http3` | `Candidate.http3` |
| `WEBTRANSPORT` | `dial_webtransport` | `connect_webtransport` | `serve_webtransport` | `Candidate.webtransport` |

TLS settings come from `TlsConfig` (PEM paths or bytes; clients default to
the bundled web roots). `pipe_from_streams(reader, writer)` runs a session
over any asyncio stream pair (slower: bytes pass through Python), and
`zmux.adapter.pipe_pair()` gives an in-memory pipe whose other end you drive.

A `PipeIo`'s settings are properties, changed in place until the input is
given to a session: `carrier_kind`, `variant` (the host's name of the
transform a carrier runs, reported in `PipeStats.variant`), `write_overhead`
and `terminated_tls`; `declare_secure()` declares the carrier secure for the
Bound record mode. What a carrier's author sets once is a parameter of the
function that builds the input (`pipe_from_streams`, `zmux.adapter.pipe_pair`):
`max_record`, the largest record plaintext, `exporter`, the exporter of an
end-to-end handshake, and `unsent` (a `zmux.adapter.UnsentCount` the
application keeps up to date, read by the session without the interpreter
lock).

Fragment, a QUIC session with a priority:

```python
session = await zmux.connect_quic(
    "example.net", 443, config=zmux.Config(max_idle_timeout=30.0)
)
async with session:
    send, recv = await session.open_bi(info=b"route", priority=zmux.Priority(1))
    async with send:  # finish on exit, reset on error
        await send.write(b"request")
    async for chunk in recv:  # until the end of the stream
        ...
```

HTTP: one endpoint serves every HTTP carrier on one path, each request told
apart by its head. `serve_http(host, port, exchange=..., websocket=True)`
takes bidirectional POSTs (`dial_streaming`), uplink POSTs and downlink GETs
(`dial_streaming(..., direction=zmux.Direction.OUT)` or `Direction.IN`), split
bootstraps (`dial_split`: a POST and a GET paired by a token, for paths that
stream each body but not both on one request; run them over TLS), exchange requests
and WebSocket upgrades. The exchange carrier is for paths that pass only
plain request and response HTTP; both ends share `psk` and `encoding`.
Fragment:

```python
opts = zmux.ExchangeOptions(psk=b"shared secret", encoding="base64")
await listener.serve_http("0.0.0.0", 8080, exchange=opts)  # server
session = await zmux.connect_exchange("example.net", 8080, options=opts)  # client
```

## Carrier choice

A carrier choice picks among kinds for paths through reverse proxies and
CDNs: `CarrierChoice.explicit(candidate)` uses one kind and reports its
failure; `CarrierChoice.auto([...])` tries candidates in order of preference
(no early data, no racing), remembers per key in a `CarrierCache` which kinds
passed, and with `max_pipes` above 1 starts on the most robust one and moves
to a preferred kind that joins. `CarrierChoicePolicy` holds the cache, key
and timers. The choice and every try are session events (`CarrierChosen`,
`CarrierCandidate`) and in `session.stats()`. Fragment:

```python
auth = zmux.PrefixAuth(b"shared secret", slot=30)
choice = zmux.CarrierChoice.auto(
    [
        zmux.Candidate.websocket("wss://example.net/zmux", carrier_credential=auth),
        zmux.Candidate.streaming("example.net", 80, carrier_credential=auth),
        zmux.Candidate.split("example.net", 80, carrier_credential=auth),
        zmux.Candidate.exchange("example.net", 80, options=opts),
    ]
)
policy = zmux.CarrierChoicePolicy(cache=cache, key="example.net|office")
session = await zmux.connect_choice(choice, choice_policy=policy)
print(session.stats().carrier)
```

`PipePool(2, choice=choice, choice_policy=policy)` keeps further members over
the choice's kinds the same way (`session.maintain_pipes(pool)`). The cache
outlives the process as JSON text: `text = cache.snapshot()`, later
`cache.restore(text)`.

## Configuration

`zmux.Config` is a frozen dataclass of keyword fields. A keyword left out
keeps the library's default, which is the field's default; `None` is the
off, no-timeout or unlimited setting of a field that has one (and raises
`ValueError` for any other). Settings that are not values have objects of
their own: `zmux.AUTO` (an automatic cap or a derived value, the default
where a field has it), `zmux.STAGED` (staged unidirectional credit, the
default), `zmux.INHERIT` (a pipe setting that follows the session's, the
default of those) and `zmux.CLEAR` (`Pipe.update` and the settings of
`PipeOptions` that it changes). Durations are seconds
(`float`). Fragment:

```python
config = zmux.Config(
    max_idle_timeout=60.0,
    liveness=zmux.Liveness(keep_alive_period=10.0, probe_interval=None),
    memory_budget=None,  # unlimited
    max_stream_receive_window=zmux.AUTO,  # the default
    scheduler=zmux.sched.Scheduler.SPREAD_ETA,
)
```

`Config(liveness=zmux.Liveness(...))` holds the keep-alive and probe
settings; a running session replaces them with `session.liveness = ...`.
The other runtime settings of a session are writable properties too, and read
back as in force, whether the configuration or an assignment set them:
`scheduler`, `quality_band`, `capacity_floor`, `shaper` (an opaque
`zmux.shaping.InstalledShaper`) and `shaping_limits`; an invalid value raises `ValueError` and
changes nothing. Use `config.replace(...)` to derive a variant. The defaults are exported as
constants (`DEFAULT_KEEP_ALIVE_PERIOD`, `DEFAULT_IDLE_TIMEOUT`,
`DEFAULT_PROBE_JITTER`, `DEFAULT_STANDBY_PROBE`, `DEFAULT_MAX_RECORD_SIZE`,
`DEFAULT_MIN_BACKOFF`, `DEFAULT_MAX_BACKOFF`, `DEFAULT_BACKOFF_JITTER`,
`DEFAULT_LANES`, `DEFAULT_JOIN_TIMEOUT`). `zmux.MAX_STREAM_CREDIT` (2**60) is the largest stream
count: pass it as `max_incoming_streams` or `max_incoming_uni_streams` to
let the peer open as many streams as the protocol can count.

Datagram queues are bounded per stream by `datagram_stream_queue` (32
datagrams) and `datagram_stream_bytes` (512 KiB; `None`: the count alone),
and the session queue by `datagram_receive_queue` and
`datagram_receive_bytes` (1 MiB), which does not count the stream queues.
`session.send_datagram(data)` never waits and drops the oldest queued
datagram when the send queue is full; `await session.send_datagram_wait(data)`
waits for room instead and is cancellation-safe.

## Streams

`open_bi(info=, tlvs=, pipe_carrier=, priority=, peer_priority=)` fixes the
preamble before the first frame; `try_open_bi()` and `try_open_uni()` open
without waiting.
`finish()` ends the sending part, `reset(code)` abandons it and
`recv.stop(code)` asks the peer to stop sending; `reset` and `stop` return at
once, like `asyncio.Transport.abort`; both always take the code. Every
coroutine is cancellation-safe except `write`: a cancelled `write` may have
sent a prefix of its data and says nothing about how much, so reset the
stream rather than write to it again. `await send.write_some(data)` and
`await send.writev(buffers)` are the cancellation-safe writes: they take a
prefix once the stream has room and return its length; cancelled while they
wait, they took nothing (a cancellation that lands just as one completes
cannot take the bytes back; `stats().bytes_written` tells). Use
`asyncio.timeout()` for deadlines. `send.priority` is writable, and so are the runtime settings of a stream, which
read back as in force: `send.send_buffer`, `send.scheduler`,
`send.redundant`, `recv.receive_window` and `recv.peer_priority`;
`await recv.read_chunk(n)` returns a `memoryview` of the received buffer, and
every write takes any buffer-protocol object without copying it (the caller
leaves a mutable buffer unchanged until the write returned).

`open_bi` and `accept_bi` give a `BiStream`, which unpacks as `send, recv`.
`await session.open_stream_pair(limit=...)` returns a `(StreamPairReader,
StreamPairWriter)` pair: the reader has the reads of `asyncio.StreamReader`
(`read`, `readexactly`, `readline`, `readuntil`, `at_eof`; `limit` is its
buffer limit), the writer the writes of `asyncio.StreamWriter` (`write`,
`drain`, `close`, `abort(code)`, `wait_closed`); after a failed send every
later write raises that error.
Fragment:

```python
reader, writer = await session.open_stream_pair()
writer.write(b"GET /\n")
await writer.drain()
line = await reader.readline()
```

`session.next_event()` and `session.events()` read one event queue,
`session.read_datagram()` and `session.datagrams()` one datagram queue: each
item goes to one reader. Fragment:

```python
async for event in session.events():
    match event:
        case zmux.PipeFailed(pipe=p, failure=why):
            log.warning("pipe %d failed: %s", p, why)
        case zmux.ResumeUnattended():
            log.warning("suspended, and nothing redials")
```

Relays and nested sessions: `await zmux.helpers.splice((send_a, recv_a), (send_b,
recv_b), a_to_b=limiter)` forwards two streams into each other.
`zmux.helpers.SpliceAbort()` given as `abort=` ends the splices sharing it
with a chosen code: `abort.abort(0x77)` resets the downstream parts and stops
the upstream parts with it, and the directions still running report
`SpliceEnd.CANCELLED` with `code` (an aborted handle at the start ends the
splice at once); cancelling the task keeps resetting with `ZMUX_CANCELLED`.
`await session.open_pipe_stream(info=..., tlvs=...)` opens a carrier stream
and `zmux.adapter.stream_pipe(send, recv)` wraps an accepted one, either a `PipeIo`.

Packet streams: `await session.open_packet_stream(info=..., policy=...)`
opens a stream and `zmux.helpers.PacketStream(send, recv, policy=...)` wraps
an accepted one; each packet goes as a datagram of the stream or as a
DATAGRAM capsule in its bytes, by `zmux.helpers.SendPolicy`
(`PREFER_DATAGRAM`, `STREAM_ONLY`, `DATAGRAM_ONLY`). `send(payload,
context=0)` returns how it left (`zmux.helpers.Sent`), `recv()` a `Packet`
or `None` once the peer called `close()`, and `async for` iterates the
packets; `split()` gives a sender and a receiver for two tasks, `stats()` the
counters. Its send and receive are cancellation-safe. Errors sit under
`zmux.PacketError`: `PacketTooLargeError` above `max_packet` (65535 by
default), and `MalformedPacketError` when the peer's bytes were malformed
(the stream is then reset and stopped with `ZMUX_PACKET_ERROR`).
`await zmux.helpers.splice_packets(a, b)` relays two packet streams, sending
a datagram that does not fit the next hop as a capsule. Fragment:

```python
packets = await session.open_packet_stream()
await packets.send(b"ping", context=1)
async for packet in packets:
    print(packet.context, packet.payload)
```

## Closing

`session.close(code=0, reason=b"")` starts the graceful close and returns at
once: the data the streams wrote is sent first, so that the peer reads it
ahead of the code, then CONNECTION_CLOSE, within 1 s. With no arguments it
is a close without error; give an application `code` and `reason` when the
peer should learn why the session ended. `session.abort(code, reason)` ends
the session at once with an application error, draining nothing. Both are
idempotent: the first call decides what is sent, code and reason included,
and an `abort` while a close is still flushing ends it at once.
`await session.shutdown(code, reason)` sends GOAWAY and closes once the open
streams ended.

`await session.wait_closed()` waits for the session's whole end and returns
the `SessionClosedError` that describes it (it is not raised): it returns
once every pipe's inbound side has ended (the peer read the close and ended
its side) or the linger timeout has passed, so a return before the linger
confirms that the peer read the close. An application that exits right after
`close()` awaits it first. "Delivered, or given up after d" is the caller's
own bound, not an option; the timeout changes nothing in the session:

```python
session.close(0x2A, b"replaced")
try:
    async with asyncio.timeout(5):
        end = await session.wait_closed()
        print(end.code, end.reason, end.remote)
except TimeoutError:
    ...  # not confirmed within 5 s; the linger goes on
```

`async with session:` closes with code 0 and waits on a normal exit; an exit
by an exception starts a close with `zmux.ApplicationErrorCode.ZMUX_CANCELLED`
and an empty reason and returns at once, so the peer can tell it from a
normal end. The same code is what leaving `async with stream:` by an
exception resets a sending part with (a normal exit finishes it; both
return at once); leaving `async with` on a receiving part stops it with code 0
unless it ended (automatic release); a pipe left by an exception is aborted. `async for` over a session, a listener or its
datagrams ends silently only on a clean end (a listener closed here, a
session closed by either application with code 0) and raises the error
otherwise.

On the receiving side, a peer's close does not discard what it sent before:
for up to the linger timeout, streams the application opened or accepted
still deliver the data received ahead of the close and then raise the close's
code and reason, while new streams and writes fail at once. A reader that
pauses longer than the linger loses what it has not read. Only a close the
peer sent starts this read drain; a carrier that just ends gives none. During
it `recv.stop(code)` and `send.reset(code)` raise the session's error (a `stop` still
discards the unread data), and dropping or stopping the last stream with
unread data ends the drain early. The cleanup of `async with` ignores that
error.

Over QUIC (`dial_quic`, `QuicClient`, `serve_quic`, and the HTTP/3 and
WebTransport carriers) the connection is closed only after the zmux close was
delivered or lingered, and with the same application code.

## Multipath and resume

Give both ends `Config(max_pipes=8, pipe_auth=zmux.PipeAuth.psk(key).with_end_to_end())`
(or `PipeAuth.exporter()` over TLS or QUIC; a first pipe from `establish`
needs no `pipe_auth`). Then, fragment:

```python
pipe = await session.add_pipe(
    await zmux.dial_tcp(host, port),
    options=zmux.PipeOptions(send_priority=1, receive_priority=1),
)
pipe.update(weight=2, send_priority=zmux.CLEAR)  # CLEAR: follow the peer again
```

`add_pipe` returns once the peer attached the pipe (`return_on_reply=True`:
once the Reply is verified), within `Config(join_timeout=...)`, and raises
`zmux.JoinRefusedError` when the peer refused the join and
`zmux.DeadlineExceededError` when the bound passed. `PipeOptions` holds every
option of a pipe; `pipe.update(**fields)` is the one way to change the
settings of a live pipe, together: `send_priority`, `receive_priority`,
`send_standby`, `receive_standby`, `weight`, `probation`, `liveness` and
`quality_band`, each left out (kept), `zmux.CLEAR` (cleared) or a value (set).
`PipeOptions` takes the same fields in the same form, `zmux.CLEAR` being their
default. A pipe's own liveness is `PipeOptions(liveness=zmux.PipeLiveness(...))`.
`await pipe.wait_closed()` waits for a pipe's end.

Pools: `handle = session.maintain_pipes(zmux.helpers.PipePool(count, dial))` keeps
`count` usable pipes dialled by the async `dial()`, with backoff, rotation
(`rotate_max_bytes`, `rotate_max_age`) and an optional `pool_policy`;
`join=` takes groups of pipes such as `zmux.join_split`, `choice=` a carrier
choice, and `backoff=` a `zmux.Backoff`. `handle.stop()` ends it.

Resume: with `resume_timeout` set, a session whose pipes are lost waits that
long for a pipe to join again; a `redial` hook dials it, waiting by
`Config(redial_backoff=zmux.Backoff(1.0, 60.0, jitter=0.2))` between
attempts (these are the defaults; `jitter=0` is the fixed schedule). Fragment:

```python
async def redial(direction: zmux.Direction) -> zmux.PipeIo:
    return await zmux.dial_tcp(host, port)


config = zmux.Config(
    pipe_auth=zmux.PipeAuth.psk(key).with_end_to_end(),
    resume_timeout=60.0,
    redial=redial,
    logger=logging.getLogger("zmux"),
)
```

A suspected leak of a session-level secret is answered by
`await session.replace_pipes()`, which advances the epoch and replaces every
pipe through `redial`; bound it with `asyncio.timeout(seconds)`.

## Admission

`ListenerConfig(admission=...)` decides on each new carrier at every entry
before anything is answered, and `dial_x(..., carrier_credential=...)` presents
what it checks. `PrefixAuth` tokens are the shared mechanism: a token is the
carrier's first bytes, or the `Zmux-Prefix-Auth` request header on WebSocket
and WebTransport. Fragment:

```python
auth = zmux.PrefixAuth(b"shared secret", slot=30, bind_tls=True)
listener = zmux.Listener(
    listener_config=zmux.ListenerConfig(
        admission=zmux.Admission.prefix_auth(auth, skew=1)
    )
)
await listener.serve_websocket("0.0.0.0", 443, tls=server_tls)
pipe = await zmux.dial_websocket("wss://example.net/", carrier_credential=auth)
```

`Admission(decide, *, peek=N)` takes a decision of your own:
`decide(info, prefix)` gets the `CarrierInfo` and up to `N` first bytes, and
returns an `AdmissionVerdict` (`accept(skip, value=...)`, `FALLBACK`,
`STALL`, `CLOSE`, `more(need)`), synchronously or `async`. An accept's
`value` is the carrier's admitted value (`session.admitted`,
`pipe.admitted`). A carrier credential of your own is any object with
`prefix(info)` and `header(info)` (`zmux.CarrierCredential`).
`Listener(config=..., listener_config=...)` takes the sessions' `Config` and
the listener's own `ListenerConfig`, whose `max_pending` (1024; `None`:
unlimited) bounds every carrier before it enters a session.
`max_pending_per_source` counts a source by its prefix, `source_prefix_v4`
(1 to 32, default 32) for IPv4 and `source_prefix_v6` (1 to 128, default 64)
for IPv6; a value outside its range raises `ValueError`.

`ListenerConfig(inbound_transform=f)` runs `f(pipe, hint)` for every carrier
after its admission and goes on with the carrier it returns. Fragment:

```python
async def tls(reader, writer):
    await writer.start_tls(server_context)
    return reader, writer


async def transform(pipe, hint):
    pipe = await pipe.wrap(tls, server_side=True)
    pipe.write_overhead = 22
    return pipe


listener = zmux.Listener(
    listener_config=zmux.ListenerConfig(inbound_transform=transform)
)
```

## Secure carrier

`zmux.establish` runs the secure carrier's handshake on a carrier; a
listener runs the server's side with `secure_server`. Joins then take their
keys from it. Fragment:

```python
config = zmux.Config(max_pipes=4)  # the secure carrier is the join source
handle, psk = zmux.adapter.derive_handle_psk(secret, b"my-domain")
listener = zmux.Listener(
    config=config,
    listener_config=zmux.ListenerConfig(
        secure_server=zmux.SecureServer(gate, node_key)
    ),
)

pipe, peer = await zmux.establish(
    await zmux.dial_tcp(host, port),
    verifier=zmux.PinVerifier(key_id),
    handle=handle,
    psk=psk,
)
session = await zmux.Session.connect(pipe, config=config)
```

`gate` is any object with `resolve(handle, source)`, `credential(handle,
profile, local_context, source)` and `commit(handle, peer, source)`. A
verifier is any object with `verify(input)` returning a `VerifyVerdict`, or
raising `VerifyRejectedError` or `VerifyUnavailableError`; each callback may
be synchronous or `async`. `signer=` takes a `zmux.SigningKey` (of
`zmux.KeyAlg.MLDSA44`) or any object with `proof_key` and `sign(message)`.
`max_app_data` bounds the peer's handshake application data (256 bytes;
`None`: no bound beyond the message).

## Errors

Every error class zmux defines derives from `zmux.ZmuxError` (with `kind`,
`retryable` and `code`) and, where one fits, from the built-in exception for
the same condition. The end of a session is `SessionClosedError` (a
`ConnectionError`) with the subclasses `ApplicationClosedError`,
`TransportClosedError`, `IdleTimeoutError`, `HandshakeTimeoutError`,
`ResumeTimeoutError`, `PipesLostError`, `ResumeFailedError` and
`EarlyDataRejectedError`: it is never a `TimeoutError`, so code that retries
timed-out operations does not retry on it. `DeadlineExceededError` (a
`TimeoutError`) is a bound the library applies, such as `join_timeout`, and
the object stays usable; your own `asyncio.timeout` raises its own
`TimeoutError`. `StreamResetError` and `StreamStoppedError` are
`ConnectionError`s; `StreamClosedError` and `ListenerClosedError` say that
this end closed the stream direction or listener; `IncompleteReadError` is an
`asyncio.IncompleteReadError` (the one `StreamPairReader` raises too);
`InvalidArgumentError` and `PreambleTooLargeError` are `ValueError`s, as are
the mistakes the binding finds in an argument. Errors are classified by what
happened, not by the call (`GoingAwayError` and `StreamRejectedError` are
stream errors wherever they are raised). Fragment:

```python
try:
    await recv.read_to_end()
except zmux.ApplicationClosedError as e:
    print("closed by", "peer" if e.remote else "us", e.code)
except (zmux.ResumeTimeoutError, zmux.PipesLostError) as e:
    print("lost; last pipe:", e.__cause__)
```

## Shaping and early data

`session.shaper = zmux.shaping.Shaper(definition=...)` (or a
`zmux.shaping.ShapingBundle`; `None` removes it), `Config(shaping=...,
shaping_limits=..., shaping_budget=...)` and `ShapingBundle` take JSON
definitions run natively; no Python code runs per record. Bounds left unset
keep the library's defaults (`ShapingLimits.max_delay`,
`ShapingSizeLimits.max_slots`); `None` lifts a bound.

`Config(early_data=True)` toward a zmux peer sends the first streams before
the peer's parameters arrive. QUIC 0-RTT: keep one
`QuicClient(tls, zero_rtt=True)` with `Config(carrier_early_data=True)` at
both ends and `serve_quic(..., zero_rtt=True)`. Early data can be replayed,
so servers should refuse non-idempotent requests on replayable streams.
Fragment:

```python
async for send, recv in session:
    if recv.is_replayable and not idempotent(recv.preamble.info):
        recv.stop(1)
        send.reset(1)
        continue
    ...
```

License: Apache-2.0.
