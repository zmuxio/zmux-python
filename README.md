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
and `terminated_tls`; `declare_carrier_secure()` declares the carrier secure for the
Bound record mode, and `set_max_record(n)` limits the largest record
plaintext the carrier takes (at least 8192, the carrier record floor; no upper
bound; the smaller limit holds; a pipe whose limit falls below 8192 after a
Sealed transform's overhead is refused). What a carrier's author sets once is a parameter of the
function that builds the input (`pipe_from_streams`, `zmux.adapter.pipe_pair`):
`max_record` (as `set_max_record`), `exporter`, the exporter of an
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
default of those, and the unset value of every updatable field of a
`PipeOptions`) and `zmux.CLEAR` (only `Pipe.update` clears a setting; a
`PipeOptions` given `CLEAR` raises `TypeError`). Durations are seconds
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
The other runtime settings of a session are writable properties too. Each
reads back what the session holds (the last assignment, or the configuration
that set it), never fails and still answers after the session ended:
`scheduler` (its name), `quality_band` and `capacity_floor` (`None` while
unset), `shaper` (an opaque `zmux.shaping.InstalledShaper`) and
`shaping_limits`; an invalid value raises `ValueError` and changes nothing. `zmux.QualityBand(rtt=None, rate_ratio=None, min_interval=1.0)`
reports a pipe's quality once its RTT moved by more than `rtt` seconds
(positive) or its rate by more than the factor `rate_ratio` (at least 1; 1
reports every change), at most once per `min_interval` seconds (positive;
`None`: no minimum); a half left `None` reports nothing, a band with both
halves `None` raises `ValueError`, and `session.quality_band = None` turns the
reports off. `zmux.CapacityFloor(rate, recovery_ratio=1.25)` takes a `rate` of
at least 1 and a finite `recovery_ratio` of at least 1. A pipe follows the
session's band by default (`PipeOptions(quality_band=zmux.INHERIT)`, which
`pipe.update(quality_band=zmux.CLEAR)` returns to), has a band of its own
(`quality_band=band`), or is off whatever the session's band is
(`quality_band=None`). Use `config.replace(...)` to derive a variant. The defaults are exported as
constants (`DEFAULT_KEEP_ALIVE_PERIOD`, `DEFAULT_MAX_IDLE_TIMEOUT`,
`DEFAULT_PROBE_JITTER`, `DEFAULT_STANDBY_PROBE`, `DEFAULT_MAX_RECORD_SIZE`,
`DEFAULT_MIN_BACKOFF`, `DEFAULT_MAX_BACKOFF`, `DEFAULT_BACKOFF_JITTER`,
`DEFAULT_MAX_LANES`, `DEFAULT_JOIN_TIMEOUT`, `DEFAULT_RECOVERY_RATIO`,
`DEFAULT_MIN_INTERVAL`; `DEFAULT_LANES` is the QUIC carriers' lane count, a
different default than `DEFAULT_MAX_LANES`, the lanes accepted per inbound
pipe). `zmux.MAX_STREAM_CREDIT` (2**60) is the largest stream
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
`await send.writev(buffers)` are the cancellation-safe writes: they wait for
`await send.writable()` (room in the send buffer, which takes nothing; it
returns the bytes `try_write` takes now), then write synchronously and return
the length taken, so a cancelled call took nothing. `send_capacity()` and
`wait_send_capacity(minimum)` report the flow-control credit instead. `send.try_write(data)` and
`send.try_writev(buffers)` write without waiting (0 when there is no room).
Reading mirrors it: `await recv.wait_readable()` returns `None` once the next
read returns at once, that is when data is readable or the part has ended (a
FIN, a reset, your own `stop`, the session's end), and takes nothing; the end
is reported once, by the read that follows. `recv.try_read(n=65536)` reads
without waiting: the bytes, `None` when nothing is readable now, `b""` once
the stream ended with a FIN and everything was read, and a reset or the
session's end raises as `read` does. Wait, then `try_read`, is a read that a
cancellation cannot lose data from.
Use
`asyncio.timeout()` for deadlines. `send.priority` is writable, and so are the runtime settings of a stream. Each
reads back the value the part holds, never as the session's value it follows:
`send.priority` (a new part holds `zmux.Priority.LOCAL_DEFAULT`, urgency 3 and
incremental; `Priority.WIRE_DEFAULT`, urgency 3 and not incremental, is what
the wire means without a signal; the peer's update replaces the local value if
it comes later), `send.send_buffer`, `send.scheduler` and `send.redundant`
(`None` follows the session), `recv.receive_window` and `recv.peer_priority`
(`None` when none was asked). A reading never fails and never waits: it
answers while a write, `flush` or `wait_send_capacity` holds the part, and so do
`send.send_datagram` and `send.max_datagram_size`. An
assignment does not take the part either: it works meanwhile too, and a
raised `send.send_buffer` wakes a write that waits for room;
`await recv.read_chunk(n)` returns a `memoryview` of the received buffer, and
`recv.preamble_priority` is the priority the peer put in the stream's opening
preamble (`None` when it sent none), for a relay that copies it to the next
hop; every write takes any buffer-protocol object: `bytes` (or a contiguous
`memoryview` of `bytes`) goes without a copy, any other buffer is copied when
the call is made, so it may be reused at once.

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
recv_b), a_to_b=limiter)` forwards two streams into each other; a limiter
(`zmux.helpers.Limiter`) reserves bytes with `acquire(min, max)` and
`try_acquire(min, max)` and takes back what was not forwarded with
`refund(n)`, all on the event loop. A stream direction asks `acquire(1, k)`
per chunk; `splice_packets` asks `acquire(n, n)` per whole capsule; a
forwarded stream datagram needs `try_acquire(n, n)` and is dropped without a
grant. An `acquire` that raises ends the direction with
`SpliceEnd.LIMITER_FAILED`.
The result is a `zmux.helpers.SpliceResult` of two `SpliceDirection`s
(`a_to_b`, `b_to_a`) with `bytes`, `datagram_bytes`, `datagrams_dropped`
(every datagram received and not forwarded), `datagrams_too_large` (of those,
the ones dropped for their size: larger than a datagram of the downstream
stream, or, in `splice_packets`, larger than `DEFAULT_MAX_PACKET`),
`datagrams_limited`, `datagrams_as_capsules`, `end` (a `SpliceEnd`) and `code`.
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
and an `abort` while a close is still flushing ends it at once. A reason
above 1024 bytes is cut to at most 1024, never inside a UTF-8 character.
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
pipe.options.send_priority  # zmux.INHERIT: unset, as a PipeOptions writes it
```

`add_pipe` returns once the peer attached the pipe (`return_on_reply=True`:
once the Reply is verified, after which `await pipe.wait_attached()` waits for the attachment), within `Config(join_timeout=...)`, and raises
`zmux.JoinRefusedError` when the peer refused the join and
`zmux.DeadlineExceededError` when the bound passed. `PipeOptions` holds every
option of a pipe; `pipe.update(**fields)` is the one way to change the
settings of a live pipe, together: `send_priority`, `receive_priority`,
`send_standby`, `receive_standby`, `weight`, `probation`, `liveness` and
`quality_band`, each left out (kept), `zmux.CLEAR` (cleared) or a value (set).
`PipeOptions` takes the same fields, each `zmux.INHERIT` (unset: the session's
value, the peer's request or the default) unless given a value; `None` is the
off setting of `probation` and `quality_band`, and `CLEAR` is only for
`update`. `pipe.options` reads every option back as the pipe holds it, after
each update exactly what it set or cleared (unset reads `INHERIT`), with
`direction` from this end, the `record_mode` and `key_group` the join used,
and `return_on_reply` as given, so options read from one pipe add another the
same way; a pipe the peer added reads as the join made it, the rest as a
`PipeOptions` default. It never fails, also after the pipe ended. A pipe's own
liveness is `PipeOptions(liveness=zmux.PipeLiveness(...))`.
`await pipe.wait_closed()` waits for a pipe's end, and raises
`zmux.PipeAbortedError` when this endpoint removed it abruptly (`pipe.abort()`,
a resource limit, room made for a join); wait before the removal to see it.

Pools: `handle = session.maintain_pipes(zmux.helpers.PipePool(count, dial))` keeps
`count` usable pipes dialled by the async `dial()`, with backoff, rotation
(`rotate_max_bytes`, `rotate_max_age`) and an optional `policy`;
`join=` takes groups of pipes such as `zmux.join_split`, `choice=` a carrier
choice, and `backoff=` a `zmux.Backoff`. `handle.stop()` ends it.

A pool's `policy` is an object with `decide(view)`, the protocol
`zmux.helpers.PoolPolicy`: at each look of the pool it is given a
`zmux.helpers.PoolView` (`members` as `PoolMember`s with `pipe`, `age`, `idle`,
`pipes`, `bytes_sent`, `bytes_received`, `usable` and `replacing`, `failures`,
`since_last_dial` and `dialing`) and returns a `zmux.helpers.PoolDecision`,
whose fields left at their defaults keep the pool's own behaviour: `count`
(the members to keep), `dial_after` (the wait before the next dial, in place
of the backoff's), `retire_pipes` (members to replace now, by `pipe`),
`recheck` (look again within that many seconds) and `liveness` (a
`PipeLiveness` for the pipes dialled from then on). A smaller `count` cancels
dials in progress first, then closes members gracefully, those in
`retire_pipes` first, then the longest idle. `decide` runs on the event loop
that runs `maintain_pipes`, keeps whatever state the object holds, and should
return promptly: no bound is put on it, and one that does not return holds
the looks of its own pool and nothing else. It must not call into the
session. A look is
rejected when `decide` raises or returns anything but a `PoolDecision`: the
pool applies the default decision for it and calls
`PipePool(decision_rejected=f)` with the exception, on the event loop, or,
without `f`, logs it at warning level through the session's logger.
`zmux.helpers.MachinePoolPolicy(json)` is a policy the binding runs natively
from a JSON definition, passed the same way. Its `evaluate(view)` gives the
values the definition evaluates to, unchanged (a `zmux.helpers.PoolEvaluation`),
which is how a policy file is tested; `decide(view)` builds the
`PoolDecision` from them, and a value `PoolDecision` refuses (an idle-probe
interval between 0 and 1 s) is a `ValueError`: that is a rejected look in a
pool.

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

Every Python hook runs on the event loop of its `Config` or `Listener`: the
one running when it is made, else the one running at its first use. Once
that loop closes, hooks are answered at once without it (a deciding hook
refuses, `redial` fails, observed events are dropped and counted) until the
next use from a running loop binds the object to that loop, so a `Config`
can serve one `asyncio.run` after another.
`logger` and `tracer` read a bounded queue
there (`hook_queue`, which drops the item that arrives when it is full and
counts it, except a session's `established` and `closed`; a `Tracer` is told the session's `Session.id`, a
`zmux.SessionId`), and deciding hooks (`authorize_join`,
`allow_record_mode`, `on_reject`, `session_config`, an admission decider)
may be `async` and are cancelled at the library's deadline. Choices the
library makes in its own calls are data: `record_policy=zmux.RecordPolicy(...)`,
`shaping_budget=ShapingBudget(...)` and handshake plans from a
`ShapingBundle`. A custom `carrier_credential` is the one hook called on the
library's thread that dials; it must be quick.

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
        secure_server=zmux.SecureServer(gate, node_key)  # a zmux.StaticKey
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

A node's static key is a `zmux.StaticKey`: `StaticKey.generate()` (which
raises `SecureCarrierError` with `kind == "random_failed"` when the operating
system's random source fails), `StaticKey.from_scalar(32 bytes)`, and the
properties `public_key` and `scalar`. A server takes one in
`SecureServer(gate, static_key)`; a client gives `establish(static_key=...)`,
and without one uses a key generated once per process. `zmux.static_key_id(key.public_key)`
is the `KeyId` a `PinVerifier` pins. A handshake a verifier rejects raises
`zmux.CredentialsFailedError`, any other failure of the secure carrier
`zmux.SecureCarrierError`; both carry the secure carrier's error class as a
string in `kind` (`"credentials_failed"`, `"random_failed"`, ...), and `code`
stays what it is everywhere else, a wire error code (`None` here: an error
class is not on the wire). `CredentialsFailedError` is raised only by the side
that judged the peer: a client whose verifier rejected the server or could not
decide, whose required proof failed, or whose `require_pq_auth` did not hold,
fails `establish` with it. A server that judges a client the same way closes
that carrier, reports it to `ListenerConfig(on_reject=...)` and the
statistics, and raises nothing; `RejectInfo.reason` is then
`"credentials_failed"` (its verifier rejected the client), `"proof"` (a
required proof is missing or wrong) or `"pq_auth_required"`, and `"auth"` only
for a failed AEAD or Confirm. A verifier that could not decide closes the
carrier without an `on_reject` call. The side whose credentials were refused
learns nothing from the wire: its carrier just ends.

## Errors

Every error class zmux defines derives from `zmux.ZmuxError` (with `kind`, what
happened; `retryable`; and `code`, only a wire error code, `None` without one) and, where one fits, from the built-in exception for
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
`InvalidArgumentError`, `PreambleTooLargeError` and `DuplicateUndecidedError`
(`resolve_duplicate` could not decide) are `ValueError`s, as are
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
definitions and values run natively; no Python code runs per record. Bounds left unset
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
