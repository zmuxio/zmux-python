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
(`Http2Connection` opens several pipes on one connection), the HTTP
exchange carrier, HTTP/3 and
WebTransport. `dial_x(target, *, ...)` gives a `PipeIo`,
`connect_x(target, *, tls=None, config=None, ...)` a `Session`, and
`Listener.serve_x(addr, *, ...)` accepts. `pipe_from_streams(reader, writer)`
runs a session over any asyncio stream pair (slower: bytes pass through
Python); the transport's `get_write_buffer_size()` is its unsent count.
`PipeIo.with_unsent(count)` gives any carrier such a count
(`PipeStats.queued_bytes`, the carrier's part of the pipe's queue): a
`zmux.UnsentCount` the application sets at each write, which the session
reads without the interpreter lock.

```python
session = await zmux.connect_quic(
    "example.net:443", config=zmux.Config(max_idle_timeout=30)
)
async with session:
    send, recv = await session.open_bi(info=b"route", priority=zmux.Priority(1))
    async with send:  # finish on exit, reset on error
        await send.write(b"request")
    async for chunk in recv:  # until the end of the stream
        ...
```

HTTP exchange carrier, for paths that only pass plain request/response
HTTP (no upgrades, no streaming bodies): the client sends POST requests, the
server answers on `serve_http`. Both ends share `psk` and `encoding`:

```python
opts = zmux.ExchangeOptions(
    psk=b"shared secret",
    encoding="base64",
    path="/up/{instance}",
    down_path="/down/{instance}/{nonce}",
)
await listener.serve_http("0.0.0.0:8080", exchange=opts)  # server
session = await zmux.connect_exchange("example.net:8080", options=opts)  # client
```

`dial_exchange(addr, *, options, down_addr=None, tls=None)` sends DOWN
requests to another endpoint when `down_addr` is given.

One endpoint serves every HTTP carrier on one path, each request told apart
by its head: `serve_http(addr, exchange=..., websocket=True)` takes
bidirectional POSTs (`dial_http`), uplink POSTs and downlink GETs
(`dial_http(..., carrier="uplink" | "downlink", join=...)`), split
bootstraps (`connect_http_split`: a POST and a GET paired by a token, for
paths that stream each body but not both on one request; run them over TLS),
exchange requests and WebSocket upgrades. Carrier requests forwarded from
TLS early data (`Early-Data: 1`) are answered 425.

Carrier modes choose among kinds for paths through reverse proxies and CDNs:
`Mode.explicit(candidate)` uses one kind and reports its failure;
`Mode.auto([...])` tries candidates in order of preference (no early data,
no racing), remembers per `key` in a `CarrierCache` which kinds passed, and
with `max_pipes` above 1 starts on the most robust one and moves to a
preferred kind that joins. The choice and every try are session events
(`CarrierChosen`, `CarrierCandidate`) and in `session.stats()`:

```python
auth = zmux.PrefixAuth(b"shared secret", slot=30)
mode = zmux.Mode.auto(
    [
        zmux.Candidate.websocket("wss://example.net/zmux", credential=auth),
        zmux.Candidate.streaming("example.net:80", credential=auth),
        zmux.Candidate.split("example.net:80", credential=auth),
        zmux.Candidate.exchange("example.net:80", options=opts),
    ]
)
session = await zmux.dial_mode(
    mode, zmux.Config(), cache=cache, key="example.net|office"
)
print(session.stats().carrier)
```

`PipePool.mode(mode, count=2, cache=cache, key=...)` keeps further members
over a mode's kinds the same way (`session.maintain_pipes(pool)`): each
dialed over the most robust kind available, then upgraded make before break
to a preferred kind once it stayed usable for `settle`. The cache outlives
the process as JSON text: `text = cache.snapshot()`, later
`cache.restore(text)` (merged, newer entries win; the form is shared by every
zmux implementation).

Behind trusted intermediaries, `Listener(trusted_proxies=["10.0.0.0/8"],
forwarded_header="X-Forwarded-For", proxy_protocol=False)` takes a
carrier's source (per-source limits, admission) from what they report.

Admission: `Listener(admission=...)` decides on each new carrier at every
entry (each `serve_x`, and `handle_pipe` for joins and resumptions as for new
sessions) before anything is answered, and `dial_x(..., credential=...)`
presents what it checks. Every carrier first takes a slot of its source's
`max_pending_per_source` (refused at once beyond it), then its outer
handshake (TLS, HTTP upgrade, QUIC), then the admission, then its first
record. `PrefixAuth` tokens are the shared mechanism: a token is the
carrier's first bytes, or the `Zmux-Prefix-Auth` request header on
WebSocket and WebTransport; with `bind_tls=True` it is bound to the
carrier's TLS or QUIC handshake. A carrier without a valid token goes to the
fallback (it is held open, then closed):

```python
auth = zmux.PrefixAuth(b"shared secret", slot=30, bind_tls=True)
listener = zmux.Listener(admission=zmux.Admission.prefix_auth(auth, skew=1))
await listener.serve_websocket("0.0.0.0:443", tls=server_tls)
pipe = await zmux.dial_websocket("wss://example.net/", credential=auth)
```

`Admission(decide, *, peek=N)` takes a decision of your own:
`decide(info, prefix)` gets the `CarrierInfo` (`source` and `peer` as
`(host, port)`, `alpn`, `server_name`, `headers` of HTTP carriers,
`export(label)` for the TLS exporter) and up to `N` first bytes, and returns
a `Verdict` (`Verdict.accept(skip, value=...)`, `FALLBACK`, `STALL`,
`CLOSE`), once per carrier. An accept's `value`, any object (a user record,
say), is the carrier's admitted value: `session.admitted` (the carrier that
started the session), `pipe.admitted` (the carrier that brought the pipe)
and the inbound transform's `hint.admitted`. A plain function runs on a native thread holding the GIL: keep it
quick and never block in it. An `async def decide` runs on the event loop
the `Listener` was made in, within what remains of the peek timeout, and is
cancelled when that ends or the listener closes. An exception closes the
carrier. `listener.stats().admission` (`AdmissionStats`) counts each
outcome once: `accepted`, `fallback`, `stalled`, `closed`, `stall_overflow`,
`peek_timed_out`, `handshake_failed`. `await listener.shutdown()` refuses new
sessions while the live sessions' joins and resumptions are still taken
until they end; `close()` refuses everything at once. A preamble beyond the
peer's limit raises `PreambleTooLargeError` (a `ValueError`). A credential of your own is
any object with `prefix(info) -> bytes` and `header(info) -> (name, value)`
(`zmux.Credential`).

`Listener(inbound_transform=f)` runs `f(pipe, hint)` once for every carrier
after its admission and before its first record (each half of a split
bootstrap included) and goes on with the carrier it returns, for a layer of
your own over every carrier. `await pipe.wrap(layer)` runs `layer(reader,
writer)` over the carrier as asyncio streams and keeps the carrier's
framing, kind and other properties; each carrier write is one write on the
layer's writer, so the layer must turn each write into exactly one write
below and never merge writes (asyncio's TLS does):

```python
async def tls(reader, writer):
    await writer.start_tls(server_context)
    return reader, writer


async def transform(pipe, hint):
    return (await pipe.wrap(tls, server_side=True)).with_write_overhead(22)


listener = zmux.Listener(inbound_transform=transform)
```

The client runs the same layer on its carrier before the session
(`await (await zmux.dial_tcp(addr)).wrap(client_tls)`). `with_write_overhead(n)`
tells the shaper the bytes the layer adds per write. `zmux.open_carrier(pipe)`
gives a carrier as a plain asyncio stream pair. A transform's exception, a
carrier of another kind or the handshake timeout closes the carrier as a
setup failure (`listener.stats().setup_failures`). `Listener(answer_unknown_joins=True)` answers a join that
names no session (with the listener's `instance_id` prefix) with
`TransportErrorCode.RESUME_FAILED`, so a suspended joiner ends at once
instead of at its resume timeout; enable it only where such locators reach
no other instance.

Streams: `finish()` ends the sending half, `reset(code)` abandons it,
`recv.stop(code)` asks the peer to stop sending. Every coroutine is
cancellation-safe; use `asyncio.timeout()` for deadlines (durations are
seconds). `open_connection(session)` returns an asyncio-style
`(reader, StreamWriter)` pair whose `drain()` applies backpressure.

Events and statistics:

```python
async for event in session.events():
    match event:
        case zmux.PipeStateChanged(
            pipe=p, state=zmux.OutboundState.FAILED, failure=why
        ):
            log.warning("pipe %d failed: %s", p, why)
        case zmux.Suspended() | zmux.Resumed():
            log.info("%s", event.kind)
print(session.stats().bytes_sent, [s.smoothed_rtt for s in session.pipe_stats()])
```

A direction's state is a `zmux.OutboundState` (`JOINING`, `ACTIVE`,
`SUSPECT`, `DRAINING`, `FAILED`, `CLOSED`) or a `zmux.InboundState`
(`JOINING`, `OPEN`, `ENDED`): `PipeStateChanged.state` by its `half`,
`PipeStats.outbound` and `PipeStats.inbound`. Retirement is reported only
by `PipesRetired` (`retired`, `failed`, `closed`, `dropped` counts since it
was last read and `last`, up to four IDs, oldest first). A retired pipe's
`stats()` and `state` are `None`, and its operations raise `PipeError`.

Statistics are snapshots with the same fields as in the other languages:
`session.stats()` (`SessionStats`: carrier and application bytes, streams,
datagrams, RTT, multipath counts), `session.pipe_stats()` and
`pipe.stats()` (`PipeStats`, with `lanes`), `send.stats()` and
`recv.stats()` (`StreamStats`, the same snapshot for both parts, kept
with its final values once the session released the stream) and
`listener.stats()` (`ListenerStats`).

Streams: `try_open_bi()` opens without waiting (`OpenError` without
credit); `open_bi(info=, tlvs=, pipe_carrier=, priority=, peer_priority=)`
fixes the preamble before the first frame. `await recv.read_chunk(n)`
returns a `memoryview` of the received buffer and
`await send.write_chunk(buf)` takes any buffer without copying it.
`send.send_capacity()` and `await send.wait_send_capacity(n)` tell how
much the part can transmit; `set_send_buffer`, `set_scheduler`,
`set_redundant` (`True`, `False`, or `None` to follow the session's
`redundancy`), `set_reliable_boundary` and `send_datagram(payload,
context=0)` are on `SendStream`; `set_receive_window`,
`set_peer_priority`, `await read_datagram()` and `reject()` on
`RecvStream`.

Relays and nested sessions: `await zmux.splice((send_a, recv_a),
(send_b, recv_b), a_to_b=limiter)` forwards two streams into each other
(a `zmux.Limiter` rate-limits a direction) and returns a `Spliced`;
`await session.open_pipe_stream(tlvs)` opens a carrier stream and
`zmux.stream_pipe(send, recv)` wraps an accepted one, either a `PipeIo`
for `Session.connect`/`accept` or `add_pipe`.
`zmux.resolve_duplicate(s1, s2, local_identity=, peer_identity=)` keeps one
of two sessions that raced between the same endpoints.

Datagrams: `Config(enable_datagrams=True)`, with the queue sizes
`datagram_send_queue` (64 datagrams waiting to be sent),
`datagram_receive_queue` (128 received session datagrams),
`datagram_stream_queue` (32 per stream) and `datagram_receive_bytes`
(1 MiB of received datagrams in all); a full queue drops its oldest.

Schedulers: `Config(scheduler=...)` and `send.set_scheduler(...)` take
the name of a built-in policy (`"affinity"`, `"session-affinity"`,
`"spread-eta"`, `"spread-round-robin"`, `"spread-rate-weighted"`). A
policy written in Python is not offered: it would run on the driver's
decision path under the interpreter lock.

Multipath: give both ends `Config(max_pipes=8, pipe_auth=zmux.PipeAuth.psk(key))`
(or `PipeAuth.exporter()` over TLS/QUIC, `PipeAuth.exporter().with_psk(key)` for
both), then
`session.add_pipe(await zmux.dial_tcp(addr), options=zmux.PipeOptions(send_priority=1, receive_priority=1))`.
`PipeOptions` holds every option of a pipe (`None`: unset); a live pipe
changes its priorities, standby flags, weight and probation together with
`pipe.update(weight=2, send_priority=None)` (`None` clears `send_priority`
and `send_standby`; fixed or unknown fields raise `TypeError`, invalid
values `ValueError`), and `pipe.options` returns the options in force.
A split carrier joins as two further pipes, a downlink and an uplink:
`await zmux.join_http_split(session, addr)` (its bootstrap carrier from
`dial_http_split` makes pipe pair 0 only).
For an out-of-band join, `r = session.reserve_pipe()`, send `r.header` as the
`Zmux-Pipe-Join` request header
(`dial_websocket(url, headers={"Zmux-Pipe-Join": r.header})`), then
`r.attach(pipe)`. Resumption: `Config(resume_timeout=..., dead_timeout=...)`,
and `session.revalidate_pipes()` after a network change.

Idle pipes are probed (their heartbeat): an outbound pipe that has sent
nothing ack-eliciting for `Config(probe_interval=...)` seconds (default 15, at least 1;
`None` turns these probes off) gets a probe, each wait drawn from
`[k * (1 - j), k]` with `Config(probe_jitter=j)` (default 0.25; 0 gives a
fixed schedule), the first wait of the bootstrap pipe from `[0, k]`. A pipe's own
`add_pipe(..., options=zmux.PipeOptions(probe_interval=..., probe_jitter=...))`
overrides them (interval at least 1 s, a one-way attachment at most 15 s;
`PipeOptions(idle_probes=False)` turns the pipe's idle probes off).
Probes do not keep a session from its idle timeout; keep-alive does
(`Config(keep_alive_period=...)`, default 15 s, capped at half the idle timeout and
at least 1 s, jittered like the probes; `None` turns it off, and the idle timeout then ends a
session without application activity). The timers and periods of `Config`
hold their defaults and take `None` for no timeout or off:
`handshake_timeout`, `max_idle_timeout` (at least 0.001 s; `None` announces
no idle timeout), `keep_alive_period`, `standby_probe` and `probe_interval`;
a period of 0 raises. Every other field keeps its default when `None`;
`math.inf` makes `memory_budget` unlimited (also for
`Listener(memory_budget=...)`), and a budget of 0 is no byte. `PipeStats.since_last_traffic`
is the time since stream data or a datagram last went either way on the pipe.
`bytes_lost` / `records_lost` are what a failed pipe left unacknowledged,
`bytes_retransmitted` the carrier's own retransmissions (TCP on Linux,
Android, Apple platforms and Windows; QUIC) and `loss_rate` its smoothed
estimate.

Pools: `handle = session.maintain_pipes(zmux.PipePool(count, dial, ...))`
keeps `count` usable pipes dialled by the async `dial()`, redials failed ones
with backoff from the start of the previous attempt and, with
`rotate_max_bytes` / `rotate_max_age` (seconds, reduced by up to
`rotate_jitter`), replaces them make before break; `handle.stop()` ends it.
With `join=` in place of `dial` (an async `join(session, options)` returning
the pipes it joined, such as `join_http_split`), each member is a group of
pipes, usable while all of them are, counted once and redialled or rotated
whole. It looks again at once when a
pipe changes state or the session is suspended or resumed, and keeps dialling
while suspended. `options=` are the `PipeOptions` of the pool's pipes. `pool_policy=` takes a
`zmux.PoolPolicy` or its JSON (`str`, `bytes` or `dict`), evaluated natively
at each look of the maintainer:

```python
policy = {
    "count": {"const": 2},
    "dial_after": [{"const": 1}, {"range": [5, 10]}],
    "retire": [{"metric": "age", "above": {"range": [600, 900], "scope": "pipe"}}],
}
```

Values have the JSON form and validation of the shaping definition's values;
times are in seconds. `count` replaces the pool's count, rounded; it cannot draw below 1 (a
distribution that can, such as `normal`, needs a `min` of at least 1).
Entry `min(failures, len - 1)` of `dial_after` is the delay after the
last dial for that many consecutive failed dials, in place of the backoff's
(the backoff maximum bounds it; a negative delay makes the decision invalid); `dial_jitter` (0 to below 1)
reduces each wait by its own random fraction of up to it. A pipe is replaced
when any `retire` rule's metric is strictly above its threshold, reduced by a
fraction of up to the rule's optional `jitter` drawn once per pipe; metrics are
`age`, `idle` (the pipe's `since_last_traffic`), `pipes` (1 per pipe),
`bytes_sent`, `bytes_received` and `bytes` (their sum). `probe_interval` (a
value, at least 1 s) and `probe_jitter` set the probes of the pipes the pool
adds from then on. Scope `shared` draws once per policy, `pipe` once per pipe
while it is in the pool (only in `retire`), `each` or empty at every decision.
Absent members keep the pool's own behaviour; unknown members, metrics or
scopes raise `ValueError` with the native message. The maintainer also looks
again by itself when an `age` or `idle` rule of a kept pipe is due or
`dial_after` has elapsed. `PoolPolicy.decide(failures, members, since_dial=s)`
runs one decision directly and returns a `PoolPolicyDecision` (`count`,
`dial_after`, `retire`, `recheck`: seconds until that next look, or `None`,
`probe_interval`, `probe_jitter`); one made directly checks its probe
settings (`ValueError`). A pool rejects a policy decision whose probe interval
is neither 0 nor at least 1 s, or whose dial delay is negative, as a whole, keeps its own behaviour and calls
`PipePool(decision_rejected=f)` with the reason on the event loop.

Defaults are exported as constants: `DEFAULT_KEEP_ALIVE_PERIOD` (15 s),
`DEFAULT_IDLE_TIMEOUT` (30 s), `DEFAULT_PROBE_JITTER` (0.25),
`DEFAULT_STANDBY_PROBE` (1 s),
`DEFAULT_MAX_RECORD_SIZE` (16382), `DEFAULT_BACKOFF_MAX` (60 s, the largest
redial delay of a pool), `MIN_MAX_LEN` (64, the smallest shaping `max_len`)
and `STARTUP_ALLOWANCE` (16382).

Shaping: `session.set_shaper(json=...)` or `set_shaper(sequence=...)` shapes
every outbound pipe by a definition, run natively; `set_shaper()` stops it and
`session.shaping_stats()` returns its counters. `limits=ShapingSizeLimits(...)`
bounds the definition (`max_bytes`, `max_machines`, `max_states`,
`max_actions`, `max_transitions`, `max_points`; one beyond raises
`ValueError`). A length, time, rate, burst or counter value of a definition
that can draw below 0 (such as `normal`) needs a `min` of at least 0, or the
definition raises `ValueError`. `Config(shaping_limits=ShapingLimits(...))` bounds what the
shaper may do over a session (`max_padding_bytes`, `max_padding_ratio`,
`max_injected`, `max_pause_total`, `max_delay` in seconds; each finite and
non-negative, `max_padding_ratio` at most 1, else `ValueError` at
construction); a decision beyond is reduced to the bound and counted as
`clamped`. In both, a field left `None` is unbounded and 0 allows none. Under
a set ratio, `STARTUP_ALLOWANCE` bytes of PADDING are always allowed (without
one only `max_padding_bytes` bounds PADDING), and a padding-only record the allowance does
not cover waits and goes whole later.
`seed=b"..."` replaces the operating system's generator by a deterministic one
so that every pipe draws the same values; it is for tests only.

Shaping by carrier kind: every pipe has the carrier kind of its carrier
(`PipeStats.carrier`, `PipeStateChanged.carrier`): `websocket`, `streaming`,
`split`, `exchange`, `quic`, `http3` or `webtransport`, set by the binding's
dialers and listeners on both ends, or `None` for TCP and TLS.
`pipe_pair(carrier=...)` and `pipe.with_carrier(kind)` label a carrier of
your own. `Config(shaping={CarrierKind.WEBSOCKET: json, None: json})` maps
kinds (`None`: the default, for a pipe of no kind or of a kind not listed) to
definitions in the JSON form; each session made with that configuration,
accepted sessions and joined pipes included, shapes each pipe by its kind's
definition from its first record, and a pipe without one is not shaped.
`session.set_shaper(by_kind={...})` replaces it on a running session. The
choice runs natively; no Python code runs per record.

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
