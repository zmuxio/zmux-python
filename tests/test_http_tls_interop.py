"""A bidirectional HTTP/2 carrier over TLS 1.3 against the Go scripted HTTP
peer (ZMUX_GO_HTTP_PEER, `server tls2 ADDR`): the second carrier joins in
Bound at both ends. Skipped when the peer is not set."""

import asyncio
import os

import pytest
import zmux

PEER = os.environ.get("ZMUX_GO_HTTP_PEER", "")


async def ping(session: zmux.Session) -> bytes:
    send, recv = await session.open_bi()
    await send.write(b"ping")
    await send.finish()
    return await recv.read_to_end()


@pytest.mark.skipif(not PEER, reason="ZMUX_GO_HTTP_PEER not set")
async def test_bound_join_with_go_over_http2_tls() -> None:
    proc = await asyncio.create_subprocess_exec(
        PEER, "server", "tls2", "127.0.0.1:0", stdout=asyncio.subprocess.PIPE
    )
    assert proc.stdout is not None
    try:
        async with asyncio.timeout(20):
            # The peer binds a free port and prints `READY <address>`.
            ready = (await proc.stdout.readline()).split()
            assert len(ready) == 2
            assert ready[0] == b"READY"
            port = int(ready[1].rsplit(b":", 1)[1])
            cfg = zmux.Config(
                session_policy=zmux.SessionPolicy(
                    limits=zmux.CapacityLimits(steady_attachments=4)
                ),
                pipe_auth=zmux.PipeAuth.psk(b"\x07" * 32).with_end_to_end(),
            )
            conn = await zmux.Http2Connection.dial(
                "127.0.0.1",
                port,
                tls=zmux.TlsConfig(verify=False),
                server_name="localhost",
            )
            async with await zmux.Session.connect(
                await conn.open_pipe(), config=cfg
            ) as c:
                assert await ping(c) == b"ping"
                pipe = await c.add_pipe(
                    await conn.open_pipe(),
                    options=zmux.PipeOptions(record_mode=zmux.RecordMode.BOUND),
                )
                stats = pipe.stats()
                assert stats is not None
                assert stats.record_mode == zmux.RecordMode.BOUND
                assert await ping(c) == b"ping"
                lines = []
                while b"MODE bound" not in lines:
                    lines.append((await proc.stdout.readline()).strip())
    finally:
        proc.kill()
        await proc.wait()
