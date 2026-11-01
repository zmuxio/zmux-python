"""Pipes through a TCP relay that fails in controlled ways: a black hole,
a cut of every connection, and pool retirement."""

import asyncio
import time
from collections.abc import Callable
from typing import Any, TypedDict

import zmux

PSK = b"fault-relay-psk-0123456789abcdef"


def _config(**kw: Any) -> zmux.Config:
    return zmux.Config(
        max_pipes=6,
        pipe_auth=zmux.PipeAuth.psk(PSK),
        max_idle_timeout=None,
        resume_timeout=120,
        **kw,
    )


class _Conn(TypedDict):
    blackhole: bool
    writers: tuple[asyncio.StreamWriter, asyncio.StreamWriter]


class Relay:
    """Forwards TCP connections to `target`; each can be black-holed (bytes
    taken, none forwarded, ends kept open) or cut (both ends closed)."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.conns: list[_Conn] = []
        self.server: asyncio.Server | None = None

    async def start(self) -> str:
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        host, port = self.server.sockets[0].getsockname()[:2]
        return f"{host}:{port}"

    async def _serve(self, r1: asyncio.StreamReader, w1: asyncio.StreamWriter) -> None:
        host, port = self.target.rsplit(":", 1)
        r2, w2 = await asyncio.open_connection(host, int(port))
        conn: _Conn = {"blackhole": False, "writers": (w1, w2)}
        self.conns.append(conn)

        async def pump(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            try:
                while data := await r.read(65536):
                    if not conn["blackhole"]:
                        w.write(data)
                        await w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                w.close()

        await asyncio.gather(pump(r1, w2), pump(r2, w1))

    def cut(self) -> None:
        for c in self.conns:
            for w in c["writers"]:
                w.transport.abort()

    def close(self) -> None:
        self.cut()
        if self.server is not None:
            self.server.close()


async def _until(cond: Callable[[], bool], limit: float) -> float:
    end = time.monotonic() + limit
    while not cond():
        assert time.monotonic() < end, "timed out"
        await asyncio.sleep(0.01)
    return time.monotonic()


def _pool_pipes(session: zmux.Session, first: int) -> list[zmux.PipeStats]:
    return [
        s
        for s in session.pipe_stats()
        if s.pipe != first and s.outbound is zmux.OutboundState.ACTIVE
    ]


async def test_a_black_hole_is_found_by_the_probe() -> None:
    config = _config()
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        relay = Relay(addr)
        raddr = await relay.start()
        try:
            async with await zmux.connect_tcp(addr, config=config) as session:
                first = session.pipes()[0].id

                async def dial() -> zmux.PipeIo:
                    return await zmux.dial_tcp(raddr)

                pool = zmux.PipePool(
                    1, dial, options=zmux.PipeOptions(probe_interval=1)
                )
                handle = session.maintain_pipes(pool)
                await _until(lambda: len(_pool_pipes(session, first)) == 1, 10)
                # Idle for a few probe intervals: the relay keeps it alive.
                await asyncio.sleep(3)
                (pipe,) = _pool_pipes(session, first)
                start = time.monotonic()
                relay.conns[0]["blackhole"] = True
                found = await _until(
                    lambda: (
                        pipe.pipe not in {s.pipe for s in _pool_pipes(session, first)}
                    ),
                    20,
                )
                # Within the probe interval and the failure bound (default
                # dead timeout); generous for a loaded host.
                assert found - start <= 1 + 5 + 2, found - start
                handle.stop()
                await _until(lambda: handle.finished, 5)
        finally:
            relay.close()


async def test_the_last_pipe_cut_resumes_without_loss() -> None:
    config = _config()
    async with zmux.Listener(
        config, instance_id=b"instance", max_suspended=16
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        relay = Relay(addr)
        raddr = await relay.start()
        try:
            async with await zmux.Session.connect(
                await zmux.dial_tcp(raddr), config
            ) as client:
                server = await listener.accept()
                events: list[zmux.Event] = []

                async def watch() -> None:
                    async for e in client.events():
                        events.append(e)

                watcher = asyncio.ensure_future(watch())

                async def dial() -> zmux.PipeIo:
                    return await zmux.dial_tcp(raddr)

                pool = zmux.PipePool(1, dial)
                handle = client.maintain_pipes(pool)
                first = client.pipes()[0].id
                await _until(lambda: len(_pool_pipes(client, first)) == 1, 10)
                total = 2 << 20
                chunk = 16 * 1024

                async def write() -> None:
                    send, _ = await client.open_bi()
                    for off in range(0, total, chunk):
                        await send.write(
                            bytes((i % 251) for i in range(off, off + chunk))
                        )
                        await asyncio.sleep(0.002)
                    await send.finish()

                async def read() -> int:
                    _, recv = await server.accept_bi()
                    got = 0
                    while data := await recv.read():
                        assert data == bytes(
                            (i % 251) for i in range(got, got + len(data))
                        )
                        got += len(data)
                    return got

                writer = asyncio.ensure_future(write())
                reader = asyncio.ensure_future(read())
                await asyncio.sleep(0.3)
                relay.cut()
                # Suspended and Resumed share one slot (the latest unread
                # wins), so a slow reader may see only Resumed; the counter
                # shows the suspension happened.
                await _until(
                    lambda: any(isinstance(e, zmux.Resumed) for e in events), 25
                )
                assert client.stats().suspensions >= 1
                assert await asyncio.wait_for(reader, 30) == total
                await asyncio.wait_for(writer, 5)
                retired = [e for e in events if isinstance(e, zmux.PipesRetired)]
                # The cut pipes are retired; their failures were read as
                # they happened, so the summary does not count them again.
                assert sum(e.retired for e in retired) >= 2, retired
                assert first in {i for e in retired for i in e.last}, retired
                handle.stop()
                await _until(lambda: handle.finished, 5)
                watcher.cancel()
        finally:
            relay.close()
