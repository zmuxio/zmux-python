"""Shaping echo peer for cross-implementation tests.

    shape_peer.py server        listens on 127.0.0.1:0, prints "LISTEN addr"
    shape_peer.py client ADDR   opens 8 streams, each echoed back

SHAPE_DEF names a shaping definition (JSON) applied to the session's
outbound pipes. At the end each side prints
"STATS padding=.. injected=.. dropped=.. clamped=.. faults=.." and "OK";
a shaped side fails unless it sent padding and recorded no fault.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys

import zmux

STREAMS = 8


def die(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)
    os._exit(1)


def payload(i: int) -> bytes:
    return random.Random(i).randbytes(200_000 + i * 7919)


def shape(session: zmux.Session) -> None:
    path = os.environ.get("SHAPE_DEF")
    if not path:
        return
    with open(path, encoding="utf-8") as f:
        definition = f.read()
    try:
        session.set_shaper(json=definition)
    except ValueError as e:
        die(f"def: {e}")


def report(session: zmux.Session) -> None:
    st = session.shaping_stats()
    print(
        f"STATS padding={st['padding_bytes']} injected={st['injected']} "
        f"dropped={st['inject_dropped']} clamped={st['clamped']} faults={st['faults']}",
        flush=True,
    )
    if os.environ.get("SHAPE_DEF") and (st["padding_bytes"] == 0 or st["faults"] != 0):
        die("not shaped")


async def server() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        print("LISTEN", addr, flush=True)
        session = await listener.accept()
    shape(session)

    async def echo(send: zmux.SendStream, recv: zmux.RecvStream) -> None:
        await send.write(await recv.read_to_end())
        await send.finish()

    async with asyncio.TaskGroup() as tg:
        for _ in range(STREAMS):
            send, recv = await session.accept_bi()
            tg.create_task(echo(send, recv))
    await session.wait_closed()
    report(session)
    print("OK", flush=True)


async def client(addr: str) -> None:
    session = await zmux.Session.connect(await zmux.dial_tcp(addr))
    shape(session)

    async def one(i: int) -> None:
        send, recv = await session.open_bi()
        p = payload(i)

        async def write() -> None:
            await send.write(p)
            await send.finish()

        w = asyncio.create_task(write())
        b = await recv.read_to_end()
        await w
        if b != p:
            die(f"stream {i}: {len(b)} of {len(p)} bytes")

    async with asyncio.TaskGroup() as tg:
        for i in range(STREAMS):
            tg.create_task(one(i))
    await asyncio.sleep(0.3)  # injections run on a timer
    report(session)
    session.close()
    await asyncio.wait_for(session.wait_closed(), 5)
    print("OK", flush=True)


def main() -> None:
    loop = asyncio.new_event_loop()
    loop.call_later(60, die, "deadline")
    if sys.argv[1] == "server":
        loop.run_until_complete(server())
    else:
        loop.run_until_complete(client(sys.argv[2]))


if __name__ == "__main__":
    main()
