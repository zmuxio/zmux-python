"""Packet streams and the packet relay of `zmux.helpers`."""

import asyncio
import time

import pytest
import zmux
from zmux.helpers import Packet, PacketStream, SendPolicy, Sent

from test_api import pair

DGRAM = zmux.Config(enable_datagrams=True)


async def accept_packets(s: zmux.Session, max_packet: int = 65535) -> PacketStream:
    send, recv = await s.accept_bi()
    return PacketStream(send, recv, max_packet=max_packet)


async def test_policies_and_context_ids() -> None:
    async with pair(DGRAM, DGRAM) as (c, s, _l):
        a = await c.open_packet_stream(info=b"packets")
        sent = await a.send(b"first", context=7)
        assert sent is Sent.DATAGRAM
        b = await asyncio.wait_for(accept_packets(s), 5)
        assert await asyncio.wait_for(b.recv(), 5) == Packet(7, b"first")

        assert await b.send(b"reliable") is Sent.DATAGRAM
        assert await asyncio.wait_for(a.recv(), 5) == (0, b"reliable")
        st = b.stats()
        assert (st.sent_datagrams, st.received_datagrams) == (1, 1)

        with pytest.raises(zmux.InvalidArgumentError):
            await a.send(b"x", context=1 << 62)
        assert await a.send(b"top", context=(1 << 62) - 1) is Sent.DATAGRAM
        assert await asyncio.wait_for(b.recv(), 5) == ((1 << 62) - 1, b"top")

        tx, rx = a.split()
        with pytest.raises(zmux.StreamClosedError):
            await a.send(b"gone")
        await tx.close()
        await b.close()
        assert await asyncio.wait_for(rx.recv(), 5) is None
        assert [p async for p in b] == []


async def test_stream_only_in_order_and_iteration_ends() -> None:
    async with pair(DGRAM, DGRAM) as (c, s, _l):
        a = await c.open_packet_stream(policy=SendPolicy.STREAM_ONLY)
        for i in range(5):
            assert await a.send(bytes([i]) * 10, context=i) is Sent.CAPSULE
        await a.close()
        b = await asyncio.wait_for(accept_packets(s), 5)
        got = [p async for p in b]
        assert got == [Packet(i, bytes([i]) * 10) for i in range(5)]
        assert b.stats().received_capsules == 5 == a.stats().sent_capsules


async def test_fallback_to_capsules() -> None:
    # No datagrams on the session: PreferDatagram sends capsules,
    # DatagramOnly fails.
    async with pair() as (c, s, _l):
        a = await c.open_packet_stream()
        assert await a.send(b"no datagrams") is Sent.CAPSULE
        b = await asyncio.wait_for(accept_packets(s), 5)
        assert await asyncio.wait_for(b.recv(), 5) == (0, b"no datagrams")
        d = await c.open_packet_stream(policy="datagram_only")
        with pytest.raises(zmux.NotNegotiatedError):
            await d.send(b"x")
    # Larger than the stream's largest datagram now: a capsule, or a failure
    # for DatagramOnly.
    async with pair(DGRAM, DGRAM) as (c, s, _l):
        send, recv = await c.open_bi()
        limit = send.max_datagram_size()
        assert limit is not None
        a = PacketStream(send, recv)
        big = b"z" * (limit + 1)
        assert await a.send(big, context=3) is Sent.CAPSULE
        assert await a.send(b"small") is Sent.DATAGRAM
        b = await asyncio.wait_for(accept_packets(s), 5)
        got = {await asyncio.wait_for(b.recv(), 5) for _ in range(2)}
        assert got == {Packet(3, big), Packet(0, b"small")}
        st = b.stats()
        assert (st.received_capsules, st.received_datagrams) == (1, 1)
        d = await c.open_packet_stream(policy=SendPolicy.DATAGRAM_ONLY)
        with pytest.raises(zmux.PacketTooLargeError) as e:
            await d.send(big)
        assert e.value.max <= limit and isinstance(e.value, zmux.PacketError)


async def test_oversize_is_a_packet_error() -> None:
    async with pair() as (c, s, _l):
        a = await c.open_packet_stream(max_packet=100)
        with pytest.raises(zmux.PacketTooLargeError) as e:
            await a.send(b"x" * 101)
        assert e.value.max == 100 and isinstance(e.value, ValueError)

        big = await c.open_packet_stream(max_packet=4096)
        await big.send(b"x" * 1000)
        b = await asyncio.wait_for(accept_packets(s, max_packet=100), 5)
        with pytest.raises(zmux.MalformedPacketError) as m:
            await asyncio.wait_for(b.recv(), 5)
        assert m.value.code == zmux.ApplicationErrorCode.ZMUX_PACKET_ERROR
        assert isinstance(m.value, zmux.PacketError)
        with pytest.raises(zmux.MalformedPacketError):
            await b.recv()
        with pytest.raises(zmux.StreamResetError) as r:
            async with asyncio.timeout(5):
                async for _ in big:
                    pass
        assert r.value.code == zmux.ApplicationErrorCode.ZMUX_PACKET_ERROR


async def test_cancelled_receive_keeps_the_packet() -> None:
    async with pair() as (c, s, _l):
        a = await c.open_packet_stream()
        await a.send(b"hello")
        b = await asyncio.wait_for(accept_packets(s), 5)
        t = asyncio.ensure_future(b.recv())
        await asyncio.sleep(0)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        assert await asyncio.wait_for(b.recv(), 5) == (0, b"hello")


async def test_receive_cancelled_across_split_keeps_the_packet() -> None:
    async with pair() as (c, s, _l):
        a = await c.open_packet_stream()
        await a.send(b"hello")
        b = await asyncio.wait_for(accept_packets(s), 5)
        t = asyncio.ensure_future(b.recv())
        await asyncio.sleep(0)
        # The receive completes while the loop is held: its result is
        # given back when the loop sees it cancelled.
        time.sleep(0.2)
        _tx, rx = b.split()
        # A receive of the half, waiting for a new packet, takes the one
        # the cancelled receive gives back.
        waiting = asyncio.ensure_future(rx.recv())
        time.sleep(0.1)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        assert await asyncio.wait_for(waiting, 5) == (0, b"hello")


async def test_relay_turns_datagrams_into_capsules() -> None:
    # Datagrams on the first hop, none on the second: each datagram goes on
    # as a capsule.
    async with (
        pair(DGRAM, DGRAM) as (c, relay_in, _l1),
        pair() as (relay_out, server, _l2),
    ):

        async def relay() -> zmux.helpers.Spliced:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice_packets(a, b, chunk=1024)

        task = asyncio.ensure_future(relay())
        p = await c.open_packet_stream()
        assert await p.send(b"datagram", context=5) is Sent.DATAGRAM
        q = await asyncio.wait_for(accept_packets(server), 5)
        assert await asyncio.wait_for(q.recv(), 5) == (5, b"datagram")
        assert q.stats().received_capsules == 1
        await p.close()
        assert await asyncio.wait_for(q.recv(), 5) is None
        await q.close()
        assert await asyncio.wait_for(p.recv(), 5) is None
        done = await asyncio.wait_for(task, 10)
        f = done.a_to_b
        assert f.datagrams_as_capsules == 1 and f.datagram_bytes == 8
        assert (f.datagrams_dropped, f.datagrams_too_large) == (0, 0)
        assert f.datagrams_limited == 0
        assert f.end is zmux.helpers.SpliceEnd.FINISHED
        assert done.b_to_a.datagrams_as_capsules == 0


async def test_splice_counts_dropped_datagrams() -> None:
    # A plain splice drops what does not fit the downstream datagrams.
    async with (
        pair(DGRAM, DGRAM) as (c, relay_in, _l1),
        pair() as (relay_out, server, _l2),
    ):

        async def relay() -> zmux.helpers.Spliced:
            a = await relay_in.accept_bi()
            b = await relay_out.open_bi()
            return await zmux.helpers.splice(a, b)

        task = asyncio.ensure_future(relay())
        p = await c.open_packet_stream()
        assert await p.send(b"lost") is Sent.DATAGRAM
        assert await p.send(b"kept", context=1) is Sent.DATAGRAM
        await p.close()
        q = await asyncio.wait_for(accept_packets(server), 5)
        assert await asyncio.wait_for(q.recv(), 5) is None
        await q.close()
        done = await asyncio.wait_for(task, 10)
        f = done.a_to_b
        assert f.datagrams_too_large == 2 == f.datagrams_dropped
        assert f.datagrams_as_capsules == 0


def capsule(payload: bytes) -> bytes:
    """A DATAGRAM capsule of Context ID 0 (one-byte varints)."""
    body = b"\x00" + payload
    assert len(body) < 64
    return b"\x00" + bytes([len(body)]) + body


async def relayed(
    upstream: zmux.Session, downstream: zmux.Session, chunk: int = 1024
) -> tuple[asyncio.Future[zmux.helpers.Spliced], int]:
    """A packet relay of the next stream `upstream` accepts onto a new
    stream of `downstream`, and the largest datagram payload with Context
    ID 0 there."""
    send, recv = await downstream.open_bi()
    await send.flush()
    down = send.max_datagram_size(0)
    assert down is not None

    async def relay() -> zmux.helpers.Spliced:
        a = await upstream.accept_bi()
        return await zmux.helpers.splice_packets(a, (send, recv), chunk=chunk)

    return asyncio.ensure_future(relay()), down


async def accept_relayed(s: zmux.Session) -> PacketStream:
    """The stream of `relayed` on the far side."""
    return await asyncio.wait_for(accept_packets(s), 5)


async def upstream_stream(c: zmux.Session) -> tuple[zmux.BiStream, int]:
    """The session's first stream, opened, and its largest datagram payload
    with Context ID 0."""
    stream = await c.open_bi()
    await stream.send.flush()
    assert stream.send.id == 0
    up = stream.send.max_datagram_size(0)
    assert up is not None
    return stream, up


async def test_relay_sends_what_is_too_large_downstream_as_capsules() -> None:
    # Datagrams on both hops, the second one's smaller (its carrier takes
    # records of at most 8192 bytes): only the datagram too large there goes
    # on as a capsule.
    async with (
        pair(DGRAM, DGRAM) as (c, relay_in, _l1),
        pair(DGRAM, DGRAM, max_record=8192) as (relay_out, server, _l2),
    ):
        task, down = await relayed(relay_in, relay_out)
        (send, recv), up = await upstream_stream(c)
        assert down < up
        q = await accept_relayed(server)
        # The largest datagram downstream goes on as one, a byte more as a
        # capsule.
        send.send_datagram(b"s" * down, 0)
        send.send_datagram(b"L" * (down + 1), 0)
        got = {await asyncio.wait_for(q.recv(), 5) for _ in range(2)}
        assert got == {Packet(0, b"s" * down), Packet(0, b"L" * (down + 1))}
        st = q.stats()
        assert (st.received_datagrams, st.received_capsules) == (1, 1)
        await send.finish()
        assert await asyncio.wait_for(q.recv(), 5) is None
        await q.close()
        assert await asyncio.wait_for(recv.read_to_end(), 5) == b""
        f = (await asyncio.wait_for(task, 10)).a_to_b
        assert f.datagrams_as_capsules == 1 and f.datagram_bytes == 2 * down + 1
        assert (f.datagrams_dropped, f.datagrams_too_large) == (0, 0)
        assert f.end is zmux.helpers.SpliceEnd.FINISHED


async def test_relay_fin_inside_a_capsule() -> None:
    # The upstream ends inside a capsule: the receiver refuses the cut
    # capsule with ZMUX_PACKET_ERROR, and the datagram that waited for the
    # capsule's end is dropped as too large.
    async with (
        pair(DGRAM, DGRAM) as (c, relay_in, _l1),
        pair(DGRAM, DGRAM, max_record=8192) as (relay_out, server, _l2),
    ):
        task, _ = await relayed(relay_in, relay_out)
        (send, recv), up = await upstream_stream(c)
        await send.write(capsule(b"x" * 40)[:10])
        q = await accept_relayed(server)
        await asyncio.sleep(0.1)  # the relay is inside the capsule
        send.send_datagram(b"L" * up)
        await asyncio.sleep(0.1)  # and holds the datagram
        await send.finish()
        with pytest.raises(zmux.MalformedPacketError) as m:
            await asyncio.wait_for(q.recv(), 5)
        assert m.value.code == zmux.ApplicationErrorCode.ZMUX_PACKET_ERROR
        # The receiver's reset goes back to the sender, code unchanged.
        with pytest.raises(zmux.StreamResetError) as r:
            await asyncio.wait_for(recv.read_to_end(), 5)
        assert r.value.code == zmux.ApplicationErrorCode.ZMUX_PACKET_ERROR
        done = await asyncio.wait_for(task, 10)
        assert done.b_to_a.end is zmux.helpers.SpliceEnd.RESET
        assert done.b_to_a.code == zmux.ApplicationErrorCode.ZMUX_PACKET_ERROR
        f = done.a_to_b
        assert f.datagrams_too_large == 1 and f.datagrams_dropped == 1
        assert f.datagrams_as_capsules == 0 and f.datagram_bytes == 0
        assert f.end is zmux.helpers.SpliceEnd.FINISHED


async def test_relay_capsule_queue_full() -> None:
    # Inside a capsule the datagrams that need a capsule wait for its end,
    # a bounded number of them: the rest are dropped as too large.
    async with (
        pair(DGRAM, DGRAM) as (c, relay_in, _l1),
        pair(DGRAM, DGRAM, max_record=8192) as (relay_out, server, _l2),
    ):
        task, _ = await relayed(relay_in, relay_out)
        (send, recv), up = await upstream_stream(c)
        whole = capsule(b"x" * 40)
        await send.write(whole[:10])
        q = await accept_relayed(server)
        await asyncio.sleep(0.1)  # the relay is inside the capsule
        sent = 4
        for i in range(sent):
            send.send_datagram(bytes([i]) * up)
        await asyncio.sleep(0.2)  # all of them reached the relay
        await send.write(whole[10:])
        await send.finish()
        got = [p async for p in q]
        await q.close()
        assert await asyncio.wait_for(recv.read_to_end(), 5) == b""
        f = (await asyncio.wait_for(task, 10)).a_to_b
        assert got[0] == Packet(0, b"x" * 40)
        assert len(got) - 1 == f.datagrams_as_capsules >= 1
        assert f.datagrams_too_large >= 1
        assert f.datagrams_as_capsules + f.datagrams_too_large == sent
        assert f.datagrams_dropped == f.datagrams_too_large
        assert f.end is zmux.helpers.SpliceEnd.FINISHED
