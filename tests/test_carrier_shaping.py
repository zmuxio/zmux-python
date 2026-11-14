"""Carrier kinds on pipes, and shaping picked by carrier kind."""

import pytest
import zmux

PAD = '{"machines":[{"start":0,"states":[{"record":{"pad_to":1000}}]}]}'


async def exchange(client: zmux.Session, server: zmux.Session) -> None:
    send, _ = await client.open_bi()
    await send.write(b"x" * 10)
    await send.finish()
    _, s_recv = await server.accept_bi()
    assert await s_recv.read_to_end() == b"x" * 10


def test_pipe_carrier() -> None:
    pipe, _ = zmux.adapter.pipe_pair(carrier_kind=zmux.CarrierKind.WEBSOCKET)
    assert pipe.carrier_kind is zmux.CarrierKind.WEBSOCKET
    pipe.carrier_kind = zmux.CarrierKind.QUIC
    kind: object = pipe.carrier_kind
    assert kind is zmux.CarrierKind.QUIC
    assert zmux.adapter.pipe_pair()[0].carrier_kind is None
    with pytest.raises(ValueError):
        zmux.adapter.pipe_pair(carrier_kind="carrier pigeon")
    with pytest.raises(ValueError):
        zmux.Config(shaping={"carrier pigeon": PAD})
    with pytest.raises(ValueError):
        zmux.Config(shaping={None: "{}"})


async def test_config_shapes_by_kind_from_the_first_record() -> None:
    # Only WebSocket pipes are shaped: there is no default.
    config = zmux.Config(shaping={zmux.CarrierKind.WEBSOCKET: PAD})
    async with zmux.Listener(config=config) as listener:
        ws = await listener.serve_websocket("127.0.0.1", 0)
        tcp = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_websocket(
            f"ws://{ws[0]}:{ws[1]}/", config=config
        ) as client:
            server = await listener.accept()
            await exchange(client, server)
            for s in (client, server):
                assert s.pipe_stats()[0].carrier == zmux.CarrierKind.WEBSOCKET
                st = s.shaping_stats()
                assert st["wire_spent"] > 0 and st["faults"] == 0, st
        async with await zmux.connect_tcp(*tcp, config=config) as client:
            server = await listener.accept()
            await exchange(client, server)
            for s in (client, server):
                assert s.pipe_stats()[0].carrier is None
                assert s.shaping_stats()["wire_spent"] == 0


async def test_set_shaper_by_kind() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr) as client:
            server = await listener.accept()
            with pytest.raises(ValueError):
                client.shaper = zmux.shaping.Shaper(definition=PAD, by_kind={None: PAD})
            client.shaper = zmux.shaping.Shaper(by_kind={zmux.CarrierKind.QUIC: PAD})
            await exchange(client, server)
            assert client.shaping_stats()["wire_spent"] == 0
            client.shaper = zmux.shaping.Shaper(by_kind={None: PAD})
            await exchange(client, server)
            assert client.shaping_stats()["wire_spent"] > 0


DELAY_FIRST = '{"machines":[{"start":0,"states":[{"record":{"delay":20000},"next":[{"on":"record_out","to":1}]},{}]}]}'
DELAY_ALL = '{"machines":[{"start":0,"states":[{"record":{"delay":20000}}]}]}'


@pytest.mark.parametrize("definition", [DELAY_FIRST, DELAY_ALL], ids=["first", "all"])
async def test_a_delayed_first_record_keeps_the_parameters_first(
    definition: str,
) -> None:
    # A delay of the bootstrap pipe's first record, from the session's
    # creation on both ends, holds the transport parameters, which still
    # lead the pipe once it ends: both ends establish and carry a stream.
    config = zmux.Config(shaping={None: definition})
    async with zmux.Listener(config=config) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        async with await zmux.connect_tcp(*addr, config=config) as client:
            server = await listener.accept()
            await exchange(client, server)
            await exchange(server, client)
            for s in (client, server):
                st = s.shaping_stats()
                assert st["stall_spent"] > 0 and st["faults"] == 0, st
