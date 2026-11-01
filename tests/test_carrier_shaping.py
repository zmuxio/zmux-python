"""Carrier kinds on pipes, and shaping picked by carrier kind."""

import pytest
import zmux

PAD = '{"version":1,"machines":[{"states":[{"record":{"pad_to":{"const":1000}}}]}]}'


async def exchange(client: zmux.Session, server: zmux.Session) -> None:
    send, _ = await client.open_bi()
    await send.write(b"x" * 10)
    await send.finish()
    _, s_recv = await server.accept_bi()
    assert await s_recv.read_to_end() == b"x" * 10


def test_pipe_carrier() -> None:
    pipe, _ = zmux.pipe_pair(carrier=zmux.CarrierKind.WEBSOCKET)
    assert pipe.carrier == "websocket"
    relabelled = pipe.with_carrier("quic")
    assert relabelled.carrier == "quic"
    with pytest.raises(RuntimeError):
        _ = pipe.carrier
    assert zmux.pipe_pair()[0].carrier is None
    with pytest.raises(ValueError):
        zmux.pipe_pair(carrier="carrier pigeon")
    with pytest.raises(ValueError):
        zmux.Config(shaping={"carrier pigeon": PAD})
    with pytest.raises(ValueError):
        zmux.Config(shaping={None: "{}"})


async def test_config_shapes_by_kind_from_the_first_record() -> None:
    # Only WebSocket pipes are shaped: there is no default.
    config = zmux.Config(shaping={zmux.CarrierKind.WEBSOCKET: PAD})
    async with zmux.Listener(config) as listener:
        ws = await listener.serve_websocket("127.0.0.1:0")
        tcp = await listener.serve_tcp("127.0.0.1:0")
        async with await zmux.connect_websocket(f"ws://{ws}/", config=config) as client:
            server = await listener.accept()
            await exchange(client, server)
            for s in (client, server):
                assert s.pipe_stats()[0].carrier == zmux.CarrierKind.WEBSOCKET
                st = s.shaping_stats()
                assert st["padding_bytes"] > 0 and st["faults"] == 0, st
        async with await zmux.connect_tcp(tcp, config=config) as client:
            server = await listener.accept()
            await exchange(client, server)
            for s in (client, server):
                assert s.pipe_stats()[0].carrier is None
                assert s.shaping_stats()["padding_bytes"] == 0


async def test_set_shaper_by_kind() -> None:
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        async with await zmux.connect_tcp(addr) as client:
            server = await listener.accept()
            with pytest.raises(ValueError):
                client.set_shaper(json=PAD, by_kind={None: PAD})
            client.set_shaper(by_kind={zmux.CarrierKind.QUIC: PAD})
            await exchange(client, server)
            assert client.shaping_stats()["padding_bytes"] == 0
            client.set_shaper(by_kind={None: PAD})
            await exchange(client, server)
            assert client.shaping_stats()["padding_bytes"] > 0


DELAY_FIRST = '{"version":1,"machines":[{"states":[{"record":{"delay":{"const":0.02}},"next":[{"on":"record_out","to":1}]},{}]}]}'
DELAY_ALL = (
    '{"version":1,"machines":[{"states":[{"record":{"delay":{"const":0.02}}}]}]}'
)


@pytest.mark.parametrize("definition", [DELAY_FIRST, DELAY_ALL], ids=["first", "all"])
async def test_a_delayed_first_record_keeps_the_parameters_first(
    definition: str,
) -> None:
    # A delay of the bootstrap pipe's first record, from the session's
    # creation on both ends, holds the transport parameters, which still
    # lead the pipe once it ends: both ends establish and carry a stream.
    config = zmux.Config(shaping={None: definition})
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        async with await zmux.connect_tcp(addr, config=config) as client:
            server = await listener.accept()
            await exchange(client, server)
            await exchange(server, client)
            for s in (client, server):
                st = s.shaping_stats()
                assert st["pause_total"] > 0 and st["faults"] == 0, st
