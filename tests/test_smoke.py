import asyncio
import datetime

import pytest

import zmux


@pytest.fixture(scope="module")
def tls():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return zmux.TlsConfig(cert=cert_pem, key=key_pem), zmux.TlsConfig(ca=cert_pem)


async def echo(listener):
    async for session in listener:
        async for send, recv in session:
            await send.write(await recv.read_to_end())
            await send.finish()


async def round_trip(session, data=b"hello", **open_args):
    send, recv = await session.open_bi(**(open_args or {"info": b"meta", "priority": (2, False)}))
    await send.write(data)
    await send.finish()
    assert await recv.read_to_end() == data


@pytest.mark.parametrize(
    "carrier", ["tcp", "tls", "quic", "websocket", "wss", "http", "http2", "http2-tls", "h3", "webtransport"]
)
async def test_carrier(carrier, tls):
    server_tls, client_tls = tls
    async with zmux.Listener() as listener:
        if carrier == "tcp":
            addr = await listener.serve_tcp("127.0.0.1:0")
            dial = zmux.dial_tcp(addr)
        elif carrier == "tls":
            addr = await listener.serve_tls("127.0.0.1:0", server_tls)
            dial = zmux.dial_tls(addr, "localhost", client_tls)
        elif carrier == "quic":
            addr = await listener.serve_quic("127.0.0.1:0", server_tls)
            dial = zmux.dial_quic(addr, "localhost", client_tls)
        elif carrier == "websocket":
            addr = await listener.serve_websocket("127.0.0.1:0")
            dial = zmux.dial_websocket(f"ws://{addr}/")
        elif carrier == "wss":
            addr = await listener.serve_websocket("127.0.0.1:0", server_tls)
            port = addr.rsplit(":", 1)[1]
            dial = zmux.dial_websocket(f"wss://localhost:{port}/", client_tls)
        elif carrier == "http2":
            addr = await listener.serve_http("127.0.0.1:0")
            dial = zmux.dial_http2(addr)
        elif carrier == "http2-tls":
            addr = await listener.serve_http("127.0.0.1:0", tls=server_tls)
            dial = zmux.dial_http2(addr, tls=client_tls, server_name="localhost")
        elif carrier == "h3":
            addr = await listener.serve_h3("127.0.0.1:0", server_tls)
            port = addr.rsplit(":", 1)[1]
            dial = zmux.dial_h3(f"https://localhost:{port}/zmux", client_tls, addr)
        elif carrier == "webtransport":
            # The client resolves the URL's host: serve on its first address.
            addr = await listener.serve_webtransport("localhost:0", server_tls)
            port = addr.rsplit(":", 1)[1]
            dial = zmux.dial_webtransport(f"https://localhost:{port}/zmux", client_tls)
        else:
            addr = await listener.serve_http("127.0.0.1:0")
            dial = zmux.dial_http(addr)
        server = asyncio.create_task(echo(listener))
        async with await zmux.Session.connect(await dial) as session:
            await round_trip(session)
        server.cancel()


async def test_preamble_and_errors():
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        async with await zmux.connect_tcp(addr) as client:
            server = await listener.accept()
            send, _ = await client.open_bi(info=b"route", tlvs=[(0x1000, b"x")])
            await send.write(b"a")
            _, recv = await server.accept_bi()
            assert recv.preamble() == (b"route", [(0x1000, b"x")])
            await send.reset(7)
            with pytest.raises(zmux.StreamReset) as e:
                await recv.read_to_end()
            assert e.value.code == 7 and isinstance(e.value, zmux.ZmuxError)
            server.close(code=3)
            with pytest.raises(zmux.SessionClosed) as e:
                await client.accept_bi()
            assert e.value.code == 3 and not e.value.retryable


async def test_cancellation():
    async with zmux.Listener() as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        async with await zmux.connect_tcp(addr) as client:
            server = await listener.accept()
            _, recv = await client.open_bi()
            task = asyncio.ensure_future(recv.read())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await recv.stop(1)  # the cancelled read released the stream
            accept = asyncio.ensure_future(server.accept_uni())
            await asyncio.sleep(0.05)
            accept.cancel()
            with pytest.raises(asyncio.CancelledError):
                await accept
            assert await client.ping() >= 0  # the session is still healthy


async def test_multipath():
    config = zmux.Config(psk=b"k" * 32)
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(addr, config) as session:
            pipe = session.add_pipe(await zmux.dial_tcp(addr), priority=1, standby=True)
            await pipe.joined()
            assert len(session.pipe_stats()) == 2
            await round_trip(session, b"x" * 100_000)
        server.cancel()


async def test_early_data():
    config = zmux.Config(early_data=True)
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(addr, config) as session:
            # Before the peer's parameters arrive: the preamble and the
            # requested priority travel within the floor.
            await round_trip(session, b"early", info=b"meta", peer_priority=(1, True))
        server.cancel()


async def test_quic_zero_rtt(tls):
    server_tls, client_tls = tls
    # Carrier early data only: connect waits for the server's parameters,
    # which the client remembers for the next connection.
    config = zmux.Config(carrier_early_data=True)
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_quic("127.0.0.1:0", server_tls, zero_rtt=True)
        server = asyncio.create_task(echo(listener))
        client = zmux.QuicClient(client_tls, zero_rtt=True)
        session, zero = await client.connect(addr, "localhost", config)
        async with session:
            await round_trip(session)
        assert not zero.sent and client.remembers("localhost")
        session, zero = await client.connect(addr, "localhost", config)
        async with session:
            await round_trip(session)
        assert zero.sent
        server.cancel()


async def test_resume_controls():
    config = zmux.Config(psk=b"k" * 32, resume_timeout=5, dead_timeout=2, suspect_floor=0.1, probation=0)
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_tcp("127.0.0.1:0")
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_tcp(addr, config) as session:
            assert session.join_ready
            session.revalidate_pipes()
            await round_trip(session)
        server.cancel()


async def test_reserve_pipe():
    config = zmux.Config(psk=b"k" * 32)
    async with zmux.Listener(config) as listener:
        addr = await listener.serve_websocket("127.0.0.1:0")
        server = asyncio.create_task(echo(listener))
        async with await zmux.connect_websocket(f"ws://{addr}/", config) as session:
            r = session.reserve_pipe()
            pipe = await zmux.dial_websocket(f"ws://{addr}/", headers=[("Zmux-Pipe-Join", r.header)])
            await r.attach(pipe).joined()
            assert len(session.pipe_stats()) == 2
            await round_trip(session)
        server.cancel()


async def test_stream_pair():
    async with zmux.Listener() as listener:
        server = asyncio.create_task(echo(listener))

        async def handle(reader, writer):
            await listener.handle_pipe(zmux.pipe_from_streams(reader, writer))

        tcp = await asyncio.start_server(handle, "127.0.0.1", 0)
        host, port = tcp.sockets[0].getsockname()[:2]
        reader, writer = await asyncio.open_connection(host, port)
        async with await zmux.Session.connect(zmux.pipe_from_streams(reader, writer)) as session:
            await round_trip(session)
        server.cancel()
        tcp.close()


def test_threads():
    """Sessions on several threads' event loops at once (free-threaded builds run them in parallel)."""
    import threading

    async def one():
        async with zmux.Listener() as listener:
            addr = await listener.serve_tcp("127.0.0.1:0")
            server = asyncio.ensure_future(echo(listener))
            async with await zmux.connect_tcp(addr) as session:
                for _ in range(20):
                    await round_trip(session, b"t" * 10_000)
            server.cancel()

    errors = []

    def run():
        try:
            asyncio.run(one())
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors
