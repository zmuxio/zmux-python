"""Scripted peer of the cross-implementation secure-carrier matrix.

    matrix_peer.py matrix-server <scenario>
    matrix_peer.py matrix-client <scenario> <addr> [<tls-addr>] [<proof-key-id-hex>]

The scenarios, fixed keys, output lines and exit codes are those of the
matrix driver's contract.
"""

from __future__ import annotations

import asyncio
import os
import sys

import certs
import zmux

SERVER_SECRET = zmux.StaticKey.from_scalar(b"\x5a" * 32)
CLIENT_SECRET = zmux.StaticKey.from_scalar(b"\x6b" * 32)
HANDLE, PSK = zmux.adapter.derive_handle_psk(
    b"zmux interop pre-shared key 0123", b"interop", b""
)
PROFILE = {
    "psk": 1,
    "xx": 4,
    "join": 1,
    "epoch": 1,
    "appdata": 4,
    "proof": 4,
    "close": 1,
    "close-idle": 1,
}
MULTIPATH = {"join", "epoch"}
SIZE_A = 1 << 20
SIZE_B = 64 << 10
CLOSE_CODE = 85
CLOSE_REASON = b"matrix-close"
LIMIT = 30.0


class Failure(Exception):
    pass


class ClosedBy(Exception):
    """The client's verdict on the end of a session the server closed."""

    def __init__(self, info: zmux.SessionClosedError):
        self.info = info


def split_address(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


def say(line: str) -> None:
    print(line, flush=True)


def finish(code: int) -> None:
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def pattern(n: int) -> bytes:
    period = bytes((i * 31 + 7) % 256 for i in range(256))
    return (period * (n // 256 + 1))[:n]


def pin_of(secret: zmux.StaticKey) -> bytes:
    return zmux.static_key_id(secret.public_key)


def config(scenario: str) -> zmux.Config:
    if scenario in MULTIPATH:
        return zmux.Config(max_pipes=4, allow_record_mode=lambda *_: True)
    return zmux.Config()


def flag(b: bool) -> str:
    return "true" if b else "false"


def print_app_data(peer: zmux.Peer) -> None:
    for e in peer.app_data:
        say(
            f"APPDATA {e.message} {e.data.decode(errors='replace')}"
            f" fs={flag(e.forward_secret)} auth={flag(e.authenticated)}"
        )


def self_signed() -> zmux.TlsConfig:
    cert, key = certs.self_signed()
    return zmux.TlsConfig(cert=cert, key=key)


async def echo_one(session: zmux.Session) -> None:
    send, recv = await session.accept_bi()
    data = await recv.read_to_end()
    await send.write(data)
    await send.finish()
    await send.stopped()


async def send_and_check(session: zmux.Session, size: int, name: str) -> None:
    want = pattern(size)
    send, recv = await session.open_bi()
    await send.write(want)
    await send.finish()
    got = await recv.read_to_end()
    if got != want:
        raise Failure(f"stream {name}: echo of {len(got)} bytes differs")


class Watch:
    """Follows a session's events: whether an epoch was committed."""

    def __init__(self, session: zmux.Session):
        self.committed = asyncio.Event()
        self.task = asyncio.ensure_future(self._run(session))

    async def _run(self, session: zmux.Session) -> None:
        async for ev in session.events():
            if isinstance(ev, zmux.EpochCommitted):
                self.committed.set()


# The server.


class Gate:
    def resolve(self, handle: bytes, source: object) -> bytes:
        if handle != HANDLE:
            raise zmux.VerifyRejectedError("unknown handle")
        return PSK

    def credential(
        self, handle: bytes, profile: int, local_context: bytes, source: object
    ) -> None:
        return None

    def commit(self, handle: bytes, peer: zmux.Peer, source: object) -> zmux.Peer:
        return peer


async def server(scenario: str) -> int:
    signer = None
    if scenario == "proof":
        signer = zmux.SigningKey.generate(zmux.KeyAlg.MLDSA44)
        say(f"PROOFKEY {signer.key_id.hex()}")
    secure = zmux.SecureServer(
        Gate(),
        SERVER_SECRET,
        accepted_profiles=[1, 3, 4, 5],
        allow_record_mode=(lambda m, p: True) if scenario in MULTIPATH else None,
        client_verifier=(
            zmux.PinVerifier(pin_of(CLIENT_SECRET)) if scenario == "appdata" else None
        ),
        signer=signer,
        app_data=(
            (lambda m, i, v: b"srv-msg2" if m == 2 else None)
            if scenario == "appdata"
            else None
        ),
    )
    async with zmux.Listener(
        config=config(scenario),
        listener_config=zmux.ListenerConfig(secure_server=secure),
    ) as listener:
        addr = await listener.serve_tcp("127.0.0.1", 0)
        tls_addr = None
        if scenario == "join":
            tls_addr = await listener.serve_tls("127.0.0.1", 0, tls=self_signed())
        say(f"LISTEN {addr[0]}:{addr[1]}")
        if tls_addr is not None:
            say(f"LISTENTLS {tls_addr[0]}:{tls_addr[1]}")
        session = await anext(aiter(listener))
        watch = Watch(session)
        if scenario == "appdata":
            peer = session.admitted
            if not isinstance(peer, zmux.Peer):
                raise Failure(f"no established peer: {peer!r}")
            print_app_data(peer)
        if scenario == "close":
            _, recv = await session.accept_bi()
            await recv.read_exact(SIZE_B)
            session.abort(CLOSE_CODE, CLOSE_REASON)
            await session.wait_closed()
            say("CLOSING")
            return 0
        await echo_one(session)
        await send_and_check(session, SIZE_B, "B")
        if scenario == "close-idle":
            session.abort(CLOSE_CODE, CLOSE_REASON)
            await session.wait_closed()
            return 0
        await session.wait_closed()
        if scenario == "epoch":
            if not watch.committed.is_set():
                raise Failure("no EpochCommitted")
            say(f"EPOCH {session.epoch}")
    return 0


# The client.


async def client(scenario: str, args: list[str]) -> int:
    profile = PROFILE[scenario]
    host, port = split_address(args[0])
    proof_key = bytes.fromhex(args[1]) if scenario == "proof" else None
    pipe, peer = await zmux.establish(
        await zmux.dial_tcp(host, port),
        verifier=zmux.PinVerifier(pin_of(SERVER_SECRET), proof_key=proof_key),
        handle=HANDLE if profile in (1, 3) else b"",
        psk=PSK if profile in (1, 3) else b"",
        static_key=(
            CLIENT_SECRET if scenario == "appdata" else zmux.StaticKey.generate()
        ),
        allowed_profiles=[profile],
        app_data=(
            (lambda m, i, v: b"cli-msg3" if m == 3 else None)
            if scenario == "appdata"
            else None
        ),
        require_pq_auth=scenario == "proof",
    )
    if peer.profile != profile:
        raise Failure(f"profile {peer.profile}, want {profile}")
    if scenario == "appdata":
        print_app_data(peer)
    if scenario == "proof":
        say(
            f"PQ confidential={flag(peer.pq_confidential)}"
            f" authenticated={flag(peer.pq_authenticated)}"
        )
        if not peer.pq_authenticated:
            raise Failure("server not post-quantum authenticated")
    session = await zmux.Session.connect(pipe, config=config(scenario))
    if scenario == "close":
        send, _ = await session.open_bi()
        chunk = pattern(SIZE_B)
        try:
            while True:
                await send.write(chunk)
        except zmux.ZmuxError:
            pass
        raise ClosedBy(await session.wait_closed())
    watch = None
    if scenario == "join":
        extra = await session.add_pipe(
            await zmux.dial_tls(
                *split_address(args[1]), tls=zmux.TlsConfig(verify=False)
            ),
            options=zmux.PipeOptions(record_mode="bound"),
        )
        await extra.wait_attached()
        n = len(session.pipes())
        say(f"PIPES {n}")
        if n < 2:
            raise Failure(f"{n} pipes after the join")
    if scenario == "epoch":
        watch = Watch(session)
        session.advance_epoch()
        await watch.committed.wait()
        extra = await session.add_pipe(
            await zmux.dial_tcp(host, port),
            options=zmux.PipeOptions(record_mode="sealed"),
        )
        await extra.wait_attached()
    await send_and_check(session, SIZE_A, "A")
    if scenario == "close-idle":
        send, recv = await session.accept_bi()
        await send.write(await recv.read_to_end())
        await send.finish()
        raise ClosedBy(await session.wait_closed())
    await echo_one(session)
    # Graceful: an immediate close could drop the echo of B before the server reads it.
    await asyncio.wait_for(session.shutdown(0), 10)
    if watch is not None:
        say(f"EPOCH {session.epoch}")
    return 0


def judge_close(info: zmux.SessionClosedError) -> int:
    if info.code == CLOSE_CODE and info.reason == CLOSE_REASON:
        say(f"CLOSE code={CLOSE_CODE} reason={CLOSE_REASON.decode()}")
        return 0
    say(f"CLOSE lost {info!r} code={info.code} reason={info.reason!r}")
    return 3


async def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("matrix-server", "matrix-client"):
        raise Failure(
            "usage: matrix-server <scenario> | matrix-client <scenario> <addr> ..."
        )
    role, scenario, rest = argv[0], argv[1], argv[2:]
    if scenario not in PROFILE:
        raise Failure(f"unknown scenario {scenario!r}")
    async with asyncio.timeout(LIMIT):
        if role == "matrix-server":
            return await server(scenario)
        return await client(scenario, rest)


if __name__ == "__main__":
    try:
        rc = asyncio.run(main(sys.argv[1:]))
    except ClosedBy as c:
        rc = judge_close(c.info)
        if rc == 0:
            say("OK")
        finish(rc)
    except TimeoutError:
        say("FAIL timeout")
        finish(1)
    except BaseException as e:
        say(f"FAIL {type(e).__name__}: {e}")
        finish(1)
    if rc == 0:
        say("OK")
    finish(rc)
