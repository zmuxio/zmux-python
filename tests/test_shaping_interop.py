"""Shaping against another implementation's echo peer (tests/shape_peer.py
contract). Set ZMUX_SHAPE_PEER to the peer executable and ZMUX_SHAPE_DEF to
a shaping definition (JSON); skipped otherwise."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

PEER = os.environ.get("ZMUX_SHAPE_PEER")
DEF = os.environ.get("ZMUX_SHAPE_DEF")
SELF = [sys.executable, str(Path(__file__).with_name("shape_peer.py"))]

pytestmark = pytest.mark.skipif(
    not (PEER and DEF), reason="ZMUX_SHAPE_PEER and ZMUX_SHAPE_DEF not set"
)


def run(server: list[str], client: list[str], server_def: str, client_def: str) -> None:
    env = dict(os.environ)
    srv = subprocess.Popen(
        [*server, "server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**env, "SHAPE_DEF": server_def},
    )
    try:
        assert srv.stdout is not None
        line = srv.stdout.readline()
        assert line.startswith("LISTEN "), line
        cli = subprocess.run(
            [*client, "client", line.split()[1]],
            capture_output=True,
            check=False,
            text=True,
            timeout=70,
            env={**env, "SHAPE_DEF": client_def},
        )
        out, _ = srv.communicate(timeout=70)
    finally:
        srv.kill()
        srv.wait()
    assert cli.returncode == 0 and cli.stdout.rstrip().endswith("OK"), (
        cli.stdout + cli.stderr
    )
    assert srv.returncode == 0 and out.rstrip().endswith("OK"), out


@pytest.mark.parametrize("shaped", ["server", "client", "both"])
@pytest.mark.parametrize("python", ["server", "client"])
def test_shaping_interop(python: str, shaped: str) -> None:
    assert PEER and DEF
    peer = [PEER]
    server, client = (SELF, peer) if python == "server" else (peer, SELF)
    run(
        server,
        client,
        DEF if shaped != "client" else "",
        DEF if shaped != "server" else "",
    )
