"""Go quicmux interop smoke for the aioquic adapter.

Gated like tests/test_interop_go.py: set ZMUX_INTEROP=1 and ZMUX_GO_ROOT to the
zmux-go checkout. Requires the go toolchain and aioquic.
"""

import asyncio
import importlib.util
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from pathlib import Path

import zmux

_AIOQUIC_SRC = Path(__file__).resolve().parents[1] / "packages" / "zmuxio-aioquic" / "src"
if str(_AIOQUIC_SRC) not in sys.path:
    sys.path.insert(0, str(_AIOQUIC_SRC))

import zmux_aioquic

HAVE_AIOQUIC = (
    importlib.util.find_spec("aioquic") is not None
    and importlib.util.find_spec("cryptography") is not None
)

ALPN = "zmux-python-go-quic-interop"
STEP = 10.0

GO_HELPER = r'''
package main

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "errors"
    "fmt"
    "io"
    "math/big"
    "os"
    "time"

    "github.com/quic-go/quic-go"
    zmux "github.com/zmuxio/zmux-go"
    quicmux "github.com/zmuxio/zmux-go/adapter/quicmux"
)

const alpn = "ALPN_PLACEHOLDER"

func fatal(format string, args ...any) {
    fmt.Fprintf(os.Stdout, "ERR "+format+"\n", args...)
    os.Exit(1)
}

func ptr(v uint64) *uint64 { return &v }

func serverTLS() *tls.Config {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        fatal("generate key: %v", err)
    }
    template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{CommonName: "localhost"},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter: time.Now().Add(time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames: []string{"localhost"},
    }
    der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    if err != nil {
        fatal("create cert: %v", err)
    }
    return &tls.Config{
        Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
        NextProtos: []string{alpn},
    }
}

func expectApplicationCode(err error, code uint64, what string) {
    var appErr *zmux.ApplicationError
    if !errors.As(err, &appErr) || appErr.Code != code {
        fatal("%s: err = %v, want application code %d", what, err, code)
    }
}

func main() {
    if len(os.Args) != 3 {
        fatal("usage: helper <server ready-file|client addr>")
    }
    switch os.Args[1] {
    case "server":
        runServer(os.Args[2])
    case "client":
        runClient(os.Args[2])
    default:
        fatal("unknown mode %q", os.Args[1])
    }
}

func runServer(readyFile string) {
    listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS(), nil)
    if err != nil {
        fatal("listen: %v", err)
    }
    defer listener.Close()
    if err := os.WriteFile(readyFile, []byte(listener.Addr().String()), 0600); err != nil {
        fatal("ready file: %v", err)
    }
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    conn, err := listener.Accept(ctx)
    if err != nil {
        fatal("accept conn: %v", err)
    }
    session := quicmux.WrapSession(conn)

    stream, err := session.AcceptStream(ctx)
    if err != nil {
        fatal("accept stream: %v", err)
    }
    if got := string(stream.OpenInfo()); got != "python-open" {
        fatal("open info = %q", got)
    }
    meta := stream.Metadata()
    if meta.Priority != 7 || meta.Group == nil || *meta.Group != 11 {
        fatal("metadata = priority:%d group:%v", meta.Priority, meta.Group)
    }
    payload, err := io.ReadAll(stream)
    if err != nil {
        fatal("read stream: %v", err)
    }
    if got := string(payload); got != "python->go" {
        fatal("payload = %q", got)
    }
    if _, err := stream.WriteFinal([]byte("go:" + string(payload))); err != nil {
        fatal("write final: %v", err)
    }

    recv, err := session.AcceptUniStream(ctx)
    if err != nil {
        fatal("accept uni stream: %v", err)
    }
    uniPayload, err := io.ReadAll(recv)
    if err != nil {
        fatal("read uni stream: %v", err)
    }
    if got := string(uniPayload); got != "python-uni" {
        fatal("uni payload = %q", got)
    }

    send, err := session.OpenUniStreamWithOptions(ctx, zmux.OpenOptions{OpenInfo: []byte("go-uni")})
    if err != nil {
        fatal("open uni stream: %v", err)
    }
    if _, err := send.WriteFinal([]byte("go-uni-payload")); err != nil {
        fatal("uni write final: %v", err)
    }

    resetStream, err := session.OpenStream(ctx)
    if err != nil {
        fatal("open reset stream: %v", err)
    }
    if _, err := resetStream.Write([]byte("x")); err != nil {
        fatal("reset stream write: %v", err)
    }
    var buf [16]byte
    _, err = resetStream.Read(buf[:])
    expectApplicationCode(err, 79, "read after python cancel_write")
    if err := resetStream.CancelWrite(77); err != nil {
        fatal("cancel write: %v", err)
    }

    var gate [1]byte
    if _, err := os.Stdin.Read(gate[:]); err != nil {
        fatal("read close signal: %v", err)
    }
    if err := session.Close(); err != nil {
        fatal("close session: %v", err)
    }
}

func runClient(addr string) {
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    conn, err := quic.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}, nil)
    if err != nil {
        fatal("dial: %v", err)
    }
    session := quicmux.WrapSession(conn)

    stream, err := session.OpenStreamWithOptions(ctx, zmux.OpenOptions{
        InitialPriority: ptr(7),
        InitialGroup: ptr(11),
        OpenInfo: []byte("go-open"),
    })
    if err != nil {
        fatal("open stream: %v", err)
    }
    if _, err := stream.WriteFinal([]byte("go->python")); err != nil {
        fatal("write final: %v", err)
    }
    response, err := io.ReadAll(stream)
    if err != nil {
        fatal("read response: %v", err)
    }
    if got := string(response); got != "python:go->python" {
        fatal("response = %q", got)
    }

    send, err := session.OpenUniStream(ctx)
    if err != nil {
        fatal("open uni stream: %v", err)
    }
    if _, err := send.WriteFinal([]byte("go-uni")); err != nil {
        fatal("uni write final: %v", err)
    }
    recv, err := session.AcceptUniStream(ctx)
    if err != nil {
        fatal("accept uni stream: %v", err)
    }
    uniPayload, err := io.ReadAll(recv)
    if err != nil {
        fatal("read uni stream: %v", err)
    }
    if got := string(uniPayload); got != "python-uni" {
        fatal("uni payload = %q", got)
    }

    resetStream, err := session.OpenStream(ctx)
    if err != nil {
        fatal("open reset stream: %v", err)
    }
    if _, err := resetStream.Write([]byte("x")); err != nil {
        fatal("reset stream write: %v", err)
    }
    var buf [16]byte
    _, err = resetStream.Read(buf[:])
    expectApplicationCode(err, 78, "read after python cancel_write")
    if err := resetStream.CancelWrite(76); err != nil {
        fatal("cancel write: %v", err)
    }

    var gate [1]byte
    if _, err := os.Stdin.Read(gate[:]); err != nil {
        fatal("read close signal: %v", err)
    }
    if err := session.Close(); err != nil {
        fatal("close session: %v", err)
    }
}
'''.replace("ALPN_PLACEHOLDER", ALPN)


if HAVE_AIOQUIC:
    from aioquic.asyncio import connect, serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    class ZmuxProtocol(QuicConnectionProtocol):
        def __init__(self, quic, stream_handler=None):
            super().__init__(quic, stream_handler=self._handle_stream)
            self.session = zmux_aioquic.wrap_session(self)

        def _handle_stream(self, reader, writer):
            self.session.queue_incoming_stream(reader, writer)

else:  # pragma: no cover - exercised only without aioquic
    ZmuxProtocol = None


async def _read_to_end(stream):
    chunks = []
    while True:
        chunk = await stream.read(65536, timeout=STEP)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


@unittest.skipUnless(HAVE_AIOQUIC, "aioquic is not installed")
class AioquicGoQuicInteropSmokeTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("ZMUX_INTEROP") != "1":
            raise unittest.SkipTest("set ZMUX_INTEROP=1 to run Go QUIC interop smoke")
        go_root = os.environ.get("ZMUX_GO_ROOT")
        if not go_root:
            raise unittest.SkipTest("set ZMUX_GO_ROOT to the Go implementation root")
        cls.go_root = pathlib.Path(go_root)
        if not (cls.go_root / "adapter" / "quicmux").is_dir():
            raise unittest.SkipTest("Go quicmux adapter not found under %s" % cls.go_root)
        if shutil.which("go") is None:
            raise unittest.SkipTest("go executable not found")
        cls.work = pathlib.Path(tempfile.mkdtemp(prefix="zmux-python-go-quic-interop-"))
        cls.helper = cls._build_helper()

    @classmethod
    def tearDownClass(cls):
        work = getattr(cls, "work", None)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    @classmethod
    def _build_helper(cls) -> pathlib.Path:
        quic_go = "v0.59.0"
        adapter = cls.go_root / "adapter" / "quicmux"
        for line in (adapter / "go.mod").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "github.com/quic-go/quic-go":
                quic_go = parts[1]
                break
        go_root = str(cls.go_root.resolve()).replace(os.sep, "/")
        adapter_root = str(adapter.resolve()).replace(os.sep, "/")
        (cls.work / "go.mod").write_text(
            "module zmux_python_go_quic_interop_smoke\n\n"
            "go 1.25\n\n"
            "require (\n"
            "    github.com/quic-go/quic-go %s\n"
            "    github.com/zmuxio/zmux-go v0.0.0\n"
            "    github.com/zmuxio/zmux-go/adapter/quicmux v0.0.0\n"
            ")\n\n"
            'replace github.com/zmuxio/zmux-go => "%s"\n'
            'replace github.com/zmuxio/zmux-go/adapter/quicmux => "%s"\n'
            % (quic_go, go_root, adapter_root)
        )
        (cls.work / "main.go").write_text(GO_HELPER)
        helper = cls.work / ("interop-helper.exe" if os.name == "nt" else "interop-helper")
        result = subprocess.run(
            ["go", "build", "-mod=mod", "-o", str(helper), "."],
            cwd=cls.work,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                "go helper build failed\nstdout:\n%s\nstderr:\n%s"
                % (result.stdout, result.stderr)
            )
        return helper

    def setUp(self):
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.filterwarnings(
            "ignore", message=r"unclosed <StreamWriter", category=ResourceWarning
        )

    async def test_python_client_talks_to_go_quicmux_server(self):
        ready = self.work / "go-server.ready"
        process = self._spawn("server", str(ready))
        try:
            host, port = (await self._wait_ready(ready)).rsplit(":", 1)
            config = QuicConfiguration(
                is_client=True,
                alpn_protocols=[ALPN],
                server_name="localhost",
                verify_mode=ssl.CERT_NONE,
            )
            async with connect(
                    host, int(port), configuration=config, create_protocol=ZmuxProtocol
            ) as client:
                session = client.session
                stream = await session.open_stream(
                    zmux.OpenOptions(
                        initial_priority=7, initial_group=11, open_info=b"python-open"
                    )
                )
                await stream.write_final(b"python->go", timeout=STEP)
                self.assertEqual(await _read_to_end(stream), b"go:python->go")

                uni = await session.open_uni_stream()
                await uni.write_final(b"python-uni", timeout=STEP)
                recv = await session.accept_uni_stream(STEP)
                self.assertIsInstance(recv, zmux_aioquic.AioquicRecvStream)
                self.assertEqual(recv.stream_id, 3)
                self.assertEqual(recv.open_info, b"go-uni")
                self.assertEqual(await _read_to_end(recv), b"go-uni-payload")

                reset_peer = await session.accept_stream(STEP)
                self.assertEqual(reset_peer.stream_id, 1)
                self.assertEqual(await reset_peer.read(1, timeout=STEP), b"x")
                await reset_peer.cancel_write(79)
                with self.assertRaises(zmux.ApplicationError) as caught:
                    while await reset_peer.read(16, timeout=STEP):
                        pass
                self.assertEqual(caught.exception.code, 77)
                self.assertEqual(caught.exception.termination_kind, zmux.TerminationKind.RESET)

                process.stdin.write(b"\x01")
                process.stdin.flush()
                await self._assert_process_success(process)
                self.assertIsNone(await session.wait(STEP))
                self.assertIsNone(session.peer_close_error)
        finally:
            self._terminate(process)

    async def test_go_quicmux_client_talks_to_python_server(self):
        certificate, key = _self_signed_certificate()
        config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN])
        config.certificate = certificate
        config.private_key = key
        protocols = []

        def create_protocol(*args, **kwargs):
            protocol = ZmuxProtocol(*args, **kwargs)
            protocols.append(protocol)
            return protocol

        server = await serve("127.0.0.1", 0, configuration=config, create_protocol=create_protocol)
        process = None
        try:
            port = server._transport.get_extra_info("sockname")[1]
            process = self._spawn("client", "127.0.0.1:%d" % port)
            deadline = time.monotonic() + STEP
            while not protocols:
                self.assertLess(time.monotonic(), deadline, "Go client did not connect")
                await asyncio.sleep(0.01)
            session = protocols[0].session

            stream = await session.accept_stream(STEP)
            self.assertEqual(stream.stream_id, 0)
            self.assertEqual(stream.open_info, b"go-open")
            self.assertEqual(stream.metadata.priority, 7)
            self.assertEqual(stream.metadata.group, 11)
            payload = await _read_to_end(stream)
            self.assertEqual(payload, b"go->python")
            await stream.write_final(b"python:" + payload, timeout=STEP)

            recv = await session.accept_uni_stream(STEP)
            self.assertEqual(recv.stream_id, 2)
            self.assertEqual(await _read_to_end(recv), b"go-uni")
            await session.open_uni_and_send(b"python-uni", timeout=STEP)

            reset_peer = await session.accept_stream(STEP)
            self.assertEqual(reset_peer.stream_id, 4)
            self.assertEqual(await reset_peer.read(1, timeout=STEP), b"x")
            await reset_peer.cancel_write(78)
            with self.assertRaises(zmux.ApplicationError) as caught:
                while await reset_peer.read(16, timeout=STEP):
                    pass
            self.assertEqual(caught.exception.code, 76)

            process.stdin.write(b"\x01")
            process.stdin.flush()
            await self._assert_process_success(process)
            self.assertIsNone(await session.wait(STEP))
            self.assertEqual(session.state, zmux.SessionState.CLOSED)
        finally:
            if process is not None:
                self._terminate(process)
            server.close()

    def _spawn(self, *args):
        return subprocess.Popen(
            [str(self.helper), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    async def _wait_ready(self, path: pathlib.Path) -> str:
        deadline = time.monotonic() + STEP
        while time.monotonic() < deadline:
            if path.exists():
                value = path.read_text().strip()
                if value:
                    return value
            await asyncio.sleep(0.02)
        raise AssertionError("Go helper did not publish its ready address")

    async def _assert_process_success(self, process):
        try:
            stdout, stderr = await asyncio.to_thread(process.communicate, timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(
                "Go helper timed out\nstdout:\n%s\nstderr:\n%s" % (stdout, stderr)
            )
        if process.returncode != 0:
            raise AssertionError(
                "Go helper exited %d\nstdout:\n%s\nstderr:\n%s"
                % (process.returncode, stdout.decode(), stderr.decode())
            )

    @staticmethod
    def _terminate(process):
        if process.poll() is None:
            process.kill()
            process.communicate()


def _self_signed_certificate():
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


if __name__ == "__main__":
    unittest.main()
