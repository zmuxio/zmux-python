import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import zmux


GO_HELPER = r'''
package main

import (
    "context"
    "fmt"
    "io"
    "net"
    "os"
    "time"

    zmux "github.com/zmuxio/zmux-go"
)

func fatal(format string, args ...any) {
    fmt.Fprintf(os.Stdout, "ERR "+format+"\n", args...)
    os.Exit(1)
}

func config() *zmux.Config {
    caps := zmux.CapabilityOpenMetadata | zmux.CapabilityPriorityUpdate | zmux.CapabilityPriorityHints | zmux.CapabilityStreamGroups
    return &zmux.Config{
        Capabilities: caps,
        PrefacePadding: true,
        PrefacePaddingMinBytes: 16,
        PrefacePaddingMaxBytes: 16,
        PingPadding: true,
        PingPaddingMinBytes: 16,
        PingPaddingMaxBytes: 16,
    }
}

func main() {
    if len(os.Args) < 2 {
        fatal("usage: helper <server|client|client-large> ...")
    }
    switch os.Args[1] {
    case "server":
        runServer()
    case "client":
        runClient(false)
    case "client-large":
        runClient(true)
    default:
        fatal("unknown mode %q", os.Args[1])
    }
}

func runServer() {
    if len(os.Args) != 4 {
        fatal("usage: helper server <addr> <ready-file>")
    }
    listener, err := net.Listen("tcp", os.Args[2])
    if err != nil {
        fatal("listen: %v", err)
    }
    defer listener.Close()
    if err := os.WriteFile(os.Args[3], []byte(listener.Addr().String()), 0600); err != nil {
        fatal("ready file: %v", err)
    }
    raw, err := listener.Accept()
    if err != nil {
        fatal("accept: %v", err)
    }
    session, err := zmux.Server(raw, config())
    if err != nil {
        fatal("server: %v", err)
    }
    defer session.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if session.LocalPreface().Settings.PingPaddingKey == 0 || session.PeerPreface().Settings.PingPaddingKey == 0 {
        fatal("ping padding key was not advertised")
    }
    if _, err := session.Ping(ctx, []byte("go-ping-python-client")); err != nil {
        fatal("ping python client: %v", err)
    }
    stream, err := session.AcceptStream(ctx)
    if err != nil {
        fatal("accept stream: %v", err)
    }
    if got := string(stream.OpenInfo()); got != "python-open" {
        fatal("open info = %q", got)
    }
    meta := stream.Metadata()
    if meta.Priority != 7 || meta.Group == nil || *meta.Group != 9 {
        fatal("metadata = priority:%d group:%v", meta.Priority, meta.Group)
    }
    payload, err := io.ReadAll(stream)
    if err != nil {
        fatal("read stream: %v", err)
    }
    if got := string(payload); got != "python->go" {
        fatal("payload = %q", got)
    }
    if _, err := stream.WriteFinal([]byte("go:"+string(payload))); err != nil {
        fatal("write final: %v", err)
    }
    _ = session.Close()
    _ = session.Wait(ctx)
}

func runClient(large bool) {
    if len(os.Args) != 3 {
        fatal("usage: helper client <addr>")
    }
    raw, err := net.Dial("tcp", os.Args[2])
    if err != nil {
        fatal("dial: %v", err)
    }
    session, err := zmux.Client(raw, config())
    if err != nil {
        fatal("client: %v", err)
    }
    defer session.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if session.LocalPreface().Settings.PingPaddingKey == 0 || session.PeerPreface().Settings.PingPaddingKey == 0 {
        fatal("ping padding key was not advertised")
    }
    if _, err := session.Ping(ctx, []byte("go-ping-python-server")); err != nil {
        fatal("ping python server: %v", err)
    }
    stream, err := session.OpenStreamWithOptions(ctx, zmux.OpenOptions{
        InitialPriority: ptr(uint64(7)),
        InitialGroup: ptr(uint64(9)),
        OpenInfo: []byte("go-open"),
    })
    if err != nil {
        fatal("open stream: %v", err)
    }
    payload := []byte("go->python")
    if large {
        payload = make([]byte, 70000)
        for i := range payload {
            payload[i] = 'g'
        }
    }
    if _, err := stream.WriteFinal(payload); err != nil {
        fatal("write final: %v", err)
    }
    response, err := io.ReadAll(stream)
    if err != nil {
        fatal("read response: %v", err)
    }
    if large {
        if got := string(response); got != "ok" {
            fatal("large response = %q", got)
        }
    } else if got := string(response); got != "python:go->python" {
        fatal("response = %q", got)
    }
    _ = session.Close()
    _ = session.Wait(ctx)
}

func ptr[T any](value T) *T {
    return &value
}
'''


def _interop_config() -> zmux.Config:
    caps = int(
        zmux.Capability.OPEN_METADATA
        | zmux.Capability.PRIORITY_UPDATE
        | zmux.Capability.PRIORITY_HINTS
        | zmux.Capability.STREAM_GROUPS
    )
    return zmux.Config(
        capabilities=caps,
        preface_padding=True,
        preface_padding_min_bytes=16,
        preface_padding_max_bytes=16,
        ping_padding=True,
        ping_padding_min_bytes=16,
        ping_padding_max_bytes=16,
    )


class GoNativeInteropTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("ZMUX_INTEROP") != "1":
            raise unittest.SkipTest("set ZMUX_INTEROP=1 to run Go interop smoke")
        go_root = os.environ.get("ZMUX_GO_ROOT")
        if not go_root:
            raise unittest.SkipTest("set ZMUX_GO_ROOT to the Go implementation root")
        cls.go_root = pathlib.Path(go_root)
        if not cls.go_root.is_dir():
            raise unittest.SkipTest("Go implementation root not found: %s" % cls.go_root)
        if shutil.which("go") is None:
            raise unittest.SkipTest("go executable not found")
        cls.work = pathlib.Path(tempfile.mkdtemp(prefix="zmux-python-go-interop-"))
        cls.helper = cls._build_helper()

    @classmethod
    def tearDownClass(cls):
        work = getattr(cls, "work", None)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    @classmethod
    def _build_helper(cls) -> pathlib.Path:
        go_version = "1.25"
        for line in (cls.go_root / "go.mod").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "go":
                go_version = parts[1]
                break
        go_root = str(cls.go_root.resolve()).replace(os.sep, "/")
        (cls.work / "go.mod").write_text(
            "module zmux_python_go_interop_smoke\n\n"
            + "go %s\n\n" % go_version
            + "require github.com/zmuxio/zmux-go v0.0.0\n\n"
            + 'replace github.com/zmuxio/zmux-go => "%s"\n' % go_root
        )
        (cls.work / "main.go").write_text(GO_HELPER)
        helper = cls.work / ("interop-helper.exe" if os.name == "nt" else "interop-helper")
        result = subprocess.run(
            ["go", "build", "-mod=mod", "-o", str(helper), "."],
            cwd=cls.work,
            text=True,
            capture_output=True,
            timeout=90,
        )
        if result.returncode != 0:
            raise AssertionError(
                "go helper build failed\nstdout:\n%s\nstderr:\n%s"
                % (result.stdout, result.stderr)
            )
        return helper

    def test_python_client_talks_to_go_server_with_open_metadata(self):
        ready = self.work / "go-server.ready"
        process = self._spawn("server", "127.0.0.1:0", str(ready))
        try:
            host, port = self._wait_ready(ready).rsplit(":", 1)
            session = zmux.client(socket.create_connection((host, int(port)), timeout=2), _interop_config())
            try:
                session.ping(b"python-ping-go-server", timeout=5.0)
                stream = session.open_stream(
                    zmux.OpenOptions(
                        initial_priority=7,
                        initial_group=9,
                        open_info=b"python-open",
                    ),
                    timeout=5.0,
                )
                stream.write_final(b"python->go", timeout=5.0)
                self.assertEqual(stream.read(timeout=5.0), b"go:python->go")
                session.close()
            finally:
                session.close()
            self._assert_process_success(process)
        finally:
            self._terminate(process)

    def test_go_client_talks_to_python_server_with_open_metadata(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        result = {}

        def serve():
            raw = None
            session = None
            try:
                raw, _ = listener.accept()
                session = zmux.server(raw, _interop_config())
                session.ping(b"python-ping-go-client", timeout=5.0)
                stream = session.accept_stream(timeout=5.0)
                self.assertEqual(stream.open_info, b"go-open")
                self.assertEqual(stream.metadata.priority, 7)
                self.assertEqual(stream.metadata.group, 9)
                payload = stream.read(timeout=5.0)
                self.assertEqual(payload, b"go->python")
                stream.write_final(b"python:" + payload, timeout=5.0)
                session.wait(timeout=5.0)
            except BaseException as exc:
                result["error"] = exc
            finally:
                if session is not None:
                    session.close()
                elif raw is not None:
                    raw.close()
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        process = self._spawn("client", "%s:%d" % listener.getsockname())
        try:
            self._assert_process_success(process)
            thread.join(10)
            self.assertFalse(thread.is_alive())
            if "error" in result:
                raise result["error"]
        finally:
            self._terminate(process)

    def test_go_sender_advances_on_python_receive_max_data(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        result = {}

        def serve():
            raw = None
            session = None
            try:
                raw, _ = listener.accept()
                session = zmux.server(raw, _interop_config())
                session.ping(b"python-ping-go-large", timeout=5.0)
                stream = session.accept_stream(timeout=5.0)
                payload = stream.read(timeout=8.0)
                self.assertEqual(len(payload), 70000)
                stream.write_final(b"ok", timeout=5.0)
                session.wait(timeout=5.0)
            except BaseException as exc:
                result["error"] = exc
            finally:
                if session is not None:
                    session.close()
                elif raw is not None:
                    raw.close()
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        process = self._spawn("client-large", "%s:%d" % listener.getsockname())
        try:
            self._assert_process_success(process)
            thread.join(10)
            self.assertFalse(thread.is_alive())
            if "error" in result:
                raise result["error"]
        finally:
            self._terminate(process)

    def _spawn(self, *args):
        return subprocess.Popen(
            [str(self.helper), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _wait_ready(self, path: pathlib.Path) -> str:
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if path.exists():
                value = path.read_text().strip()
                if value:
                    return value
            time.sleep(0.02)
        raise AssertionError("Go helper did not publish its ready address")

    def _assert_process_success(self, process):
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError("Go helper timed out\nstdout:\n%s\nstderr:\n%s" % (stdout, stderr))
        if process.returncode != 0:
            raise AssertionError(
                "Go helper exited %d\nstdout:\n%s\nstderr:\n%s"
                % (process.returncode, stdout, stderr)
            )

    @staticmethod
    def _terminate(process):
        if process.poll() is None:
            process.kill()
            process.communicate()
