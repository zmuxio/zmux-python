import os
import pathlib
import shutil
import socket
import subprocess
import sys
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
    "strconv"
    "sync"
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
    case "server-zero-window":
        runZeroWindowServer()
    case "server-many":
        runManyStreamsServer()
    case "client-cancelled-upload":
        runCancelledUploadClient()
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

// runZeroWindowServer advertises no initial stream credit for peer-opened
// bidirectional streams: the peer must open with a zero-length DATA before
// any stream BLOCKED, or this side fails the session with PROTOCOL.
func runZeroWindowServer() {
    if len(os.Args) != 4 {
        fatal("usage: helper server-zero-window <addr> <ready-file>")
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
    cfg := config()
    cfg.Settings = zmux.DefaultSettings()
    cfg.Settings.InitialMaxStreamDataBidiPeerOpened = 0
    session, err := zmux.Server(raw, cfg)
    if err != nil {
        fatal("server: %v", err)
    }
    defer session.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    stream, err := session.AcceptStream(ctx)
    if err != nil {
        fatal("accept stream: %v", err)
    }
    if _, err := stream.WriteFinal([]byte("accepted")); err != nil {
        fatal("write final: %v", err)
    }
    if err := session.Wait(ctx); err != nil && ctx.Err() != nil {
        fatal("wait: %v", err)
    }
}

// runManyStreamsServer accepts streams the peer opened concurrently.  Their
// openers must arrive in stream-ID order, or this side fails the session with
// PROTOCOL (SPEC section 3.1).
func runManyStreamsServer() {
    if len(os.Args) != 5 {
        fatal("usage: helper server-many <addr> <ready-file> <count>")
    }
    count, err := strconv.Atoi(os.Args[4])
    if err != nil {
        fatal("count: %v", err)
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

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()
    var wg sync.WaitGroup
    errs := make(chan error, count)
    for i := 0; i < count; i++ {
        stream, err := session.AcceptStream(ctx)
        if err != nil {
            fatal("accept stream %d: %v", i, err)
        }
        wg.Add(1)
        go func() {
            defer wg.Done()
            payload, err := io.ReadAll(stream)
            if err != nil {
                errs <- fmt.Errorf("read stream %d: %w", stream.StreamID(), err)
                return
            }
            if _, err := stream.WriteFinal([]byte(strconv.Itoa(len(payload)))); err != nil {
                errs <- fmt.Errorf("write stream %d: %w", stream.StreamID(), err)
            }
        }()
    }
    wg.Wait()
    close(errs)
    for err := range errs {
        fatal("%v", err)
    }
    if err := session.Wait(ctx); err != nil && ctx.Err() != nil {
        fatal("wait: %v", err)
    }
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

// runCancelledUploadClient keeps writing on streams the Python side stops
// reading or aborts mid-transfer, so a full stream window of DATA is in flight
// when the stop lands.  The session must survive: every later stream still
// round-trips.
func runCancelledUploadClient() {
    if len(os.Args) != 4 {
        fatal("usage: helper client-cancelled-upload <addr> <rounds>")
    }
    rounds, err := strconv.Atoi(os.Args[3])
    if err != nil {
        fatal("rounds: %v", err)
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

    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    chunk := make([]byte, 16384)
    for i := range chunk {
        chunk[i] = 'u'
    }
    for round := 0; round < rounds; round++ {
        upload, err := session.OpenStream(ctx)
        if err != nil {
            fatal("open upload %d: %v", round, err)
        }
        for written := 0; written < 4<<20; written += len(chunk) {
            if _, err := upload.Write(chunk); err != nil {
                break
            }
        }
        _ = upload.CloseWithError(uint64(zmux.CodeCancelled), "")
        check, err := session.OpenStream(ctx)
        if err != nil {
            fatal("open check %d: %v", round, err)
        }
        if _, err := check.WriteFinal([]byte("after")); err != nil {
            fatal("write check %d: %v", round, err)
        }
        response, err := io.ReadAll(check)
        if err != nil {
            fatal("read check %d: %v", round, err)
        }
        if got := string(response); got != "python:after" {
            fatal("check response %d = %q", round, got)
        }
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

    def test_python_client_opens_stream_on_go_server_with_zero_stream_window(self):
        # The opener must be a zero-length DATA: a stream BLOCKED first is a
        # session PROTOCOL error at the Go receiver (SPEC section 9.1).
        ready = self.work / "go-zero-window.ready"
        process = self._spawn("server-zero-window", "127.0.0.1:0", str(ready))
        try:
            host, port = self._wait_ready(ready).rsplit(":", 1)
            session = zmux.client(socket.create_connection((host, int(port)), timeout=2), _interop_config())
            try:
                stream = session.open_stream(timeout=5.0)
                try:
                    stream.write(b"hello", timeout=0.5)
                except zmux.WriteTimeout:
                    pass  # the receiver may keep its zero window closed
                self.assertEqual(stream.read(timeout=5.0), b"accepted")
                self.assertIsNone(session.close_error)
                stream.close_with_error(int(zmux.ErrorCode.CANCELLED))
            finally:
                session.close()
            self._assert_process_success(process)
        finally:
            self._terminate(process)

    def test_python_client_concurrent_opens_reach_go_server_in_id_order(self):
        # Every thread opens a stream and writes at once; the Go receiver fails
        # the session if an opener ever overtakes a lower stream ID.
        count = 64
        ready = self.work / "go-many.ready"
        process = self._spawn("server-many", "127.0.0.1:0", str(ready), str(count))
        switch_interval = sys.getswitchinterval()
        # A tiny GIL switch interval widens any window between assigning a
        # stream ID and queueing that stream's opener.
        sys.setswitchinterval(1e-5)
        try:
            host, port = self._wait_ready(ready).rsplit(":", 1)
            session = zmux.client(socket.create_connection((host, int(port)), timeout=2), _interop_config())
            try:
                start = threading.Barrier(count)
                errors = []

                def open_and_write(index):
                    try:
                        options = zmux.OpenOptions(initial_priority=index % 8)
                        stream = session.open_stream(options, timeout=5.0)
                        start.wait(5.0)
                        stream.write_final(b"x" * 100, timeout=5.0)
                        self.assertEqual(stream.read(timeout=5.0), b"100")
                    except BaseException as exc:
                        errors.append(exc)

                threads = [
                    threading.Thread(target=open_and_write, args=(index,), daemon=True)
                    for index in range(count)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(10.0)
                self.assertEqual(errors, [])
                self.assertIsNone(session.close_error)
            finally:
                session.close()
            self._assert_process_success(process)
        finally:
            sys.setswitchinterval(switch_interval)
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

    def test_python_stop_or_abort_mid_upload_keeps_go_session(self):
        # A Go sender may have a whole stream window in flight when the Python
        # receiver stops reading or aborts; those bytes must be discarded, not
        # turned into a session PROTOCOL error (SPEC 9.3/9.5, DESIGN D2).
        rounds = 6
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
                for round_index in range(rounds):
                    upload = session.accept_stream(timeout=10.0)
                    self.assertGreater(len(upload.read(16384, timeout=10.0)), 0)
                    if round_index % 2:
                        upload.close_with_error(int(zmux.ErrorCode.CANCELLED))
                    else:
                        upload.close_read()
                    check = session.accept_stream(timeout=10.0)
                    payload = check.read(timeout=10.0)
                    self.assertEqual(payload, b"after")
                    check.write_final(b"python:" + payload, timeout=5.0)
                    upload.close()
                self.assertIsNone(session.close_error)
                session.wait(timeout=10.0)
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
        process = self._spawn(
            "client-cancelled-upload",
            "%s:%d" % listener.getsockname(),
            str(rounds),
        )
        try:
            self._assert_process_success(process)
            thread.join(15)
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
