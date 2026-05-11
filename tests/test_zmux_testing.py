import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import zmux
import zmux_testing
import zmux_testing.session_contract as session_contract
from zmux_testing.fixtures import load_ndjson, read_json

_EOF = object()


class MemorySession:
    def __init__(self):
        self.peer = None
        self.bidi_queue = asyncio.Queue()
        self.uni_queue = asyncio.Queue()
        self.closed_event = asyncio.Event()
        self.close_error_value = None

    async def open_stream(self, options=None, *, timeout=None):
        del options, timeout
        self._check_open()
        local, remote = MemoryStream.pair()
        await self.peer.bidi_queue.put(remote)
        return local

    async def open_uni_stream(self, options=None, *, timeout=None):
        del options, timeout
        self._check_open()
        local, remote = MemoryStream.pair(local_readable=False, peer_writable=False)
        await self.peer.uni_queue.put(remote)
        return local

    async def accept_stream(self, timeout=None):
        self._check_open()
        return await asyncio.wait_for(self.bidi_queue.get(), timeout)

    async def accept_uni_stream(self, timeout=None):
        self._check_open()
        return await asyncio.wait_for(self.uni_queue.get(), timeout)

    async def close(self):
        if self.closed:
            return
        self.closed_event.set()
        if self.peer is not None:
            self.peer._remote_closed(None)

    async def close_with_error(self, code, reason=""):
        if self.closed:
            return
        error = zmux.ApplicationError(code, reason)
        self.close_error_value = error
        self.closed_event.set()
        if self.peer is not None:
            self.peer._remote_closed(zmux.ApplicationError(code, reason))

    async def wait(self, timeout=None):
        await asyncio.wait_for(self.closed_event.wait(), timeout)
        if self.close_error_value is not None:
            raise self.close_error_value

    @property
    def closed(self):
        return self.closed_event.is_set()

    def _remote_closed(self, error):
        if self.closed:
            return
        self.close_error_value = error
        self.closed_event.set()

    def _check_open(self):
        if self.closed:
            error = self.close_error_value
            if isinstance(error, zmux.ApplicationError):
                raise zmux.ApplicationError(error.code, error.reason)
            raise zmux.SessionClosed()


class SessionClosedWaitSession(MemorySession):
    async def wait(self, timeout=None):
        await super().wait(timeout)
        raise zmux.SessionClosed()


class MemoryStream:
    def __init__(self, readable=True, writable=True):
        self.peer = None
        self.inbound = asyncio.Queue()
        self.buffer = bytearray()
        self.readable = readable
        self.writable = writable
        self.read_closed_value = not readable
        self.write_closed_value = not writable
        self.read_error = None
        self.write_error = None

    @classmethod
    def pair(cls, local_readable=True, peer_writable=True):
        local = cls(readable=local_readable, writable=True)
        remote = cls(readable=True, writable=peer_writable)
        local.peer = remote
        remote.peer = local
        return local, remote

    @property
    def read_closed(self):
        return self.read_closed_value

    @property
    def write_closed(self):
        return self.write_closed_value

    async def read(self, max_bytes=-1):
        self._check_readable()
        if max_bytes is None or max_bytes < 0:
            max_bytes = 65536
        if self.buffer:
            return self._take_buffer(max_bytes)
        item = await self.inbound.get()
        if item is _EOF:
            self.read_closed_value = True
            return b""
        if isinstance(item, BaseException):
            self.read_closed_value = True
            self.read_error = item
            raise item
        self.buffer.extend(item)
        return self._take_buffer(max_bytes)

    async def read_exact(self, size, timeout=None):
        chunks = bytearray()
        while len(chunks) < size:
            chunk = await asyncio.wait_for(self.read(size - len(chunks)), timeout)
            if not chunk:
                raise EOFError("unexpected EOF")
            chunks.extend(chunk)
        return bytes(chunks)

    async def write(self, data):
        self._check_writable()
        data = bytes(data)
        if not data:
            return 0
        await self.peer.inbound.put(data)
        return len(data)

    async def close_write(self):
        self._check_writable()
        self.write_closed_value = True
        await self.peer.inbound.put(_EOF)

    async def cancel_read(self, code):
        self._check_readable()
        self.read_closed_value = True
        self.read_error = zmux.ReadClosed()
        if self.peer is not None:
            self.peer.write_error = zmux.ApplicationError(code)
            self.peer.write_closed_value = True

    async def close_with_error(self, code, reason=""):
        error = zmux.ApplicationError(code, reason)
        self.read_closed_value = True
        self.write_closed_value = True
        self.read_error = error
        self.write_error = error
        if self.peer is not None:
            self.peer.read_error = zmux.ApplicationError(code, reason)
            self.peer.write_error = zmux.ApplicationError(code, reason)
            await self.peer.inbound.put(self.peer.read_error)

    def set_write_timeout(self, timeout):
        return None

    async def close(self):
        if self.writable and not self.write_closed_value:
            await self.close_write()
        self.read_closed_value = True

    def _take_buffer(self, max_bytes):
        out = bytes(self.buffer[:max_bytes])
        del self.buffer[:max_bytes]
        return out

    def _check_readable(self):
        if not self.readable:
            raise zmux.StreamNotReadable()
        if self.read_closed_value:
            raise self.read_error or zmux.ReadClosed()

    def _check_writable(self):
        if not self.writable:
            raise zmux.StreamNotWritable()
        if self.write_error is not None:
            raise self.write_error
        if self.write_closed_value:
            raise zmux.WriteClosed()


class BoolProgressStream(MemoryStream):
    async def write(self, data):
        await super().write(data)
        return True


class NoneReadStream(MemoryStream):
    async def read(self, max_bytes=-1):
        del max_bytes
        return None


class ShortExactStream:
    async def read_exact(self, size, timeout=None):
        del timeout
        return b"x" * max(0, size - 1)


class EndlessReadStream:
    async def read(self, max_bytes=-1, timeout=None):
        del timeout
        if max_bytes is None or max_bytes < 0:
            max_bytes = 1
        return b"x" * max(1, max_bytes)


class TooLongReadStream:
    async def read(self, max_bytes=-1, timeout=None):
        del max_bytes, timeout
        return b"xx"


class CallableClosedSession:
    def __init__(self, value):
        self.value = value

    def closed(self):
        return self.value


def make_pair():
    client = MemorySession()
    server = MemorySession()
    client.peer = server
    server.peer = client
    return client, server


def make_session_closed_wait_pair():
    client = SessionClosedWaitSession()
    server = SessionClosedWaitSession()
    client.peer = server
    server.peer = client
    return client, server


def _link_streams(local, remote):
    local.peer = remote
    remote.peer = local
    return local, remote


def make_bool_progress_pair():
    client, server = make_pair()

    async def open_stream(options=None, *, timeout=None):
        del options, timeout
        client._check_open()
        local, remote = _link_streams(BoolProgressStream(), MemoryStream())
        await server.bidi_queue.put(remote)
        return local

    client.open_stream = open_stream
    return client, server


def make_none_read_pair():
    client, server = make_pair()

    async def open_stream(options=None, *, timeout=None):
        del options, timeout
        client._check_open()
        local, remote = _link_streams(MemoryStream(), NoneReadStream())
        await server.bidi_queue.put(remote)
        return local

    client.open_stream = open_stream
    return client, server


class ZmuxTestingSurfaceTest(unittest.TestCase):
    def test_session_contract_exports(self):
        self.assertIs(zmux_testing.DEFAULT_TIMEOUT, zmux_testing.DEFAULT_TIMEOUT)
        self.assertTrue(callable(zmux_testing.run_session_contract))
        self.assertTrue(callable(zmux_testing.run_async_session_contract))
        self.assertTrue(callable(zmux_testing.locate_fixture_dir))
        self.assertTrue(callable(zmux_testing.load_fixture_ndjson))
        self.assertTrue(callable(zmux_testing.read_fixture_json))
        self.assertFalse(hasattr(zmux_testing, "load_ndjson"))
        self.assertFalse(hasattr(zmux_testing, "read_json"))
        self.assertNotIn("load_ndjson", zmux_testing.__all__)
        self.assertNotIn("read_json", zmux_testing.__all__)

    def test_run_session_contract_accepts_complete_async_pair(self):
        zmux_testing.run_session_contract(make_pair, timeout=1.0)

    def test_run_session_contract_accepts_session_closed_wait_result(self):
        zmux_testing.run_session_contract(make_session_closed_wait_pair, timeout=1.0)

    def test_run_session_contract_rejects_invalid_pair(self):
        with self.assertRaises(AssertionError):
            zmux_testing.run_session_contract(lambda: (None, MemorySession()), timeout=1.0)
        with self.assertRaises(TypeError):
            zmux_testing.run_session_contract(None, timeout=1.0)

    def test_run_session_contract_rejects_non_positive_timeout(self):
        with self.assertRaises(ValueError):
            zmux_testing.run_session_contract(make_pair, timeout=0)
        with self.assertRaises(ValueError):
            zmux_testing.run_session_contract(make_pair, timeout=float("inf"))
        with self.assertRaises(TypeError):
            zmux_testing.run_session_contract(make_pair, timeout=True)
        with self.assertRaises(TypeError):
            zmux_testing.run_session_contract(make_pair, timeout="1")

    def test_run_session_contract_rejects_invalid_write_progress(self):
        with self.assertRaisesRegex(AssertionError, "write returned invalid progress"):
            zmux_testing.run_session_contract(make_bool_progress_pair, timeout=1.0)

    def test_run_session_contract_rejects_non_bytes_read_result(self):
        with self.assertRaisesRegex(AssertionError, "read returned None"):
            zmux_testing.run_session_contract(make_none_read_pair, timeout=1.0)

    def test_session_contract_rejects_short_read_exact_result(self):
        async def run():
            with self.assertRaisesRegex(AssertionError, "read_exact returned 0 bytes"):
                await session_contract._read_exact(ShortExactStream(), 1, 1.0)

        asyncio.run(run())

    def test_session_contract_bounds_read_all_and_accepts_callable_closed(self):
        async def run():
            with self.assertRaisesRegex(AssertionError, "read_all exceeded"):
                await session_contract._read_all(EndlessReadStream(), 1.0, limit=3)
            with self.assertRaisesRegex(AssertionError, "read returned 2 bytes"):
                await session_contract._read_some(TooLongReadStream(), 1, 1.0)
            self.assertFalse(await session_contract._closed(CallableClosedSession(False)))
            self.assertTrue(await session_contract._closed(CallableClosedSession(True)))

        asyncio.run(run())

    def test_sync_runner_rejects_running_event_loop(self):
        async def run():
            with self.assertRaises(RuntimeError):
                zmux_testing.run_session_contract(make_pair, timeout=1.0)

        asyncio.run(run())

    def test_fixture_loader_locates_reads_caches_and_clones_json_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "testdata" / "fixtures"
            fixtures.mkdir(parents=True)
            (fixtures / "wire_valid.ndjson").write_text(
                '{\n  "id": "one",\n  "items": [1]\n}\n'
                '{\n  "id": "two",\n  "items": [2]\n}\n',
                encoding="utf-8",
            )
            (fixtures / "wire_invalid.ndjson").write_text(
                '{"id":"bad"}\n',
                encoding="utf-8",
            )
            (fixtures / "case_sets.json").write_text(
                json.dumps({"codec": ["one", "two"]}),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {}, clear=True):
                zmux_testing.clear_fixture_caches()
                self.assertEqual(zmux_testing.locate_fixture_dir(root), fixtures)

                loaded = zmux_testing.load_fixture_ndjson(
                    "wire_valid.ndjson", fixture_dir=fixtures
                )
                self.assertEqual([case["id"] for case in loaded], ["one", "two"])
                loaded[0]["items"].append(99)
                loaded_again = zmux_testing.load_fixture_ndjson(
                    "wire_valid.ndjson", fixture_dir=fixtures
                )
                self.assertEqual(loaded_again[0]["items"], [1])

                case_sets = zmux_testing.read_fixture_json(
                    "case_sets.json", fixture_dir=fixtures
                )
                case_sets["codec"].append("mutated")
                self.assertEqual(
                    zmux_testing.read_fixture_json(
                        "case_sets.json", fixture_dir=fixtures
                    )["codec"],
                    ["one", "two"],
                )
                self.assertEqual(
                    load_ndjson(fixtures / "wire_valid.ndjson")[0]["id"],
                    "one",
                )
                self.assertEqual(
                    read_json(fixtures / "case_sets.json")["codec"],
                    ["one", "two"],
                )
                with self.assertRaises(ValueError):
                    zmux_testing.load_fixture_ndjson(
                        "../wire_valid.ndjson",
                        fixture_dir=fixtures,
                    )
                for unsafe_name in (
                        "C:wire_valid.ndjson",
                        r"\wire_valid.ndjson",
                        r"nested\..\wire_valid.ndjson",
                ):
                    with self.subTest(unsafe_name=unsafe_name):
                        with self.assertRaises(ValueError):
                            zmux_testing.load_fixture_ndjson(
                                unsafe_name,
                                fixture_dir=fixtures,
                            )
                with self.assertRaises(ValueError):
                    zmux_testing.read_fixture_json(
                        fixtures / "case_sets.json",
                        fixture_dir=fixtures,
                    )

    def test_fixture_loader_accepts_spec_layout_and_env_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            fixtures.mkdir(parents=True)
            (fixtures / "wire_valid.ndjson").write_text('{"id":"one"}\n', encoding="utf-8")
            (fixtures / "wire_invalid.ndjson").write_text('{"id":"bad"}\n', encoding="utf-8")

            with mock.patch.dict("os.environ", {}, clear=True):
                zmux_testing.clear_fixture_caches()
                self.assertEqual(zmux_testing.locate_fixture_dir(root), fixtures)
                self.assertEqual(zmux_testing.locate_fixture_dir(fixtures), fixtures)

            with mock.patch.dict("os.environ", {"ZMUX_FIXTURE_DIR": str(fixtures)}, clear=True):
                zmux_testing.clear_fixture_caches()
                self.assertEqual(zmux_testing.locate_fixture_dir(root / "missing"), fixtures)

    def test_fixture_loader_reports_missing_empty_and_invalid_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "testdata" / "fixtures"
            fixtures.mkdir(parents=True)
            (fixtures / "wire_valid.ndjson").write_text("", encoding="utf-8")
            (fixtures / "wire_invalid.ndjson").write_text("not-json\n", encoding="utf-8")

            with mock.patch.dict("os.environ", {}, clear=True):
                zmux_testing.clear_fixture_caches()
                with self.assertRaises(ValueError):
                    zmux_testing.load_fixture_ndjson(
                        "wire_valid.ndjson", fixture_dir=fixtures
                    )
                with self.assertRaises(ValueError):
                    zmux_testing.load_fixture_ndjson(
                        "wire_invalid.ndjson", fixture_dir=fixtures
                    )

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict("os.environ", {}, clear=True):
                zmux_testing.clear_fixture_caches()
                with self.assertRaises(unittest.SkipTest):
                    zmux_testing.locate_fixture_dir(Path(tmp))


class ZmuxTestingAsyncSurfaceTest(unittest.IsolatedAsyncioTestCase):
    async def test_run_async_session_contract_accepts_async_pair_factory(self):
        async def async_pair():
            return make_pair()

        await zmux_testing.run_async_session_contract(async_pair, timeout=1.0)


if __name__ == "__main__":
    unittest.main()
