"""Runs the vendored zmux-spec fixture bundle against the Python package.

``testdata/fixtures`` is a byte-for-byte copy of ``zmux-spec/fixtures`` (see
the README there).  The tests below cover every bundle file:

* ``wire_valid``: each preface and frame decodes with every reader, matches
  the fixture's ``expect`` fields, and re-encodes to the same bytes.
* ``wire_invalid``: each vector fails in every codec reader with the fixture
  code, and each invalid frame makes a live session send ``CLOSE`` with it.
* ``invalid_cases``: like the Go harness (zmux-go ``fixtures_test.go``), every
  id needs an explicit runner in ``_INVALID_CASE_RUNNERS`` and an unmapped id
  fails, so a new or renamed upstream case cannot pass silently.  The expected
  code or action always comes from the fixture; there is no local override
  table.  Session- and stream-scope cases run on the wire: a raw zmux peer
  (role initiator, so the Python session is the responder) sends the frames
  over ``socket.socketpair`` and must receive ``CLOSE`` or ``ABORT`` with the
  fixture's code.
* ``state_cases``: the ``portable_state`` case set (zmux-spec
  ``examples/fixture_mapping.md`` section 2.1) runs through the same raw peer;
  the other state cases are reference-harness labels and are only inventoried.
* ``case_sets`` and ``index``: counts, ids and set membership stay consistent.

Set ``ZMUX_SPEC_ROOT`` to a zmux-spec checkout to also check that the vendored
copy is current.
"""

import collections
import contextlib
import io
import os
import socket
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

import zmux
import zmux_testing
from zmux._runtime.keepalive import has_ping_padding_tag, ping_padding_tag
from zmux._state.stream_id import stream_is_bidi
from zmux._wire.frame import read_session_frame

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VENDORED_DIR = _REPO_ROOT / "testdata" / "fixtures"
_SPEC_ROOT_ENV = "ZMUX_SPEC_ROOT"
_NDJSON_FILES = (
    "wire_valid.ndjson",
    "wire_invalid.ndjson",
    "state_cases.ndjson",
    "invalid_cases.ndjson",
)
_BUNDLE_FILES = _NDJSON_FILES + ("case_sets.json", "index.json")
_WAIT = 2.0
_QUIET = 0.05
_BARRIER_TOKEN = b"fixture:"

# The raw peer is the initiator, so the Python session under test is the
# responder: peer-owned IDs start at 4 (bidi) and 2 (uni), local ones at 1
# (bidi) and 3 (uni).
_PEER_BIDI = 4
_PEER_UNI = 2
_LOCAL_BIDI = 1
_LOCAL_UNI = 3

_CAPABILITY_BITS = {
    "open_metadata": zmux.CAPABILITY_OPEN_METADATA,
    "priority_hints": zmux.CAPABILITY_PRIORITY_HINTS,
    "stream_groups": zmux.CAPABILITY_STREAM_GROUPS,
    "priority_update": zmux.CAPABILITY_PRIORITY_UPDATE,
}
_SETTING_IDS = {
    "max_frame_payload": zmux.SETTING_MAX_FRAME_PAYLOAD,
    "max_control_payload_bytes": zmux.SETTING_MAX_CONTROL_PAYLOAD_BYTES,
    "max_extension_payload_bytes": zmux.SETTING_MAX_EXTENSION_PAYLOAD_BYTES,
}
_METADATA_TLV_NAMES = {
    zmux.METADATA_STREAM_PRIORITY: "stream_priority",
    zmux.METADATA_STREAM_GROUP: "stream_group",
    zmux.METADATA_OPEN_INFO: "open_info",
}
_FLAG_NAMES = (
    (zmux.FRAME_FLAG_OPEN_METADATA, "OPEN_METADATA"),
    (zmux.FRAME_FLAG_FIN, "FIN"),
)


# ---- bundle access ----


def _fixture_dir():
    return zmux_testing.locate_fixture_dir(_REPO_ROOT)


def _load(name):
    return zmux_testing.load_fixture_ndjson(name, fixture_dir=_fixture_dir())


def _read_json(name):
    return zmux_testing.read_fixture_json(name, fixture_dir=_fixture_dir())


def _case_sets():
    return _read_json("case_sets.json")["sets"]


def _ids(fixtures):
    return [fixture["id"] for fixture in fixtures]


# ---- encoding helpers ----


def _hex(text):
    return bytes.fromhex(text)


def _varint(value):
    return zmux.encode_varint(value)


def _raw_frame(code, stream_id, payload=b""):
    stream_id_bytes = _varint(stream_id)
    return (
            _varint(1 + len(stream_id_bytes) + len(payload))
            + bytes([code])
            + stream_id_bytes
            + payload
    )


def _tlvs(*items):
    out = bytearray()
    for typ, value in items:
        zmux.append_tlv(out, typ, value)
    return bytes(out)


def _priority_update_payload(*priorities):
    return _varint(zmux.EXT_PRIORITY_UPDATE) + _tlvs(
        *((zmux.METADATA_STREAM_PRIORITY, _varint(value)) for value in priorities)
    )


def _open_metadata_payload(tlvs, app_data):
    block = _tlvs(*tlvs)
    return _varint(len(block)) + block + app_data


def _preface_bytes(role, nonce=0, min_proto=1, max_proto=1, settings_tlv=b"", capabilities=0):
    return (
            zmux.MAGIC
            + bytes([zmux.PREFACE_VERSION, role])
            + _varint(nonce)
            + _varint(min_proto)
            + _varint(max_proto)
            + _varint(capabilities)
            + _varint(len(settings_tlv))
            + settings_tlv
    )


def _preface_layout(raw):
    """Split a raw preface into (bytes before settings_len, settings_len, settings)."""

    offset = 6  # magic, preface_ver, role
    for _ in range(4):  # tie_breaker_nonce, min_proto, max_proto, capabilities
        offset += zmux.parse_varint(raw, offset)[1]
    settings_len, length = zmux.parse_varint(raw, offset)
    settings = raw[offset + length:]
    return raw[:offset], settings_len, settings


def _capabilities(shape):
    bits = 0
    for name in shape.get("capabilities", ()):
        bits |= _CAPABILITY_BITS[name]
    return bits


def _error_code(frame):
    return zmux.parse_error_payload(frame.payload)[0]


def _first_frame_payload(frame_type):
    if frame_type in (zmux.FrameType.MAX_DATA, zmux.FrameType.BLOCKED):
        return _varint(64)
    if frame_type in (zmux.FrameType.STOP_SENDING, zmux.FrameType.RESET, zmux.FrameType.ABORT):
        return zmux.build_error_payload(int(zmux.ErrorCode.CANCELLED))
    raise AssertionError(f"no first-frame payload for {frame_type.name}")


def _frame(frame_type, stream_id, payload=b"", flags=0):
    return zmux.Frame(frame_type, stream_id, flags, payload)


def _is_frame(frame_type, stream_id=None):
    return lambda frame: frame.frame_type == frame_type and (
            stream_id is None or frame.stream_id == stream_id
    )


def _wait_until(predicate, timeout=_WAIT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def _run(target, *args, **kwargs):
    result = {}

    def runner():
        try:
            result["value"] = target(*args, **kwargs)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, result


def _close_quietly(session):
    try:
        session.close_with_error(int(zmux.ErrorCode.NO_ERROR))
    except zmux.ZmuxError:
        pass


# ---- raw peer ----


class _RawPeer:
    """Hand-driven zmux initiator that records every frame it receives."""

    def __init__(self, sock):
        self.socket = sock
        self._frames = []
        self._cond = threading.Condition()
        self._pings = 0

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)

    def send_preface(self, capabilities=0, settings=None):
        config = zmux.Config(
            role=zmux.Role.INITIATOR,
            capabilities=capabilities,
            disable_capabilities=capabilities == 0,
            settings=settings or zmux.Settings(),
            preface_padding=False,
            ping_padding=False,
        )
        self.socket.sendall(config.local_preface_payload())

    def start_collecting(self):
        zmux.read_preface(self)
        threading.Thread(target=self._collect, daemon=True).start()

    def _collect(self):
        while True:
            try:
                frame = zmux.read_frame(self)
            except (zmux.ZmuxError, OSError, ValueError):
                return
            with self._cond:
                self._frames.append(frame)
                self._cond.notify_all()

    def mark(self):
        with self._cond:
            return len(self._frames)

    def frames(self, since=0):
        with self._cond:
            return self._frames[since:]

    def wait_for(self, predicate, timeout=_WAIT, since=0):
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for frame in self._frames[since:]:
                    if predicate(frame):
                        return frame
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def barrier(self):
        """Return once the session processed every frame sent before."""

        self._pings += 1
        # Unique per call: a reused token would match an earlier PONG.
        token = _BARRIER_TOKEN + self._pings.to_bytes(8, "big")
        self.send(_frame(zmux.FrameType.PING, 0, token))
        pong = self.wait_for(
            lambda frame: frame.frame_type == zmux.FrameType.PONG
            and frame.payload.startswith(token)
        )
        if pong is None:
            raise AssertionError("session did not answer the barrier PING")

    def send(self, frame):
        self.socket.sendall(frame.marshal())

    def send_raw(self, raw):
        self.socket.sendall(raw)

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass


class _SocketReader:
    def __init__(self, sock):
        self.socket = sock

    def read(self, max_bytes):
        return self.socket.recv(max_bytes)


@contextlib.contextmanager
def _peer_session(capabilities=0, settings=None, peer_settings=None, **config):
    """A Python responder session with a raw initiator peer on a socketpair."""

    left, right = socket.socketpair()
    peer = _RawPeer(left)
    session = None
    try:
        peer.send_preface(capabilities, peer_settings)
        config.setdefault("keepalive_interval", None)
        session = zmux.server(right, zmux.Config(settings=settings or zmux.Settings(), **config))
        peer.start_collecting()
        yield session, peer
    finally:
        if session is not None:
            _close_quietly(session)
        peer.close()
        right.close()


# ---- outcomes ----

_Outcome = collections.namedtuple("_Outcome", "kind code action")


def _session_error(code):
    return _Outcome("session", code, None)


def _establishment_error(code):
    return _Outcome("session_establishment", code, None)


def _stream_error(code):
    return _Outcome("stream", code, None)


def _action(action):
    return _Outcome("action", None, action)


def _assert_outcome(t, fixture, outcome):
    expected = fixture["expected_result"]
    t.assertIsNotNone(outcome, "runner returned no outcome")
    if "error" in expected:
        # The kind names the observed signal: CLOSE on an established session,
        # an establishment failure, or ABORT on the stream.
        t.assertEqual(outcome.kind, expected["scope"], f"error scope (outcome {outcome!r})")
        t.assertEqual(
            zmux.error_code_name(outcome.code),
            expected["error"],
            f"error code (outcome {outcome!r})",
        )
        return
    t.assertEqual(outcome.kind, "action", f"expected a verified action, got {outcome!r}")
    t.assertEqual(outcome.action, expected["action"])


def _assert_session_open(t, session, peer):
    peer.barrier()
    t.assertIsNone(peer.wait_for(_is_frame(zmux.FrameType.CLOSE), timeout=_QUIET), "unexpected CLOSE")
    t.assertFalse(session.closed, "session terminated")
    t.assertEqual(session.state, zmux.SessionState.READY)


def _local_error_code(error):
    """Return the numeric code the local session error carries.

    It must be the code of the fatal ``CLOSE``, so ``close_error``, ``wait()``
    and the peer agree (``None`` here fails the comparison).
    """

    return zmux.error_code(error)


def _await_session_close(t, session, peer):
    """The session must fail and signal it with CLOSE (DESIGN D1)."""

    close = peer.wait_for(_is_frame(zmux.FrameType.CLOSE))
    t.assertIsNotNone(close, "session sent no CLOSE")
    code = _error_code(close)
    t.assertTrue(_wait_until(lambda: session.closed), "session did not terminate")
    t.assertEqual(session.state, zmux.SessionState.FAILED)
    t.assertEqual(_local_error_code(session.close_error), code, "local error and CLOSE code differ")
    return _session_error(code)


def _await_stream_abort(t, session, peer, stream_id, since):
    abort = peer.wait_for(_is_frame(zmux.FrameType.ABORT, stream_id), since=since)
    t.assertIsNotNone(abort, f"no ABORT on stream {stream_id}")
    _assert_session_open(t, session, peer)
    return _stream_error(_error_code(abort))


def _assert_no_error_signal(t, peer, stream_id, since):
    """The case's frame was ignored: no CLOSE, and no ABORT/RESET/STOP_SENDING on the stream."""

    time.sleep(_QUIET)
    for frame in peer.frames(since):
        t.assertNotEqual(frame.frame_type, zmux.FrameType.CLOSE, "unexpected CLOSE")
        if frame.stream_id == stream_id:
            t.assertNotIn(
                frame.frame_type,
                (zmux.FrameType.ABORT, zmux.FrameType.RESET, zmux.FrameType.STOP_SENDING),
                f"unexpected {frame.frame_type.name} on stream {stream_id}",
            )


def _restorable_session_credit(pressure):
    """Session receive credit the peer has, or will get back once pending credit is sent."""

    return (
            pressure.recv_session_advertised_bytes
            - pressure.recv_session_received_bytes
            + pressure.recv_session_pending_bytes
    )


def _open_peer_stream(t, session, peer, stream_id, payload=b"x"):
    peer.send(_frame(zmux.FrameType.DATA, stream_id, payload))
    accept = session.accept_stream if stream_is_bidi(stream_id) else session.accept_uni_stream
    stream = accept(timeout=_WAIT)
    t.assertEqual(stream.stream_id, stream_id, "accepted stream ID")
    return stream


def _open_local_uni_stream(t, session, peer):
    since = peer.mark()
    stream = session.open_uni_stream()
    stream.write(b"x", timeout=_WAIT)
    opener = peer.wait_for(_is_frame(zmux.FrameType.DATA), since=since)
    t.assertIsNotNone(opener, "local uni opener")
    t.assertEqual(opener.stream_id, _LOCAL_UNI, "first local uni stream ID")
    t.assertEqual(stream.stream_id, _LOCAL_UNI)
    return stream


# ---- codec helpers ----


def _codec_frame_failure(t, raw, limits=None, deferred=False):
    """Judge one encoded frame with every codec reader; all must agree.

    ``deferred`` marks the extension-subtype cases that the session-frame
    reader leaves to the session, which checks negotiation first (finding 12).
    """

    readers = [
        ("parse_frame", lambda: zmux.parse_frame(raw, limits)),
        ("read_frame", lambda: zmux.read_frame(io.BytesIO(raw), limits)),
    ]
    if deferred:
        read_session_frame(io.BytesIO(raw), limits)
    else:
        readers.append(("read_session_frame", lambda: read_session_frame(io.BytesIO(raw), limits)))
    codes = set()
    for label, read in readers:
        with t.assertRaises(zmux.ZmuxError, msg=label + " must reject the frame") as raised:
            read()
        codes.add(zmux.error_code(raised.exception))
    t.assertEqual(len(codes), 1, f"codec readers disagree: {codes!r}")
    return codes.pop()


def _codec_preface_failure(t, raw, local):
    codes = set()
    for label, read in (
            ("parse_preface", lambda: zmux.parse_preface(raw)),
            ("read_preface", lambda: zmux.read_preface(io.BytesIO(raw))),
    ):
        with t.assertRaises(zmux.ZmuxError, msg=label + " + negotiate must reject") as raised:
            zmux.negotiate_prefaces(local.local_preface(), read())
        codes.add(zmux.error_code(raised.exception))
    t.assertEqual(len(codes), 1, f"preface readers disagree: {codes!r}")
    return codes.pop()


def _session_preface_failure(t, raw, local):
    """Establish a real session against ``raw``; return the failure code.

    The session must also tell the peer: its complete preface, then
    ``CLOSE(code)`` (SPEC 2.4, DESIGN D1).
    """

    left, right = socket.socketpair()
    try:
        left.settimeout(_WAIT)
        config = replace(local, keepalive_interval=None, establishment_timeout=_WAIT)
        thread, result = _run(zmux.open, right, config)
        left.sendall(raw)
        thread.join(_WAIT)
        t.assertFalse(thread.is_alive(), "session establishment did not finish")
        if "value" in result:
            _close_quietly(result["value"])
            t.fail("session establishment accepted an invalid preface")
        code = zmux.error_code(result["error"])
        t.assertIsNotNone(code, f"establishment failure without a zmux code: {result['error']!r}")
        reader = _SocketReader(left)
        zmux.read_preface(reader)
        close = zmux.read_frame(reader)
        t.assertEqual(close.frame_type, zmux.FrameType.CLOSE)
        t.assertEqual(_error_code(close), code, "CLOSE code")
        return code
    finally:
        left.close()
        right.close()


# ---- invalid_cases runners: preface ----


def _preface_case(t, raw, local):
    codec = _codec_preface_failure(t, raw, local)
    live = _session_preface_failure(t, raw, local)
    t.assertEqual(live, codec, "codec and session establishment must agree")
    return _establishment_error(live)


def _hex_preface_case(t, fixture):
    raw = _hex(fixture["hex"])
    peer_initiator = len(raw) > 5 and raw[5] == int(zmux.Role.INITIATOR)
    role = zmux.Role.RESPONDER if peer_initiator else zmux.Role.INITIATOR
    return _preface_case(t, raw, zmux.Config(role=role))


def _preface_duplicate_setting_id(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["type"], "settings_tlv")
    settings = _tlvs(
        *((setting_id, _varint(100 + index)) for index, setting_id in enumerate(shape["setting_ids"]))
    )
    raw = _preface_bytes(int(zmux.Role.INITIATOR), settings_tlv=settings)
    return _preface_case(t, raw, zmux.Config(role=zmux.Role.RESPONDER))


def _preface_auto_equal_nonce(t, fixture):
    shape = fixture["input_shape"]
    local = zmux.Config(
        role=zmux.Role[shape["local_role"].upper()],
        tie_breaker_nonce=shape["local_tie_breaker_nonce"],
    )
    raw = _preface_bytes(
        int(zmux.Role[shape["peer_role"].upper()]),
        nonce=shape["peer_tie_breaker_nonce"],
    )
    return _preface_case(t, raw, local)


def _preface_setting_limit(t, fixture):
    shape = fixture["input_shape"]
    settings = _tlvs((_SETTING_IDS[shape["setting"]], _varint(shape["value"])))
    raw = _preface_bytes(int(zmux.Role.INITIATOR), settings_tlv=settings)
    return _preface_case(t, raw, zmux.Config(role=zmux.Role.RESPONDER))


def _preface_no_version_overlap(t, fixture):
    shape = fixture["input_shape"]
    local = zmux.Config(
        role=zmux.Role.RESPONDER,
        min_proto=shape["local_min_proto"],
        max_proto=shape["local_max_proto"],
    )
    raw = _preface_bytes(
        int(zmux.Role.INITIATOR),
        min_proto=shape["peer_min_proto"],
        max_proto=shape["peer_max_proto"],
    )
    return _preface_case(t, raw, local)


def _preface_same_role(t, fixture):
    shape = fixture["input_shape"]
    local = zmux.Config(role=zmux.Role[shape["local_role"].upper()])
    raw = _preface_bytes(int(zmux.Role[shape["peer_role"].upper()]))
    return _preface_case(t, raw, local)


# ---- invalid_cases runners: malformed frames ----


def _invalid_frame_case(t, raw, capabilities=0, setup=(), deferred=False):
    """Judge one encoded frame with the codec and with a live session."""

    codec = _codec_frame_failure(t, raw, deferred=deferred)
    with _peer_session(capabilities) as (session, peer):
        for frame in setup:
            peer.send(frame)
        if setup:
            peer.barrier()
        peer.send_raw(raw)
        outcome = _await_session_close(t, session, peer)
    t.assertEqual(outcome.code, codec, f"codec and session must agree on {raw.hex()}")
    return outcome


def _hex_frame_case(t, fixture):
    return _invalid_frame_case(t, _hex(fixture["hex"]))


def _frame_length_too_small(t, fixture):
    frame_length = fixture["input_shape"]["frame_length"]
    raw = _varint(frame_length) + bytes([int(zmux.FrameType.DATA)]) * frame_length
    return _invalid_frame_case(t, raw)


def _frame_ext_payload_underflow(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["frame_type"], "EXT")
    t.assertEqual(shape["frame_length_shape"], "too_small_for_ext_type_prefix")
    return _invalid_frame_case(t, _raw_frame(int(zmux.FrameType.EXT), 0))


def _frame_length_smaller_than_stream_id_prefix(t, fixture):
    shape = fixture["input_shape"]
    encoding_length = shape["stream_id_encoding_length"]
    stream_id = 0 if encoding_length == 1 else 1 << (8 * (encoding_length // 2) - 2)
    stream_id_bytes = _varint(stream_id)
    t.assertEqual(len(stream_id_bytes), encoding_length, "stream_id encoding length")
    raw = _varint(shape["frame_length"]) + bytes([int(zmux.FrameType.DATA)]) + stream_id_bytes
    return _invalid_frame_case(t, raw)


def _frame_pong_too_short(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["frame_type"], "PONG")
    raw = _raw_frame(int(zmux.FrameType.PONG), 0, bytes(shape["payload_len"]))
    return _invalid_frame_case(t, raw)


def _frame_abort_on_stream_zero(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["frame_type"], "ABORT")
    raw = _raw_frame(
        int(zmux.FrameType.ABORT),
        shape["stream_id"],
        _first_frame_payload(zmux.FrameType.ABORT),
    )
    return _invalid_frame_case(t, raw)


def _frame_trailing_garbage(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["payload_shape"], "canonical_varint_plus_trailing_bytes")
    frame_type = zmux.FrameType[shape["frame_type"]]
    raw = _raw_frame(int(frame_type), shape["stream_id"], _varint(1024) + b"\x01")
    return _invalid_frame_case(t, raw)


def _priority_update_structural_case(t, fixture, payload):
    shape = fixture["input_shape"]
    t.assertEqual(shape["ext_type"], "PRIORITY_UPDATE")
    stream_id = shape["stream_id"]
    # Open the target stream first so the receiver unquestionably parses the
    # update payload.
    return _invalid_frame_case(
        t,
        _raw_frame(int(zmux.FrameType.EXT), stream_id, payload),
        capabilities=_capabilities(shape),
        setup=(_frame(zmux.FrameType.DATA, stream_id, b"x"),),
        deferred=True,
    )


def _frame_priority_update_truncated_tlv_header(t, fixture):
    t.assertEqual(fixture["input_shape"]["payload_shape"], "truncated_stream_hint_tlv_header")
    payload = _varint(zmux.EXT_PRIORITY_UPDATE) + _varint(zmux.METADATA_STREAM_PRIORITY)
    return _priority_update_structural_case(t, fixture, payload)


def _frame_priority_update_tlv_value_overrun(t, fixture):
    t.assertEqual(fixture["input_shape"]["payload_shape"], "stream_hint_tlv_value_overrun")
    payload = (
            _varint(zmux.EXT_PRIORITY_UPDATE)
            + _varint(zmux.METADATA_STREAM_PRIORITY)
            + _varint(2)
            + b"\x01"
    )
    return _priority_update_structural_case(t, fixture, payload)


def _frame_priority_update_noncanonical_value(t, fixture):
    shape = fixture["input_shape"]
    t.assertTrue(shape["stream_exists"])
    raw = _hex(fixture["hex"])
    t.assertEqual(zmux.parse_varint(raw, 2)[0], shape["stream_id"], "fixture hex targets the stream")
    return _invalid_frame_case(
        t,
        raw,
        capabilities=_capabilities(shape),
        setup=(_frame(zmux.FrameType.DATA, shape["stream_id"], b"x"),),
        deferred=True,
    )


# ---- invalid_cases runners: session behaviour ----


def _frame_ping_payload_exceeds_local_echoable_limit(t, fixture):
    shape = fixture["input_shape"]
    local_limit = shape["local_max_control_payload_bytes"]
    peer_limit = shape["peer_max_control_payload_bytes"]
    with _peer_session(
            settings=zmux.Settings(max_control_payload_bytes=local_limit),
            peer_settings=zmux.Settings(max_control_payload_bytes=peer_limit),
    ) as (session, peer):
        since = peer.mark()
        # PING payload = 8-byte token + echo, so this echo makes the attempted
        # payload length.
        with t.assertRaises(zmux.FrameSizeError) as raised:
            session.ping(bytes(shape["attempted_ping_payload_len"] - 8), timeout=1.0)
        t.assertEqual(raised.exception.code, int(zmux.ErrorCode.FRAME_SIZE))
        time.sleep(_QUIET)
        t.assertFalse(
            [frame for frame in peer.frames(since) if frame.frame_type == zmux.FrameType.PING],
            "an oversized PING reached the wire",
        )

        fitting = bytes(min(local_limit, peer_limit) - 8 - 64)
        thread, result = _run(session.ping, fitting, timeout=_WAIT)
        ping = peer.wait_for(_is_frame(zmux.FrameType.PING), since=since)
        t.assertIsNotNone(ping, "PING within the limit")
        t.assertLessEqual(len(ping.payload), min(local_limit, peer_limit))
        peer.send(_frame(zmux.FrameType.PONG, 0, ping.payload))
        thread.join(_WAIT)
        t.assertNotIn("error", result)
        _assert_session_open(t, session, peer)
    return _action("forbid_send")


def _frame_priority_update_duplicate_singleton(t, fixture):
    shape = fixture["input_shape"]
    stream_id = shape["stream_id"]
    priorities = []
    for tlv in shape["stream_metadata_tlvs"]:
        t.assertEqual(tlv["type"], "stream_priority")
        priorities.append(tlv["value"])
    # priority_hints as well, so the control update below is applicable.
    capabilities = _capabilities(shape) | zmux.CAPABILITY_PRIORITY_HINTS
    with _peer_session(capabilities) as (session, peer):
        stream = _open_peer_stream(t, session, peer, stream_id)
        since = peer.mark()
        peer.send(_frame(zmux.FrameType.EXT, stream_id, _priority_update_payload(*priorities)))
        _assert_session_open(t, session, peer)
        t.assertIsNone(stream.metadata.priority, "a duplicate singleton must void the whole update")
        _assert_no_error_signal(t, peer, stream_id, since)

        # Control: a well-formed update on the same stream applies, so the
        # ignore above is not vacuous.
        peer.send(_frame(zmux.FrameType.EXT, stream_id, _priority_update_payload(9)))
        peer.barrier()
        t.assertEqual(stream.metadata.priority, 9)
    return _action("ignore_entire_update_payload")


def _frame_priority_update_without_capability(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(_capabilities(shape), 0)
    stream_id = shape["stream_id"]
    with _peer_session() as (session, peer):
        stream = _open_peer_stream(t, session, peer, stream_id)
        since = peer.mark()
        peer.send(_frame(zmux.FrameType.EXT, stream_id, _priority_update_payload(9)))
        _assert_session_open(t, session, peer)
        t.assertIsNone(stream.metadata.priority, "an unnegotiated update must be ignored")
        _assert_no_error_signal(t, peer, stream_id, since)
    return _action("ignore")


def _frame_priority_update_on_unused_stream(t, fixture):
    shape = fixture["input_shape"]
    t.assertFalse(shape["stream_exists"])
    stream_id = shape["stream_id"]
    capabilities = zmux.CAPABILITY_PRIORITY_UPDATE | zmux.CAPABILITY_PRIORITY_HINTS
    with _peer_session(capabilities) as (session, peer):
        peer.send(_frame(zmux.FrameType.EXT, stream_id, _priority_update_payload(9)))
        _assert_session_open(t, session, peer)
        with t.assertRaises(zmux.AcceptTimeout, msg="PRIORITY_UPDATE must not open the stream"):
            session.accept_stream(timeout=_QUIET)
        _assert_no_error_signal(t, peer, stream_id, 0)

        # The ID was not consumed: DATA still opens it, without the ignored
        # priority.
        stream = _open_peer_stream(t, session, peer, stream_id)
        t.assertIsNone(stream.metadata.priority, "the ignored update must not apply later")
    return _action("ignore")


def _frame_priority_update_on_terminal_stream(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["stream_state"], "terminal")
    stream_id = shape["stream_id"]
    capabilities = zmux.CAPABILITY_PRIORITY_UPDATE | zmux.CAPABILITY_PRIORITY_HINTS
    # An accepted stream is forgotten once terminal; an unaccepted one stays
    # in the accept queue as a terminal stream object.  Both must ignore it.
    for accepted in (True, False):
        with _peer_session(capabilities) as (session, peer):
            if accepted:
                stream = _open_peer_stream(t, session, peer, stream_id)
            else:
                peer.send(_frame(zmux.FrameType.DATA, stream_id, b"x"))
            peer.send(_frame(zmux.FrameType.ABORT, stream_id, _first_frame_payload(zmux.FrameType.ABORT)))
            peer.barrier()
            since = peer.mark()
            peer.send(_frame(zmux.FrameType.EXT, stream_id, _priority_update_payload(9)))
            _assert_session_open(t, session, peer)
            if not accepted:
                stream = session.accept_stream(timeout=_WAIT)
                t.assertEqual(stream.stream_id, stream_id)
            t.assertIsNone(stream.metadata.priority, "PRIORITY_UPDATE must not revive a terminal stream")
            _assert_no_error_signal(t, peer, stream_id, since)
    return _action("ignore")


def _frame_unknown_ext_subtype(t, fixture):
    shape = fixture["input_shape"]
    stream_id = shape["stream_id"]
    with _peer_session() as (session, peer):
        since = peer.mark()
        peer.send(_frame(zmux.FrameType.EXT, stream_id, _varint(shape["ext_type"]) + b"\xaa\xbb"))
        _assert_session_open(t, session, peer)
        _assert_no_error_signal(t, peer, stream_id, since)
    return _action("ignore")


def _frame_data_open_metadata_without_capability(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(_capabilities(shape), 0)
    payload = _open_metadata_payload([(zmux.METADATA_OPEN_INFO, b"a")], b"hi")
    with _peer_session() as (session, peer):
        peer.send(_frame(zmux.FrameType.DATA, shape["stream_id"], payload, zmux.FRAME_FLAG_OPEN_METADATA))
        return _await_session_close(t, session, peer)


def _frame_data_open_metadata_on_open_stream(t, fixture):
    shape = fixture["input_shape"]
    t.assertTrue(shape["stream_exists"])
    stream_id = shape["stream_id"]
    payload = _open_metadata_payload([(zmux.METADATA_OPEN_INFO, b"a")], b"hi")
    with _peer_session(zmux.CAPABILITY_OPEN_METADATA) as (session, peer):
        peer.send(_frame(zmux.FrameType.DATA, stream_id, b"x"))
        peer.barrier()
        peer.send(_frame(zmux.FrameType.DATA, stream_id, payload, zmux.FRAME_FLAG_OPEN_METADATA))
        return _await_session_close(t, session, peer)


def _frame_data_open_metadata_duplicate_singleton(t, fixture):
    shape = fixture["input_shape"]
    stream_id = shape["stream_id"]
    tlvs = []
    for tlv in shape["stream_metadata_tlvs"]:
        t.assertEqual(tlv["type"], "open_info")
        tlvs.append((zmux.METADATA_OPEN_INFO, _hex(tlv["value_hex"])))
    app_data = _hex(shape["application_payload_hex"])
    with _peer_session(zmux.CAPABILITY_OPEN_METADATA) as (session, peer):
        peer.send(
            _frame(
                zmux.FrameType.DATA,
                stream_id,
                _open_metadata_payload(tlvs, app_data),
                zmux.FRAME_FLAG_OPEN_METADATA,
            )
        )
        stream = session.accept_stream(timeout=_WAIT)
        t.assertEqual(stream.stream_id, stream_id, "the DATA must still open the stream")
        t.assertEqual(stream.open_info, b"", "a duplicate singleton drops the whole block")
        t.assertEqual(stream.read_exact(len(app_data), timeout=_WAIT), app_data)
        _assert_no_error_signal(t, peer, stream_id, 0)
        _assert_session_open(t, session, peer)
    return _action("ignore_entire_open_metadata_block")


def _frame_data_exceeds_stream_max_data(t, fixture):
    shape = fixture["input_shape"]
    stream_id = shape["stream_id"]
    received = shape["stream_bytes_received"]
    limit = shape["peer_stream_max_data"]
    incoming = shape["incoming_data_length"]
    t.assertTrue(received <= limit < received + incoming, "fixture overruns the stream window")
    settings = zmux.Settings(
        initial_max_stream_data_bidi_peer_opened=limit,
        initial_max_stream_data_bidi_locally_opened=limit,
    )
    with _peer_session(settings=settings) as (session, peer):
        peer.send(_frame(zmux.FrameType.DATA, stream_id, bytes(received)))
        peer.barrier()
        t.assertIsNone(
            peer.wait_for(_is_frame(zmux.FrameType.MAX_DATA, stream_id), timeout=0),
            "harness precondition: no stream credit granted before the overrun",
        )
        since = peer.mark()
        peer.send(_frame(zmux.FrameType.DATA, stream_id, bytes(incoming)))
        return _await_stream_abort(t, session, peer, stream_id, since)


def _frame_data_exceeds_session_max_data(t, fixture):
    shape = fixture["input_shape"]
    stream_id = shape["stream_id"]
    received = shape["session_bytes_received"]
    limit = shape["peer_session_max_data"]
    incoming = shape["incoming_data_length"]
    t.assertTrue(received <= limit < received + incoming, "fixture overruns the session window")
    settings = zmux.Settings(
        initial_max_data=limit,
        initial_max_stream_data_bidi_peer_opened=4 * limit,
    )
    with _peer_session(settings=settings) as (session, peer):
        peer.send(_frame(zmux.FrameType.DATA, stream_id, bytes(received)))
        peer.barrier()
        t.assertIsNone(
            peer.wait_for(_is_frame(zmux.FrameType.MAX_DATA, 0), timeout=0),
            "harness precondition: no session credit granted before the overrun",
        )
        peer.send(_frame(zmux.FrameType.DATA, stream_id, bytes(incoming)))
        return _await_session_close(t, session, peer)


def _frame_first_frame_on_unused_stream(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["initial_stream_state"], "idle")
    frame_type = zmux.FrameType[shape["incoming_frame"]]
    with _peer_session() as (session, peer):
        peer.send(_frame(frame_type, shape["stream_id"], _first_frame_payload(frame_type)))
        return _await_session_close(t, session, peer)


def _frame_peer_stream_id_gap(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["expected_next_stream_id"], _PEER_BIDI, "fixture assumes the responder's view")
    frame_type = zmux.FrameType[shape["incoming_frame"]]
    with _peer_session() as (session, peer):
        peer.send(_frame(frame_type, shape["incoming_stream_id"], b"x"))
        return _await_session_close(t, session, peer)


def _frame_wrong_side_uni(t, fixture):
    """Wrong-side frames on an opened uni stream.

    On a local send-only stream the peer may not send DATA, BLOCKED or RESET;
    on a local receive-only stream it may not send MAX_DATA or STOP_SENDING.
    """

    shape = fixture["input_shape"]
    frame_type = zmux.FrameType[shape["incoming_frame"]]
    with _peer_session() as (session, peer):
        kind = shape["stream_kind"]
        if kind == "uni_local_send_only":
            stream_id = _open_local_uni_stream(t, session, peer).stream_id
        elif kind == "uni_local_receive_only":
            stream_id = _open_peer_stream(t, session, peer, _PEER_UNI).stream_id
        else:
            raise AssertionError(f"unsupported stream_kind {kind!r}")
        peer.barrier()
        since = peer.mark()
        payload = b"y" if frame_type == zmux.FrameType.DATA else _first_frame_payload(frame_type)
        peer.send(_frame(frame_type, stream_id, payload))
        return _await_stream_abort(t, session, peer, stream_id, since)


def _session_goaway_increase(t, fixture):
    shape = fixture["input_shape"]
    with _peer_session() as (session, peer):
        peer.send(
            _frame(
                zmux.FrameType.GOAWAY,
                0,
                zmux.build_go_away_payload(
                    shape["prior_last_accepted_bidi_stream_id"],
                    shape["prior_last_accepted_uni_stream_id"],
                    int(zmux.ErrorCode.NO_ERROR),
                ),
            )
        )
        peer.barrier()
        t.assertFalse(session.closed, "the first GOAWAY must be accepted")
        peer.send(
            _frame(
                zmux.FrameType.GOAWAY,
                0,
                zmux.build_go_away_payload(
                    shape["incoming_last_accepted_bidi_stream_id"],
                    shape["incoming_last_accepted_uni_stream_id"],
                    int(zmux.ErrorCode.NO_ERROR),
                ),
            )
        )
        return _await_session_close(t, session, peer)


def _local_provisional_open_cancel(t, fixture):
    shape = fixture["input_shape"]
    t.assertTrue(shape["cancel_before_first_frame_commit"])
    t.assertEqual(shape["open_stage"], "provisional")
    with _peer_session() as (session, peer):
        first = session.open_stream()
        first.close_with_error(int(zmux.ErrorCode.CANCELLED))
        second = session.open_stream()
        second.write(b"x", timeout=_WAIT)
        data = peer.wait_for(_is_frame(zmux.FrameType.DATA, second.stream_id))
        t.assertIsNotNone(data, "DATA from the second stream")
        peer.barrier()

        # Whatever reached the wire for this class must use contiguous IDs:
        # either the cancelled stream never used an ID, or its ID was consumed
        # on the wire before the second opener.
        order = []
        for frame in peer.frames():
            if frame.stream_id % 4 == _LOCAL_BIDI and frame.stream_id not in order:
                order.append(frame.stream_id)
        t.assertEqual(order[-1], second.stream_id, "the second stream is the latest local bidi ID")
        t.assertEqual(order, [_LOCAL_BIDI + 4 * index for index in range(len(order))], f"gap in {order!r}")
    return _action("forbid_gap")


def _hidden_control_opened_hard_cap(t, fixture):
    shape = fixture["input_shape"]
    count = shape["hidden_control_opened_count"]
    hard_cap = shape["hidden_control_opened_hard_cap"]
    t.assertEqual(shape["attempted_action"], "keep_all_hidden_streams")
    with _peer_session(
            hidden_control_opened_limit=hard_cap,
            hidden_abort_churn_threshold=4 * count,
    ) as (session, peer):
        abort = _first_frame_payload(zmux.FrameType.ABORT)
        for index in range(count):
            peer.send(_frame(zmux.FrameType.ABORT, _PEER_BIDI + 4 * index, abort))
        _assert_session_open(t, session, peer)
        # White-box: the native session does not export the hidden-state
        # count in its stats.
        retained = session._terminal_state.hidden_control_state_retained()
        t.assertLessEqual(retained, hard_cap, "hidden state above the hard cap")
        with t.assertRaises(zmux.AcceptTimeout, msg="ABORT-first streams must not surface"):
            session.accept_stream(timeout=_QUIET)

        # Shed IDs stay used: late DATA on the oldest or the newest one opens
        # nothing and does not fail the session.
        for stream_id in (_PEER_BIDI, _PEER_BIDI + 4 * (count - 1)):
            peer.send(_frame(zmux.FrameType.DATA, stream_id, b"late"))
        _assert_session_open(t, session, peer)
        with t.assertRaises(zmux.AcceptTimeout, msg="late DATA must not reopen a shed stream"):
            session.accept_stream(timeout=_QUIET)
    return _action("forbid_unbounded_hidden_state")


def _late_data_aggregate_cap(t, fixture):
    shape = fixture["input_shape"]
    directions = shape["stopped_directions"]
    t.assertEqual(shape["late_data_session_aggregate"], "above_cap")
    t.assertEqual(shape["attempted_action"], "continue_buffering_without_bound")
    tail = 512
    aggregate_cap = 16 * 1024
    t.assertGreater(directions * tail, aggregate_cap, "harness precondition: tails exceed the cap")
    with _peer_session(
            aggregate_late_data_cap=aggregate_cap,
            accept_backlog_limit=2 * directions,
    ) as (session, peer):
        initial_window = session.stats.pressure.recv_session_advertised_bytes
        stream_ids = []
        for index in range(directions):
            stream = _open_peer_stream(t, session, peer, _PEER_BIDI + 4 * index)
            stream.close_read()
            stream_ids.append(stream.stream_id)
        for stream_id in stream_ids:
            peer.send(_frame(zmux.FrameType.DATA, stream_id, bytes(tail)))
        _assert_session_open(t, session, peer)
        pressure = session.stats.pressure
        t.assertGreaterEqual(
            pressure.aggregate_late_data_bytes,
            aggregate_cap,
            "harness precondition: the tails reach the aggregate cap",
        )
        t.assertEqual(pressure.buffered_receive_bytes, 0, "late tails must not be buffered")
        t.assertGreaterEqual(
            _restorable_session_credit(pressure),
            initial_window,
            "discarded late bytes must be released to the session window",
        )
    return _action("forbid_unbounded_late_tail_buffering")


def _rapid_open_abort_churn(t, fixture):
    shape = fixture["input_shape"]
    t.assertEqual(shape["pattern"], "open_then_abort_loop")
    threshold = 8
    with _peer_session(
            hidden_abort_churn_threshold=threshold,
            hidden_abort_churn_window=3600.0,
    ) as (session, peer):
        abort = _first_frame_payload(zmux.FrameType.ABORT)
        for index in range(threshold):
            peer.send(_frame(zmux.FrameType.ABORT, _PEER_BIDI + 4 * index, abort))
        _assert_session_open(t, session, peer)
        peer.send(_frame(zmux.FrameType.ABORT, _PEER_BIDI + 4 * threshold, abort))
        outcome = _await_session_close(t, session, peer)
        t.assertEqual(outcome.code, int(zmux.ErrorCode.PROTOCOL), "the churn limit closes with PROTOCOL")
    return _action("forbid_unbounded_stream_churn")


_INVALID_CASE_RUNNERS = {
    "preface_duplicate_setting_id": _preface_duplicate_setting_id,
    "preface_invalid_role_value": _hex_preface_case,
    "preface_auto_equal_nonce_conflict": _preface_auto_equal_nonce,
    "preface_auto_zero_nonce": _hex_preface_case,
    "preface_frame_payload_limit_too_small": _preface_setting_limit,
    "preface_control_payload_limit_too_small": _preface_setting_limit,
    "preface_extension_payload_limit_too_small": _preface_setting_limit,
    "preface_invalid_magic": _hex_preface_case,
    "preface_unsupported_preface_ver": _hex_preface_case,
    "preface_no_protocol_version_overlap": _preface_no_version_overlap,
    "preface_explicit_same_role_conflict": _preface_same_role,
    "preface_settings_len_exceeds_limit": _hex_preface_case,
    "preface_duplicate_padding": _hex_preface_case,
    "preface_duplicate_unknown_setting_id": _hex_preface_case,
    "preface_setting_empty_value": _hex_preface_case,
    "preface_setting_truncated_value": _hex_preface_case,
    "preface_setting_noncanonical_value": _hex_preface_case,
    "preface_setting_trailing_byte": _hex_preface_case,
    "preface_settings_tlv_overrun": _hex_preface_case,
    "frame_length_too_small": _frame_length_too_small,
    "frame_ext_payload_underflow": _frame_ext_payload_underflow,
    "frame_length_smaller_than_stream_id_prefix": _frame_length_smaller_than_stream_id_prefix,
    "frame_ping_with_forbidden_fin_flag": _hex_frame_case,
    "frame_pong_too_short": _frame_pong_too_short,
    "frame_ping_payload_exceeds_local_echoable_limit": _frame_ping_payload_exceeds_local_echoable_limit,
    "frame_abort_on_stream_zero": _frame_abort_on_stream_zero,
    "frame_max_data_trailing_garbage": _frame_trailing_garbage,
    "frame_blocked_trailing_garbage": _frame_trailing_garbage,
    "frame_unknown_core_type": _hex_frame_case,
    "frame_priority_update_duplicate_singleton": _frame_priority_update_duplicate_singleton,
    "frame_priority_update_truncated_tlv_header": _frame_priority_update_truncated_tlv_header,
    "frame_priority_update_tlv_value_overrun": _frame_priority_update_tlv_value_overrun,
    "frame_priority_update_noncanonical_value": _frame_priority_update_noncanonical_value,
    "frame_priority_update_without_capability": _frame_priority_update_without_capability,
    "frame_priority_update_on_unused_stream": _frame_priority_update_on_unused_stream,
    "frame_priority_update_on_terminal_stream": _frame_priority_update_on_terminal_stream,
    "frame_unknown_ext_subtype": _frame_unknown_ext_subtype,
    "frame_data_open_metadata_without_capability": _frame_data_open_metadata_without_capability,
    "frame_data_open_metadata_on_open_stream": _frame_data_open_metadata_on_open_stream,
    "frame_data_open_metadata_duplicate_singleton": _frame_data_open_metadata_duplicate_singleton,
    "frame_data_exceeds_stream_max_data": _frame_data_exceeds_stream_max_data,
    "frame_first_max_data_on_unused_stream": _frame_first_frame_on_unused_stream,
    "frame_first_blocked_on_unused_stream": _frame_first_frame_on_unused_stream,
    "frame_first_stop_sending_on_unused_stream": _frame_first_frame_on_unused_stream,
    "frame_first_reset_on_unused_stream": _frame_first_frame_on_unused_stream,
    "frame_data_exceeds_session_max_data": _frame_data_exceeds_session_max_data,
    "frame_peer_stream_id_gap": _frame_peer_stream_id_gap,
    "frame_blocked_wrong_side_uni": _frame_wrong_side_uni,
    "frame_data_wrong_side_uni": _frame_wrong_side_uni,
    "frame_max_data_wrong_side_uni": _frame_wrong_side_uni,
    "frame_stop_sending_wrong_side_uni": _frame_wrong_side_uni,
    "frame_reset_wrong_side_uni": _frame_wrong_side_uni,
    "session_goaway_last_accepted_increase": _session_goaway_increase,
    "local_provisional_open_cancel_must_not_burn_stream_id": _local_provisional_open_cancel,
    "hidden_control_opened_stream_exceeds_hard_cap_without_shedding": _hidden_control_opened_hard_cap,
    "late_data_after_close_read_exceeds_session_aggregate_cap": _late_data_aggregate_cap,
    "rapid_open_abort_churn_without_local_limit": _rapid_open_abort_churn,
}


# ---- portable_state runner ----
#
# Initial states are reached with ordinary frames and API calls, each event is
# driven exactly as fixture_mapping section 2.1 defines it, and expect_state is
# checked through what the API can observe: a read that times out, ends or
# fails, and a write that reaches the wire or fails.

_LATE_DATA_BYTES = 100


class _StateTarget:
    """The case's stream S: its ID once known and its local API object, if any."""

    def __init__(self):
        self.stream_id = None
        self.stream = None
        self.local_failure = None
        self.session_received_before = 0
        self.session_restorable_before = 0


def _is_barrier_pong(frame):
    return frame.frame_type == zmux.FrameType.PONG and frame.payload.startswith(_BARRIER_TOKEN)


def _run_portable_state_case(t, fixture):
    steps = fixture["steps"]
    initial = fixture["initial_state"]
    with _peer_session() as (session, peer):
        target = _establish_state(
            t,
            session,
            peer,
            fixture["stream_kind"],
            fixture["ownership"],
            initial,
            steps[0]["event"],
        )
        if isinstance(initial, dict):
            _assert_half_states(t, "initial_state", session, peer, target, initial)
        for index, step in enumerate(steps):
            label = f"step {index + 1} {step['event']}"
            since = peer.mark()
            _apply_state_event(t, label, session, peer, target, step["event"], since)
            if "expect_result" in step:
                _assert_state_result(t, label, session, peer, target, step["expect_result"], since)
            if "expect_state" in step:
                _assert_half_states(t, label, session, peer, target, step["expect_state"])
            if session.closed:
                t.assertEqual(index, len(steps) - 1, label + ": the session ended before the last step")
                break


def _establish_state(t, session, peer, kind, ownership, initial, first_event):
    """Reach ``initial_state`` for S with ordinary frames and API calls."""

    if kind == "bidi":
        bidi = True
    elif kind == "uni_local_send_only":
        bidi = False
        t.assertEqual(ownership, "local_owned", "a local send-only uni stream is locally owned")
    else:
        raise AssertionError(f"unsupported stream_kind {kind!r}")
    if ownership not in ("peer_owned", "local_owned"):
        raise AssertionError(f"unsupported ownership {ownership!r}")
    peer_owned = ownership == "peer_owned"
    if peer_owned:
        t.assertTrue(bidi, "peer-owned portable streams are bidirectional")

    target = _StateTarget()
    if initial == "idle":
        if peer_owned:
            target.stream_id = _PEER_BIDI
        elif first_event.startswith("local_"):
            # A local API object that sent nothing yet, so no ID is committed.
            target.stream = session.open_stream() if bidi else session.open_uni_stream()
        else:
            # Never opened locally: the peer names an ID the session has not used.
            target.stream_id = _LOCAL_BIDI if bidi else _LOCAL_UNI
        return target

    halves = (initial["send_half"], initial["recv_half"])
    if peer_owned:
        target.stream_id = _PEER_BIDI
        target.stream = _open_peer_stream(t, session, peer, _PEER_BIDI)
        if halves == ("send_open", "recv_reset"):
            peer.send(_frame(zmux.FrameType.RESET, _PEER_BIDI, _first_frame_payload(zmux.FrameType.RESET)))
            peer.barrier()
        elif halves == ("send_aborted", "recv_aborted"):
            peer.send(_frame(zmux.FrameType.ABORT, _PEER_BIDI, _first_frame_payload(zmux.FrameType.ABORT)))
            peer.barrier()
        elif halves != ("send_open", "recv_open"):
            raise AssertionError(f"unsupported peer-owned initial_state {initial!r}")
        return target

    if halves == ("send_open", "recv_open" if bidi else "absent"):
        since = peer.mark()
        target.stream = session.open_stream() if bidi else session.open_uni_stream()
        target.stream.write(b"o", timeout=_WAIT)
        opener = peer.wait_for(
            lambda frame: frame.frame_type == zmux.FrameType.DATA and frame.stream_id != 0,
            since=since,
        )
        t.assertIsNotNone(opener, "local opener")
        t.assertEqual(opener.stream_id, _LOCAL_BIDI if bidi else _LOCAL_UNI, "first local ID of its class")
        target.stream_id = opener.stream_id
        return target
    raise AssertionError(f"unsupported local-owned initial_state {initial!r}")


def _apply_state_event(t, label, session, peer, target, event, since):
    s = target.stream_id
    if event == "peer_first_DATA":
        t.assertIsNone(target.stream, label + ": S should be unopened")
        target.stream = _open_peer_stream(t, session, peer, s)
    elif event == "peer_first_ABORT":
        peer.send(_frame(zmux.FrameType.ABORT, s, _first_frame_payload(zmux.FrameType.ABORT)))
    elif event in ("peer_first_RESET", "peer_late_RESET"):
        peer.send(_frame(zmux.FrameType.RESET, s, _first_frame_payload(zmux.FrameType.RESET)))
    elif event == "peer_first_MAX_DATA":
        peer.send(_frame(zmux.FrameType.MAX_DATA, s, _first_frame_payload(zmux.FrameType.MAX_DATA)))
    elif event in ("peer_first_BLOCKED", "peer_BLOCKED"):
        peer.send(_frame(zmux.FrameType.BLOCKED, s, _first_frame_payload(zmux.FrameType.BLOCKED)))
    elif event == "peer_first_opening_frame_stream_id_gap":
        peer.send(_frame(zmux.FrameType.DATA, s + 4, b"x"))
    elif event == "peer_DATA":
        peer.send(_frame(zmux.FrameType.DATA, s, b"y"))
    elif event == "peer_DATA_FIN":
        peer.send(_frame(zmux.FrameType.DATA, s, b"y", zmux.FRAME_FLAG_FIN))
    elif event in ("peer_STOP_SENDING", "peer_late_STOP_SENDING"):
        peer.send(_frame(zmux.FrameType.STOP_SENDING, s, _first_frame_payload(zmux.FrameType.STOP_SENDING)))
    elif event == "peer_late_DATA":
        peer.barrier()
        pressure = session.stats.pressure
        target.session_received_before = pressure.recv_session_received_bytes
        target.session_restorable_before = _restorable_session_credit(pressure)
        peer.send(_frame(zmux.FrameType.DATA, s, bytes(_LATE_DATA_BYTES)))
    elif event == "peer_same_MAX_DATA":
        peer.send(_frame(zmux.FrameType.MAX_DATA, s, _varint(0)))
    elif event == "peer_same_BLOCKED":
        peer.send(_frame(zmux.FrameType.BLOCKED, s, _varint(0)))
    elif event == "local_DATA_FIN":
        target.stream.close_write(timeout=_WAIT)
        fin = peer.wait_for(
            lambda frame: frame.frame_type == zmux.FrameType.DATA
            and frame.stream_id == s
            and frame.flags & zmux.FRAME_FLAG_FIN,
            since=since,
        )
        t.assertIsNotNone(fin, label + ": DATA|FIN on S")
    elif event in ("local_STOP_SENDING", "local_MAX_DATA"):
        t.assertIsNotNone(target.stream, label + ": S should be a local API object")
        try:
            if event == "local_STOP_SENDING":
                target.stream.close_read()
            else:
                target.stream.read(1, timeout=_QUIET)
        except zmux.ZmuxError as exc:
            target.local_failure = exc
    else:
        raise AssertionError(label + ": event outside the portable vocabulary")


def _assert_state_result(t, label, session, peer, target, result, since):
    s = target.stream_id
    if result == "protocol_violation":
        outcome = _await_session_close(t, session, peer)
        t.assertEqual(outcome.code, int(zmux.ErrorCode.PROTOCOL), label + ": CLOSE code")
    elif result == "abort_stream_state":
        outcome = _await_stream_abort(t, session, peer, s, since)
        t.assertEqual(outcome.code, int(zmux.ErrorCode.STREAM_STATE), label + ": ABORT code")
    elif result == "local_invalid":
        t.assertIsInstance(
            target.local_failure,
            (zmux.StreamNotReadable, zmux.ReadClosed),
            label + ": expected a local stream-side error",
        )
        peer.barrier()
        for frame in peer.frames(since):
            t.assertEqual(frame.stream_id, 0, label + f": nothing may be sent for S, saw {frame!r}")
    elif result == "sender_must_finish_with_reset_or_fin":
        finish = peer.wait_for(
            lambda frame: frame.stream_id == s
            and (
                    frame.frame_type == zmux.FrameType.RESET
                    or (frame.frame_type == zmux.FrameType.DATA and frame.flags & zmux.FRAME_FLAG_FIN)
            ),
            since=since,
        )
        t.assertIsNotNone(finish, label + ": RESET or DATA|FIN on S")
        _assert_session_open(t, session, peer)
    elif result == "restore_session_budget_only_after_terminal_data":
        _assert_session_open(t, session, peer)
        for frame in peer.frames(since):
            t.assertNotEqual(frame.stream_id, s, label + f": nothing may be sent on S, saw {frame!r}")
        pressure = session.stats.pressure
        t.assertEqual(
            pressure.recv_session_received_bytes,
            target.session_received_before + _LATE_DATA_BYTES,
            label + ": discarded bytes count against the session receive window",
        )
        t.assertGreaterEqual(
            _restorable_session_credit(pressure),
            target.session_restorable_before,
            label + ": discarded bytes are released back to the session window",
        )
        t.assertEqual(pressure.buffered_receive_bytes, 0, label + ": terminal-stream DATA is not buffered")
    elif result == "no_control_flush":
        _assert_session_open(t, session, peer)
        sent = [frame for frame in peer.frames(since) if not _is_barrier_pong(frame)]
        t.assertEqual(sent, [], label + ": nothing may be sent in response")
    else:
        raise AssertionError(label + ": result outside the portable vocabulary")


def _probe_receive(stream):
    """Drain S without blocking: recv_open (would block), recv_fin (EOF) or recv_error."""

    try:
        while True:
            if not stream.read(256, timeout=_QUIET):
                return "recv_fin", None
    except zmux.ReadTimeout:
        return "recv_open", None
    except zmux.ZmuxError as exc:
        return "recv_error", exc


def _assert_half_states(t, label, session, peer, target, expect):
    """Check the conceptual half states through what the API can observe."""

    send = expect["send_half"]
    recv = expect["recv_half"]
    stream = target.stream
    if stream is None:
        # ABORT-first: the ID is used and terminal, but no stream object
        # ever surfaces.
        t.assertEqual((send, recv), ("send_aborted", "recv_aborted"), label + ": S has no API object")
        with t.assertRaises(zmux.AcceptTimeout, msg=label + ": S must not surface to accept"):
            session.accept_stream(timeout=_QUIET)
        t.assertEqual(session.state, zmux.SessionState.READY)
        return

    cancelled = int(zmux.ErrorCode.CANCELLED)  # the code this harness sends
    if recv == "absent":
        with t.assertRaises(zmux.StreamNotReadable, msg=label + ": S has no receive direction"):
            stream.read(1, timeout=_QUIET)
    else:
        observed, error = _probe_receive(stream)
        if recv in ("recv_open", "recv_fin"):
            t.assertEqual(observed, recv, label + f": recv_half ({error!r})")
        elif recv in ("recv_reset", "recv_aborted"):
            t.assertEqual(observed, "recv_error", label + f": {recv} must fail reads")
            t.assertEqual(zmux.error_code(error), cancelled, label + ": read error code")
        else:
            t.fail(label + f": unsupported recv_half {recv!r}")

    if send == "send_open":
        since = peer.mark()
        stream.write(b"w", timeout=_WAIT)
        data = peer.wait_for(_is_frame(zmux.FrameType.DATA, target.stream_id), since=since)
        t.assertIsNotNone(data, label + ": DATA on the open send half")
        t.assertFalse(data.flags & zmux.FRAME_FLAG_FIN, label + ": an open send half must not FIN")
    elif send == "send_fin":
        with t.assertRaises(zmux.WriteClosed, msg=label + ": send_fin must reject writes"):
            stream.write(b"w", timeout=_QUIET)
    elif send in ("send_reset", "send_aborted"):
        with t.assertRaises(zmux.ZmuxError, msg=label + f": {send} must reject writes") as raised:
            stream.write(b"w", timeout=_QUIET)
        t.assertEqual(zmux.error_code(raised.exception), cancelled, label + ": write error code")
    else:
        t.fail(label + f": unsupported send_half {send!r}")


# ---- tests ----


class FixtureBundleTest(unittest.TestCase):
    """The vendored bundle is complete, current and self-consistent."""

    def test_vendored_bundle_is_complete(self):
        for name in _BUNDLE_FILES:
            self.assertTrue((_VENDORED_DIR / name).is_file(), "missing testdata/fixtures/" + name)

    def test_vendored_bundle_matches_spec_checkout_when_configured(self):
        spec_root = os.environ.get(_SPEC_ROOT_ENV)
        if not spec_root:
            self.skipTest(f"set {_SPEC_ROOT_ENV} to a zmux-spec checkout to compare the vendored bundle")
        for name in _BUNDLE_FILES:
            with self.subTest(name=name):
                self.assertEqual(
                    (_VENDORED_DIR / name).read_bytes(),
                    (Path(spec_root) / "fixtures" / name).read_bytes(),
                    f"testdata/fixtures/{name} is stale; copy zmux-spec/fixtures/* again",
                )

    def test_index_counts_and_paths_match_the_bundle(self):
        index = _read_json("index.json")
        self.assertEqual(index["schema"], "zmux-fixture-bundle-v1")
        listed = {}
        for entry in index["files"]:
            name = Path(entry["path"]).name
            self.assertEqual(entry["path"], "fixtures/" + name)
            self.assertEqual(entry["kind"], Path(name).stem)
            listed[name] = entry["count"]
        self.assertEqual(sorted(listed), sorted(_NDJSON_FILES))
        for name, count in listed.items():
            self.assertEqual(len(_load(name)), count, name)

    def test_fixture_ids_are_unique_across_bundles(self):
        seen = collections.Counter()
        for name in _NDJSON_FILES:
            seen.update(_ids(_load(name)))
        self.assertEqual([fixture_id for fixture_id, count in seen.items() if count > 1], [])

    def test_case_set_ids_resolve_and_codec_sets_equal_the_wire_bundles(self):
        known = set()
        for name in _NDJSON_FILES:
            known.update(_ids(_load(name)))
        sets = _case_sets()
        for set_name, ids in sets.items():
            with self.subTest(set=set_name):
                self.assertEqual(sorted(set(ids) - known), [], "unknown ids")
        self.assertEqual(sorted(sets["codec_valid"]), sorted(_ids(_load("wire_valid.ndjson"))))
        self.assertEqual(sorted(sets["codec_invalid"]), sorted(_ids(_load("wire_invalid.ndjson"))))

    def test_every_invalid_case_runner_matches_a_vendored_fixture(self):
        stale = set(_INVALID_CASE_RUNNERS) - set(_ids(_load("invalid_cases.ndjson")))
        self.assertEqual(sorted(stale), [], "runners without a vendored invalid_cases fixture")

    def test_every_portable_state_case_is_a_state_fixture(self):
        portable = set(_case_sets()["portable_state"])
        self.assertTrue(portable, "portable_state is empty")
        self.assertEqual(sorted(portable - set(_ids(_load("state_cases.ndjson")))), [])


_PREFACE_EXPECT_KEYS = frozenset(
    (
        "preface_ver",
        "role",
        "tie_breaker_nonce",
        "min_proto",
        "max_proto",
        "capabilities",
        "settings_len",
        "settings",
    )
)
_FRAME_EXPECT_KEYS = frozenset(
    ("frame_length", "frame_type", "flags", "stream_id", "payload_hex", "decoded")
)
_DECODED_KEYS = frozenset(
    (
        "max_offset",
        "blocked_at",
        "error_code",
        "debug_text",
        "diag_block_dropped",
        "goaway",
        "ext_type",
        "ext_type_value",
        "stream_metadata_tlvs",
        "open_metadata_block_dropped",
        "application_payload_hex",
        "ping_padding_tag",
    )
)


class WireValidFixtureTest(unittest.TestCase):
    """wire_valid: decode, check every expect field, re-encode byte for byte."""

    def test_wire_valid_fixtures_decode_and_round_trip(self):
        for fixture in _load("wire_valid.ndjson"):
            with self.subTest(id=fixture["id"]):
                raw = _hex(fixture["hex"])
                if fixture["category"] == "preface_valid":
                    self._assert_preface(raw, fixture["expect"])
                elif fixture["category"] == "frame_valid":
                    self._assert_frame(raw, fixture["expect"])
                else:
                    self.fail("unsupported wire_valid category {!r}".format(fixture["category"]))

    def _assert_preface(self, raw, expect):
        self.assertLessEqual(set(expect), _PREFACE_EXPECT_KEYS, "unhandled expect fields")
        preface = zmux.parse_preface(raw)
        self.assertEqual(zmux.read_preface(io.BytesIO(raw)), preface)
        self.assertEqual(zmux.parse_preface_prefix(raw + b"\x00")[1], len(raw))
        self.assertEqual(preface.preface_version, expect["preface_ver"])
        self.assertEqual(preface.role, zmux.Role[expect["role"].upper()])
        self.assertEqual(preface.tie_breaker_nonce, expect["tie_breaker_nonce"])
        self.assertEqual(preface.min_proto, expect["min_proto"])
        self.assertEqual(preface.max_proto, expect["max_proto"])
        self.assertEqual(preface.capabilities, expect["capabilities"])
        # Settings not named in the fixture keep their defaults.
        self.assertEqual(preface.settings, zmux.Settings(**expect.get("settings", {})))

        header, settings_len, settings = _preface_layout(raw)
        self.assertEqual(settings_len, expect["settings_len"])
        self.assertEqual(len(settings), settings_len)
        tlvs = zmux.parse_tlvs(settings)
        padding = [tlv.value for tlv in tlvs if tlv.typ == zmux.SETTING_PREFACE_PADDING]
        kept = zmux.encode_tlvs([tlv for tlv in tlvs if tlv.typ != zmux.SETTING_PREFACE_PADDING])
        # Re-encoding never emits padding on its own, and padding is the last
        # settings TLV the encoder writes.
        self.assertEqual(zmux.marshal_preface(preface), header + _varint(len(kept)) + kept)
        self.assertLessEqual(len(padding), 1)
        if not padding:
            self.assertEqual(zmux.marshal_preface(preface), raw)
        elif padding[0]:
            self.assertEqual(zmux.marshal_preface_with_settings_padding(preface, padding[0]), raw)
        else:
            # An empty preface_padding TLV cannot be requested from the
            # encoder (empty padding means "no padding TLV"); check that the
            # vector is exactly the unpadded encoding plus that 2-byte TLV.
            self.assertEqual(
                raw,
                header + _varint(len(kept) + 2) + kept + _tlvs((zmux.SETTING_PREFACE_PADDING, b"")),
            )

    def _assert_frame(self, raw, expect):
        self.assertLessEqual(set(expect), _FRAME_EXPECT_KEYS, "unhandled expect fields")
        frame, consumed = zmux.parse_frame(raw)
        self.assertEqual(consumed, len(raw))
        self.assertEqual(zmux.read_frame(io.BytesIO(raw)), frame)
        self.assertEqual(read_session_frame(io.BytesIO(raw)), frame)
        frame_length, prefix_len = zmux.parse_varint(raw)
        self.assertEqual(frame_length, expect["frame_length"])
        self.assertEqual(prefix_len + frame_length, len(raw))
        self.assertEqual(frame.frame_type.name, expect["frame_type"])
        flag_names = [name for bit, name in _FLAG_NAMES if frame.flags & bit]
        self.assertEqual(sorted(flag_names), sorted(expect.get("flags", [])))
        self.assertEqual(frame.stream_id, expect["stream_id"])
        if "payload_hex" in expect:
            self.assertEqual(frame.payload.hex(), expect["payload_hex"])
        if "decoded" in expect:
            self._assert_decoded(frame, expect["decoded"])
        self.assertEqual(frame.marshal(), raw)
        self.assertEqual(zmux.marshal_frame(frame), raw)

    def _assert_decoded(self, frame, decoded):
        self.assertLessEqual(set(decoded), _DECODED_KEYS, "unhandled decoded fields")
        frame_type = frame.frame_type
        payload = frame.payload
        if "max_offset" in decoded:
            self.assertEqual(frame_type, zmux.FrameType.MAX_DATA)
            self.assertEqual(zmux.parse_varint(payload), (decoded["max_offset"], len(payload)))
        if "blocked_at" in decoded:
            self.assertEqual(frame_type, zmux.FrameType.BLOCKED)
            self.assertEqual(zmux.parse_varint(payload), (decoded["blocked_at"], len(payload)))
        if "error_code" in decoded:
            code, reason = zmux.parse_error_payload(payload)
            self.assertEqual(code, decoded["error_code"])
            self.assertEqual(reason, decoded.get("debug_text", ""))
            if decoded.get("diag_block_dropped"):
                # The block carries debug_text, so only dropping it empties
                # the reason.
                diag = zmux.parse_tlvs(payload[zmux.parse_varint(payload)[1]:])
                texts = [tlv for tlv in diag if tlv.typ == zmux.DIAG_DEBUG_TEXT]
                self.assertGreaterEqual(len(texts), 2, "fixture repeats debug_text")
        if "goaway" in decoded:
            self.assertEqual(frame_type, zmux.FrameType.GOAWAY)
            expected = decoded["goaway"]
            go_away = zmux.parse_go_away_payload(payload)
            self.assertEqual(go_away.last_accepted_bidi, expected["last_accepted_bidi_stream_id"])
            self.assertEqual(go_away.last_accepted_uni, expected["last_accepted_uni_stream_id"])
            self.assertEqual(go_away.code, expected["error_code"])
        if "ext_type_value" in decoded:
            self.assertEqual(frame_type, zmux.FrameType.EXT)
            self.assertEqual(zmux.parse_varint(payload)[0], decoded["ext_type_value"])
        if "ext_type" in decoded:
            self.assertEqual(frame_type, zmux.FrameType.EXT)
            self.assertEqual(decoded["ext_type"], "PRIORITY_UPDATE")
            ext_type, ext_len = zmux.parse_varint(payload)
            self.assertEqual(ext_type, zmux.EXT_PRIORITY_UPDATE)
            metadata, valid = zmux.parse_priority_update_payload(payload)
            self.assertTrue(valid)
            tlvs = zmux.parse_tlvs(payload[ext_len:])
            self._assert_metadata(metadata, tlvs, decoded["stream_metadata_tlvs"])
        if frame_type == zmux.FrameType.DATA:
            data = zmux.parse_data_payload(payload, frame.flags)
            self.assertEqual(data.has_metadata, bool(frame.flags & zmux.FRAME_FLAG_OPEN_METADATA))
            if data.has_metadata:
                self.assertEqual(data.metadata_valid, not decoded.get("open_metadata_block_dropped", False))
                self._assert_metadata(data.metadata, data.metadata_tlvs, decoded["stream_metadata_tlvs"])
                self.assertEqual(data.open_info, data.metadata.open_info)
            self.assertEqual(data.app_data.hex(), decoded["application_payload_hex"])
        if "ping_padding_tag" in decoded:
            self.assertEqual(frame_type, zmux.FrameType.PING)
            expected = decoded["ping_padding_tag"]
            key = expected["ping_padding_key"]
            self.assertEqual(payload[:8].hex(), expected["token_hex"])
            self.assertEqual(payload[8:16].hex(), expected["tag_hex"])
            tag = ping_padding_tag(key, int.from_bytes(payload[:8], "big"))
            self.assertEqual(tag.to_bytes(8, "big").hex(), expected["tag_hex"])
            self.assertTrue(has_ping_padding_tag(payload, key))

    def _assert_metadata(self, metadata, tlvs, expected):
        """Compare the interpreted metadata and its TLVs (wire order) with the fixture."""

        actual = []
        for tlv in tlvs:
            name = _METADATA_TLV_NAMES.get(tlv.typ)
            self.assertIsNotNone(name, f"unexpected metadata TLV type {tlv.typ}")
            if tlv.typ == zmux.METADATA_OPEN_INFO:
                actual.append({"type": name, "value_hex": tlv.value.hex()})
            else:
                actual.append({"type": name, "value": zmux.parse_varint(tlv.value)[0]})
        self.assertEqual(actual, expected)
        by_type = {entry["type"]: entry for entry in expected}
        self.assertEqual(metadata.priority, by_type.get("stream_priority", {}).get("value"))
        self.assertEqual(metadata.group, by_type.get("stream_group", {}).get("value"))
        self.assertEqual(metadata.open_info.hex(), by_type.get("open_info", {}).get("value_hex", ""))


class WireInvalidFixtureTest(unittest.TestCase):
    """wire_invalid: every codec reader and a live session reject with the fixture code."""

    def test_wire_invalid_fixtures_fail_with_the_fixture_code(self):
        for fixture in _load("wire_invalid.ndjson"):
            with self.subTest(id=fixture["id"]):
                raw = _hex(fixture["hex"])
                category = fixture["category"]
                if category == "bytes_invalid":
                    codes = set()
                    for label, read in (
                            ("parse_varint", zmux.parse_varint),
                            ("read_varint", lambda data: zmux.read_varint(io.BytesIO(data))),
                    ):
                        with self.assertRaises(zmux.ZmuxError, msg=label) as raised:
                            read(raw)
                        codes.add(zmux.error_code(raised.exception))
                    self.assertEqual(len(codes), 1, f"varint readers disagree: {codes!r}")
                    code = codes.pop()
                elif category == "frame_invalid":
                    limits = zmux.Limits(**fixture.get("receiver_limits", {}))
                    code = _codec_frame_failure(self, raw, limits)
                else:
                    self.fail(f"unsupported wire_invalid category {category!r}")
                self.assertEqual(zmux.error_code_name(code), fixture["expect_error"])

    def test_wire_invalid_frames_close_the_session_with_the_fixture_code(self):
        for fixture in _load("wire_invalid.ndjson"):
            if fixture["category"] != "frame_invalid":
                continue
            with self.subTest(id=fixture["id"]):
                settings = zmux.Settings(**fixture.get("receiver_limits", {}))
                with _peer_session(settings=settings) as (session, peer):
                    peer.send_raw(_hex(fixture["hex"]))
                    outcome = _await_session_close(self, session, peer)
                self.assertEqual(zmux.error_code_name(outcome.code), fixture["expect_error"])


class InvalidCaseFixtureTest(unittest.TestCase):
    """invalid_cases: every id has a runner; the fixture decides the outcome."""

    def test_invalid_case_fixtures_behave_as_specified(self):
        for fixture in _load("invalid_cases.ndjson"):
            with self.subTest(id=fixture["id"]):
                runner = _INVALID_CASE_RUNNERS.get(fixture["id"])
                if runner is None:
                    self.fail(
                        "invalid fixture {!r} has no runner; add one to _INVALID_CASE_RUNNERS".format(fixture["id"])
                    )
                _assert_outcome(self, fixture, runner(self, fixture))


class PortableStateFixtureTest(unittest.TestCase):
    """state_cases: the portable_state set runs against a live session."""

    def test_portable_state_cases_behave_as_specified(self):
        cases = {fixture["id"]: fixture for fixture in _load("state_cases.ndjson")}
        for fixture_id in _case_sets()["portable_state"]:
            with self.subTest(id=fixture_id):
                self.assertIn(fixture_id, cases, "portable_state names an unknown state case")
                _run_portable_state_case(self, cases[fixture_id])


if __name__ == "__main__":
    unittest.main()
