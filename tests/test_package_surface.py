import asyncio
import inspect
import unittest
from dataclasses import replace
from io import BytesIO

import zmux
import zmux.protocol as protocol_registry
import zmux.settings as settings_surface
from zmux import conformance
from zmux._wire.errors import ERR_INVALID_MAGIC, error_code_of, is_code, wrap_error
from zmux._wire.errors import frame_size_error, protocol_error
from zmux._wire.frame import append_frame_header_trusted_cached_stream_id
from zmux._wire.frame import frame_length_for_payload, max_inbound_frame_len
from zmux.errors import (
    ApplicationError,
    ErrorDirection,
    ErrorOperation,
    ErrorScope,
    ErrorSource,
    FrameSizeError,
    ProtocolError,
    TerminationKind,
)
from zmux.protocol import (
    CAPABILITY_METADATA_CARRIAGE_MASK,
    DIAG_OFFENDING_FRAME_TYPE,
    EXT_PRIORITY_UPDATE,
    METADATA_OPEN_INFO,
    SETTING_INITIAL_MAX_DATA,
    SETTING_PING_PADDING_KEY,
    SETTING_PREFACE_PADDING,
    SETTING_SCHEDULER_HINTS,
    Capability,
    DiagnosticType,
    ErrorCode,
    ExtensionSubtype,
    FrameType,
    MetadataType,
    Role,
    SchedulerHint,
    SettingID,
    capabilities_can_carry_group_in_update,
    capabilities_can_carry_group_on_open,
    capabilities_can_carry_priority_in_update,
    capabilities_can_carry_priority_on_open,
    capabilities_have_peer_visible_group_semantics,
    capabilities_have_peer_visible_priority_semantics,
    capabilities_support_open_metadata,
    capabilities_support_priority_update,
)
from zmux.settings import (
    Settings,
    append_settings_tlv,
    known_setting_seen_bit,
    marshal_settings_tlv,
    parse_settings_tlv,
    settings_tlv_len,
)
from zmux.tlv import (
    Tlv,
    TlvView,
    append_tlv,
    encode_tlvs,
    iter_tlvs_view,
    parse_tlvs,
    parse_tlvs_view,
    tlv_encoded_len,
    tlv_parse_capacity_hint,
    validate_tlv_header,
    validate_tlvs,
    visit_tlvs,
)
from zmux.varint import (
    append_packed_varint,
    append_varint,
    encode_varint,
    encode_varint_into,
    encoded_len_from_first,
    pack_varint,
    parse_varint,
    read_varint,
    validate_decoded_varint,
    varint_len,
)


class PackageSurfaceTest(unittest.TestCase):
    def assert_protocol_read_error(self, error, message):
        self.assertEqual(str(error), message)
        self.assertEqual(
            (error.code, error.scope, error.operation, error.source, error.direction),
            (
                int(ErrorCode.PROTOCOL),
                ErrorScope.SESSION,
                ErrorOperation.READ,
                ErrorSource.REMOTE,
                ErrorDirection.READ,
            ),
        )

    def test_distribution_import_surface(self) -> None:
        self.assertEqual(zmux.__version__, "0.1.0")
        self.assertEqual(len(zmux.__all__), len(set(zmux.__all__)))
        self.assertEqual(zmux.MAGIC, b"ZMUX")
        self.assertEqual(zmux.PROTO_VERSION, 1)
        self.assertIs(settings_surface.SettingID, zmux.SettingID)
        self.assertEqual(
            settings_surface.SETTING_INITIAL_MAX_DATA,
            zmux.SETTING_INITIAL_MAX_DATA,
        )
        self.assertEqual(
            settings_surface.SETTING_PREFACE_PADDING,
            zmux.SETTING_PREFACE_PADDING,
        )
        self.assertIs(zmux.Event, __import__("zmux.events").events.Event)
        self.assertEqual(
            zmux.core_module_target_claims(),
            conformance.core_module_target_claims(),
        )
        namespace = {}
        exec("from zmux import *", namespace)
        self.assertIs(namespace["Event"], zmux.Event)
        self.assertIs(namespace["FrameType"], zmux.FrameType)
        self.assertIs(namespace["OpenOptions"], zmux.OpenOptions)
        self.assertIn("core_module_target_claims", namespace)
        self.assertEqual(zmux.default_settings().max_frame_payload, 16384)
        self.assertEqual(zmux.encode_varint(64), b"\x40\x40")
        self.assertEqual(zmux.parse_varint(b"\x40\x40"), (64, 2))
        for name in ("write_frame", "join", "open", "client", "server"):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(zmux, name)))
        self.assertFalse(hasattr(zmux, "open_session"))
        self.assertFalse(hasattr(zmux, "open_async_session"))
        self.assertIs(zmux.WritableBuffer, __import__("zmux.streams").streams.WritableBuffer)
        self.assertTrue(callable(zmux.AsyncRecvStream.readinto))
        self.assertTrue(
            zmux.has_capability(
                zmux.CAPABILITY_OPEN_METADATA,
                zmux.CAPABILITY_OPEN_METADATA,
            )
        )
        self.assertEqual(
            zmux.parse_settings_tlv(zmux.marshal_settings_tlv(zmux.default_settings())),
            zmux.default_settings(),
        )

    def test_core_conformance_targets(self) -> None:
        self.assertEqual(
            conformance.known_claims(),
            (
                "zmux-wire-v1",
                "zmux-api-semantics-profile-v1",
                "zmux-stream-adapter-profile-v1",
                "zmux-open_metadata",
                "zmux-priority_update",
            ),
        )
        self.assertEqual(
            conformance.known_implementation_profiles(),
            ("zmux-v1", "zmux-reference-profile-v1"),
        )
        self.assertEqual(
            conformance.known_conformance_suites(),
            (
                "core-wire-interoperability",
                "invalid-input-handling",
                "extension-tolerance",
                "core-stream-lifecycle",
                "core-flow-control",
                "core-session-lifecycle",
                "open_metadata",
                "priority_update",
                "priority-hints-and-stream-groups",
                "v1-profile-compatibility",
                "api-semantics-profile",
                "stream-adapter-profile",
                "reference-profile-claim-gate",
                "reference-quality-behaviors",
            ),
        )
        self.assertEqual(
            conformance.core_module_target_claims(),
            (
                "zmux-wire-v1",
                "zmux-api-semantics-profile-v1",
                "zmux-open_metadata",
                "zmux-priority_update",
            ),
        )
        self.assertEqual(
            conformance.core_module_target_implementation_profiles(),
            ("zmux-v1",),
        )
        self.assertEqual(
            conformance.core_module_target_suites(),
            (
                "core-wire-interoperability",
                "invalid-input-handling",
                "extension-tolerance",
                "core-stream-lifecycle",
                "core-flow-control",
                "core-session-lifecycle",
                "open_metadata",
                "priority_update",
                "priority-hints-and-stream-groups",
                "v1-profile-compatibility",
                "api-semantics-profile",
            ),
        )
        self.assertIs(
            conformance.Claim.from_name("zmux-priority_update"),
            conformance.Claim.PRIORITY_UPDATE,
        )
        self.assertTrue(conformance.Claim.is_known_name("zmux-wire-v1"))
        with self.assertRaises(conformance.ParseConformanceError):
            conformance.Claim.parse("unknown")
        self.assertIs(
            conformance.ImplementationProfile.parse("zmux-reference-profile-v1"),
            conformance.ImplementationProfile.REFERENCE_PROFILE_V1,
        )
        self.assertIs(
            conformance.ConformanceSuite.parse("v1-profile-compatibility"),
            conformance.ConformanceSuite.V1_PROFILE_COMPATIBILITY,
        )
        self.assertEqual(
            tuple(str(claim) for claim in conformance.ImplementationProfile.V1.claims()),
            ("zmux-wire-v1", "zmux-open_metadata", "zmux-priority_update"),
        )
        self.assertIn(
            conformance.ConformanceSuite.V1_PROFILE_COMPATIBILITY,
            conformance.ImplementationProfile.V1.required_conformance_suites(),
        )
        self.assertEqual(
            conformance.ImplementationProfile.REFERENCE_PROFILE_V1.release_certification_gate(),
            conformance.ImplementationProfile.REFERENCE_PROFILE_V1.required_conformance_suites(),
        )
        self.assertIn(
            "repository-default Close() acts as a full local close helper",
            conformance.reference_profile_claim_gate(),
        )
        self.assertIn("Claim", zmux.__all__)

    def test_event_values_match_rust_lifecycle_shape(self) -> None:
        metadata = zmux.StreamMetadata(priority=7, group=9, open_info=b"ssh")
        stream = zmux.StreamEventInfo(
            stream_id=4,
            metadata=metadata,
            local=True,
            bidirectional=True,
            application_visible=False,
            local_addr="local",
            remote_addr="remote",
        )
        self.assertEqual(stream.open_info, b"ssh")
        self.assertTrue(stream.has_open_info)
        self.assertEqual(stream.local_addr, "local")
        self.assertEqual(stream.remote_addr, "remote")
        event = zmux.Event(
            "stream_opened",
            session_state="ready",
            stream=stream,
            time=123.5,
            error=zmux.StreamClosed(),
        )
        self.assertIs(event.event_type, zmux.EventType.STREAM_OPENED)
        self.assertEqual(str(event.event_type), "stream_opened")
        self.assertEqual(event.session_state, zmux.SessionState.READY)
        self.assertEqual(event.stream_id, 4)
        self.assertTrue(event.local)
        self.assertTrue(event.bidirectional)
        self.assertFalse(event.application_visible)
        self.assertTrue(event.is_stream_event)
        self.assertIsInstance(event.error, zmux.StreamClosed)
        self.assertIs(event.error_details, event.error)
        self.assertTrue(event.error_has_code)
        self.assertEqual(event.error_code(-1), int(ErrorCode.STREAM_CLOSED))
        self.assertEqual(
            (
                event.error_operation,
                event.error_reason,
                event.error_scope,
                event.error_source,
                event.error_direction,
                event.error_termination_kind,
            ),
            (
                ErrorOperation.UNKNOWN,
                zmux.STREAM_CLOSED_MESSAGE,
                ErrorScope.UNKNOWN,
                ErrorSource.UNKNOWN,
                ErrorDirection.UNKNOWN,
                TerminationKind.UNKNOWN,
            ),
        )
        self.assertFalse(event.error_timeout)
        self.assertFalse(event.error_interrupted)

        closed_error = zmux.ApplicationError(
            ErrorCode.INTERNAL,
            "close",
            scope=ErrorScope.SESSION,
            source=ErrorSource.LOCAL,
            direction=ErrorDirection.BOTH,
            termination_kind=TerminationKind.SESSION_TERMINATION,
        )
        error_event = zmux.Event(zmux.EventType.SESSION_CLOSED, error=closed_error)
        self.assertEqual(error_event.error_code(-1), int(ErrorCode.INTERNAL))
        self.assertEqual(error_event.error_reason, "close")
        self.assertEqual(error_event.error_scope, ErrorScope.SESSION)
        self.assertEqual(error_event.error_source, ErrorSource.LOCAL)
        self.assertEqual(error_event.error_direction, ErrorDirection.BOTH)
        self.assertEqual(
            error_event.error_termination_kind,
            TerminationKind.SESSION_TERMINATION,
        )

        closed = zmux.Event(zmux.EventType.SESSION_CLOSED, time=124)
        self.assertEqual(closed.stream_id, 0)
        self.assertFalse(closed.local)
        self.assertFalse(closed.is_stream_event)
        self.assertFalse(closed.error_has_code)
        self.assertEqual(closed.error_code(-1), -1)
        self.assertEqual(closed.error_reason, "")
        with self.assertRaises(ValueError):
            zmux.Event("unknown")
        with self.assertRaises(TypeError):
            zmux.StreamEventInfo(stream_id=True)
        with self.assertRaises(TypeError):
            zmux.StreamEventInfo(stream_id=4, local=1)

    def test_public_session_api_surface_matches_reference_lifecycle(self) -> None:
        options_source = bytearray(b"abc")
        options = zmux.OpenOptions(
            initial_priority=7,
            initial_group=9,
            open_info=options_source,
        )
        options_source[0] = ord("x")
        self.assertEqual(options.open_info, b"abc")
        self.assertEqual(len(options.open_info), 3)
        self.assertTrue(options.open_info)
        self.assertFalse(options.is_empty())
        self.assertTrue(zmux.OpenOptions().is_empty())
        with self.assertRaises(TypeError):
            zmux.OpenOptions(initial_priority=True)
        with self.assertRaises(ValueError):
            zmux.OpenOptions(initial_group=-1)
        with self.assertRaises(ValueError):
            zmux.OpenOptions(initial_priority=zmux.MAX_VARINT62 + 1)

        self.assertEqual(str(zmux.SessionState.READY), "ready")
        self.assertFalse(zmux.SessionState.INVALID.valid())
        self.assertTrue(zmux.SessionState.CLOSED.terminal())
        self.assertFalse(zmux.SessionState.DRAINING.terminal())

        active = zmux.ActiveStreamStats(1, 2, 3, 4)
        self.assertEqual(active.total, 10)
        queues = zmux.QueueStats(urgent=1, advisory=2, ordinary=3)
        self.assertEqual(queues.total, 6)
        backlog = zmux.AcceptBacklogStats(count=5, count_limit=5, bytes=8, bytes_limit=8)
        self.assertEqual(backlog.count, 5)
        self.assertTrue(backlog.at_count_limit())
        self.assertTrue(backlog.at_bytes_limit())
        self.assertTrue(backlog.at_count_cap)
        self.assertTrue(backlog.at_bytes_cap)
        retained = zmux.RetainedStateBreakdownStats(
            hidden_control=zmux.RetainedBucketStats(1, 2),
            accept_backlog=zmux.RetainedBucketStats(3, 4),
        )
        self.assertEqual(retained.total_bytes, 6)
        pressure = zmux.PressureStats(
            retained_buckets=retained,
            tracked_buffered_bytes=10,
            tracked_buffered_limit=12,
            tracked_buffered_high=True,
        )
        self.assertEqual(pressure.retained_state_breakdown.total_bytes, 6)
        self.assertEqual(pressure.tracked_retained_state_memory_bytes, 6)
        self.assertEqual(pressure.tracked_session_memory_bytes, 10)
        self.assertTrue(pressure.memory_pressure_high)
        reasons = zmux.ReasonStats(reset={1: 2}, abort={3: 4})
        self.assertEqual(dict(reasons.reset), {1: 2})
        self.assertEqual(dict(reasons.abort), {3: 4})

        stats = zmux.SessionStats(state=zmux.SessionState.CLOSED)
        self.assertEqual(stats.state, zmux.SessionState.CLOSED)
        self.assertEqual(stats.active_streams.total, 0)
        self.assertEqual(stats.queues.total, 0)
        detailed_stats = zmux.SessionStats(
            telemetry=zmux.TelemetryStats(
                last_open_latency=0.5,
                send_rate_estimate_bytes_per_second=123,
            ),
            writer_queue=zmux.WriterQueueStats(
                urgent_jobs=1,
                advisory_jobs=2,
                ordinary_jobs=3,
                queued_bytes=6,
            ),
            liveness=zmux.LivenessStats(
                keepalive_interval=1.0,
                last_ping_rtt=0.25,
                inbound_idle_for=2.0,
            ),
            retention=zmux.RetentionStats(tombstones=4),
            memory=zmux.MemoryStats(tracked_bytes=5, hard_cap=6, over_cap=True),
            abuse=zmux.AbuseStats(ignored_control=7),
        )
        self.assertEqual(detailed_stats.telemetry.send_rate_estimate_bytes_per_second, 123)
        self.assertEqual(detailed_stats.writer_queue.urgent_jobs, 1)
        self.assertEqual(detailed_stats.liveness.last_ping_rtt, 0.25)
        self.assertEqual(detailed_stats.retention.tombstones, 4)
        self.assertTrue(detailed_stats.memory.over_cap)
        self.assertEqual(detailed_stats.abuse.ignored_control, 7)
        with self.assertRaises(TypeError):
            zmux.SessionStats(ping_outstanding=1)
        with self.assertRaises(TypeError):
            zmux.LivenessStats(ping_stalled=1)
        with self.assertRaises(TypeError):
            zmux.MemoryStats(over_cap=1)
        with self.assertRaises(TypeError):
            zmux.PressureStats(tracked_buffered_high=1)
        with self.assertRaises(TypeError):
            zmux.HiddenStats(at_soft_cap=1)
        with self.assertRaises(TypeError):
            zmux.AcceptBacklogStats(at_count_cap=1)
        with self.assertRaises(TypeError):
            zmux.ProvisionalStats(bidi_at_soft=1)

        closed = zmux.closed_session()
        self.assertIsInstance(closed, zmux.ClosedSession)
        self.assertIsInstance(closed, zmux.Session)
        with closed as managed:
            self.assertIs(managed, closed)
        missing = zmux.as_session(None)
        self.assertIsInstance(missing, zmux.InvalidSession)
        self.assertTrue(missing.closed)
        self.assertEqual(missing.state, zmux.SessionState.INVALID)
        self.assertEqual(missing.stats.state, zmux.SessionState.INVALID)
        closed.close()
        closed.close_with_error(1, "ignored")
        closed.wait(0)
        self.assertTrue(closed.closed)
        self.assertEqual(closed.state, zmux.SessionState.CLOSED)
        self.assertEqual(closed.stats.state, zmux.SessionState.CLOSED)
        self.assertIsNone(closed.local_addr)
        self.assertIsNone(closed.remote_addr)
        self.assertEqual(closed.local_preface().preface_version, 0)
        self.assertEqual(closed.negotiated().peer_settings.max_frame_payload, 0)
        with self.assertRaises(zmux.SessionClosed) as raised:
            closed.open_stream()
        self.assertEqual(raised.exception.operation, ErrorOperation.OPEN)
        self.assertEqual(raised.exception.scope, ErrorScope.SESSION)
        self.assertEqual(raised.exception.source, ErrorSource.LOCAL)
        self.assertEqual(raised.exception.direction, ErrorDirection.BOTH)
        self.assertEqual(raised.exception.termination_kind, TerminationKind.SESSION_TERMINATION)
        self.assertTrue(inspect.isclass(zmux.Conn))
        self.assertTrue(inspect.isclass(zmux.NativeStream))

    def test_async_closed_session_api_surface(self) -> None:
        async def run() -> None:
            closed = zmux.async_closed_session()
            self.assertIsInstance(closed, zmux.AsyncSession)
            async with closed as managed:
                self.assertIs(managed, closed)
            missing = zmux.as_async_session(None)
            self.assertIsInstance(missing, zmux.AsyncInvalidSession)
            self.assertIsInstance(missing, zmux.AsyncSession)
            self.assertTrue(missing.closed)
            self.assertEqual(missing.state, zmux.SessionState.INVALID)
            self.assertEqual(missing.stats.state, zmux.SessionState.INVALID)
            await closed.close()
            await closed.close_with_error(1, "ignored")
            await closed.wait(0)
            self.assertTrue(closed.closed)
            self.assertEqual(closed.state, zmux.SessionState.CLOSED)
            with self.assertRaises(zmux.SessionClosed) as raised:
                await closed.ping()
            self.assertEqual(raised.exception.operation, ErrorOperation.PING)
            with self.assertRaises(zmux.SessionClosed) as goaway_raised:
                await closed.go_away(
                    0,
                    0,
                    code=int(zmux.ErrorCode.CANCELLED),
                    reason="stop",
                )
            self.assertEqual(goaway_raised.exception.operation, ErrorOperation.CLOSE)
            self.assertFalse(hasattr(closed, "go_away_with_error"))

        asyncio.run(run())

    def test_session_timeout_parameters_are_keyword_only(self) -> None:
        for owner in (zmux.Session, zmux.AsyncSession, zmux.ClosedSession, zmux.AsyncClosedSession):
            for name in ("open_stream", "open_uni_stream", "open_and_send", "open_uni_and_send"):
                parameter = inspect.signature(getattr(owner, name)).parameters["timeout"]
                self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            ping_timeout = inspect.signature(getattr(owner, "ping")).parameters["timeout"]
            self.assertEqual(ping_timeout.kind, inspect.Parameter.KEYWORD_ONLY)
        read_exact_timeout = inspect.signature(zmux.RecvStream.read_exact).parameters["timeout"]
        self.assertEqual(read_exact_timeout.kind, inspect.Parameter.KEYWORD_ONLY)

    def test_config_defaults_open_options_and_preface_surface(self) -> None:
        zmux.reset_default_config()
        cfg = zmux.default_config()
        self.assertEqual(cfg.role, Role.AUTO)
        self.assertEqual(cfg.min_proto, zmux.PROTO_VERSION)
        self.assertEqual(cfg.max_proto, zmux.PROTO_VERSION)
        self.assertEqual(cfg.keepalive_interval, zmux.DEFAULT_KEEPALIVE_INTERVAL)
        self.assertEqual(
            cfg.keepalive_max_ping_interval,
            zmux.DEFAULT_KEEPALIVE_MAX_PING_INTERVAL,
        )
        self.assertTrue(cfg.preface_padding)
        self.assertTrue(cfg.ping_padding)
        self.assertEqual(cfg.capabilities, zmux.DEFAULT_CAPABILITIES)
        self.assertFalse(cfg.disable_capabilities)
        self.assertEqual(
            cfg.preface_padding_min_bytes,
            zmux.DEFAULT_PREFACE_PADDING_MIN_BYTES,
        )
        self.assertEqual(
            cfg.ping_padding_max_bytes,
            zmux.DEFAULT_PING_PADDING_MAX_BYTES,
        )
        self.assertEqual(
            zmux.default_accept_backlog_bytes_limit(0),
            zmux.DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR,
        )
        self.assertEqual(
            zmux.default_late_data_aggregate_cap(32 * 1024),
            128 * 1024,
        )

        self.assertEqual(zmux.Config(role=Role.INITIATOR).role, Role.INITIATOR)
        self.assertEqual(zmux.Config(role=Role.RESPONDER).role, Role.RESPONDER)
        self.assertEqual(zmux.DEFAULT_WRITE_BATCH_MAX_FRAMES, 32)
        self.assertEqual(zmux.DEFAULT_MAX_PROVISIONAL_STREAMS_BIDI, 64)
        self.assertEqual(zmux.DEFAULT_IGNORED_CONTROL_BUDGET, 128)
        self.assertEqual(zmux.DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR, 64 * 1024)
        self.assertEqual(
            zmux.DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR,
            256 * 1024,
        )
        self.assertEqual(
            zmux.DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR,
            256 * 1024,
        )
        self.assertEqual(zmux.DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX, 2.0)
        explicit = zmux.Config(role=Role.INITIATOR, tie_breaker_nonce=123)
        self.assertEqual(explicit.tie_breaker_nonce, 0)
        disabled = replace(cfg, disable_capabilities=True)
        self.assertEqual(disabled.capabilities, 0)
        self.assertTrue(disabled.disable_capabilities)
        self.assertEqual(zmux.Config(capabilities=0).capabilities, zmux.DEFAULT_CAPABILITIES)
        self.assertEqual(
            zmux.Config(disable_capabilities=True, capabilities=zmux.DEFAULT_CAPABILITIES).capabilities,
            0,
        )
        flood_budget = replace(cfg, ignored_control_budget=22)
        self.assertEqual(flood_budget.ignored_control_budget, 22)

        zero_payload_limits = Settings(
            initial_max_data=123,
            max_frame_payload=0,
            max_control_payload_bytes=0,
            max_extension_payload_bytes=0,
        )
        normalized = zmux.Config(
            min_proto=0,
            max_proto=0,
            settings=zero_payload_limits,
        )
        self.assertEqual(normalized.min_proto, zmux.PROTO_VERSION)
        self.assertEqual(normalized.max_proto, zmux.PROTO_VERSION)
        self.assertEqual(normalized.settings.initial_max_data, 123)
        self.assertEqual(
            normalized.settings.max_frame_payload,
            zmux.default_settings().max_frame_payload,
        )
        with self.assertRaises(ValueError):
            zmux.Config(min_proto=2, max_proto=1)
        with self.assertRaises(ValueError):
            zmux.Config(capabilities=zmux.MAX_VARINT62 + 1)
        with self.assertRaises(ValueError):
            zmux.Config(keepalive_interval=-1)
        with self.assertRaises(ValueError):
            zmux.Config(keepalive_interval=float("nan"))
        with self.assertRaises(TypeError):
            zmux.Config(preface_padding=1)
        with self.assertRaises(TypeError):
            zmux.Config(nonce_source=object())
        with self.assertRaises(TypeError):
            zmux.Config(event_handler=object())

        auto_preface = cfg.local_preface()
        self.assertEqual(auto_preface.role, Role.AUTO)
        self.assertNotEqual(auto_preface.tie_breaker_nonce, 0)
        self.assertEqual(auto_preface.capabilities, zmux.DEFAULT_CAPABILITIES)
        self.assertEqual(
            zmux.Config(disable_capabilities=True).local_preface().capabilities,
            0,
        )
        deterministic_cfg = replace(
            cfg,
            ping_padding=True,
            nonce_source=lambda n: b"\x00" * (n - 1) + b"\x05",
        )
        deterministic_preface = deterministic_cfg.local_preface()
        self.assertEqual(deterministic_preface.tie_breaker_nonce, 5)
        self.assertEqual(deterministic_preface.settings.ping_padding_key, 5)
        file_source_preface = replace(
            cfg,
            nonce_source=BytesIO(b"\x00" * 7 + b"\x06" + b"\x00" * 7 + b"\x08"),
        ).local_preface()
        self.assertEqual(file_source_preface.tie_breaker_nonce, 6)
        self.assertEqual(file_source_preface.settings.ping_padding_key, 8)

        class PartialRandom(object):
            def __init__(self, data: bytes) -> None:
                self._data = bytearray(data)

            def read(self, size: int = -1) -> bytes:
                if not self._data:
                    return b""
                n = 1 if size < 0 else min(1, size, len(self._data))
                out = bytes(self._data[:n])
                del self._data[:n]
                return out

        self.assertEqual(
            zmux.random_varint62(PartialRandom(b"\x00" * 7 + b"\x07")),
            7,
        )
        self.assertEqual(
            zmux.random_preface_padding(
                zmux.default_settings(),
                3,
                3,
                lambda n: b"\xaa" * n,
            ),
            b"\xaa\xaa\xaa",
        )
        self.assertEqual(
            len(
                zmux.random_preface_padding(
                    zmux.default_settings(),
                    zmux.MAX_PREFACE_SETTINGS_BYTES,
                    zmux.MAX_PREFACE_SETTINGS_BYTES,
                    lambda n: b"\xbb" * n,
                )
            ),
            zmux.MAX_PREFACE_SETTINGS_BYTES
            - zmux.varint_len(zmux.SETTING_PREFACE_PADDING)
            - zmux.varint_len(zmux.MAX_PREFACE_SETTINGS_BYTES - 3),
        )
        with self.assertRaises(ValueError):
            zmux.random_varint62(lambda n: b"\x00")
        with self.assertRaises(RuntimeError):
            zmux.random_varint62(lambda n: b"\x00" * n)
        with self.assertRaises(TypeError):
            zmux.random_varint62(lambda n: n)
        initiator_preface = zmux.Config(
            role=Role.INITIATOR,
            tie_breaker_nonce=99,
        ).local_preface()
        self.assertEqual(initiator_preface.tie_breaker_nonce, 0)
        padded_cfg = replace(
            cfg,
            preface_padding=True,
            preface_padding_min_bytes=8,
            preface_padding_max_bytes=8,
        )
        padded_preface = padded_cfg.local_preface()
        padded_payload = padded_cfg.local_preface_payload(padded_preface)
        self.assertGreaterEqual(len(padded_payload), len(padded_preface.marshal()))
        self.assertEqual(zmux.parse_preface(padded_payload), padded_preface)

        ping_preface = cfg.local_preface()
        self.assertNotEqual(ping_preface.settings.ping_padding_key, 0)
        dirty_key = replace(
            cfg,
            settings=Settings(ping_padding_key=77),
            ping_padding=False,
        ).local_preface()
        self.assertEqual(dirty_key.settings.ping_padding_key, 0)

        options = zmux.OpenOptions(7, 9, "ssh")
        self.assertEqual(options.initial_priority, 7)
        self.assertIsNotNone(options.initial_priority)
        self.assertEqual(options.initial_group, 9)
        self.assertIsNotNone(options.initial_group)
        self.assertEqual(options.open_info, b"ssh")
        self.assertEqual(zmux.OpenOptions(initial_priority=5).initial_priority, 5)
        self.assertEqual(zmux.OpenOptions(initial_group=6).initial_group, 6)
        self.assertEqual(zmux.OpenOptions(open_info="x").open_info, b"x")
        self.assertEqual(zmux.OpenOptions(open_info=memoryview(b"x")).open_info, b"x")
        with self.assertRaises(TypeError):
            zmux.OpenOptions(open_info=3)
        self.assertIn("open_info_len=3", repr(options))
        self.assertFalse(hasattr(zmux.OpenOptions, "empty"))
        self.assertFalse(hasattr(zmux.OpenOptions, "of"))
        self.assertFalse(hasattr(zmux.Config, "initiator"))
        self.assertFalse(hasattr(zmux.Config, "with_role"))
        self.assertFalse(hasattr(zmux.SessionStats, "empty"))
        self.assertFalse(hasattr(zmux, "client_session"))
        self.assertFalse(hasattr(zmux, "server_session"))
        self.assertTrue(callable(zmux.client))
        self.assertTrue(callable(zmux.server))

        padding = zmux.random_preface_padding(Settings(), 4, 4)
        self.assertEqual(len(padding), 4)
        with self.assertRaises(TypeError):
            zmux.random_preface_padding(Settings(), True, 4)
        with self.assertRaises(TypeError):
            zmux.random_ping_padding_len(True, 4)
        for _ in range(8):
            self.assertGreaterEqual(zmux.random_ping_padding_len(2, 5, 5), 2)
            self.assertLessEqual(zmux.random_ping_padding_len(2, 5, 5), 5)

        zmux.configure_default_config(
            lambda current: replace(
                current,
                role=Role.INITIATOR,
                tie_breaker_nonce=123,
                settings=Settings(ping_padding_key=55),
            )
        )
        updated_default = zmux.default_config()
        self.assertEqual(updated_default.role, Role.INITIATOR)
        self.assertEqual(updated_default.tie_breaker_nonce, 0)
        self.assertEqual(updated_default.settings.ping_padding_key, 0)
        zmux.reset_default_config()
        self.assertEqual(zmux.default_config().role, Role.AUTO)
        self.assertTrue(zmux.default_config().preface_padding)
        self.assertTrue(zmux.default_config().ping_padding)
        self.assertEqual(zmux.clone_config(None), zmux.default_config())

    def test_error_helpers_preserve_codes_through_wrapping(self) -> None:
        app = ApplicationError(ErrorCode.CANCELLED, "stop")
        self.assertEqual(str(app), "zmux application error 8: stop")
        self.assertEqual(app.reason, "stop")
        self.assertEqual(app.numeric_code, int(ErrorCode.CANCELLED))
        self.assertEqual(app.application_code, int(ErrorCode.CANCELLED))
        self.assertEqual(app.clone().reason, "stop")
        self.assertTrue(app.is_error_code(ErrorCode.CANCELLED))
        detailed_app = ApplicationError(
            ErrorCode.CANCELLED,
            "reset",
            scope=ErrorScope.STREAM,
            operation=ErrorOperation.WRITE,
            source=ErrorSource.REMOTE,
            direction=ErrorDirection.WRITE,
            termination_kind=TerminationKind.RESET,
        )
        self.assertEqual(
            (
                detailed_app.scope,
                detailed_app.operation,
                detailed_app.source,
                detailed_app.direction,
                detailed_app.termination_kind,
            ),
            (
                ErrorScope.STREAM,
                ErrorOperation.WRITE,
                ErrorSource.REMOTE,
                ErrorDirection.WRITE,
                TerminationKind.RESET,
            ),
        )
        self.assertEqual(detailed_app.clone().termination_kind, TerminationKind.RESET)

        try:
            raise RuntimeError("outer") from app
        except RuntimeError as wrapped:
            self.assertIs(zmux.find_error(wrapped, ApplicationError), app)
            self.assertTrue(zmux.has_code(wrapped))
            self.assertEqual(zmux.error_code(wrapped), int(ErrorCode.CANCELLED))
            self.assertEqual(zmux.typed_code(wrapped), ErrorCode.CANCELLED)
            self.assertTrue(zmux.is_error_code(wrapped, ErrorCode.CANCELLED))
            self.assertEqual(zmux.error_reason(wrapped), "stop")

        with self.assertRaises(ValueError):
            ApplicationError(zmux.MAX_VARINT62 + 1, "bad")
        with self.assertRaises(ValueError):
            ApplicationError(-1, "bad")
        with self.assertRaises(TypeError):
            ApplicationError(True, "bad")

        self.assertTrue(zmux.read_closed(zmux.ReadClosed()))
        self.assertTrue(zmux.write_closed(zmux.WriteClosed()))
        self.assertTrue(zmux.session_closed(zmux.SessionClosed()))
        self.assertTrue(zmux.stream_closed(zmux.StreamClosed()))
        self.assertTrue(
            zmux.session_closed(ProtocolError("closing", code=int(ErrorCode.SESSION_CLOSING)))
        )
        self.assertTrue(
            zmux.stream_closed(ProtocolError("closed", code=int(ErrorCode.STREAM_CLOSED)))
        )
        self.assertTrue(zmux.stream_not_readable(zmux.StreamNotReadable()))
        self.assertTrue(zmux.stream_not_writable(zmux.StreamNotWritable()))
        self.assertTrue(zmux.open_limited(zmux.OpenLimited()))
        self.assertTrue(zmux.open_expired(zmux.OpenExpired()))
        self.assertTrue(zmux.adapter_unsupported(zmux.AdapterUnsupported()))
        self.assertTrue(zmux.open_info_unavailable(zmux.OpenInfoUnavailable()))
        self.assertTrue(zmux.open_metadata_too_large(zmux.OpenMetadataTooLarge()))
        self.assertTrue(
            zmux.priority_update_unavailable(zmux.PriorityUpdateUnavailable())
        )
        self.assertTrue(zmux.priority_update_too_large(zmux.PriorityUpdateTooLarge()))
        self.assertTrue(zmux.empty_metadata_update(zmux.EmptyMetadataUpdate()))
        self.assertTrue(zmux.keepalive_timeout(zmux.KeepaliveTimeout()))
        self.assertTrue(zmux.graceful_close_timeout(zmux.GracefulCloseTimeout()))
        self.assertTrue(zmux.timeout(zmux.PingTimeout()))
        self.assertTrue(zmux.timeout(zmux.ReadTimeout()))
        self.assertTrue(zmux.timeout(zmux.JoinedHalfPauseTimeout()))
        self.assertTrue(zmux.timeout(RuntimeError(zmux.JOINED_HALF_PAUSE_TIMEOUT_MESSAGE)))
        self.assertTrue(zmux.interrupted(zmux.ZmuxInterruptedError()))
        self.assertEqual(zmux.SessionClosed().scope, ErrorScope.SESSION)
        self.assertEqual(zmux.SessionClosed().direction, ErrorDirection.BOTH)
        self.assertEqual(
            zmux.SessionClosed().termination_kind,
            TerminationKind.SESSION_TERMINATION,
        )
        self.assertEqual(zmux.WriteClosed().termination_kind, TerminationKind.GRACEFUL)
        self.assertEqual(zmux.OpenLimited().direction, ErrorDirection.BOTH)
        self.assertEqual(zmux.OpenExpired().code, int(ErrorCode.CANCELLED))
        self.assertEqual(zmux.OpenExpired().termination_kind, TerminationKind.ABORT)
        self.assertEqual(zmux.OpenInfoUnavailable().scope, ErrorScope.SESSION)
        self.assertEqual(zmux.OpenMetadataTooLarge().scope, ErrorScope.SESSION)
        self.assertEqual(zmux.PriorityUpdateUnavailable().scope, ErrorScope.STREAM)
        self.assertEqual(zmux.EmptyMetadataUpdate().scope, ErrorScope.STREAM)
        self.assertEqual(zmux.PingTimeout().direction, ErrorDirection.BOTH)
        transport_timeout = zmux.TransportError(TimeoutError("late"))
        self.assertEqual(transport_timeout.code, int(ErrorCode.INTERNAL))
        self.assertEqual(transport_timeout.source, ErrorSource.TRANSPORT)
        self.assertEqual(transport_timeout.termination_kind, TerminationKind.TIMEOUT)
        self.assertTrue(zmux.timeout(transport_timeout))
        self.assertIs(zmux.source_exception(transport_timeout), transport_timeout.source_error)
        transport_interrupt = zmux.TransportError(InterruptedError("stop"))
        self.assertEqual(
            transport_interrupt.termination_kind,
            TerminationKind.INTERRUPTED,
        )
        self.assertTrue(zmux.interrupted(transport_interrupt))
        nil_connection = zmux.NilConnection()
        self.assertIs(zmux.as_structured_error(nil_connection), nil_connection)
        with self.assertRaises(TypeError):
            zmux.error_code_name(True)

    def test_wire_error_wrapper_matches_go_error_code_helpers(self) -> None:
        inner = ValueError(ERR_INVALID_MAGIC)
        wrapped = wrap_error(ErrorCode.PROTOCOL, "parse preface", inner)

        self.assertEqual(str(wrapped), ERR_INVALID_MAGIC)
        self.assertIs(wrapped.__cause__, inner)
        self.assertEqual(error_code_of(wrapped), int(ErrorCode.PROTOCOL))
        self.assertTrue(is_code(wrapped, ErrorCode.PROTOCOL))
        self.assertEqual(wrapped.scope, ErrorScope.SESSION)
        self.assertEqual(wrapped.operation, ErrorOperation.READ)
        self.assertEqual(wrapped.source, ErrorSource.REMOTE)
        self.assertEqual(wrapped.direction, ErrorDirection.READ)

        unknown = wrap_error(999, "parse extension", ValueError("unknown"))
        self.assertEqual(error_code_of(unknown), 999)
        self.assertTrue(is_code(unknown, 999))
        self.assertNotIsInstance(unknown, FrameSizeError)

        without_cause = wrap_error(ErrorCode.PROTOCOL, "parse frame", None)
        self.assertEqual(str(without_cause), "parse frame")
        self.assertIsNone(without_cause.__cause__)
        self.assertEqual(without_cause.operation, ErrorOperation.READ)

        built = wrap_error(ErrorCode.PROTOCOL, "build priority update", ValueError("bad"))
        self.assertEqual(built.operation, ErrorOperation.WRITE)
        self.assertEqual(built.source, ErrorSource.LOCAL)
        self.assertEqual(built.direction, ErrorDirection.WRITE)

        frame_size = wrap_error(ErrorCode.FRAME_SIZE, "read frame", ValueError("short"))
        self.assertIsInstance(frame_size, FrameSizeError)
        self.assertEqual(frame_size.operation, ErrorOperation.READ)
        self.assertEqual(frame_size.source, ErrorSource.REMOTE)
        self.assertEqual(frame_size.direction, ErrorDirection.READ)

        validated = wrap_error(ErrorCode.PROTOCOL, "validate flags", ValueError("bad"))
        self.assertEqual(validated.operation, ErrorOperation.UNKNOWN)
        self.assertEqual(validated.source, ErrorSource.UNKNOWN)
        self.assertEqual(validated.direction, ErrorDirection.BOTH)

        unknown = protocol_error("bad", ErrorOperation.UNKNOWN)
        self.assertEqual(unknown.source, ErrorSource.UNKNOWN)
        self.assertEqual(unknown.direction, ErrorDirection.BOTH)
        write_size = frame_size_error("too large", "write frame")
        self.assertIsInstance(write_size, FrameSizeError)
        self.assertEqual(write_size.operation, ErrorOperation.WRITE)
        self.assertEqual(write_size.source, ErrorSource.LOCAL)
        with self.assertRaises(TypeError):
            wrap_error(True, "read frame", ValueError("bad"))
        with self.assertRaises(TypeError):
            wrap_error(ErrorCode.PROTOCOL, True, ValueError("bad"))
        with self.assertRaises(TypeError):
            protocol_error("bad", True)
        with self.assertRaises(ValueError):
            wrap_error(zmux.MAX_VARINT62 + 1, "read frame", ValueError("bad"))

        cyclic = RuntimeError("cycle")
        cyclic.__cause__ = cyclic
        self.assertIsNone(error_code_of(cyclic))
        self.assertFalse(is_code(cyclic, ErrorCode.PROTOCOL))

        multi = RuntimeError("multi")
        multi.exceptions = (RuntimeError("ignored"), wrapped)
        self.assertEqual(error_code_of(multi), int(ErrorCode.PROTOCOL))

        timeout_error = ProtocolError(
            "zmux: keepalive timeout",
            code=int(ErrorCode.IDLE_TIMEOUT),
            termination_kind=TerminationKind.TIMEOUT,
        )
        self.assertTrue(zmux.timeout(timeout_error))
        interrupted_error = ProtocolError(
            "interrupted",
            termination_kind=TerminationKind.INTERRUPTED,
        )
        self.assertTrue(zmux.interrupted(interrupted_error))

        try:
            raise RuntimeError("wrapped timeout") from TimeoutError("late")
        except RuntimeError as wrapped_timeout:
            self.assertTrue(zmux.timeout(wrapped_timeout))

        try:
            raise RuntimeError("wrapped interrupt") from InterruptedError("stop")
        except RuntimeError as wrapped_interrupt:
            self.assertTrue(zmux.interrupted(wrapped_interrupt))

    def test_protocol_registry_surface_matches_reference_implementations(self) -> None:
        self.assertEqual(str(Role.INITIATOR), "initiator")
        self.assertEqual(Role.from_code(1), Role.RESPONDER)
        self.assertTrue(Role.AUTO.valid())
        with self.assertRaises(ValueError):
            Role.from_code(3)
        with self.assertRaises(TypeError):
            Role.from_code(True)

        self.assertEqual(SchedulerHint.from_code(4), SchedulerHint.GROUP_FAIR)
        self.assertEqual(SchedulerHint.from_code(999), SchedulerHint.UNSPECIFIED_OR_BALANCED)
        self.assertEqual(str(SchedulerHint.BALANCED_FAIR), "balanced_fair")
        self.assertEqual(SchedulerHint.BULK_THROUGHPUT.as_str(), "bulk_throughput")
        with self.assertRaises(TypeError):
            SchedulerHint.from_code(True)

        self.assertEqual(FrameType.from_code(11), FrameType.EXT)
        self.assertEqual(str(FrameType.MAX_DATA), "MAX_DATA")
        self.assertTrue(FrameType.DATA.valid())
        with self.assertRaises(ValueError):
            FrameType.from_code(31)
        with self.assertRaises(TypeError):
            FrameType.from_code(1.0)

        self.assertEqual(ErrorCode.from_code(13), ErrorCode.INTERNAL)
        self.assertEqual(str(ErrorCode.ROLE_CONFLICT), "ROLE_CONFLICT")
        with self.assertRaisesRegex(ValueError, "unknown zmux error code: 999"):
            ErrorCode.from_code(999)
        with self.assertRaises(TypeError):
            ErrorCode.from_code("13")  # type: ignore[arg-type]

        self.assertEqual(SettingID.from_code(SETTING_PREFACE_PADDING), SettingID.PREFACE_PADDING)
        self.assertEqual(MetadataType.from_code(3), MetadataType.OPEN_INFO)
        self.assertEqual(DiagnosticType.from_code(4), DiagnosticType.OFFENDING_FRAME_TYPE)
        with self.assertRaises(TypeError):
            SettingID.from_code(False)
        with self.assertRaises(TypeError):
            MetadataType.from_code(b"\x03")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            DiagnosticType.from_code(None)  # type: ignore[arg-type]
        self.assertEqual(DIAG_OFFENDING_FRAME_TYPE, 4)
        self.assertEqual(
            ExtensionSubtype.from_code(EXT_PRIORITY_UPDATE),
            ExtensionSubtype.PRIORITY_UPDATE,
        )
        with self.assertRaises(TypeError):
            ExtensionSubtype.from_code(True)
        with self.assertRaises(ValueError):
            ExtensionSubtype.from_code(2)
        self.assertEqual(SETTING_PING_PADDING_KEY, 11)
        self.assertEqual(SETTING_PREFACE_PADDING, 12)
        self.assertEqual(protocol_registry.FRAME_FLAG_RESERVED_TYPE_SPECIFIC, 0x80)
        self.assertIn("FRAME_FLAG_RESERVED_TYPE_SPECIFIC", protocol_registry.__all__)
        self.assertIn("capabilities_support_open_metadata", protocol_registry.__all__)
        self.assertNotIn("capabilities_supports_open_metadata", protocol_registry.__all__)
        self.assertFalse(hasattr(protocol_registry, "capabilities_supports_open_metadata"))
        self.assertEqual(
            CAPABILITY_METADATA_CARRIAGE_MASK,
            int(Capability.OPEN_METADATA | Capability.PRIORITY_UPDATE),
        )

    def test_protocol_capability_semantics_match_go_java_rust(self) -> None:
        priority_open = int(Capability.OPEN_METADATA | Capability.PRIORITY_HINTS)
        group_update = int(Capability.PRIORITY_UPDATE | Capability.STREAM_GROUPS)

        self.assertTrue(capabilities_support_open_metadata(priority_open))
        self.assertFalse(capabilities_support_priority_update(priority_open))
        self.assertTrue(capabilities_can_carry_priority_on_open(priority_open))
        self.assertFalse(capabilities_can_carry_priority_in_update(priority_open))
        self.assertTrue(capabilities_have_peer_visible_priority_semantics(priority_open))

        self.assertTrue(capabilities_can_carry_group_in_update(group_update))
        self.assertFalse(capabilities_can_carry_group_on_open(group_update))
        self.assertTrue(capabilities_have_peer_visible_group_semantics(group_update))
        self.assertFalse(
            capabilities_have_peer_visible_priority_semantics(
                int(Capability.PRIORITY_HINTS)
            )
        )
        with self.assertRaises(TypeError):
            zmux.has_capability(True, int(Capability.OPEN_METADATA))
        with self.assertRaises(ValueError):
            zmux.has_any_capability(-1, int(Capability.OPEN_METADATA))
        with self.assertRaises(ValueError):
            zmux.has_all_capabilities(
                int(Capability.OPEN_METADATA),
                zmux.MAX_VARINT62 + 1,
            )

    def test_settings_tlv_round_trip_and_defaults(self) -> None:
        self.assertEqual(marshal_settings_tlv(zmux.default_settings()), b"")
        self.assertEqual(settings_tlv_len(zmux.default_settings()), 0)
        self.assertEqual(
            marshal_settings_tlv(Settings(initial_max_data=1024)),
            b"\x04\x02\x44\x00",
        )
        self.assertEqual(
            marshal_settings_tlv(Settings(scheduler_hints=SchedulerHint.LATENCY)),
            b"\x0a\x01\x01",
        )

        settings = Settings(
            initial_max_data=12345,
            max_frame_payload=8192,
            scheduler_hints=SchedulerHint.GROUP_FAIR,
            ping_padding_key=123456,
        )
        encoded = marshal_settings_tlv(settings)

        self.assertEqual(settings.encoded_tlv_len(), len(encoded))
        self.assertEqual(settings.to_tlv(), encoded)
        appended = bytearray(b"\xaa")
        settings.append_tlv_to(appended)
        self.assertEqual(appended[0], 0xAA)
        self.assertEqual(bytes(appended[1:]), encoded)

        parsed = parse_settings_tlv(encoded)
        self.assertEqual(parsed, settings)
        self.assertEqual(parsed.limits().max_frame_payload, 8192)
        self.assertEqual(parsed.scheduler_hints, SchedulerHint.GROUP_FAIR)
        with self.assertRaises(TypeError):
            marshal_settings_tlv(object())
        with self.assertRaises(TypeError):
            settings_tlv_len(object())
        with self.assertRaises(TypeError):
            zmux.settings_entries(Settings(), object())
        invalid_dst = bytearray(b"\xaa")
        with self.assertRaises(TypeError):
            append_settings_tlv(invalid_dst, object())
        self.assertEqual(invalid_dst, b"\xaa")

        class FailingList(list):
            def extend(self, values):
                for value in values:
                    super().append(value)
                    raise RuntimeError("synthetic extend failure")

        failing_dst = FailingList([0xAA])
        with self.assertRaises(RuntimeError):
            append_settings_tlv(failing_dst, settings)
        self.assertEqual(failing_dst, [0xAA])

    def test_settings_tlv_duplicate_and_unknown_rules(self) -> None:
        value = encode_varint(10)
        duplicate_known = bytearray()
        append_tlv(duplicate_known, SETTING_INITIAL_MAX_DATA, value)
        append_tlv(duplicate_known, SETTING_INITIAL_MAX_DATA, value)
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(duplicate_known)
        self.assertEqual(str(raised.exception), "duplicate setting id 4")

        duplicate_unknown = bytearray()
        append_tlv(duplicate_unknown, 1000, b"\xff")
        append_tlv(duplicate_unknown, 1000, b"\x00")
        with self.assertRaises(ProtocolError):
            parse_settings_tlv(duplicate_unknown)

        many_unknown = bytearray()
        for setting_id in range(1000, 1010):
            append_tlv(many_unknown, setting_id, b"\xff")
        self.assertEqual(parse_settings_tlv(many_unknown), zmux.default_settings())
        append_tlv(many_unknown, 1002, b"\x00")
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(many_unknown)
        self.assertEqual(str(raised.exception), "duplicate setting id 1002")

        opaque = bytearray()
        append_tlv(opaque, 1000, b"\xff")
        append_tlv(opaque, SETTING_PREFACE_PADDING, b"\x40\x00garbage")
        self.assertEqual(parse_settings_tlv(opaque), zmux.default_settings())

        duplicate_padding = bytearray()
        append_tlv(duplicate_padding, SETTING_PREFACE_PADDING, b"a")
        append_tlv(duplicate_padding, SETTING_PREFACE_PADDING, b"b")
        with self.assertRaises(ProtocolError):
            parse_settings_tlv(duplicate_padding)

        for setting_id in (
                SETTING_INITIAL_MAX_DATA,
                SETTING_PING_PADDING_KEY,
                SETTING_PREFACE_PADDING,
        ):
            self.assertIsNotNone(known_setting_seen_bit(setting_id))

    def test_settings_tlv_rejects_malformed_values(self) -> None:
        trailing = bytearray()
        append_tlv(trailing, SETTING_INITIAL_MAX_DATA, b"\x01\x02")
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(trailing)
        self.assertEqual(str(raised.exception), "setting 4 has trailing bytes")

        empty = bytearray()
        append_tlv(empty, SETTING_INITIAL_MAX_DATA, b"")
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(empty)
        self.assertEqual(str(raised.exception), "truncated varint62")

        bounded_truncated = bytearray()
        append_varint(bounded_truncated, SETTING_INITIAL_MAX_DATA)
        append_varint(bounded_truncated, 1)
        bounded_truncated.append(0x40)
        append_tlv(bounded_truncated, 99, b"\x01")
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(bounded_truncated)
        self.assertEqual(str(raised.exception), "truncated varint62")
        self.assertEqual(raised.exception.operation, ErrorOperation.READ)

        noncanonical = bytearray()
        append_tlv(noncanonical, SETTING_INITIAL_MAX_DATA, b"\x40\x01")
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(noncanonical)
        self.assertEqual(str(raised.exception), "non-canonical varint62")

        overrun = b"\x04\x02\x01"
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(overrun)
        self.assert_protocol_read_error(
            raised.exception, "tlv value overruns containing payload"
        )

        huge_value_length = bytearray()
        append_varint(huge_value_length, SETTING_PREFACE_PADDING)
        append_varint(huge_value_length, zmux.MAX_VARINT62)
        with self.assertRaises(ProtocolError) as raised:
            parse_settings_tlv(huge_value_length)
        self.assertEqual(str(raised.exception), "tlv value overruns containing payload")

        with self.assertRaises(ValueError):
            Settings(max_frame_payload=zmux.MAX_VARINT62 + 1)
        with self.assertRaises(ValueError):
            Settings(initial_max_data=-1)
        with self.assertRaises(TypeError):
            Settings(ping_padding_key=True)

    def test_settings_scheduler_unknown_value_uses_balanced_fallback(self) -> None:
        raw = bytearray()
        append_tlv(raw, SETTING_SCHEDULER_HINTS, encode_varint(999))

        parsed = parse_settings_tlv(raw)

        self.assertEqual(parsed.scheduler_hints, SchedulerHint.UNSPECIFIED_OR_BALANCED)
        self.assertEqual(
            Settings(scheduler_hints=999).scheduler_hints,
            SchedulerHint.UNSPECIFIED_OR_BALANCED,
        )
        self.assertEqual(
            Settings(scheduler_hints=None).scheduler_hints,
            SchedulerHint.UNSPECIFIED_OR_BALANCED,
        )
        settings = Settings()
        self.assertIs(settings.limits(), settings.limits())
        dst = bytearray(b"\x00")
        append_settings_tlv(dst, Settings(scheduler_hints=SchedulerHint.LATENCY))
        self.assertEqual(parse_settings_tlv(dst[1:]).scheduler_hints, SchedulerHint.LATENCY)

    def test_preface_minimal_examples_and_prefix_parsing(self) -> None:
        initiator = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.INITIATOR,
            tie_breaker_nonce=0,
            min_proto=zmux.PROTO_VERSION,
            max_proto=zmux.PROTO_VERSION,
            capabilities=0,
            settings=zmux.default_settings(),
        )
        responder = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.RESPONDER,
            tie_breaker_nonce=0,
            min_proto=zmux.PROTO_VERSION,
            max_proto=zmux.PROTO_VERSION,
            capabilities=0,
            settings=zmux.default_settings(),
        )

        self.assertEqual(
            zmux.marshal_preface(initiator).hex(),
            "5a4d555801000001010000",
        )
        self.assertEqual(
            responder.marshal().hex(),
            "5a4d555801010001010000",
        )
        self.assertIs(type(initiator.preface_version), int)
        self.assertIs(type(initiator.tie_breaker_nonce), int)
        self.assertEqual(zmux.parse_preface(initiator.marshal()), initiator)
        self.assertEqual(zmux.read_preface(BytesIO(responder.marshal())), responder)
        self.assertTrue(callable(zmux.write_preface))
        preface_writer = BytesIO()
        zmux.write_preface(preface_writer, initiator)
        self.assertEqual(preface_writer.getvalue(), initiator.marshal())

        prefaced, consumed = zmux.parse_preface_prefix(initiator.marshal() + b"next")
        self.assertEqual(prefaced, initiator)
        self.assertEqual(consumed, len(initiator.marshal()))
        with self.assertRaises(ProtocolError):
            zmux.parse_preface(initiator.marshal() + b"x")

        class PartialWriter(object):
            def __init__(self) -> None:
                self.chunks = []

            def write(self, payload) -> int:
                chunk = bytes(memoryview(payload)[:1])
                self.chunks.append(chunk)
                return len(chunk)

        partial_writer = PartialWriter()
        zmux.write_preface(partial_writer, responder)
        self.assertEqual(b"".join(partial_writer.chunks), responder.marshal())

        class StalledWriter(object):
            def write(self, payload) -> int:
                return 0

        with self.assertRaises(zmux.TransportError) as stalled_raised:
            zmux.write_preface(StalledWriter(), responder)
        self.assertEqual(stalled_raised.exception.operation, ErrorOperation.WRITE)
        self.assertEqual(stalled_raised.exception.source, ErrorSource.TRANSPORT)
        self.assertEqual(stalled_raised.exception.direction, ErrorDirection.WRITE)

        class NoneWriter(object):
            def write(self, payload):
                return None

        with self.assertRaises(zmux.TransportError):
            zmux.write_preface(NoneWriter(), responder)
        with self.assertRaises(ProtocolError) as raised:
            zmux.write_preface(BytesIO(), object())
        self.assertEqual(str(raised.exception), "preface is required")
        self.assertEqual(raised.exception.operation, ErrorOperation.WRITE)

    def test_preface_padding_is_wire_only_and_capability_helpers_round_trip(self) -> None:
        caps = int(
            Capability.OPEN_METADATA
            | Capability.PRIORITY_HINTS
            | Capability.PRIORITY_UPDATE
        )
        preface = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.INITIATOR,
            tie_breaker_nonce=0,
            min_proto=zmux.PROTO_VERSION,
            max_proto=zmux.PROTO_VERSION,
            capabilities=caps,
            settings=Settings(ping_padding_key=99),
        )

        padded = preface.marshal_with_settings_padding(b"\xff\x00\x80\x01")

        self.assertGreater(len(padded), len(preface.marshal()))
        self.assertEqual(zmux.parse_preface(padded), preface)
        self.assertTrue(preface.has_capability(int(Capability.OPEN_METADATA)))
        self.assertTrue(preface.supports_open_metadata())
        self.assertTrue(preface.supports_priority_update())
        self.assertTrue(preface.can_carry_open_info())
        self.assertTrue(preface.can_carry_priority_on_open())
        self.assertTrue(preface.can_carry_priority_in_update())
        self.assertTrue(preface.has_peer_visible_priority_semantics())
        self.assertFalse(preface.can_carry_group_on_open())
        self.assertFalse(preface.has_peer_visible_group_semantics())

    def test_preface_negotiation_and_role_conflicts(self) -> None:
        local = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.AUTO,
            tie_breaker_nonce=10,
            min_proto=1,
            max_proto=1,
            capabilities=int(Capability.OPEN_METADATA | Capability.PRIORITY_HINTS),
            settings=zmux.default_settings(),
        )
        peer = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.AUTO,
            tie_breaker_nonce=5,
            min_proto=1,
            max_proto=1,
            capabilities=int(Capability.OPEN_METADATA),
            settings=zmux.default_settings(),
        )

        negotiated = zmux.negotiate_prefaces(local, peer)

        self.assertEqual(negotiated.proto, 1)
        self.assertEqual(negotiated.local_role, Role.INITIATOR)
        self.assertEqual(negotiated.peer_role, Role.RESPONDER)
        self.assertTrue(negotiated.supports_open_metadata())
        self.assertFalse(negotiated.can_carry_priority_on_open())
        self.assertEqual(negotiated.peer_settings, peer.settings)
        self.assertEqual(
            zmux.resolve_roles(Role.INITIATOR, 0, Role.AUTO, 0),
            (Role.INITIATOR, Role.RESPONDER),
        )
        self.assertEqual(
            zmux.resolve_roles(int(Role.INITIATOR), 0, int(Role.AUTO), 0),
            (Role.INITIATOR, Role.RESPONDER),
        )
        with self.assertRaises(TypeError):
            zmux.resolve_roles(True, 0, Role.AUTO, 0)

        with self.assertRaises(ProtocolError) as raised:
            zmux.resolve_roles(Role.AUTO, 7, Role.AUTO, 7)
        self.assertEqual(raised.exception.code, int(ErrorCode.ROLE_CONFLICT))

        with self.assertRaises(ProtocolError) as raised:
            zmux.resolve_roles(Role.RESPONDER, 0, Role.RESPONDER, 0)
        self.assertEqual(raised.exception.code, int(ErrorCode.ROLE_CONFLICT))

        with self.assertRaises(ProtocolError) as raised:
            zmux.negotiate_prefaces(
                local,
                zmux.Preface(
                    preface_version=zmux.PREFACE_VERSION,
                    role=Role.AUTO,
                    tie_breaker_nonce=0,
                    min_proto=1,
                    max_proto=1,
                    capabilities=0,
                    settings=zmux.default_settings(),
                ),
            )
        self.assertEqual(str(raised.exception), "peer auto role requires non-zero nonce")

        incompatible = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.RESPONDER,
            tie_breaker_nonce=0,
            min_proto=2,
            max_proto=2,
            capabilities=0,
            settings=zmux.default_settings(),
        )
        with self.assertRaises(ProtocolError) as raised:
            zmux.negotiate_prefaces(local, incompatible)
        self.assertEqual(raised.exception.code, int(ErrorCode.UNSUPPORTED_VERSION))

    def test_preface_rejects_invalid_wire_and_local_constraints(self) -> None:
        valid = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.INITIATOR,
            tie_breaker_nonce=0,
            min_proto=1,
            max_proto=1,
            capabilities=0,
            settings=zmux.default_settings(),
        )

        with self.assertRaises(ProtocolError) as raised:
            zmux.parse_preface(b"BAD!")
        self.assertEqual(str(raised.exception), "truncated preface")

        with self.assertRaises(ProtocolError) as raised:
            zmux.parse_preface(b"BAD!!!")
        self.assertEqual(str(raised.exception), "invalid magic")

        unsupported = bytearray(valid.marshal())
        unsupported[4] = 2
        with self.assertRaises(ProtocolError) as raised:
            zmux.parse_preface(unsupported)
        self.assertEqual(raised.exception.code, int(ErrorCode.UNSUPPORTED_VERSION))

        with self.assertRaises(ProtocolError) as raised:
            zmux.default_preface(Role.AUTO).marshal()
        self.assertEqual(str(raised.exception), "role=auto requires non-zero tie-breaker nonce")

        with self.assertRaises(ProtocolError) as raised:
            zmux.Preface(
                preface_version=zmux.PREFACE_VERSION,
                role=Role.INITIATOR,
                tie_breaker_nonce=0,
                min_proto=0,
                max_proto=1,
                capabilities=0,
                settings=zmux.default_settings(),
            ).marshal()
        self.assertEqual(str(raised.exception), "protocol version bounds must be non-zero")

        with self.assertRaises(ProtocolError) as raised:
            zmux.Preface(
                preface_version=zmux.PREFACE_VERSION,
                role=Role.INITIATOR,
                tie_breaker_nonce=0,
                min_proto=1,
                max_proto=0,
                capabilities=0,
                settings=zmux.default_settings(),
            ).marshal()
        self.assertEqual(str(raised.exception), "protocol version bounds must be non-zero")

        too_large = bytearray(valid.marshal())
        too_large[-1:] = encode_varint(4097)
        with self.assertRaises(FrameSizeError):
            zmux.parse_preface_prefix(too_large)

        with self.assertRaises(FrameSizeError):
            valid.marshal_with_settings_padding(bytes(4096))

        class FailingRead(BytesIO):
            def read(self, size=-1):
                raise TimeoutError("late")

            def readinto(self, buffer):
                raise TimeoutError("late")

        with self.assertRaises(zmux.TransportError) as raised:
            zmux.read_preface(FailingRead(valid.marshal()))
        self.assertEqual(raised.exception.source, ErrorSource.TRANSPORT)
        self.assertEqual(raised.exception.operation, ErrorOperation.READ)
        self.assertTrue(zmux.timeout(raised.exception))

        class BadRead(object):
            def read(self, size=-1):
                return "not bytes"

        with self.assertRaises(zmux.TransportError):
            zmux.read_preface(BadRead())

        with self.assertRaises(ProtocolError) as raised:
            zmux.read_preface(BytesIO(valid.marshal()[:6] + b"\x40"))
        self.assertEqual(str(raised.exception), "truncated varint62")
        self.assertEqual(raised.exception.operation, ErrorOperation.READ)
        self.assertEqual(raised.exception.source, ErrorSource.REMOTE)

        settings_preface = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.INITIATOR,
            tie_breaker_nonce=0,
            min_proto=1,
            max_proto=1,
            capabilities=0,
            settings=Settings(initial_max_data=123),
        )
        with self.assertRaises(ProtocolError) as raised:
            zmux.read_preface(BytesIO(settings_preface.marshal()[:-1]))
        self.assertEqual(str(raised.exception), "truncated settings_tlv")

        low_limits = zmux.Preface(
            preface_version=zmux.PREFACE_VERSION,
            role=Role.RESPONDER,
            tie_breaker_nonce=0,
            min_proto=1,
            max_proto=1,
            capabilities=0,
            settings=Settings(max_frame_payload=1),
        )
        with self.assertRaises(ProtocolError) as raised:
            zmux.negotiate_prefaces(valid, low_limits)
        self.assertEqual(str(raised.exception), "receive limits below compatibility floor")

    def test_frame_codec_round_trip_and_wire_examples(self) -> None:
        data = zmux.Frame(FrameType.DATA, 4, 0, b"hi")
        encoded = data.marshal()

        self.assertEqual(encoded.hex(), "0401046869")
        self.assertIn("payload_length=2", repr(data))
        self.assertNotIn("payload=b", repr(data))
        self.assertEqual(data.encoded_len(), len(encoded))
        self.assertEqual(zmux.marshal_frame(data), encoded)
        appended = bytearray(b"prefix")
        data.append_to(appended)
        self.assertEqual(bytes(appended), b"prefix" + encoded)

        class FailingExtend(bytearray):
            def extend(self, payload) -> None:
                super().extend(memoryview(payload)[:1])
                raise RuntimeError("boom")

        rollback_target = FailingExtend(b"prefix")
        with self.assertRaises(RuntimeError):
            data.append_to(rollback_target)
        self.assertEqual(bytes(rollback_target), b"prefix")

        frame_writer = BytesIO()
        zmux.write_frame(frame_writer, data)
        self.assertEqual(frame_writer.getvalue(), encoded)
        with self.assertRaises(FrameSizeError) as write_limit_raised:
            zmux.write_frame(
                BytesIO(),
                data,
                zmux.Limits(
                    max_frame_payload=1,
                    max_control_payload_bytes=8,
                    max_extension_payload_bytes=8,
                ),
            )
        self.assertEqual(write_limit_raised.exception.operation, ErrorOperation.WRITE)
        self.assertEqual(write_limit_raised.exception.source, ErrorSource.LOCAL)
        self.assertEqual(write_limit_raised.exception.direction, ErrorDirection.WRITE)

        class PartialWriter(object):
            def __init__(self) -> None:
                self.chunks = []

            def write(self, payload) -> int:
                chunk = bytes(memoryview(payload)[:1])
                self.chunks.append(chunk)
                return len(chunk)

        partial_writer = PartialWriter()
        zmux.write_frame(partial_writer, data)
        self.assertEqual(b"".join(partial_writer.chunks), encoded)

        class StalledWriter(object):
            def write(self, payload) -> int:
                return 0

        with self.assertRaises(zmux.TransportError) as stalled_raised:
            zmux.write_frame(StalledWriter(), data)
        self.assertEqual(stalled_raised.exception.operation, ErrorOperation.WRITE)
        self.assertEqual(stalled_raised.exception.source, ErrorSource.TRANSPORT)
        self.assertEqual(stalled_raised.exception.direction, ErrorDirection.WRITE)

        class NoneWriter(object):
            def write(self, payload):
                return None

        with self.assertRaises(zmux.TransportError):
            zmux.write_frame(NoneWriter(), data)
        with self.assertRaises(TypeError):
            zmux.write_frame(frame_writer, object())
        parsed, consumed = zmux.parse_frame(encoded + b"tail")
        self.assertEqual(parsed, data)
        self.assertEqual(consumed, len(encoded))
        view, view_consumed = zmux.parse_frame_view(encoded)
        self.assertEqual(view.to_owned(), data)
        self.assertIn("payload_length=2", repr(view))
        self.assertEqual(view.encoded_len(), len(encoded))
        self.assertEqual(view.payload.tobytes(), b"hi")
        self.assertEqual(view_consumed, len(encoded))
        self.assertEqual(zmux.read_frame(BytesIO(encoded)), data)

        class ChunkedReadInto(BytesIO):
            def __init__(self, payload: bytes) -> None:
                super().__init__(payload)
                self.readinto_calls = 0

            def readinto(self, buffer) -> int:
                self.readinto_calls += 1
                return super().readinto(memoryview(buffer)[:1])

        chunked = ChunkedReadInto(encoded)
        self.assertEqual(zmux.read_frame(chunked), data)
        self.assertGreater(chunked.readinto_calls, 1)

        class BoolProgressReadInto(object):
            def readinto(self, view) -> bool:
                return True

        with self.assertRaises(zmux.TransportError):
            zmux.read_frame(BoolProgressReadInto())

        with self.assertRaises(ProtocolError) as raised:
            zmux.read_frame(BytesIO(bytes([0x0C, 0x01, 0x40, 0x01])), zmux.Limits(1, 8, 8))
        self.assertIn("non-canonical varint62", str(raised.exception))

        with self.assertRaises(FrameSizeError):
            zmux.parse_frame(encoded[:-1])

        class FailingRead(BytesIO):
            def read(self, size=-1):
                raise TimeoutError("late")

            def readinto(self, buffer):
                raise TimeoutError("late")

        with self.assertRaises(zmux.TransportError) as transport_raised:
            zmux.read_frame(FailingRead(encoded))
        self.assertEqual(transport_raised.exception.source, ErrorSource.TRANSPORT)
        self.assertEqual(transport_raised.exception.operation, ErrorOperation.READ)
        self.assertTrue(zmux.timeout(transport_raised.exception))

        with self.assertRaises(zmux.TransportError) as eof_raised:
            zmux.read_frame(BytesIO(b""))
        self.assertEqual(eof_raised.exception.source, ErrorSource.TRANSPORT)
        self.assertEqual(eof_raised.exception.operation, ErrorOperation.READ)
        self.assertIsInstance(eof_raised.exception.source_error, EOFError)

        with self.assertRaises(ProtocolError) as truncated_len:
            zmux.read_frame(BytesIO(b"\x40"))
        self.assertEqual(str(truncated_len.exception), "truncated varint62")
        self.assertEqual(truncated_len.exception.source, ErrorSource.REMOTE)

        ping = zmux.Frame(FrameType.PING, 0, 0, b"12345678")
        self.assertEqual(zmux.parse_frame(ping.marshal())[0], ping)

        cached = bytearray()
        packed_stream_id, packed_len = pack_varint(4)
        append_frame_header_trusted_cached_stream_id(
            cached,
            int(FrameType.DATA),
            4,
            packed_stream_id,
            packed_len,
            2,
        )
        self.assertEqual(bytes(cached), encoded[:-2])

        fallback = bytearray()
        append_frame_header_trusted_cached_stream_id(
            fallback,
            int(FrameType.DATA),
            4,
            0,
            0,
            2,
        )
        self.assertEqual(fallback, cached)

    def test_frame_limits_flags_scope_and_varint_payloads(self) -> None:
        small_limits = zmux.Limits(
            max_frame_payload=1,
            max_control_payload_bytes=8,
            max_extension_payload_bytes=8,
        )
        with self.assertRaises(FrameSizeError):
            zmux.parse_frame(zmux.Frame(FrameType.DATA, 4, 0, b"hi").marshal(), small_limits)

        with self.assertRaises(ProtocolError) as raised:
            zmux.Frame(FrameType.PING, 0, zmux.FRAME_FLAG_FIN, b"12345678").marshal()
        self.assertEqual(str(raised.exception), "invalid flags for frame type")

        with self.assertRaises(ProtocolError) as raised:
            zmux.Frame(FrameType.DATA, 0, 0, b"x").marshal()
        self.assertEqual(str(raised.exception), "DATA requires non-zero stream_id")

        max_data = zmux.Frame(FrameType.MAX_DATA, 0, 0, encode_varint(10))
        max_data.validate()
        with self.assertRaises(ProtocolError) as raised:
            zmux.Frame(FrameType.MAX_DATA, 0, 0, encode_varint(10) + b"x").validate()
        self.assertEqual(str(raised.exception), "MAX_DATA payload has trailing bytes")

        with self.assertRaises(FrameSizeError):
            zmux.Frame(FrameType.PONG, 0, 0, b"short").validate()

        self.assertEqual(
            zmux.inbound_payload_limit(FrameType.EXT, zmux.Limits(1, 2, 3)),
            3,
        )
        self.assertEqual(zmux.normalize_limits(zmux.Limits(0, 2, 0)).max_frame_payload, 16384)
        self.assertEqual(
            max_inbound_frame_len(zmux.Limits(zmux.MAX_VARINT62, 1, 1)),
            zmux.MAX_VARINT62,
        )
        with self.assertRaises(TypeError):
            frame_length_for_payload(True, 1)
        with self.assertRaises(FrameSizeError):
            frame_length_for_payload(0, 0)

    def test_frame_open_metadata_validation(self) -> None:
        metadata = bytearray()
        append_tlv(metadata, 1, encode_varint(3))
        payload = encode_varint(len(metadata)) + bytes(metadata) + b"app"
        frame = zmux.Frame(
            FrameType.DATA,
            4,
            zmux.FRAME_FLAG_OPEN_METADATA,
            payload,
        )
        frame.validate()
        self.assertEqual(zmux.parse_frame(frame.marshal())[0], frame)

        bad = zmux.Frame(
            FrameType.DATA,
            4,
            zmux.FRAME_FLAG_OPEN_METADATA,
            encode_varint(10) + b"\x01\x00",
        )
        with self.assertRaises(FrameSizeError):
            bad.validate()

    def test_frame_control_goaway_and_ext_payload_validation(self) -> None:
        diag = bytearray()
        append_tlv(diag, 1, b"bye")
        reset = zmux.Frame(
            FrameType.RESET,
            4,
            0,
            encode_varint(int(ErrorCode.CANCELLED)) + bytes(diag),
        )
        reset.validate()
        self.assertEqual(zmux.parse_frame(reset.marshal())[0], reset)

        goaway_payload = (
                encode_varint(4)
                + encode_varint(8)
                + encode_varint(int(ErrorCode.NO_ERROR))
                + bytes(diag)
        )
        goaway = zmux.Frame(FrameType.GOAWAY, 0, 0, goaway_payload)
        goaway.validate()

        with self.assertRaises(FrameSizeError):
            zmux.Frame(FrameType.GOAWAY, 0, 0, encode_varint(1)).validate()

        priority_update = zmux.Frame(
            FrameType.EXT,
            4,
            0,
            encode_varint(EXT_PRIORITY_UPDATE),
        )
        priority_update.validate()
        with self.assertRaises(ProtocolError):
            zmux.Frame(FrameType.EXT, 0, 0, encode_varint(EXT_PRIORITY_UPDATE)).validate()

        with self.assertRaises(ProtocolError) as raised:
            zmux.parse_frame(bytes.fromhex("021f00"))
        self.assertEqual(str(raised.exception), "invalid frame type")

    def test_payload_open_metadata_and_priority_update_round_trip(self) -> None:
        caps = int(
            Capability.OPEN_METADATA
            | Capability.PRIORITY_HINTS
            | Capability.STREAM_GROUPS
            | Capability.PRIORITY_UPDATE
        )
        prefix = zmux.build_open_metadata_prefix(
            caps,
            priority=7,
            group=9,
            open_info=b"ssh",
            max_frame_payload=1024,
        )
        parsed = zmux.parse_data_payload(prefix + b"app", zmux.FRAME_FLAG_OPEN_METADATA)

        self.assertTrue(parsed.has_metadata)
        self.assertTrue(parsed.metadata_valid)
        self.assertIn("app_data_length=3", repr(parsed))
        self.assertNotIn("app_data=b", repr(parsed))
        self.assertIn("open_info_length=3", repr(parsed.metadata))
        self.assertNotIn("open_info=b", repr(parsed.metadata))
        self.assertEqual(parsed.metadata.priority, 7)
        self.assertEqual(parsed.metadata.group, 9)
        self.assertEqual(parsed.open_info, b"ssh")
        self.assertTrue(parsed.metadata.has_open_info)
        self.assertEqual(parsed.app_data, b"app")

        priority_only = zmux.build_open_metadata_prefix(
            caps,
            priority=2,
            max_frame_payload=1024,
        )
        self.assertEqual(priority_only, bytes.fromhex("03010102"))

        open_info_source = bytearray(b"ssh")
        copied_prefix = zmux.build_open_metadata_prefix(
            caps,
            open_info=memoryview(open_info_source),
            max_frame_payload=1024,
        )
        open_info_source[:] = b"bad"
        copied = zmux.parse_data_payload(copied_prefix, zmux.FRAME_FLAG_OPEN_METADATA)
        self.assertEqual(copied.open_info, b"ssh")

        update = zmux.MetadataUpdate(priority=5, group=11)
        update_payload = zmux.build_priority_update_payload(caps, update, 1024)
        update_meta, valid = zmux.parse_priority_update_payload(update_payload)
        self.assertTrue(valid)
        self.assertEqual(update_meta.priority, 5)
        self.assertEqual(update_meta.group, 11)

        duplicate_update = bytearray()
        duplicate_update.extend(encode_varint(zmux.EXT_PRIORITY_UPDATE))
        append_tlv(duplicate_update, zmux.METADATA_STREAM_PRIORITY, encode_varint(1))
        append_tlv(duplicate_update, zmux.METADATA_STREAM_PRIORITY, encode_varint(2))
        _, valid = zmux.parse_priority_update_payload(duplicate_update)
        self.assertFalse(valid)
        malformed_duplicate_update = bytearray(duplicate_update)
        malformed_duplicate_update.extend(b"\x40\x01\x00")
        _, valid = zmux.parse_priority_update_payload(malformed_duplicate_update)
        self.assertFalse(valid)

        with self.assertRaises(ProtocolError):
            zmux.build_open_metadata_prefix(0, open_info=b"ssh", max_frame_payload=1024)
        with self.assertRaises(ProtocolError):
            zmux.build_priority_update_payload(caps, zmux.MetadataUpdate(), 1024)
        with self.assertRaises(ProtocolError):
            zmux.build_priority_update_payload(
                int(Capability.PRIORITY_HINTS),
                zmux.MetadataUpdate(priority=1),
                1024,
            )
        with self.assertRaises(TypeError):
            zmux.build_open_metadata_prefix(caps, priority=1, max_frame_payload=True)
        with self.assertRaises(TypeError):
            zmux.build_open_metadata_prefix(True)
        with self.assertRaises(ValueError):
            zmux.build_open_metadata_prefix(caps, priority=1, max_frame_payload=-1)
        with self.assertRaises(ValueError):
            zmux.build_priority_update_payload(
                caps,
                zmux.MetadataUpdate(priority=1),
                zmux.MAX_VARINT62 + 1,
            )

        duplicate = bytearray()
        append_tlv(duplicate, METADATA_OPEN_INFO, b"a")
        append_tlv(duplicate, METADATA_OPEN_INFO, b"b")
        duplicate_payload = encode_varint(len(duplicate)) + bytes(duplicate)
        parsed = zmux.parse_data_payload(duplicate_payload, zmux.FRAME_FLAG_OPEN_METADATA)
        self.assertTrue(parsed.has_metadata)
        self.assertFalse(parsed.metadata_valid)
        self.assertEqual(parsed.app_data, b"")

        plain = zmux.parse_data_payload(b"app", 0)
        self.assertFalse(plain.has_metadata)
        self.assertFalse(plain.metadata_valid)
        self.assertEqual(plain.app_data, b"app")
        with self.assertRaises(TypeError):
            zmux.DataPayload(metadata_valid=1)
        with self.assertRaises(TypeError):
            zmux.DataPayloadView(has_metadata=1)
        with self.assertRaises(TypeError):
            zmux.StreamMetadata(open_info=3)

    def test_payload_data_view_and_metadata_offset(self) -> None:
        from zmux._wire.payload import parse_priority_update_metadata

        caps = int(Capability.OPEN_METADATA | Capability.PRIORITY_HINTS)
        raw = bytearray(
            zmux.build_open_metadata_prefix(
                caps,
                priority=7,
                open_info=b"ssh",
                max_frame_payload=1024,
            )
            + b"payload"
        )

        view = zmux.parse_data_payload_view(raw, zmux.FRAME_FLAG_OPEN_METADATA)
        self.assertTrue(view.has_metadata)
        self.assertTrue(view.metadata_valid)
        self.assertIn("app_data_length=7", repr(view))
        self.assertIn("open_info_length=3", repr(view.metadata))
        self.assertEqual(view.metadata.priority, 7)
        self.assertEqual(view.open_info.tobytes(), b"ssh")
        self.assertTrue(view.metadata.has_open_info)
        self.assertEqual(view.app_data.tobytes(), b"payload")

        owned = zmux.parse_data_payload(raw, zmux.FRAME_FLAG_OPEN_METADATA)
        raw[raw.index(ord("s"))] = ord("S")
        self.assertEqual(view.open_info.tobytes(), b"Ssh")
        self.assertEqual(owned.open_info, b"ssh")
        self.assertEqual(owned.app_data, b"payload")

        app_offset = len(raw) - len(b"payload")
        raw[app_offset] = ord("P")
        self.assertEqual(view.app_data.tobytes(), b"Payload")
        self.assertEqual(owned.app_data, b"payload")

        metadata, valid, offset = zmux.parse_data_payload_metadata_offset(
            raw, zmux.FRAME_FLAG_OPEN_METADATA
        )
        self.assertTrue(valid)
        self.assertEqual(metadata.priority, 7)
        self.assertEqual(metadata.open_info, b"Ssh")
        self.assertEqual(offset, app_offset)

        duplicate = bytearray()
        append_tlv(duplicate, zmux.METADATA_STREAM_PRIORITY, encode_varint(1))
        append_tlv(duplicate, zmux.METADATA_STREAM_PRIORITY, encode_varint(2))
        metadata_view, valid = zmux.parse_stream_metadata_bytes_view(duplicate)
        self.assertFalse(valid)
        self.assertTrue(metadata_view.is_empty())
        malformed_duplicate = bytearray(duplicate)
        malformed_duplicate.extend(b"\x40\x01\x00")
        metadata_view, valid = zmux.parse_stream_metadata_bytes_view(malformed_duplicate)
        self.assertFalse(valid)
        self.assertTrue(metadata_view.is_empty())

        malformed_owned_payload = (
                encode_varint(len(malformed_duplicate)) + bytes(malformed_duplicate)
        )
        with self.assertRaises(ProtocolError):
            zmux.parse_data_payload(
                malformed_owned_payload,
                zmux.FRAME_FLAG_OPEN_METADATA,
            )

        duplicate_payload = encode_varint(len(duplicate)) + bytes(duplicate) + b"app"
        data_view = zmux.parse_data_payload_view(
            duplicate_payload, zmux.FRAME_FLAG_OPEN_METADATA
        )
        self.assertTrue(data_view.has_metadata)
        self.assertFalse(data_view.metadata_valid)
        self.assertEqual(data_view.app_data.tobytes(), b"app")

        priority_metadata = bytearray()
        append_tlv(priority_metadata, zmux.METADATA_STREAM_PRIORITY, encode_varint(3))
        parsed_priority, valid = parse_priority_update_metadata(priority_metadata)
        self.assertTrue(valid)
        self.assertEqual(parsed_priority.priority, 3)

    def test_payload_goaway_error_and_diag_reason(self) -> None:
        goaway = zmux.build_go_away_payload(4, 8, int(ErrorCode.NO_ERROR), "done")
        parsed = zmux.parse_go_away_payload(goaway)
        self.assertEqual(parsed.last_accepted_bidi, 4)
        self.assertEqual(parsed.last_accepted_uni, 8)
        self.assertEqual(parsed.code, int(ErrorCode.NO_ERROR))
        self.assertEqual(parsed.reason, "done")

        error_payload = zmux.build_error_payload(int(ErrorCode.INTERNAL), "abcdef", 5)
        code_value, reason_text = zmux.parse_error_payload(error_payload)
        self.assertEqual(code_value, int(ErrorCode.INTERNAL))
        self.assertLessEqual(len(error_payload), 5)
        self.assertIn(reason_text, ("", "a", "ab"))

        growth_reason = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        growth_payload = zmux.build_error_payload(
            int(ErrorCode.INTERNAL),
            growth_reason,
            66,
        )
        self.assertEqual(len(growth_payload), 66)
        self.assertEqual(zmux.parse_error_payload(growth_payload)[1], growth_reason[:63])

        diag = bytearray()
        append_tlv(diag, 1, "€€".encode("utf-8"))
        self.assertEqual(zmux.parse_diag_reason(diag), "€€")

        duplicate_diag = bytearray()
        append_tlv(duplicate_diag, 1, b"a")
        append_tlv(duplicate_diag, 1, b"b")
        self.assertEqual(zmux.parse_diag_reason(duplicate_diag), "")
        malformed_duplicate_diag = bytearray(duplicate_diag)
        malformed_duplicate_diag.extend(b"\x40\x01\x00")
        self.assertEqual(zmux.parse_diag_reason(malformed_duplicate_diag), "")

        invalid_utf8 = bytearray()
        append_tlv(invalid_utf8, 1, b"\xff")
        self.assertEqual(zmux.parse_diag_reason(invalid_utf8), "")

        capped = zmux.build_error_payload(int(ErrorCode.INTERNAL), "€€", 7)
        self.assertLessEqual(len(capped), 7)
        self.assertEqual(zmux.parse_error_payload(capped)[1], "€")

        exact_boundary = zmux.build_error_payload(int(ErrorCode.INTERNAL), "€€", 6)
        self.assertEqual(len(exact_boundary), 6)
        self.assertEqual(zmux.parse_error_payload(exact_boundary)[1], "€")

        tight_boundary = zmux.build_error_payload(int(ErrorCode.INTERNAL), "€€", 5)
        self.assertLessEqual(len(tight_boundary), 5)
        self.assertEqual(zmux.parse_error_payload(tight_boundary)[1], "")

        invalid_reason = "\ud800"
        self.assertEqual(
            zmux.parse_error_payload(
                zmux.build_error_payload(int(ErrorCode.INTERNAL), invalid_reason, 64)
            )[1],
            "",
        )
        self.assertEqual(
            zmux.parse_go_away_payload(
                zmux.build_go_away_payload(1, 2, int(ErrorCode.INTERNAL), invalid_reason)
            ).reason,
            "",
        )
        with self.assertRaises(TypeError):
            zmux.build_error_payload(int(ErrorCode.INTERNAL), b"bytes are not text", 64)
        with self.assertRaises(TypeError):
            zmux.build_error_payload(int(ErrorCode.INTERNAL), 0, 64)
        with self.assertRaises(TypeError):
            zmux.build_go_away_payload(1, 2, int(ErrorCode.INTERNAL), object())
        with self.assertRaises(TypeError):
            zmux.GoAwayPayload(1, 2, int(ErrorCode.INTERNAL), object())
        with self.assertRaises(ValueError):
            zmux.build_error_payload(int(ErrorCode.INTERNAL), "reason", -1)
        with self.assertRaises(TypeError):
            zmux.build_error_payload(int(ErrorCode.INTERNAL), "reason", True)
        self.assertEqual(
            zmux.build_error_payload(int(ErrorCode.INTERNAL), "reason", 0),
            encode_varint(int(ErrorCode.INTERNAL)),
        )
        capped_goaway = zmux.build_go_away_payload(4, 8, 7, "reason", max_payload=0)
        self.assertEqual(zmux.parse_go_away_payload(capped_goaway).reason, "")
        with self.assertRaises(TypeError):
            zmux.build_go_away_payload(4, 8, 7, "reason", max_payload=True)

    def test_varint62_round_trip_uses_canonical_length(self) -> None:
        cases = (
            (0, 1, "00"),
            (63, 1, "3f"),
            (64, 2, "4040"),
            (16383, 2, "7fff"),
            (16384, 4, "80004000"),
            (1073741823, 4, "bfffffff"),
            (1073741824, 8, "c000000040000000"),
            ((1 << 62) - 1, 8, "ffffffffffffffff"),
        )
        for value, length, hex_encoded in cases:
            encoded = encode_varint(value)
            self.assertEqual(encoded.hex(), hex_encoded)
            self.assertEqual(len(encoded), length)
            self.assertEqual(parse_varint(encoded), (value, length))
            self.assertEqual(read_varint(BytesIO(encoded)), (value, length))
            appended = bytearray(b"\xaa")
            append_varint(appended, value)
            self.assertEqual(bytes(appended[1:]), encoded)
            packed, packed_len = pack_varint(value)
            packed_dst = bytearray()
            append_packed_varint(packed_dst, packed, packed_len)
            self.assertEqual(bytes(packed_dst), encoded)

        class BytesLikeRead(object):
            def __init__(self, chunks) -> None:
                self.chunks = list(chunks)

            def read(self, size=-1):
                return self.chunks.pop(0) if self.chunks else b""

        self.assertEqual(read_varint(BytesLikeRead([bytearray(b"\x40"), bytearray(b"\x40")])), (64, 2))
        self.assertEqual(read_varint(BytesLikeRead([memoryview(b"\x40"), memoryview(b"\x40")])), (64, 2))

    def test_varint62_rejects_invalid_inputs(self) -> None:
        for raw in (b"", b"\x40", b"\x80\x00\x00"):
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError) as raised:
                    parse_varint(raw)
                self.assertEqual(str(raised.exception), "truncated varint62")
                self.assertEqual(raised.exception.scope, ErrorScope.SESSION)
                self.assertEqual(raised.exception.operation, ErrorOperation.READ)
                self.assertEqual(raised.exception.source, ErrorSource.REMOTE)
                self.assertEqual(raised.exception.direction, ErrorDirection.READ)

        for raw in (b"\x40\x01", b"\x80\x00\x00\x01"):
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError) as raised:
                    parse_varint(raw)
                self.assertEqual(str(raised.exception), "non-canonical varint62")

        with self.assertRaises(ProtocolError):
            encode_varint(1 << 62)

        dst = bytearray(b"\xaa")
        with self.assertRaises(ProtocolError):
            append_varint(dst, zmux.MAX_VARINT62 + 1)
        self.assertEqual(dst, bytearray(b"\xaa"))

        with self.assertRaises(TypeError):
            encode_varint(True)
        with self.assertRaises(TypeError):
            varint_len(1.0)
        with self.assertRaises(TypeError):
            encoded_len_from_first(True)
        with self.assertRaises(TypeError):
            parse_varint(b"\x00", True)
        with self.assertRaises(TypeError):
            validate_decoded_varint(1, True)
        with self.assertRaises(ValueError):
            append_packed_varint(bytearray(), 256, 1)

        class FailingList(list):
            def extend(self, values):
                for value in values:
                    super().append(value)
                    raise RuntimeError("synthetic extend failure")

        failing_varint = FailingList([0xAA])
        with self.assertRaises(RuntimeError):
            append_varint(failing_varint, 64)
        self.assertEqual(failing_varint, [0xAA])

        failing_packed = FailingList([0xAA])
        packed, packed_len = pack_varint(16384)
        with self.assertRaises(RuntimeError):
            append_packed_varint(failing_packed, packed, packed_len)
        self.assertEqual(failing_packed, [0xAA])

        with self.assertRaises(ProtocolError) as raised:
            read_varint(BytesIO(b"\x40"))
        self.assertEqual(str(raised.exception), "truncated varint62")
        self.assertEqual(raised.exception.source, ErrorSource.REMOTE)

        class FailingRead(BytesIO):
            def read(self, size=-1):
                raise TimeoutError("late")

        with self.assertRaises(zmux.TransportError) as transport_raised:
            read_varint(FailingRead())
        self.assertEqual(transport_raised.exception.source, ErrorSource.TRANSPORT)
        self.assertEqual(transport_raised.exception.operation, ErrorOperation.READ)
        self.assertTrue(zmux.timeout(transport_raised.exception))

        class InvalidRead(object):
            def read(self, size=-1):
                return True

        with self.assertRaises(zmux.TransportError):
            read_varint(InvalidRead())

        class OverRead(object):
            def read(self, size=-1):
                return b"\x00\x00"

        with self.assertRaises(zmux.TransportError):
            read_varint(OverRead())

        self.assertEqual(parse_varint(b"xx\x40\x40yy", 2, 4), (64, 2))
        with self.assertRaises(IndexError):
            parse_varint(b"\x00", 0, 2)
        with self.assertRaises(IndexError):
            parse_varint(b"\x00", 1, 0)

    def test_varint62_encode_into_checks_destination(self) -> None:
        dst = bytearray(b"\xaa\xaa\xaa\xaa")
        self.assertEqual(encode_varint_into(dst, 0, 16384), 4)
        self.assertEqual(dst, bytearray.fromhex("80004000"))
        short = bytearray(b"\xaa")
        with self.assertRaises(FrameSizeError):
            encode_varint_into(short, 0, 64)
        self.assertEqual(short, bytearray(b"\xaa"))
        with self.assertRaises(ProtocolError):
            encode_varint_into(short, 0, zmux.MAX_VARINT62 + 1)
        self.assertEqual(short, bytearray(b"\xaa"))
        with self.assertRaises(FrameSizeError):
            encode_varint_into(short, -1, 1)
        self.assertEqual(short, bytearray(b"\xaa"))

    def test_tlv_round_trip_and_view(self) -> None:
        raw = bytearray()
        append_tlv(raw, 7, b"abcd")
        append_tlv(raw, 7, b"")
        append_tlv(raw, 8, None)
        self.assertEqual(raw.hex(), "07046162636407000800")

        self.assertEqual(raw[-2:].hex(), "0800")
        validate_tlvs(raw)
        self.assertEqual(parse_tlvs(memoryview(raw))[0].value, b"abcd")

        views = parse_tlvs_view(raw)
        self.assertEqual(len(views), 3)
        self.assertEqual(views[0].typ, 7)
        self.assertEqual(views[0].value.tobytes(), b"abcd")
        self.assertFalse(views[0].is_empty())
        self.assertTrue(views[1].is_empty())

        owned = parse_tlvs(raw)
        self.assertEqual(owned, [Tlv(7, b"abcd"), Tlv(7, b""), Tlv(8, None)])
        self.assertEqual(encode_tlvs(owned), bytes(raw))
        self.assertEqual(
            [(item.typ, item.value.tobytes()) for item in iter_tlvs_view(raw)],
            [(7, b"abcd"), (7, b""), (8, b"")],
        )
        visited = []
        visit_tlvs(raw, lambda typ, value: visited.append((typ, value.tobytes())))
        self.assertEqual(visited, [(7, b"abcd"), (7, b""), (8, b"")])
        self.assertFalse(owned[0].is_empty())
        self.assertTrue(owned[1].is_empty())
        self.assertEqual(repr(owned[0]), "Tlv(typ=7, value_length=4)")
        self.assertEqual(repr(views[0]), "TlvView(typ=7, value_length=4)")
        self.assertEqual(views[0].to_owned(), owned[0])
        raw[2] = ord("A")
        self.assertEqual(views[0].value.tobytes(), b"Abcd")
        self.assertEqual(owned[0].value, b"abcd")
        self.assertEqual(TlvView(9, memoryview(b"hello")).encoded_len(), 7)
        self.assertEqual(tlv_encoded_len(9, 5), 7)
        validate_tlv_header(9, 5)
        self.assertEqual(tlv_parse_capacity_hint(0), 0)
        self.assertEqual(tlv_parse_capacity_hint(1), 0)
        self.assertEqual(tlv_parse_capacity_hint(2), 1)
        self.assertEqual(tlv_parse_capacity_hint(200), 64)

    def test_tlv_rejects_truncated_headers_and_value_overrun(self) -> None:
        for raw in (b"\x40", b"\x01\x40"):
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError) as raised:
                    parse_tlvs(raw)
                self.assertEqual(str(raised.exception), "truncated tlv")

        with self.assertRaises(ProtocolError) as raised:
            parse_tlvs(b"\x01\x02\xaa")
        self.assert_protocol_read_error(
            raised.exception, "tlv value overruns containing payload"
        )

        with self.assertRaises(ProtocolError) as raised:
            parse_tlvs(b"\x40\x01\x00")
        self.assertEqual(str(raised.exception), "non-canonical varint62")

        dst = bytearray(b"\xaa")
        before = bytes(dst)
        with self.assertRaises(ProtocolError):
            append_tlv(dst, zmux.MAX_VARINT62 + 1, b"x")
        self.assertEqual(bytes(dst), before)
        with self.assertRaises(TypeError):
            append_tlv(dst, 1, 1)
        self.assertEqual(bytes(dst), before)

        class FailingList(list):
            def extend(self, values):
                for value in values:
                    super().append(value)
                    raise RuntimeError("synthetic extend failure")

        failing_dst = FailingList([0xAA])
        with self.assertRaises(RuntimeError):
            append_tlv(failing_dst, 1, b"x")
        self.assertEqual(failing_dst, [0xAA])

        with self.assertRaises(ProtocolError):
            Tlv(zmux.MAX_VARINT62 + 1, b"x")
        with self.assertRaises(TypeError):
            Tlv(1, object())

        invalid_view = TlvView(zmux.MAX_VARINT62 + 1, memoryview(b"x"))
        with self.assertRaises(ProtocolError):
            invalid_view.validate()
        view_dst = bytearray(b"\xaa")
        with self.assertRaises(ProtocolError):
            invalid_view.append_to(view_dst)
        self.assertEqual(view_dst, bytearray(b"\xaa"))

        with self.assertRaises(TypeError):
            tlv_encoded_len(True, 0)
        with self.assertRaises(TypeError):
            tlv_encoded_len(1, True)
        with self.assertRaises(ValueError):
            tlv_encoded_len(1, -1)
        with self.assertRaises(TypeError):
            tlv_parse_capacity_hint(True)
        with self.assertRaises(ValueError):
            tlv_parse_capacity_hint(-1)
        with self.assertRaises(TypeError):
            parse_tlvs(None)


if __name__ == "__main__":
    unittest.main()
