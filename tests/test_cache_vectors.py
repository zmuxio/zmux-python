"""Shared CarrierCache v2 vectors exercised through the native binding."""

import datetime
import json
from pathlib import Path
from typing import Any

import pytest
import zmux
from support import TEST_HOOKS, manual_clock

VECTORS = json.loads(
    (Path(__file__).parent / "testdata" / "carrier-cache" / "vectors.json").read_text()
)
KEY = tuple(VECTORS["default_key"])
ERRORS = {
    "unsupported-version": zmux.CarrierCacheVersionError,
    "malformed-snapshot": zmux.CarrierCacheFormatError,
    "invalid-value": zmux.CarrierCacheValueError,
}


def unix_ns(text: str) -> int:
    instant = datetime.datetime.fromisoformat(text)
    elapsed = instant - datetime.datetime.fromtimestamp(0, tz=datetime.UTC)
    return (
        elapsed.days * 86400 + elapsed.seconds
    ) * 10**9 + elapsed.microseconds * 1000


class CacheVector:
    def __init__(self, wall_at: str, backoff: dict[str, float] | None = None) -> None:
        self.clock = manual_clock()
        self.wall = zmux.WallClock(unix_ns(wall_at))
        self.base = self.clock.domain.now()
        self.wall_start = self.wall.timestamp_ns
        self.backoff = (
            None
            if backoff is None
            else zmux.Backoff(
                backoff["min_ms"] / 1000,
                max=backoff["max_ms"] / 1000,
                jitter=backoff["jitter_down"],
                jitter_up=backoff["jitter_up"],
            )
        )
        self.saved: dict[str, bytes] = {}
        self.restart()

    def restart(self) -> None:
        self.cache = zmux.CarrierCache(
            clock_domain=self.clock.domain, wall_clock=self.wall, backoff=self.backoff
        )
        self.sources: dict[tuple[str, str, str], zmux.CarrierReportSource] = {}
        self.sequence = 0

    def run(
        self, steps: list[dict[str, Any]], expected: dict[str, Any] | None = None
    ) -> None:
        for step in steps:
            key, kind, variant = step.get("key", KEY)
            identity = (key, kind, variant)
            match step["op"]:
                case "advance":
                    elapsed = step["ns"]
                    self.clock.advance(elapsed / 1e9)
                    self.wall.set(self.wall.timestamp_ns + elapsed)
                case "report":
                    if identity not in self.sources:
                        self.sources[identity] = self.cache.register_report_source(
                            key, kind=kind, variant=variant
                        )
                    at = step.get("at")
                    sample = zmux.CarrierObservation(
                        at=None
                        if at is None
                        else self.base + (unix_ns(at) - self.wall_start) / 1e9,
                        rtt=step.get("rtt_ns", 0) / 1e9,
                        rate=step.get("rate_bytes_per_second", 0),
                    )
                    self.sequence += 1
                    assert self.cache.report(
                        self.sources[identity],
                        sequence=self.sequence,
                        outcome=step["outcome"],
                        observation=sample,
                    )
                case "score":
                    score = self.cache.score(key, kind=kind, variant=variant)
                    want = step["expect"] if expected is None else expected[step["as"]]
                    score_fields(score, want)
                case "restart":
                    self.restart()
                case "save":
                    self.saved[step["as"]] = self.cache.export()
                case "import":
                    data = (
                        step["json"].encode()
                        if "json" in step
                        else self.saved[step["from"]]
                    )
                    if "error" in step:
                        with pytest.raises(ERRORS[step["error"]]):
                            self.cache.import_snapshot(data)
                    else:
                        self.cache.import_snapshot(data)
                case "assert-export":
                    exported = self.cache.export()
                    if "same_as" in step:
                        assert exported == self.saved[step["same_as"]]
                    else:
                        entries = json.loads(exported)["entries"]
                        assert [
                            [r["key"], r["kind"], r["variant"]] for r in entries
                        ] == step["key_order"]
                case other:
                    raise AssertionError(other)


def score_fields(score: zmux.CarrierScore, want: dict[str, Any]) -> None:
    for field, value in want.items():
        if field == "cooling":
            assert (score.cooldown is not None) == value
        elif field == "remaining_ms":
            cooldown = score.cooldown
            remaining = 0 if cooldown is None else cooldown.remaining
            assert remaining * 1000 == pytest.approx(value)
        elif field == "age_ns":
            # The shared numeric vectors use 0 even when history is absent.
            assert (score.age or 0) == value / 1e9
        elif isinstance(value, float):
            assert getattr(score, field) == pytest.approx(value, abs=1e-10, rel=0)
        else:
            assert getattr(score, field) == value


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_next_batch_h_shared_cache_vectors(case: dict[str, Any]) -> None:
    run = CacheVector(VECTORS["clock_start"], case.get("backoff"))
    run.run(case["steps"])


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
@pytest.mark.parametrize("case", VECTORS["snapshots"], ids=lambda case: case["name"])
def test_next_batch_h_cache_snapshot_clock_rollback(case: dict[str, Any]) -> None:
    exporter = CacheVector(VECTORS["clock_start"])
    exporter.run(case["exporter"])
    importer = CacheVector(case["import_at"])
    importer.cache.import_snapshot(exporter.cache.export())
    importer.run(case["importer"], case["expected"])


def test_next_batch_h_cache_report_replay_and_snapshot_order() -> None:
    cache = zmux.CarrierCache()
    for key, kind, variant in (
        ("z", "quic", "v"),
        ("a", "streaming", "z"),
        ("a", "streaming", "a"),
        ("a", "quic", ""),
    ):
        source = cache.register_report_source(key, kind=kind, variant=variant)
        assert cache.report(source, sequence=1, outcome=zmux.CacheOutcome.FAILED)
        assert not cache.report(source, sequence=1, outcome=zmux.CacheOutcome.USABLE)
        score = cache.score(key, kind=kind, variant=variant)
        assert score.attempts == 1 and score.cooldown is not None
    exported = cache.export()
    entries = json.loads(exported)["entries"]
    keys = [(row["key"], row["kind"], row["variant"]) for row in entries]
    assert keys == sorted(keys)
    restored = zmux.CarrierCache()
    restored.import_snapshot(exported)
    retry = restored.score("z", kind="quic", variant="v").cooldown
    assert retry is not None
    restored.import_snapshot(exported)
    replay = restored.score("z", kind="quic", variant="v").cooldown
    assert replay is not None and retry.retry_at == replay.retry_at


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
def test_next_batch_h_imports_go_cache_snapshot() -> None:
    data = (
        Path(__file__).parent / "testdata" / "carrier-cache" / "go-v2.json"
    ).read_bytes()
    run = CacheVector(
        "2027-01-15T08:00:02Z",
        {"min_ms": 30000, "max_ms": 1800000, "jitter_down": 0, "jitter_up": 0},
    )
    run.cache.import_snapshot(data)
    score = run.cache.score("shared", kind="streaming", variant="go")
    assert score.attempts == 1 and score.age == 2
    assert score.cooldown is not None and score.cooldown.remaining == 28
    assert run.cache.score("first", kind="quic").attempts == 1
    run.cache.import_snapshot(data)
    assert run.cache.score("shared", kind="streaming", variant="go") == score
    entries = json.loads(run.cache.export())["entries"]
    assert [row["key"] for row in entries] == ["first", "shared"]


@pytest.mark.skipif(not TEST_HOOKS, reason="needs a native monotonic clock domain")
def test_cache_exposes_each_measurement_and_its_original_validity() -> None:
    run = CacheVector(VECTORS["clock_start"])
    key, kind, variant = KEY

    def score() -> zmux.CarrierScore:
        return run.cache.score(key, kind=kind, variant=variant)

    empty = score()
    assert empty.age is None
    assert empty.rtt is None
    assert empty.rate is None
    source = run.cache.register_report_source(key, kind=kind, variant=variant)
    assert run.cache.report(
        source,
        sequence=1,
        outcome=zmux.CacheOutcome.PERFORMANCE,
        observation=zmux.CarrierObservation(rtt=0.05, valid_for=5),
    )
    run.clock.advance(2)
    assert run.cache.report(
        source,
        sequence=2,
        outcome=zmux.CacheOutcome.PERFORMANCE,
        observation=zmux.CarrierObservation(rate=2_500_000),
    )
    reported = score()
    assert reported.age is None
    host = zmux.CarrierMeasurementSource.HOST_REPORT
    assert reported.rtt == zmux.CarrierMeasurement(0.05, 2, 5, host)
    assert reported.rate == zmux.CarrierMeasurement(2_500_000, 0, 60, host)
    snapshot = run.cache.export()
    run.restart()
    run.cache.import_snapshot(snapshot)
    run.clock.advance(3)
    expired = score()
    assert expired.rtt == zmux.CarrierMeasurement(0.05, 5, 5, None)
    assert expired.rate == zmux.CarrierMeasurement(2_500_000, 3, 60, None)
    assert expired.score < reported.score
    assert expired.post_window_seconds == 0
    source = run.cache.register_report_source(key, kind=kind, variant=variant)
    assert run.cache.report(
        source,
        sequence=1,
        outcome=zmux.CacheOutcome.LIFETIME,
        observation=zmux.CarrierObservation(duration=10),
    )
    assert score().post_window_seconds == pytest.approx(9.9983956643, rel=1e-8)
