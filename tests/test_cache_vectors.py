"""The shared carrier cache snapshot vectors (zmux-rs testdata/carrier-cache):
each case's steps restored in order into a new cache, then its snapshot
compared with the expected entries; and the JSON round trip."""

import datetime
import json
import pathlib
import re

import pytest
import zmux

VECTORS = (
    pathlib.Path(__file__).resolve().parents[2]
    / "zmux-rs"
    / "testdata"
    / "carrier-cache"
    / "vectors.json"
)

pytestmark = pytest.mark.skipif(
    not VECTORS.exists(), reason="zmux-rs checkout not beside this one"
)


def rfc3339(t: datetime.datetime) -> str:
    return (
        t.astimezone(datetime.UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def substitute(text: str, now: datetime.datetime) -> str:
    def at(m: re.Match[str]) -> str:
        n = int(m.group(2))
        return (
            '"'
            + rfc3339(now + datetime.timedelta(seconds=n if m.group(1) == "+" else -n))
            + '"'
        )

    return re.sub(r'"@([+-])(\d+)"', at, text)


def entries(
    cache: zmux.CarrierCache, now: datetime.datetime
) -> list[dict[str, object]]:
    def ahead(t: str | None) -> bool:
        return bool(t) and datetime.datetime.fromisoformat(t) > now  # type: ignore[arg-type]

    snap = json.loads(cache.snapshot())
    assert snap["version"] == 1
    out = [
        {
            "key": e["key"],
            "kind": e["kind"],
            "usable": ahead(e.get("good_until")),
            "failed": ahead(e.get("fail_until")),
            "backoff_ms": e.get("backoff_ms", 0),
            "url": e.get("url", ""),
        }
        for e in snap["entries"]
    ]
    return sorted(out, key=lambda e: (e["key"], e["kind"]))


def test_shared_vectors() -> None:
    vectors = json.loads(VECTORS.read_text())
    assert vectors["cases"] and vectors["exact"]
    for case in vectors["cases"]:
        now = datetime.datetime.now(datetime.UTC)
        cache = zmux.CarrierCache()
        for i, step in enumerate(case["steps"]):
            text = substitute(step["snapshot"], now)
            if step.get("error"):
                before = entries(cache, now)
                with pytest.raises(ValueError):
                    cache.restore(text)
                assert entries(cache, now) == before, f"{case['name']} step {i}"
            else:
                cache.restore(text)
        assert entries(cache, now) == case["expect"], case["name"]
        # The cache's own snapshot restores to the same entries.
        other = zmux.CarrierCache()
        other.restore(cache.snapshot())
        assert entries(other, now) == case["expect"], f"{case['name']} again"


def test_canonical_forms_restore() -> None:
    # The cache keeps times on the monotonic clock, so a snapshot's times
    # are not the restored text's to the nanosecond: the exact encoding is
    # the native type's (zmux-rs tests it); here each form restores, with
    # its live entries kept.
    vectors = json.loads(VECTORS.read_text())
    for text in vectors["exact"]:
        cache = zmux.CarrierCache()
        cache.restore(text)
        want = {(e["key"], e["kind"]) for e in json.loads(text)["entries"]}
        got = {(e["key"], e["kind"]) for e in json.loads(cache.snapshot())["entries"]}
        assert got == want


def test_malformed_snapshots() -> None:
    cache = zmux.CarrierCache()
    for bad in (
        "",
        "{",
        '{"version":2,"entries":[]}',
        '{"version":1,"entries":[{"key":1}]}',
    ):
        with pytest.raises(ValueError):
            cache.restore(bad)
