"""The shared shaping vectors through the bindings: files load or fail with the listed error
class, handshake plans exist as listed and pool decisions keep the listed values in the
binding's units. The vectors' draws come from a source only the Rust tests can set, so here a
case whose steps draw nothing is compared in full, and one that draws is compared for which
fields are present."""

import json
import pathlib
from typing import Any

import pytest
import zmux

TESTDATA = pathlib.Path(__file__).parent / "testdata" / "shaping"
FORMAT = json.loads((TESTDATA / "format.json").read_text())
POOL = json.loads((TESTDATA / "pool_policy.json").read_text())
BUDGET = json.loads((TESTDATA / "budget.json").read_text())


def by_name(c: dict[str, Any]) -> str:
    return str(c["name"])


@pytest.mark.parametrize("case", FORMAT["bundles"], ids=by_name)
def test_bundle(case: dict[str, Any]) -> None:
    def load() -> Any:
        return zmux.ShapingBundle.from_json(
            case["bundle"],
            features=case["features"],
            allow_unshaped=case["allow_unshaped"],
        )

    if "error" in case:
        with pytest.raises(ValueError) as e:
            load()
        assert str(e.value).split(":")[0] == case["error"]
        return
    b = load()
    for kind, index in case["selected"].items():
        assert b.selected(kind) == index
    assert b.unshaped() == case["unshaped"]


@pytest.mark.parametrize("case", FORMAT["handshake"], ids=by_name)
def test_handshake_plans(case: dict[str, Any]) -> None:
    b = zmux.ShapingBundle.from_json(case["bundle"])
    for call in case["calls"]:
        plan = b.plan(case["kind"], call["handshake"], call["message"])
        assert (plan is None) == (call["plan"] is None), call


@pytest.mark.parametrize("case", BUDGET["parse"], ids=by_name)
def test_local_limits(case: dict[str, Any]) -> None:
    text = json.dumps(case["limits"])
    if "error" in case:
        with pytest.raises(ValueError) as e:
            zmux.shaping_limits_from_json(text)
        assert str(e.value).split(":")[0] == case["error"]
        return
    got = zmux.shaping_limits_from_json(text)
    want = case["want"]
    w = want["wire"]
    assert got.wire == zmux.ShapingAccount(
        initial=w["initial"], per_mb=w["per_mb"], per_sec=w["per_sec"]
    )
    us = want["max_delay"]
    assert got.max_delay == (
        zmux.DEFAULT_MAX_DELAY
        if us == 0
        else None
        if us < 0
        else pytest.approx(us / 1e6)
    )
    for k in ("no_padding", "no_pause", "no_injection"):
        assert getattr(got, k) == want[k], k


@pytest.mark.parametrize("case", FORMAT["budget"], ids=by_name)
def test_budget(case: dict[str, Any]) -> None:
    doc = json.dumps({"kinds": {"default": [{"budget": case["budget"]}]}})
    b = zmux.ShapingBundle.from_json(doc).budget("default")
    assert b is not None
    if all(d["consumed"] == 0 for d in case["draws"]):
        d = case["draws"][0]
        assert b.wire == zmux.ShapingAccount(**d["wire"])
        assert b.no_injection == d["no_injection"]


def seconds(m: dict[str, int]) -> dict[str, float]:
    return {k: v / 1e6 if k in ("age", "idle") else v for k, v in m.items()}


@pytest.mark.parametrize("case", POOL["decide"], ids=by_name)
def test_pool_decide(case: dict[str, Any]) -> None:
    p = zmux.PoolPolicy(case["policy"])
    exact = (
        all(s["consumed"] == 0 for s in case["steps"])
        and not case["compile"]["consumed"]
    )
    for step in case["steps"]:
        since = step.get("since_dial")
        d = p.decide(
            step.get("failures", 0),
            [seconds(m) for m in step.get("members", [])],
            since_dial=None if since is None else since / 1e6,
        )
        want = step["want"]
        for key in ("count", "dial_after", "recheck", "probe_interval", "probe_jitter"):
            assert (getattr(d, key) is None) == (want[key] is None), key
        if exact:
            assert d.retire == want["retire"]
            assert d.count == want["count"]
            for key in ("dial_after", "recheck", "probe_interval", "probe_jitter"):
                if want[key] is not None:
                    assert getattr(d, key) == pytest.approx(want[key] / 1e6, abs=1e-6)


def test_max_slots() -> None:
    doc = '{"kinds":{"default":[{"machines":[{"start":0,"counters":9000,"states":[{}]}]}]}}'
    with pytest.raises(ValueError, match="limit"):
        zmux.ShapingBundle.from_json(doc)
    zmux.ShapingBundle.from_json(doc, limits=zmux.ShapingSizeLimits(max_slots=None))
    with pytest.raises(ValueError, match="limit"):
        zmux.ShapingBundle.from_json(doc, limits=zmux.ShapingSizeLimits(max_slots=8999))
