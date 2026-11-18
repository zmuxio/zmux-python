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
        return zmux.shaping.ShapingBundle.from_json(
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
    b = zmux.shaping.ShapingBundle.from_json(case["bundle"])
    for call in case["calls"]:
        plan = b.plan(case["kind"], call["handshake"], call["message"])
        assert (plan is None) == (call["plan"] is None), call


@pytest.mark.parametrize("case", BUDGET["parse"], ids=by_name)
def test_local_limits(case: dict[str, Any]) -> None:
    text = json.dumps(case["limits"])
    if "error" in case:
        with pytest.raises(ValueError) as e:
            zmux.shaping.shaping_limits_from_json(text)
        assert str(e.value).split(":")[0] == case["error"]
        return
    got = zmux.shaping.shaping_limits_from_json(text)
    want = case["want"]
    w = want["wire"]
    assert got.wire == zmux.shaping.ShapingAccount(
        initial=w["initial"], per_mb=w["per_mb"], per_sec=w["per_sec"]
    )
    us = want["max_delay"]
    assert got.max_delay == (
        zmux.shaping.DEFAULT_MAX_DELAY
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
    b = zmux.shaping.ShapingBundle.from_json(doc).budget("default")
    assert b is not None
    if all(d["consumed"] == 0 for d in case["draws"]):
        d = case["draws"][0]
        assert b.wire == zmux.shaping.ShapingAccount(**d["wire"])
        assert b.no_injection == d["no_injection"]


def member(m: dict[str, int]) -> zmux.helpers.PoolMember:
    return zmux.helpers.PoolMember(
        pipe=zmux.PipeId(m["id"]),
        age=m.get("age", 0) / 1e6,
        idle=m.get("idle", 0) / 1e6,
        pipes=m.get("pipes", 0),
        bytes_sent=m.get("bytes_sent", 0),
        bytes_received=m.get("bytes_received", 0),
    )


def pool_view(step: dict[str, Any]) -> zmux.helpers.PoolView:
    since = step.get("since_dial")
    return zmux.helpers.PoolView(
        members=tuple(member(m) for m in step.get("members", [])),
        failures=step.get("failures", 0),
        since_last_dial=None if since is None else since / 1e6,
    )


def is_exact(case: dict[str, Any]) -> bool:
    """No step of the case draws a random number."""
    return (
        all(s["consumed"] == 0 for s in case["steps"])
        and not case["compile"]["consumed"]
    )


@pytest.mark.parametrize("case", POOL["decide"], ids=by_name)
def test_pool_evaluate(case: dict[str, Any]) -> None:
    """The shared vectors test the evaluation: its values as the policy gives
    them, a probe interval below 1 s included."""
    p = zmux.helpers.MachinePoolPolicy(case["policy"])
    for step in case["steps"]:
        got = p.evaluate(pool_view(step))
        want = step["want"]
        for key in ("count", "dial_after", "recheck", "probe_interval", "probe_jitter"):
            assert (getattr(got, key) is not None) == (want[key] is not None), key
        if not is_exact(case):
            continue
        assert list(got.retire) == want["retire"]
        if want["count"] is not None:
            assert got.count == want["count"]
        for key in ("dial_after", "recheck", "probe_interval", "probe_jitter"):
            if want[key] is not None:
                assert getattr(got, key) == pytest.approx(want[key] / 1e6, abs=1e-6), (
                    key
                )


@pytest.mark.parametrize(
    "case", [c for c in POOL["decide"] if is_exact(c)], ids=by_name
)
def test_pool_decide_builds_the_evaluated_values(case: dict[str, Any]) -> None:
    """`decide` builds a `PoolDecision` from the evaluated values, and the
    construction refuses the one out of range: a probe interval between 0 and
    1 s is a `ValueError`, which is the pool's rejection of the look."""
    p = zmux.helpers.MachinePoolPolicy(case["policy"])
    for step in case["steps"]:
        view = pool_view(step)
        want = step["want"]
        probe = want["probe_interval"]
        if probe is not None and 0 < probe < 1_000_000:
            with pytest.raises(ValueError):
                p.decide(view)
            continue
        d = p.decide(view)
        live = d.liveness
        assert (d.count is not zmux.INHERIT) == (want["count"] is not None)
        assert (d.dial_after is not zmux.INHERIT) == (want["dial_after"] is not None)
        assert (d.recheck is not None) == (want["recheck"] is not None)
        assert (live.probe_interval is not zmux.INHERIT) == (probe is not None)
        assert (live.probe_jitter is not zmux.INHERIT) == (
            want["probe_jitter"] is not None
        )
        assert list(d.retire_pipes) == want["retire"]
        if want["count"] is not None:
            assert d.count == want["count"]
        if probe == 0:
            assert live.probe_interval is None
        elif probe:
            assert live.probe_interval == pytest.approx(probe / 1e6, abs=1e-6)


def test_max_slots() -> None:
    doc = '{"kinds":{"default":[{"machines":[{"start":0,"counters":9000,"states":[{}]}]}]}}'
    with pytest.raises(ValueError, match="limit"):
        zmux.shaping.ShapingBundle.from_json(doc)
    zmux.shaping.ShapingBundle.from_json(
        doc, limits=zmux.shaping.ShapingSizeLimits(max_slots=None)
    )
    with pytest.raises(ValueError, match="limit"):
        zmux.shaping.ShapingBundle.from_json(
            doc, limits=zmux.shaping.ShapingSizeLimits(max_slots=8999)
        )
