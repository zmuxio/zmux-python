"""Property tests of the public value types' validation: each strategy covers the
range a value can take (negative, zero, boundary, huge, NaN, infinite), and an
independent oracle written from the documented ranges says which values are
valid. Valid values are kept as given and accepted by the native side; every
other raises the documented error class."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Iterator
from typing import Any

import pytest
import zmux
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# The pure checks are cheap; the native ones go through a live session.
PURE = settings(max_examples=300, deadline=None)
NATIVE = settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

TWO64 = 2.0**64

floats = st.floats(allow_nan=True, allow_infinity=True) | st.sampled_from(
    [0.0, -0.0, 1.0, 0.5, TWO64, math.nextafter(TWO64, 0.0), math.nextafter(1.0, 0.0)]
)
seconds = st.none() | floats
ints = st.integers(-(2**70), 2**70) | st.sampled_from(
    [-1, 0, 1, 2**63, 2**64 - 1, 2**64, 2**64 + 1]
)


def nanoseconds(v: float | None) -> bool:
    """None, or a number of seconds of at least 1 ns, the unit of the core's
    durations, below 2**64 (finite)."""
    return v is None or 1e-9 <= v < TWO64


def ns(v: float) -> float:
    """A number of seconds in whole nanoseconds (NaN stays NaN)."""
    n = v * 1e9
    return n if not math.isfinite(n) or abs(n) > 2.0**53 else float(round(n))


# ---- QualityBand -------------------------------------------------------------------


@PURE
@given(rtt=seconds, rate_ratio=seconds, min_interval=seconds)
def test_quality_band_accepts_exactly_the_documented_values(
    rtt: float | None, rate_ratio: float | None, min_interval: float | None
) -> None:
    valid = (
        nanoseconds(rtt)
        and nanoseconds(min_interval)
        and (rate_ratio is None or 1 <= rate_ratio < math.inf)
        and (rtt is not None or rate_ratio is not None)
    )
    if not valid:
        with pytest.raises(ValueError):
            zmux.QualityBand(rtt=rtt, rate_ratio=rate_ratio, min_interval=min_interval)
        return
    band = zmux.QualityBand(rtt=rtt, rate_ratio=rate_ratio, min_interval=min_interval)
    assert (band.rtt, band.rate_ratio, band.min_interval) == (
        rtt,
        rate_ratio,
        min_interval,
    )


# ---- CapacityFloor -----------------------------------------------------------------


@PURE
@given(rate=ints, recovery_ratio=floats)
def test_capacity_floor_accepts_exactly_the_documented_values(
    rate: int, recovery_ratio: float
) -> None:
    valid = rate >= 1 and 1 <= recovery_ratio < math.inf
    if not valid:
        with pytest.raises(ValueError):
            zmux.CapacityFloor(rate=rate, recovery_ratio=recovery_ratio)
        return
    floor = zmux.CapacityFloor(rate=rate, recovery_ratio=recovery_ratio)
    assert (floor.rate, floor.recovery_ratio) == (rate, recovery_ratio)


# ---- PoolDecision ------------------------------------------------------------------

count_or_inherit = ints | st.just(zmux.INHERIT)
dial_after = floats | st.just(zmux.INHERIT)


@PURE
@given(count=count_or_inherit, dial_after=dial_after, recheck=seconds)
def test_pool_decision_accepts_exactly_the_documented_values(
    count: Any, dial_after: Any, recheck: float | None
) -> None:
    valid = (
        (count is zmux.INHERIT or count >= 1)
        and (dial_after is zmux.INHERIT or 0 <= dial_after < TWO64)
        and (recheck is None or (ns(recheck) >= 1 and recheck < TWO64))
    )
    if not valid:
        with pytest.raises(ValueError):
            zmux.helpers.PoolDecision(
                count=count, dial_after=dial_after, recheck=recheck
            )
        return
    d = zmux.helpers.PoolDecision(count=count, dial_after=dial_after, recheck=recheck)
    assert (d.count, d.dial_after, d.recheck) == (count, dial_after, recheck)
    assert d.retire_pipes == ()


# ---- PipeOptions -------------------------------------------------------------------

UPDATABLE = (
    "send_priority",
    "receive_priority",
    "send_standby",
    "receive_standby",
    "weight",
    "probation",
    "liveness",
    "quality_band",
)


@pytest.mark.parametrize("name", UPDATABLE)
def test_clear_is_refused_in_every_updatable_option(name: str) -> None:
    with pytest.raises(TypeError):
        zmux.PipeOptions(**{name: zmux.CLEAR})
    zmux.PipeOptions(**{name: zmux.INHERIT})


async def _no_dial() -> zmux.PipeIo:
    raise AssertionError("not dialled")


@PURE
@given(
    field=st.sampled_from(["send_priority", "receive_priority", "weight"]), value=ints
)
def test_unsigned_pipe_options_take_a_u64(field: str, value: int) -> None:
    """The tier and the weight of a pipe are unsigned 64-bit integers; the pool
    checks the options where it takes them."""
    options = zmux.PipeOptions(**{field: value})
    assert getattr(options, field) == value
    if 0 <= value < 2**64:
        zmux.helpers.PipePool(1, _no_dial, options=options)
    else:
        with pytest.raises(ValueError):
            zmux.helpers.PipePool(1, _no_dial, options=options)


@PURE
@given(
    suspect_floor=floats | st.just(zmux.INHERIT),
    probe_interval=seconds | st.just(zmux.INHERIT),
    probe_jitter=floats | st.just(zmux.INHERIT),
)
def test_pipe_liveness_is_checked_where_it_is_used(
    suspect_floor: Any, probe_interval: Any, probe_jitter: Any
) -> None:
    live = zmux.PipeLiveness(
        suspect_floor=suspect_floor,
        probe_interval=probe_interval,
        probe_jitter=probe_jitter,
    )
    # The core holds nanoseconds: a value rounds to them before the range applies.
    jitter_ok = probe_jitter is zmux.INHERIT or 0 <= probe_jitter < 1
    interval_ok = (
        probe_interval is zmux.INHERIT
        or probe_interval is None
        or 1_000_000_000 <= ns(probe_interval) < TWO64 * 1e9
    )
    floor_ok = suspect_floor is zmux.INHERIT or (
        50_000_000 <= ns(suspect_floor) < TWO64 * 1e9
    )
    options = zmux.PipeOptions(liveness=live)
    if jitter_ok and interval_ok and floor_ok:
        zmux.helpers.PipePool(1, _no_dial, options=options)
    else:
        with pytest.raises(ValueError):
            zmux.helpers.PipePool(1, _no_dial, options=options)


# ---- Priority and the session settings, through a live session ---------------------


@pytest.fixture(scope="module")
def live() -> Iterator[tuple[asyncio.Runner, zmux.Session, zmux.SendStream]]:
    """One connected pair and one open stream, on a loop the properties share."""
    runner = asyncio.Runner()

    async def setup() -> tuple[zmux.Listener, zmux.Session, zmux.Session, Any]:
        listener = zmux.Listener()
        host, port = await listener.serve_tcp("127.0.0.1", 0)
        client = await zmux.connect_tcp(host, port)
        server = await listener.accept()
        send, _recv = await client.open_bi()
        return listener, client, server, send

    listener, client, server, send = runner.run(setup())

    async def teardown() -> None:
        client.abort(0)
        server.abort(0)
        await asyncio.gather(client.wait_closed(), server.wait_closed())
        listener.close()

    try:
        yield runner, client, send
    finally:
        runner.run(teardown())
        runner.close()


urgency = st.integers(-(2**70), 2**70) | st.sampled_from([-1, 0, 7, 8, 255, 256])


@NATIVE
@given(urgency=urgency, incremental=st.booleans())
def test_priority_urgency_is_zero_to_seven(
    live: Any, urgency: int, incremental: bool
) -> None:
    _runner, _session, send = live
    before = send.priority
    if 0 <= urgency <= 7:
        send.priority = zmux.Priority(urgency, incremental)
        assert send.priority == (urgency, incremental)
    else:
        with pytest.raises(ValueError):
            send.priority = (urgency, incremental)
        assert send.priority == before


@NATIVE
@given(rtt=seconds, rate_ratio=seconds, min_interval=seconds)
def test_a_valid_quality_band_is_taken_and_read_back(
    live: Any, rtt: float | None, rate_ratio: float | None, min_interval: float | None
) -> None:
    _runner, session, _send = live
    try:
        band = zmux.QualityBand(
            rtt=rtt, rate_ratio=rate_ratio, min_interval=min_interval
        )
    except ValueError:
        return
    session.quality_band = band
    got = session.quality_band
    assert got is not None
    # The core holds durations in nanoseconds.
    for name in ("rtt", "min_interval"):
        want = getattr(band, name)
        assert (getattr(got, name) is None) == (want is None)
        if want is not None:
            assert getattr(got, name) == pytest.approx(want, rel=1e-12, abs=1e-9)
    assert got.rate_ratio == band.rate_ratio
    session.quality_band = None
    assert session.quality_band is None


@NATIVE
@given(rate=ints, recovery_ratio=floats)
def test_a_valid_capacity_floor_is_taken_and_read_back(
    live: Any, rate: int, recovery_ratio: float
) -> None:
    _runner, session, _send = live
    try:
        floor = zmux.CapacityFloor(rate=rate, recovery_ratio=recovery_ratio)
    except ValueError:
        return
    if rate >= 2**64:
        # Beyond the native rate type; the conversion refuses it.
        with pytest.raises(ValueError):
            session.capacity_floor = floor
        return
    session.capacity_floor = floor
    assert session.capacity_floor == floor
    session.capacity_floor = None
