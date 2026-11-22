import math

import pytest

import zmux


@pytest.mark.skipif(
    not hasattr(zmux._zmux, "_error_data"),
    reason="the module is built without the test-hooks feature",
)
def test_native_errors_preserve_data_and_cause() -> None:
    transport, reset, timeout, lost, graceful = zmux._zmux._error_data()
    assert isinstance(transport, zmux.TransportClosedError)
    assert transport.code == 7
    assert transport.frame_type == 8
    assert transport.reason == b"limit exceeded"
    assert transport.details == (("limit", 1 << 40), ("limit", 7))
    assert transport.remote is True
    assert isinstance(reset, zmux.StreamResetError)
    assert reset.code == 42
    assert reset.reliable_size == 1 << 40
    assert isinstance(timeout, zmux.ResumeTimeoutError)
    assert isinstance(timeout.__cause__, zmux.JoinRefusedError)
    assert isinstance(lost, zmux.PipesLostError)
    assert isinstance(lost.__cause__, zmux.PipeAbortedError)
    assert isinstance(graceful, zmux.PipesLostError)
    assert graceful.__cause__ is None


@pytest.mark.parametrize("field", ["max_idle_timeout", "resume_timeout"])
def test_wire_timeout_rejects_a_float_just_below_one_millisecond(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        value = math.nextafter(0.001, 0.0)
        if field == "max_idle_timeout":
            zmux.Config(max_idle_timeout=value)
        else:
            zmux.Config(resume_timeout=value)
