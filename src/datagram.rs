//! Conversion of local Datagram options and observations.

use std::num::NonZeroU8;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::{dur, field_count, field_opt_secs, field_secs, is_setting, types};

pub(crate) fn options(value: Option<&Bound<'_, PyAny>>) -> PyResult<zmux::DatagramSendOptions> {
    let Some(v) = value else {
        return Ok(zmux::DatagramSendOptions::default());
    };
    let mode = v.getattr("copies")?;
    let mut copies = None;
    if !mode.is_none() {
        copies = Some(match mode.extract::<&str>() {
            Ok("single") => zmux::DatagramCopyPolicy::Single,
            Ok("adaptive") => zmux::DatagramCopyPolicy::Adaptive,
            Ok(_) => return Err(PyValueError::new_err("unknown datagram copy policy")),
            Err(_) => {
                let count = field_count("copies", &mode.getattr("count")?)?;
                zmux::DatagramCopyPolicy::Duplicate(
                    NonZeroU8::new(count)
                        .ok_or_else(|| PyValueError::new_err("copies must be positive"))?,
                )
            }
        });
    }
    let carrier = match v.getattr("carrier")?.extract::<Option<&str>>()? {
        None => None,
        Some("prefer_native") => Some(zmux::DatagramCarrier::PreferNative),
        Some("require_native") => Some(zmux::DatagramCarrier::RequireNative),
        Some(_) => return Err(PyValueError::new_err("unknown datagram carrier policy")),
    };
    let d = v.getattr("deadline")?;
    let deadline = if is_setting(&d, "INHERIT")? {
        None
    } else if d.is_none() {
        Some(zmux::DatagramDeadline::Never)
    } else if let Ok(at) = d.getattr("at") {
        Some(zmux::DatagramDeadline::At(crate::host::instant(
            v.py(),
            "deadline",
            at.extract()?,
        )?))
    } else {
        Some(zmux::DatagramDeadline::After(field_secs("deadline", &d)?))
    };
    Ok(zmux::DatagramSendOptions {
        deadline,
        carrier,
        copies,
        urgent: v.getattr("urgent")?.extract()?,
        independent_fate: v.getattr("independent_fate")?.extract()?,
    })
}

pub(crate) fn config(value: &Bound<'_, PyAny>) -> PyResult<zmux::DatagramConfig> {
    let mut config = zmux::DatagramConfig::default();
    macro_rules! counts {
        ($($name:ident),* $(,)?) => {$(config.$name = field_count(stringify!($name), &value.getattr(stringify!($name))?)?;)*};
    }
    counts!(
        dedup_window,
        send_bytes,
        send_flow_queue,
        send_flow_bytes,
        replica_percent
    );
    let copy_limit = field_count("copy_limit", &value.getattr("copy_limit")?)?;
    config.copy_limit = NonZeroU8::new(copy_limit)
        .ok_or_else(|| PyValueError::new_err("copy_limit must be positive"))?;
    let stream_receive_bytes = value.getattr("stream_receive_bytes")?;
    config.stream_receive_bytes = (!stream_receive_bytes.is_none())
        .then(|| field_count("stream_receive_bytes", &stream_receive_bytes))
        .transpose()?;
    let hold_packets = value.getattr("hold_packets")?;
    config.hold_packets = (!hold_packets.is_none())
        .then(|| field_count("hold_packets", &hold_packets))
        .transpose()?;
    config.hold_time = field_opt_secs("hold_time", &value.getattr("hold_time")?)?;
    config.replica_standby = value.getattr("replica_standby")?.extract()?;
    config.priority = value.getattr("priority")?.extract::<crate::Prio>()?.0;
    config.defaults = options(Some(&value.getattr("defaults")?))?;
    Ok(config)
}

pub(crate) fn defaults(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let config = zmux::DatagramConfig::default();
    let d = PyDict::new(py);
    macro_rules! fields {
        ($($name:ident),* $(,)?) => {$(d.set_item(stringify!($name), config.$name)?;)*};
    }
    fields!(
        dedup_window,
        send_bytes,
        send_flow_queue,
        send_flow_bytes,
        replica_percent,
        stream_receive_bytes,
        hold_packets,
        replica_standby
    );
    d.set_item("copy_limit", config.copy_limit.get())?;
    d.set_item("hold_time", dur(config.hold_time))?;
    d.set_item(
        "priority",
        (config.priority.urgency(), config.priority.incremental()),
    )?;
    Ok(d)
}

pub(crate) fn path_obj(py: Python<'_>, path: zmux::DatagramPath) -> PyResult<Bound<'_, PyAny>> {
    types(py)?
        .getattr("DatagramPath")?
        .call1((path.payload, path.native_payload, path.native_room))
}

pub(crate) fn channel(native: bool) -> zmux::DatagramChannelKind {
    if native {
        zmux::DatagramChannelKind::Native
    } else {
        zmux::DatagramChannelKind::Record
    }
}

fn drops(py: Python<'_>, value: zmux::DatagramDrops) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("DatagramDrops")?.call1((
        value.no_native_path,
        value.queue_overflow,
        value.limiter,
        value.codel,
        value.deadline,
        value.sequence_exhausted,
        value.closed_flow,
        value.size,
        value.carrier_rejected,
        value.carrier_cancelled,
    ))
}

fn replica_degradation(
    py: Python<'_>,
    value: zmux::DatagramReplicaDegradation,
) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("DatagramReplicaDegradation")?.call1((
        value.budget,
        value.no_eligible_pipe,
        value.fate,
        value.open_fence,
        value.size,
        value.deadline,
        value.carrier_rejected,
        value.carrier_cancelled,
    ))
}

fn dispatch(py: Python<'_>, value: zmux::DatagramDispatchStats) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("DatagramDispatchStats")?.call1((
        value.originals,
        value.original_bytes,
        value.originals_accepted,
        value.original_bytes_accepted,
        value.originals_failed,
        value.replicas,
        value.replica_bytes,
        value.replicas_accepted,
        value.replica_bytes_accepted,
        value.replicas_failed,
    ))
}

pub(crate) fn stats<'py>(py: Python<'py>, s: &zmux::DatagramStats) -> PyResult<Bound<'py, PyAny>> {
    types(py)?.getattr("DatagramStats")?.call1((
        s.duplicates_dropped,
        s.stale_dropped,
        drops(py, s.drops)?,
        replica_degradation(py, s.replica_degradation)?,
        dispatch(py, s.record)?,
        dispatch(py, s.native)?,
    ))
}

pub(crate) fn feedback(
    py: Python<'_>,
    value: zmux::DatagramFeedback,
) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("DatagramFeedback")?.call1((
        value.tracking,
        value.awaiting,
        value.arrived,
        value.expired,
        dur(value.report_rtt),
        dur(value.report_variation),
        crate::host::at(py, value.sampled_at)?,
        dur(value.sample_age),
        value.samples,
        value
            .sample_source
            .map(|source| crate::typed(py, "DatagramEvidenceSource", crate::kind_of(&source))),
    ))
}

pub(crate) fn arrivals(
    py: Python<'_>,
    value: zmux::DatagramArrivals,
) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("DatagramArrivals")?.call1((
        value.frames,
        value.bytes,
        crate::monotonic(py, value.last_at)?,
    ))
}
