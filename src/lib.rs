//! `PyO3` bindings over the zmux Rust crates. Every I/O operation runs on the
//! tokio runtime owned by `pyo3-async-runtimes`; Python awaits futures that
//! resolve on its asyncio loop. No protocol logic lives here.

use std::collections::VecDeque;
use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyStopAsyncIteration, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyType;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};
use zmux::shaping::Factory;

mod admission;
mod choice;
mod helpers;
mod layer;
mod packet;
mod pool;
mod rt;
mod seal;
mod shaping;
use admission::Admission;
use rt::{future_into_py, get_runtime};

// ---- errors ---------------------------------------------------------------------------

fn kind_of(e: &impl Debug) -> String {
    let s = format!("{e:?}");
    s.split(['(', ' ', '{']).next().unwrap_or("").to_owned()
}

/// The `zmux` exception class `name` (module `zmux._errors`).
pub(crate) fn err_type<'p>(py: Python<'p>, name: &str) -> Bound<'p, PyType> {
    static ERRORS: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
    let m = ERRORS
        .get_or_try_init(py, || py.import("zmux._errors").map(Bound::unbind))
        .expect("zmux._errors is importable")
        .bind(py);
    m.getattr(name)
        .and_then(|t| Ok(t.cast_into::<PyType>()?))
        .expect("a zmux exception class")
}

/// An exception of the class `name` with the message `msg`.
pub(crate) fn new_err(name: &str, msg: impl Into<String>) -> PyErr {
    let msg = msg.into();
    rt::attach(|py| PyErr::from_type(err_type(py, name), msg))
}

/// Builds an exception of the class `name` with the attributes `kind`,
/// `retryable` and `code`.
fn raise(name: &str, e: &(impl Debug + Display), retryable: bool, code: Option<u64>) -> PyErr {
    rt::attach(|py| {
        let err = PyErr::from_type(err_type(py, name), e.to_string());
        let v = err.value(py);
        let _ = v.setattr("kind", typed(py, "ErrorKind", kind_of(e)));
        let _ = v.setattr("retryable", retryable);
        let _ = v.setattr("code", code);
        err
    })
}

/// A `zmux._types` enum member for `v`, or `v` itself when unknown.
pub(crate) fn typed<'p>(py: Python<'p>, enum_name: &str, v: String) -> Bound<'p, PyAny> {
    types(py)
        .and_then(|t| t.getattr("_enum_of")?.call1((t.getattr(enum_name)?, &v)))
        .unwrap_or_else(|_| v.into_pyobject(py).unwrap().into_any())
}

fn types(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    py.import("zmux._types")
}

fn session_err(e: zmux::SessionError) -> PyErr {
    use zmux::SessionError as E;
    let (code, reason, remote) = match &e {
        E::ApplicationClosed {
            code,
            reason,
            remote,
        } => (Some(code.into_inner()), Some(reason.clone()), Some(*remote)),
        E::TransportClosed {
            code,
            reason,
            remote,
            ..
        } => (Some(code.0), Some(reason.clone()), Some(*remote)),
        E::IdleTimeout { remote } => (None, None, Some(*remote)),
        _ => (None, None, None),
    };
    let (code, reason, remote) = match &e {
        E::ResumeFailed { reason, remote } => (code, Some(reason.clone()), Some(*remote)),
        _ => (code, reason, remote),
    };
    let r = e.is_retryable();
    let last = match &e {
        E::ResumeTimeout { last } | E::PipesLost { last } => *last,
        _ => None,
    };
    let err = match &e {
        E::EarlyDataRejected => raise("EarlyDataRejectedError", &e, r, code),
        E::ApplicationClosed { .. } => raise("ApplicationClosedError", &e, r, code),
        E::TransportClosed { .. } => raise("TransportClosedError", &e, r, code),
        E::IdleTimeout { .. } => raise("IdleTimeoutError", &e, r, code),
        E::HandshakeTimeout => raise("HandshakeTimeoutError", &e, r, code),
        E::ResumeTimeout { .. } => raise("ResumeTimeoutError", &e, r, code),
        E::PipesLost { .. } => raise("PipesLostError", &e, r, code),
        E::ResumeFailed { .. } => raise("ResumeFailedError", &e, r, code),
        _ => raise("SessionClosedError", &e, r, code),
    };
    rt::attach(|py| {
        let v = err.value(py);
        let _ = v.setattr("reason", reason.map(|r| PyBytes::new(py, &r)));
        let _ = v.setattr("remote", remote);
        if let Some(l) = last {
            let cause = raise("PipeError", &zmux::PipeError::Failed(l), false, None);
            err.set_cause(py, Some(cause));
        }
    });
    err
}

fn stream_err(e: zmux::StreamError) -> PyErr {
    match &e {
        zmux::StreamError::Reset { code, .. } => raise(
            "StreamResetError",
            &e,
            e.is_retryable(),
            Some(code.into_inner()),
        ),
        zmux::StreamError::Stopped(code) => raise(
            "StreamStoppedError",
            &e,
            e.is_retryable(),
            Some(code.into_inner()),
        ),
        zmux::StreamError::SessionLost(s) => session_err(s.clone()),
        zmux::StreamError::PreambleTooLarge => {
            raise("PreambleTooLargeError", &e, e.is_retryable(), None)
        }
        zmux::StreamError::Rejected => raise("StreamRejectedError", &e, e.is_retryable(), None),
        zmux::StreamError::GoingAway => raise("GoingAwayError", &e, e.is_retryable(), None),
        zmux::StreamError::ClosedLocally => raise("StreamClosedError", &e, false, None),
        zmux::StreamError::NotNegotiated => raise("NotNegotiatedError", &e, false, None),
        zmux::StreamError::NotEstablished => raise("NotEstablishedError", &e, false, None),
        _ => raise("StreamError", &e, e.is_retryable(), None),
    }
}

/// An open's failure, classified by what happened.
fn open_err(e: zmux::OpenError) -> PyErr {
    match &e {
        zmux::OpenError::SessionLost(s) => session_err(s.clone()),
        zmux::OpenError::PreambleTooLarge => {
            raise("PreambleTooLargeError", &e, e.is_retryable(), None)
        }
        zmux::OpenError::GoingAway => raise("GoingAwayError", &e, e.is_retryable(), None),
        zmux::OpenError::NotNegotiated => raise("NotNegotiatedError", &e, false, None),
        zmux::OpenError::NotEstablished => raise("NotEstablishedError", &e, false, None),
        zmux::OpenError::InvalidArgument => raise("InvalidArgumentError", &e, false, None),
        _ => raise("StreamError", &e, e.is_retryable(), None),
    }
}

fn datagram_err(e: zmux::DatagramError) -> PyErr {
    match &e {
        zmux::DatagramError::SessionLost(s) => session_err(s.clone()),
        zmux::DatagramError::NotNegotiated => raise("NotNegotiatedError", &e, false, None),
        zmux::DatagramError::ClosedStream => raise("StreamClosedError", &e, false, None),
        _ => raise("DatagramError", &e, e.is_retryable(), None),
    }
}

fn pipe_err(e: zmux::PipeError) -> PyErr {
    use zmux::PipeFailure as F;
    match &e {
        zmux::PipeError::SessionLost(s) => session_err(s.clone()),
        zmux::PipeError::InvalidOptions(_) | zmux::PipeError::InvalidArgument => {
            raise("InvalidArgumentError", &e, false, None)
        }
        zmux::PipeError::NotNegotiated => raise("NotNegotiatedError", &e, false, None),
        zmux::PipeError::NotEstablished => raise("NotEstablishedError", &e, true, None),
        zmux::PipeError::JoinPending(_) => raise("JoinPendingError", &e, e.is_retryable(), None),
        zmux::PipeError::JoinSecretSet => raise("JoinSecretSetError", &e, false, None),
        zmux::PipeError::UnknownPipe => raise("PipeGoneError", &e, false, None),
        // The join was refused, or `join_timeout` passed: the language's
        // deadline error.
        zmux::PipeError::Failed(F::JoinRefused) => {
            raise("JoinRefusedError", &e, e.is_retryable(), None)
        }
        zmux::PipeError::Failed(F::JoinTimedOut) => {
            raise("DeadlineExceededError", &e, e.is_retryable(), None)
        }
        _ => raise("PipeError", &e, e.is_retryable(), None),
    }
}

fn connect_err(e: zmux::ConnectError) -> PyErr {
    match &e {
        zmux::ConnectError::SessionLost(s) => session_err(s.clone()),
        zmux::ConnectError::InvalidConfig(_) => raise("InvalidArgumentError", &e, false, None),
        _ => raise("ConnectError", &e, e.is_retryable(), None),
    }
}

/// The stream finished before `expected` bytes arrived: `partial` holds
/// those read.
fn incomplete_read(partial: &[u8], expected: usize) -> PyErr {
    let e = zmux::ReadExactError::FinishedEarly(partial.len());
    rt::attach(|py| {
        let cls = err_type(py, "IncompleteReadError");
        match cls.call1((PyBytes::new(py, partial), expected)) {
            Ok(v) => {
                let _ = v.setattr("kind", typed(py, "ErrorKind", kind_of(&e)));
                PyErr::from_value(v)
            }
            Err(err) => err,
        }
    })
}

fn export_err(e: zmux::ExportError) -> PyErr {
    let retryable = matches!(e, zmux::ExportError::Unavailable);
    if matches!(e, zmux::ExportError::NoExporter) {
        return raise("NoExporterError", &e, retryable, None);
    }
    raise("ExportError", &e, retryable, None)
}

/// An I/O error as a Python exception: a Python exception, or a zmux
/// error, carried inside it surfaces as itself; anything else is a
/// `ConnectError` of kind `Io`.
fn io_err(e: std::io::Error) -> PyErr {
    if e.get_ref().is_some_and(|i| {
        i.is::<PyErr>()
            || i.is::<zmux::SessionError>()
            || i.is::<zmux::ConnectError>()
            || i.is::<zmux::PipeError>()
            || i.is::<zmux::StreamError>()
            || i.is::<zmux::OpenError>()
    }) {
        let kind = e.kind();
        let inner = e.into_inner().expect("checked above");
        let inner = match inner.downcast::<PyErr>() {
            Ok(p) => return *p,
            Err(i) => i,
        };
        let inner = match inner.downcast::<zmux::SessionError>() {
            Ok(x) => return session_err(*x),
            Err(i) => i,
        };
        let inner = match inner.downcast::<zmux::ConnectError>() {
            Ok(x) => return connect_err(*x),
            Err(i) => i,
        };
        let inner = match inner.downcast::<zmux::PipeError>() {
            Ok(x) => return pipe_err(*x),
            Err(i) => i,
        };
        let inner = match inner.downcast::<zmux::StreamError>() {
            Ok(x) => return stream_err(*x),
            Err(i) => i,
        };
        return match inner.downcast::<zmux::OpenError>() {
            Ok(x) => open_err(*x),
            Err(i) => io_other(std::io::Error::new(kind, i)),
        };
    }
    io_other(e)
}

fn io_other(e: std::io::Error) -> PyErr {
    let err = raise("ConnectError", &e, false, None);
    rt::attach(|py| {
        let _ = err
            .value(py)
            .setattr("kind", typed(py, "ErrorKind", "Io".into()));
    });
    err
}

fn pyb(b: &[u8]) -> Py<PyBytes> {
    rt::attach(|py| PyBytes::new(py, b).unbind())
}

fn busy() -> PyErr {
    new_err(
        "StreamBusyError",
        "another operation on this stream is in progress",
    )
}

// ---- configuration --------------------------------------------------------------------

/// Session configuration from the fields of `zmux.Config`, every one
/// given: a value, `None` for the off or unlimited setting of a field that
/// has one, or a setting object (`zmux.AUTO`, `zmux.STAGED`). An unknown
/// field raises `TypeError`, `None` for a field without an off setting
/// `ValueError`.
#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct Config(Arc<zmux::Config>);

/// Whether `v` is the setting object `name` (`AUTO`, `STAGED`, `INHERIT`,
/// `CLEAR`) of `zmux._types`.
pub(crate) fn is_setting(v: &Bound<'_, PyAny>, name: &str) -> PyResult<bool> {
    Ok(v.is(&types(v.py())?.getattr(name)?))
}

/// The setting object `name` of `zmux._types`.
fn setting<'p>(py: Python<'p>, name: &str) -> PyResult<Bound<'p, PyAny>> {
    types(py)?.getattr(name)
}

/// `ValueError` for `None` given to a field without an off setting.
fn required<'a, 'py>(name: &str, v: &'a Bound<'py, PyAny>) -> PyResult<&'a Bound<'py, PyAny>> {
    if v.is_none() {
        return Err(PyValueError::new_err(format!(
            "{name} has no off setting: give a value or leave it out"
        )));
    }
    Ok(v)
}

/// A non-negative duration of the field `name` in seconds.
fn field_secs(name: &str, v: &Bound<'_, PyAny>) -> PyResult<Duration> {
    seconds(name, required(name, v)?.extract()?)
}

/// A timer or period in seconds; `None` is no timeout or off.
fn field_opt_secs(name: &str, v: &Bound<'_, PyAny>) -> PyResult<Option<Duration>> {
    if v.is_none() {
        return Ok(None);
    }
    field_secs(name, v).map(Some)
}

/// A count of the field `name`.
fn field_count<T: for<'a, 'py> FromPyObject<'a, 'py>>(
    name: &str,
    v: &Bound<'_, PyAny>,
) -> PyResult<T> {
    required(name, v)?
        .extract()
        .map_err(|_| PyValueError::new_err(format!("{name} is a non-negative integer")))
}

/// A cap: `zmux.AUTO` is auto, a value fixes it.
fn field_cap(name: &str, v: &Bound<'_, PyAny>) -> PyResult<zmux::Cap> {
    if is_setting(v, "AUTO")? {
        return Ok(zmux::Cap::Auto);
    }
    Ok(zmux::Cap::Fixed(field_count(name, v)?))
}

/// The Python value of a cap.
fn cap_obj(py: Python<'_>, c: zmux::Cap) -> PyResult<Bound<'_, PyAny>> {
    match c {
        zmux::Cap::Auto => setting(py, "AUTO"),
        zmux::Cap::Fixed(v) => Ok(v.into_pyobject(py)?.into_any()),
    }
}

/// A probation: `None` off, `zmux.AUTO` derived from the pipe's RTT, else a
/// base in seconds.
fn probation_of(name: &str, v: &Bound<'_, PyAny>) -> PyResult<Option<zmux::Cap<Duration>>> {
    if v.is_none() {
        return Ok(None);
    }
    if is_setting(v, "AUTO")? {
        return Ok(Some(zmux::Cap::Auto));
    }
    Ok(Some(zmux::Cap::Fixed(field_secs(name, v)?)))
}

/// The Python value of a probation.
fn probation_obj(py: Python<'_>, p: Option<zmux::Cap<Duration>>) -> PyResult<Bound<'_, PyAny>> {
    match p {
        None => Ok(py.None().into_bound(py)),
        Some(zmux::Cap::Auto) => setting(py, "AUTO"),
        Some(zmux::Cap::Fixed(d)) => Ok(d.as_secs_f64().into_pyobject(py)?.into_any()),
    }
}

/// The scheduling policy of a name.
fn policy(name: &str) -> PyResult<zmux::sched::Scheduler> {
    Ok(match name {
        "affinity" => zmux::sched::Scheduler::Affinity,
        "session-affinity" => zmux::sched::Scheduler::SessionAffinity,
        "spread-eta" => zmux::sched::Scheduler::SpreadEta,
        "spread-round-robin" => zmux::sched::Scheduler::SpreadRoundRobin,
        "spread-rate-weighted" => zmux::sched::Scheduler::SpreadRateWeighted,
        _ => {
            return Err(PyValueError::new_err(format!("unknown scheduler {name:?}")));
        }
    })
}

/// The scheduling policy of a `zmux.Scheduler` or its name; `None` is none.
fn scheduler_of(v: Option<&Bound<'_, PyAny>>) -> PyResult<Option<zmux::sched::Scheduler>> {
    match v {
        Some(v) if !v.is_none() => policy(&v.str()?.extract::<String>()?).map(Some),
        _ => Ok(None),
    }
}

/// The name of a built-in scheduling policy.
fn policy_name(p: &zmux::sched::Scheduler) -> &'static str {
    match p {
        zmux::sched::Scheduler::SessionAffinity => "session-affinity",
        zmux::sched::Scheduler::SpreadEta => "spread-eta",
        zmux::sched::Scheduler::SpreadRoundRobin => "spread-round-robin",
        zmux::sched::Scheduler::SpreadRateWeighted => "spread-rate-weighted",
        _ => "affinity",
    }
}

/// The native backoff of a `zmux.Backoff`.
pub(crate) fn backoff_of(v: &Bound<'_, PyAny>) -> PyResult<zmux::Backoff> {
    let min = field_secs("min", &v.getattr("min")?)?;
    let max = field_secs("max", &v.getattr("max")?)?;
    let mut b = zmux::Backoff::new(min, max);
    b.jitter = required("jitter", &v.getattr("jitter")?)?.extract()?;
    b.validate().map_err(value_err)?;
    Ok(b)
}

/// A `logging.Logger` as the session's logger: zmux's levels as logging's.
fn logger_of(v: &Bound<'_, PyAny>) -> zmux::Logger {
    let logger = v.clone().unbind();
    zmux::Logger::new(move |level, message| {
        let n: u8 = match level {
            zmux::LogLevel::Debug => 10,
            zmux::LogLevel::Info => 20,
            zmux::LogLevel::Warn => 30,
            _ => 40,
        };
        rt::attach(|py| {
            if let Err(e) = logger.bind(py).call_method1("log", (n, message)) {
                e.write_unraisable(py, Some(logger.bind(py)));
            }
        });
    })
}

/// A `zmux.Tracer` as the session's tracer: each call runs on a native
/// thread holding the interpreter lock; an exception is reported as
/// unraisable.
struct PyTracer(Py<PyAny>);

impl PyTracer {
    fn call(&self, name: &str, args: impl FnOnce(Python<'_>) -> PyResult<Bound<'_, PyTuple>>) {
        rt::attach(|py| {
            let t = self.0.bind(py);
            if let Err(e) = args(py).and_then(|a| t.call_method1(name, a)) {
                e.write_unraisable(py, Some(t));
            }
        });
    }
}

impl zmux::Tracer for PyTracer {
    fn established(&self) {
        self.call("established", |py| Ok(PyTuple::empty(py)));
    }
    fn event(&self, event: &zmux::SessionEvent) {
        self.call("event", |py| PyTuple::new(py, [event_obj(py, event)?]));
    }
    fn dropped(&self, count: u64) {
        self.call("dropped", |py| PyTuple::new(py, [count]));
    }
    fn closed(&self, reason: &zmux::SessionError) {
        self.call("closed", |py| {
            PyTuple::new(py, [session_err(reason.clone()).into_value(py)])
        });
    }
}

/// `authorize_join(pipe)`: the acceptor's further check of a join; an
/// exception refuses it.
fn authorize_join(f: Py<PyAny>) -> zmux::AuthorizeJoin {
    zmux::AuthorizeJoin::new(move |pipe| {
        rt::attach(|py| {
            f.bind(py)
                .call1((pipe.get(),))
                .and_then(|v| v.is_truthy())
                .unwrap_or_else(|e| {
                    e.write_unraisable(py, Some(f.bind(py)));
                    false
                })
        })
    })
}

/// The join credentials of a `zmux.PipeAuth`.
fn pipe_auth(v: &Bound<'_, PyAny>) -> PyResult<zmux::PipeAuth> {
    let exporter: bool = v.getattr("_exporter")?.extract()?;
    let end_to_end: bool = v.getattr("_end_to_end")?.extract()?;
    let psk: Option<Vec<u8>> = v.getattr("_psk")?.extract()?;
    let deferred: bool = v.getattr("_deferred")?.extract()?;
    let base = if exporter {
        zmux::PipeAuth::exporter()
    } else {
        zmux::PipeAuth::none()
    };
    let base = if end_to_end {
        base.with_end_to_end()
    } else {
        base
    };
    let base = match psk {
        Some(k) => base.with_psk(k),
        None => base,
    };
    Ok(if deferred {
        base.with_deferred_psk()
    } else {
        base
    })
}

/// The native settings of a `zmux.Liveness`.
fn liveness(v: &Bound<'_, PyAny>) -> PyResult<zmux::Liveness> {
    let opt = |n: &str| field_opt_secs(n, &v.getattr(n)?);
    let dead = v.getattr("dead_timeout")?;
    Ok(zmux::Liveness {
        keep_alive_period: opt("keep_alive_period")?,
        suspect_floor: field_secs("suspect_floor", &v.getattr("suspect_floor")?)?,
        dead_timeout: if is_setting(&dead, "AUTO")? {
            zmux::Cap::Auto
        } else {
            zmux::Cap::Fixed(field_secs("dead_timeout", &dead)?)
        },
        standby_probe: opt("standby_probe")?,
        probe_interval: opt("probe_interval")?,
        probe_jitter: required("probe_jitter", &v.getattr("probe_jitter")?)?.extract()?,
    })
}

/// The `zmux.Liveness` of native settings.
fn liveness_obj<'p>(py: Python<'p>, l: &zmux::Liveness) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("keep_alive_period", dur(l.keep_alive_period))?;
    d.set_item("suspect_floor", l.suspect_floor.as_secs_f64())?;
    d.set_item(
        "dead_timeout",
        match l.dead_timeout {
            zmux::Cap::Auto => setting(py, "AUTO")?,
            zmux::Cap::Fixed(t) => t.as_secs_f64().into_pyobject(py)?.into_any(),
        },
    )?;
    d.set_item("standby_probe", dur(l.standby_probe))?;
    d.set_item("probe_interval", dur(l.probe_interval))?;
    d.set_item("probe_jitter", l.probe_jitter)?;
    types(py)?.getattr("Liveness")?.call((), Some(&d))
}

/// The native policy of a `zmux.EpochPolicy`: `None` never advances by
/// time or by count.
fn epoch_policy(v: &Bound<'_, PyAny>) -> PyResult<zmux::EpochPolicy> {
    Ok(zmux::EpochPolicy {
        period: field_opt_secs("epoch_policy.period", &v.getattr("period")?)?,
        joins: v.getattr("joins")?.extract()?,
        after_first_pipe: v.getattr("after_first_pipe")?.extract()?,
        after_resume: v.getattr("after_resume")?.extract()?,
    })
}

/// A field of a pipe's settings that follows the session's unless set.
fn inherit<T>(
    v: &Bound<'_, PyAny>,
    set: impl FnOnce(&Bound<'_, PyAny>) -> PyResult<T>,
) -> PyResult<zmux::Inherit<T>> {
    if is_setting(v, "INHERIT")? {
        return Ok(zmux::Inherit::Session);
    }
    set(v).map(zmux::Inherit::Set)
}

/// The Python value of a field that follows the session's unless set.
fn inherit_obj<'p, T>(
    py: Python<'p>,
    v: zmux::Inherit<T>,
    set: impl FnOnce(T) -> PyResult<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    match v {
        zmux::Inherit::Session => setting(py, "INHERIT"),
        zmux::Inherit::Set(t) => set(t),
    }
}

/// The native settings of a `zmux.PipeLiveness`.
fn pipe_liveness(v: &Bound<'_, PyAny>) -> PyResult<zmux::PipeLiveness> {
    let get = |n: &str| v.getattr(n);
    let l = zmux::PipeLiveness {
        suspect_floor: inherit(&get("suspect_floor")?, |x| field_secs("suspect_floor", x))?,
        dead_timeout: inherit(&get("dead_timeout")?, |x| field_secs("dead_timeout", x))?,
        probe_interval: inherit(&get("probe_interval")?, |x| {
            field_opt_secs("probe_interval", x)
        })?,
        probe_jitter: inherit(&get("probe_jitter")?, |x| {
            required("probe_jitter", x)?.extract()
        })?,
    };
    l.validate().map_err(value_err)?;
    Ok(l)
}

/// The `zmux.PipeLiveness` of native settings.
fn pipe_liveness_obj<'p>(py: Python<'p>, l: &zmux::PipeLiveness) -> PyResult<Bound<'p, PyAny>> {
    let secs = |d: Duration| Ok(d.as_secs_f64().into_pyobject(py)?.into_any());
    let d = PyDict::new(py);
    d.set_item("suspect_floor", inherit_obj(py, l.suspect_floor, secs)?)?;
    d.set_item("dead_timeout", inherit_obj(py, l.dead_timeout, secs)?)?;
    d.set_item(
        "probe_interval",
        inherit_obj(py, l.probe_interval, |d| {
            Ok(dur(d).into_pyobject(py)?.into_any())
        })?,
    )?;
    d.set_item(
        "probe_jitter",
        inherit_obj(py, l.probe_jitter, |j| Ok(j.into_pyobject(py)?.into_any()))?,
    )?;
    types(py)?.getattr("PipeLiveness")?.call((), Some(&d))
}

/// The library's defaults of the `zmux.Config` fields that hold values,
/// the one source of the Python defaults; `liveness` the defaults of
/// `zmux.Liveness`.
#[pyfunction]
fn _config_defaults(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let c = zmux::Config::default();
    let d = PyDict::new(py);
    d.set_item("handshake_timeout", dur(c.handshake_timeout))?;
    d.set_item("join_timeout", c.join_timeout.as_secs_f64())?;
    d.set_item("max_idle_timeout", dur(c.max_idle_timeout))?;
    d.set_item(
        "initial_stream_receive_window",
        c.initial_stream_receive_window,
    )?;
    d.set_item(
        "max_stream_receive_window",
        cap_obj(py, c.max_stream_receive_window)?,
    )?;
    d.set_item("latency_budget", c.latency_budget.as_secs_f64())?;
    d.set_item(
        "initial_connection_receive_window",
        c.initial_connection_receive_window,
    )?;
    d.set_item(
        "max_connection_receive_window",
        cap_obj(py, c.max_connection_receive_window)?,
    )?;
    d.set_item("memory_budget", c.memory_budget)?;
    d.set_item("max_incoming_streams", c.max_incoming_streams)?;
    d.set_item(
        "max_incoming_uni_streams",
        match c.max_incoming_uni_streams {
            zmux::UniCredit::Limit(n) => n.into_pyobject(py)?.into_any(),
            zmux::UniCredit::Staged => setting(py, "STAGED")?,
        },
    )?;
    d.set_item("enable_datagrams", c.enable_datagrams)?;
    d.set_item("datagram_send_queue", c.datagram_send_queue)?;
    d.set_item("datagram_receive_queue", c.datagram_receive_queue)?;
    d.set_item("datagram_stream_queue", c.datagram_stream_queue)?;
    d.set_item("datagram_receive_bytes", c.datagram_receive_bytes)?;
    d.set_item("datagram_stream_bytes", c.datagram_stream_bytes)?;
    d.set_item("send_buffer", c.send_buffer)?;
    d.set_item("send_buffer_max", cap_obj(py, c.send_buffer_max)?)?;
    d.set_item("max_pipes", c.max_pipes)?;
    d.set_item("pipe_headroom", c.pipe_headroom)?;
    d.set_item(
        "replay_window",
        match c.replay_window {
            zmux::Cap::Auto => setting(py, "AUTO")?,
            zmux::Cap::Fixed(n) => n.into_pyobject(py)?.into_any(),
        },
    )?;
    d.set_item("max_lanes", c.max_lanes.get())?;
    d.set_item("resume_timeout", dur(c.resume_timeout))?;
    d.set_item("join_early_hello", c.join_early_hello)?;
    d.set_item("scheduler", policy_name(&c.scheduler))?;
    d.set_item("spread_chunk", c.spread_chunk)?;
    d.set_item("probation", probation_obj(py, c.probation)?)?;
    d.set_item("overflow_delay", c.overflow_delay.as_secs_f64())?;
    d.set_item(
        "redundancy",
        match c.redundancy {
            zmux::Redundancy::Off => "off",
            _ => "urgent",
        },
    )?;
    d.set_item(
        "session_crypto",
        (&c.session_crypto.suites, &c.session_crypto.groups),
    )?;
    let e = c.epoch_policy;
    d.set_item(
        "epoch_policy",
        (dur(e.period), e.joins, e.after_first_pipe, e.after_resume),
    )?;
    let l = zmux::Liveness::default();
    let ld = PyDict::new(py);
    ld.set_item("keep_alive_period", dur(l.keep_alive_period))?;
    ld.set_item("suspect_floor", l.suspect_floor.as_secs_f64())?;
    ld.set_item("standby_probe", dur(l.standby_probe))?;
    ld.set_item("probe_interval", dur(l.probe_interval))?;
    ld.set_item("probe_jitter", l.probe_jitter)?;
    d.set_item("liveness", ld)?;
    Ok(d)
}

/// The library's defaults of the `zmux.ListenerConfig` fields that hold
/// values, the one source of the Python defaults.
#[pyfunction]
fn _listener_defaults(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let l = zmux::ListenerConfig::default();
    let d = PyDict::new(py);
    d.set_item("max_pending", l.max_pending)?;
    d.set_item("max_pending_per_source", l.max_pending_per_source)?;
    d.set_item("source_prefix_v4", l.source_prefix_v4)?;
    d.set_item("source_prefix_v6", l.source_prefix_v6)?;
    d.set_item("max_pending_per_session", l.max_pending_per_session)?;
    d.set_item("first_record_timeout", l.first_record_timeout.as_secs_f64())?;
    d.set_item("handshake_timeout", l.handshake_timeout.as_secs_f64())?;
    d.set_item("max_record_size", l.max_record_size)?;
    d.set_item("accept_sessions", l.accept_sessions)?;
    d.set_item("max_suspended", l.max_suspended)?;
    d.set_item("memory_budget", l.memory_budget)?;
    Ok(d)
}

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (**fields))]
    fn new(fields: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut c = zmux::Config::default();
        let mut early = zmux::EarlyData::default();
        let (mut shaping_kinds, mut shaping_variants) = (None, None);
        for (k, v) in fields.into_iter().flatten() {
            let k: String = k.extract()?;
            let v = &v;
            // Hooks: `None` is none.
            let hook = !v.is_none();
            match k.as_str() {
                "handshake_timeout" => c.handshake_timeout = field_opt_secs(&k, v)?,
                "join_timeout" => c.join_timeout = field_secs(&k, v)?,
                "max_idle_timeout" => c.max_idle_timeout = field_opt_secs(&k, v)?,
                "liveness" => c.liveness = liveness(required(&k, v)?)?,
                "initial_stream_receive_window" => {
                    c.initial_stream_receive_window = field_count(&k, v)?;
                }
                "max_stream_receive_window" => c.max_stream_receive_window = field_cap(&k, v)?,
                "latency_budget" => c.latency_budget = field_secs(&k, v)?,
                "initial_connection_receive_window" => {
                    c.initial_connection_receive_window = field_count(&k, v)?;
                }
                "max_connection_receive_window" => {
                    c.max_connection_receive_window = field_cap(&k, v)?;
                }
                "memory_budget" => {
                    c.memory_budget = if v.is_none() {
                        None
                    } else {
                        Some(field_count(&k, v)?)
                    };
                }
                "max_incoming_streams" => c.max_incoming_streams = field_count(&k, v)?,
                "max_incoming_uni_streams" => {
                    c.max_incoming_uni_streams = if is_setting(v, "STAGED")? {
                        zmux::UniCredit::Staged
                    } else {
                        zmux::UniCredit::Limit(field_count(&k, v)?)
                    };
                }
                "enable_datagrams" => c.enable_datagrams = required(&k, v)?.extract()?,
                "datagram_send_queue" => c.datagram_send_queue = field_count(&k, v)?,
                "datagram_receive_queue" => c.datagram_receive_queue = field_count(&k, v)?,
                "datagram_stream_queue" => c.datagram_stream_queue = field_count(&k, v)?,
                "datagram_receive_bytes" => c.datagram_receive_bytes = field_count(&k, v)?,
                "datagram_stream_bytes" => {
                    c.datagram_stream_bytes = if v.is_none() {
                        None
                    } else {
                        Some(field_count(&k, v)?)
                    };
                }
                "send_buffer" => c.send_buffer = field_count(&k, v)?,
                "send_buffer_max" => c.send_buffer_max = field_cap(&k, v)?,
                "max_pipes" => c.max_pipes = field_count(&k, v)?,
                "pipe_headroom" => c.pipe_headroom = field_count(&k, v)?,
                "replay_window" => c.replay_window = field_cap(&k, v)?,
                "max_lanes" => {
                    c.max_lanes = std::num::NonZeroU64::new(field_count(&k, v)?)
                        .ok_or_else(|| PyValueError::new_err("max_lanes is at least 1"))?;
                }
                "resume_timeout" => {
                    c.resume_timeout = field_opt_secs(&k, v)?;
                    if c.resume_timeout.is_some_and(|d| d.is_zero()) {
                        return Err(PyValueError::new_err(
                            "resume_timeout is at least 0.001 s; None turns resume off",
                        ));
                    }
                }
                "redial_backoff" => c.redial_backoff = backoff_of(required(&k, v)?)?,
                "join_early_hello" => {
                    c.join_early_hello = if v.is_none() {
                        None
                    } else {
                        Some(field_count(&k, v)?)
                    };
                }
                "scheduler" => c.scheduler = policy(&required(&k, v)?.str()?.extract::<String>()?)?,
                "spread_chunk" => c.spread_chunk = field_count(&k, v)?,
                "probation" => c.probation = probation_of(&k, v)?,
                "overflow_delay" => c.overflow_delay = field_secs(&k, v)?,
                "redundancy" => {
                    c.redundancy = match required(&k, v)?.str()?.extract::<String>()?.as_str() {
                        "urgent" => zmux::Redundancy::Urgent,
                        "off" => zmux::Redundancy::Off,
                        r => {
                            return Err(PyValueError::new_err(format!(
                                "redundancy is \"urgent\" or \"off\", not {r:?}"
                            )));
                        }
                    };
                }
                "session_crypto" => c.session_crypto = seal::session_crypto_of(required(&k, v)?)?,
                "epoch_policy" => c.epoch_policy = epoch_policy(required(&k, v)?)?,
                "early_data" => early.zmux_peer = required(&k, v)?.extract()?,
                "carrier_early_data" => early.carrier_early_data = required(&k, v)?.extract()?,
                "hold_first_flight" => early.hold_first_flight = required(&k, v)?.extract()?,
                "shaping_limits" => c.shaping_limits = shaping::limits_of(required(&k, v)?)?,
                "pipe_auth" if hook => c.pipe_auth = pipe_auth(v)?,
                "redial" if hook => c.redial = Some(helpers::redial_of(v)?),
                "logger" if hook => c.logger = Some(logger_of(v)),
                "tracer" if hook => c.tracer = Some(Arc::new(PyTracer(v.clone().unbind()))),
                "authorize_join" if hook => {
                    c.authorize_join = Some(authorize_join(v.clone().unbind()));
                }
                "record_policy" if hook => {
                    c.record_policy = Some(seal::record_policy(v.clone().unbind()));
                }
                "allow_record_mode" if hook => {
                    c.allow_record_mode = Some(seal::allow_record_mode(v.clone().unbind()));
                }
                "protocols" if hook => c.protocols = Some(v.extract()?),
                "shaping_budget" if hook => {
                    c.shaping_budget = Some(shaping::budget_hook(v.clone().unbind()));
                }
                "shaping" if hook => shaping_kinds = Some(v.clone()),
                "handshake_shaper" if hook => c.handshake_shaper = Some(shaping::hook_of(v)),
                "shaping_bundle" if hook => {
                    let b = v.cast::<shaping::ShapingBundle>()?.get().0.clone();
                    c.handshake_shaper = Some(b.handshake_shaper());
                    if c.shaping_budget.is_none() {
                        c.shaping_budget = b
                            .resolve("default")
                            .and_then(zmux_shaping::Compiled::budget);
                    }
                    c.shaper = Some(b);
                }
                "shaping_by_variant" if hook => shaping_variants = Some(v.clone()),
                "pipe_auth" | "redial" | "logger" | "tracer" | "authorize_join"
                | "record_policy" | "allow_record_mode" | "protocols" | "shaping_budget"
                | "shaping" | "handshake_shaper" | "shaping_bundle" | "shaping_by_variant" => {}
                _ => return Err(PyTypeError::new_err(format!("unknown Config field {k:?}"))),
            }
        }
        c.early_data = early;
        if shaping_kinds.is_some() || shaping_variants.is_some() {
            let f = shaping::by_carrier(
                shaping_kinds.as_ref(),
                shaping_variants.as_ref(),
                &zmux_shaping::Options::default(),
            )?;
            c.shaper = Some(Arc::new(f));
        }
        c.validate().map_err(value_err)?;
        Ok(Config(Arc::new(c)))
    }
}

/// The native configuration of a `zmux.Config` (or of this class itself).
fn cfg(c: Option<Bound<'_, PyAny>>) -> PyResult<Arc<zmux::Config>> {
    let Some(c) = c else {
        return Ok(Arc::default());
    };
    let n = if c.is_instance_of::<Config>() {
        c
    } else {
        c.getattr("_native")?
    };
    Ok(n.extract::<PyRef<'_, Config>>()?.0.clone())
}

/// TLS settings for the TLS and QUIC carriers (rustls). PEM `str` arguments are
/// file paths, `bytes` arguments are PEM contents.
#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct TlsConfig {
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    ca: Option<Vec<u8>>,
    verify: bool,
    alpn: Vec<Vec<u8>>,
}

#[derive(FromPyObject)]
enum Pem {
    Path(std::path::PathBuf),
    Data(Vec<u8>),
}

impl Pem {
    fn load(self) -> PyResult<Vec<u8>> {
        match self {
            Pem::Path(p) => std::fs::read(&p)
                .map_err(|e| PyValueError::new_err(format!("{}: {e}", p.display()))),
            Pem::Data(d) => Ok(d),
        }
    }
}

/// zmux's ALPN identifiers.
fn zmux_alpn() -> Vec<Vec<u8>> {
    zmux::alpn_protocols(&[])
}

/// HTTP/1.1's ALPN identifier.
fn http1() -> Vec<Vec<u8>> {
    vec![HTTP1.to_vec()]
}

fn pem_err(e: impl Display) -> PyErr {
    PyValueError::new_err(format!("invalid PEM: {e}"))
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

type Chain = (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
);

impl TlsConfig {
    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn chain(&self) -> PyResult<Option<Chain>> {
        use rustls::pki_types::pem::PemObject;
        let (Some(cert), Some(key)) = (&self.cert, &self.key) else {
            return Ok(None);
        };
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(pem_err)?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key).map_err(pem_err)?;
        Ok(Some((certs, key)))
    }

    fn client(&self) -> PyResult<rustls::ClientConfig> {
        use rustls::pki_types::pem::PemObject;
        let builder = rustls::ClientConfig::builder_with_provider(Self::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let builder = if self.verify {
            let mut roots = rustls::RootCertStore::empty();
            match &self.ca {
                Some(ca) => {
                    for c in rustls::pki_types::CertificateDer::pem_slice_iter(ca) {
                        roots
                            .add(c.map_err(pem_err)?)
                            .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            builder.with_root_certificates(roots)
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(Self::provider())))
        };
        let mut c = match self.chain()? {
            Some((certs, key)) => builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
            None => builder.with_no_client_auth(),
        };
        c.alpn_protocols.clone_from(&self.alpn);
        Ok(c)
    }

    /// The client configuration with `defaults` when no ALPN is set.
    fn client_alpn(
        &self,
        defaults: impl FnOnce() -> Vec<Vec<u8>>,
    ) -> PyResult<rustls::ClientConfig> {
        let mut c = self.client()?;
        zmux::default_alpn(&mut c.alpn_protocols, defaults);
        Ok(c)
    }

    /// The server configuration with `defaults` when no ALPN is set.
    fn server_alpn(
        &self,
        defaults: impl FnOnce() -> Vec<Vec<u8>>,
    ) -> PyResult<rustls::ServerConfig> {
        let mut c = self.server()?;
        zmux::default_alpn(&mut c.alpn_protocols, defaults);
        Ok(c)
    }

    /// The client configuration of a zmux carrier: zmux's ALPN
    /// identifiers when none is set.
    fn client_zmux(&self) -> PyResult<rustls::ClientConfig> {
        self.client_alpn(zmux_alpn)
    }

    /// The server configuration of a zmux carrier: zmux's ALPN
    /// identifiers when none is set.
    fn server_zmux(&self) -> PyResult<rustls::ServerConfig> {
        self.server_alpn(zmux_alpn)
    }

    /// Verification against the bundled web roots, no client certificate.
    fn web() -> Self {
        TlsConfig {
            cert: None,
            key: None,
            ca: None,
            verify: true,
            alpn: Vec::new(),
        }
    }

    fn server(&self) -> PyResult<rustls::ServerConfig> {
        let (certs, key) = self
            .chain()?
            .ok_or_else(|| PyValueError::new_err("a server needs cert and key"))?;
        let mut c = rustls::ServerConfig::builder_with_provider(Self::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| PyValueError::new_err(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        c.alpn_protocols.clone_from(&self.alpn);
        Ok(c)
    }
}

#[pymethods]
impl TlsConfig {
    #[new]
    #[pyo3(signature = (*, cert=None, key=None, ca=None, verify=true, alpn=None))]
    fn new(
        cert: Option<Pem>,
        key: Option<Pem>,
        ca: Option<Pem>,
        verify: bool,
        alpn: Option<Vec<String>>,
    ) -> PyResult<Self> {
        Ok(TlsConfig {
            cert: cert.map(Pem::load).transpose()?,
            key: key.map(Pem::load).transpose()?,
            ca: ca.map(Pem::load).transpose()?,
            verify,
            alpn: alpn
                .unwrap_or_default()
                .into_iter()
                .map(String::into_bytes)
                .collect(),
        })
    }
}

// ---- pipes ----------------------------------------------------------------------------

/// A carrier's unsent count that the application keeps up to date
/// (`set`), typically at each write to the carrier; the session reads it
/// from its driver without the interpreter lock (`PipeIo.with_unsent`).
#[pyclass(frozen, module = "zmux")]
struct UnsentCount(Arc<std::sync::atomic::AtomicU64>);

impl UnsentCount {
    /// `None` is stored as `u64::MAX`.
    fn decode(c: &std::sync::atomic::AtomicU64) -> Option<u64> {
        match c.load(std::sync::atomic::Ordering::Relaxed) {
            u64::MAX => None,
            n => Some(n),
        }
    }
}

#[pymethods]
impl UnsentCount {
    /// A count of `n` bytes, `None` (the default) when the carrier cannot
    /// tell.
    #[new]
    #[pyo3(signature = (n=None))]
    fn new(n: Option<u64>) -> Self {
        Self(Arc::new(std::sync::atomic::AtomicU64::new(
            n.map_or(u64::MAX, |n| n.min(u64::MAX - 1)),
        )))
    }

    /// Sets the count: the bytes the carrier took and has not yet
    /// transmitted, or `None`.
    #[pyo3(signature = (n))]
    fn set(&self, n: Option<u64>) {
        self.0.store(
            n.map_or(u64::MAX, |n| n.min(u64::MAX - 1)),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// The count as last set.
    #[getter]
    fn value(&self) -> Option<u64> {
        Self::decode(&self.0)
    }
}

/// One call of a Python exporter; an exception, or a value of another length,
/// is reported as unraisable and gives none.
fn export_value(
    py: Python<'_>,
    export: &Py<PyAny>,
    label: &str,
    context: &[u8],
    length: usize,
) -> Option<Vec<u8>> {
    let r = export
        .call1(py, (label, PyBytes::new(py, context), length))
        .and_then(|v| v.extract::<Option<Vec<u8>>>(py))
        .and_then(|v| match v {
            Some(v) if v.len() != length => Err(PyValueError::new_err(format!(
                "the exporter gave {} bytes for {length}",
                v.len()
            ))),
            v => Ok(v),
        });
    r.unwrap_or_else(|e| {
        e.write_unraisable(py, Some(export.bind(py)));
        None
    })
}

/// A Python exporter as the native one. The session never holds its lock
/// around it, so a runtime thread may wait for the interpreter here.
fn call_exporter(export: &Arc<Py<PyAny>>, label: &str, context: &[u8], out: &mut [u8]) -> bool {
    let length = out.len();
    let value = rt::attach(|py| export_value(py, export, label, context, length));
    match value {
        Some(v) => {
            out.copy_from_slice(&v);
            true
        }
        None => false,
    }
}

/// The `zmux.TlsState` of a handshake.
pub(crate) fn tls_state_obj<'p>(py: Python<'p>, s: &zmux::TlsState) -> PyResult<Bound<'p, PyAny>> {
    let alpn = s.alpn.as_deref().map(|a| PyBytes::new(py, a));
    types(py)?
        .getattr("TlsState")?
        .call1((alpn, s.server_name.as_deref()))
}

/// A carrier connection not yet given to a session; usable once.
#[pyclass(frozen, module = "zmux")]
struct PipeIo(StdMutex<Option<zmux::PipeIo>>);

impl PipeIo {
    fn wrap(io: zmux::PipeIo) -> Self {
        PipeIo(StdMutex::new(Some(io)))
    }
    fn take(&self) -> PyResult<zmux::PipeIo> {
        self.0.lock().unwrap().take().ok_or_else(used)
    }
}

impl PipeIo {
    /// Changes the carrier in place.
    fn modify(&self, f: impl FnOnce(zmux::PipeIo) -> zmux::PipeIo) -> PyResult<()> {
        let mut g = self.0.lock().unwrap();
        let io = g.take().ok_or_else(used)?;
        *g = Some(f(io));
        Ok(())
    }

    /// Reads the carrier.
    fn read<T>(&self, f: impl FnOnce(&zmux::PipeIo) -> T) -> PyResult<T> {
        let g = self.0.lock().unwrap();
        Ok(f(g.as_ref().ok_or_else(used)?))
    }
}

fn used() -> PyErr {
    new_err(
        "PipeUsedError",
        "the pipe input was given to a session already",
    )
}

/// The settings of a pipe input, writable until it is given to a session.
#[pymethods]
impl PipeIo {
    /// The carrier kind (`CarrierKind`), or `None`: what a by-kind shaper
    /// picks by, and the kind in pipe events and statistics.
    #[getter]
    fn carrier_kind<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        let k = self.read(zmux::PipeIo::carrier)?;
        Ok(k.map(|k| typed(py, "CarrierKind", k.name().to_owned())))
    }

    #[setter]
    fn set_carrier_kind(&self, kind: &Bound<'_, PyAny>) -> PyResult<()> {
        let k = shaping::carrier_kind(kind)?;
        self.modify(|io| io.with_carrier(k))
    }

    /// The fixed bytes (0 to 65535) the layers below zmux add to each write
    /// on the carrier, such as a wrapping layer's record header and tag,
    /// which a shaper takes into account; zmux does not otherwise use it.
    #[getter]
    fn write_overhead(&self) -> PyResult<u16> {
        self.read(zmux::PipeIo::write_overhead)
    }

    #[setter]
    fn set_write_overhead(&self, overhead: i64) -> PyResult<()> {
        let n = u16::try_from(overhead)
            .map_err(|_| PyValueError::new_err("write_overhead is between 0 and 65535"))?;
        self.modify(|io| io.with_write_overhead(n))
    }

    /// Declares the carrier secure: it meets the secure carrier's Bound
    /// contract, record confidentiality and integrity included (an
    /// exporter alone is no such declaration), so a record policy may
    /// choose Bound on it.
    fn declare_secure(&self) -> PyResult<()> {
        self.modify(zmux::PipeIo::with_carrier_secure)
    }

    /// The host's name of the transform the carrier runs, or `None`:
    /// reported in `PipeStats.variant`, and what a shaper by variant picks
    /// by.
    #[getter]
    fn variant(&self) -> PyResult<Option<String>> {
        self.read(|io| io.variant().map(ToString::to_string))
    }

    #[setter]
    fn set_variant(&self, variant: &str) -> PyResult<()> {
        self.modify(|io| io.with_variant(variant))
    }

    /// What the TLS or QUIC handshake this process ran for the carrier
    /// negotiated (`TlsState`), or `None`. Assigning a `TlsState` declares
    /// such a handshake, complete.
    #[getter]
    fn terminated_tls<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        // Python runs with the lock released: a thread that waits for it holds the
        // interpreter.
        let state = self.read(zmux::PipeIo::terminated_tls)?;
        state.map(|s| tls_state_obj(py, &s)).transpose()
    }

    #[setter]
    fn set_terminated_tls(&self, state: &Bound<'_, PyAny>) -> PyResult<()> {
        let alpn: Option<Vec<u8>> = state.getattr("alpn")?.extract()?;
        let server_name: Option<String> = state.getattr("server_name")?.extract()?;
        let state = zmux::TlsState::new(alpn, server_name);
        self.modify(move |io| io.with_terminated_tls(move || Some(state.clone())))
    }

    /// The carrier's halves as one byte stream (`CarrierStream`), for a
    /// layer that runs over a stream; bytes a listener already read from it
    /// come first. Every other property of the carrier is dropped (`wrap`
    /// keeps them). This object is used up.
    #[allow(clippy::wrong_self_convention)] // Python's name; the object is used up
    fn into_stream(&self) -> PyResult<layer::CarrierStream> {
        Ok(layer::CarrierStream::new(self.take()?.into_stream()))
    }

    /// Runs a layer over the carrier: `layer(reader, writer)`, given the
    /// carrier as an asyncio stream pair, returns the layer's pair (for
    /// example after `writer.start_tls(...)`), which becomes the carrier's
    /// halves. The carrier keeps its framing, kind and other properties.
    /// Each write on the result is one write on the layer's writer, then a
    /// drain, so that a layer that writes once below for each write on it
    /// (asyncio's TLS does) keeps one carrier write per write. With
    /// `server_side`, `writer.start_tls` takes the server side. This object
    /// is used up; needs a running event loop, on which the layer runs.
    #[pyo3(name = "wrap", signature = (layer, *, server_side=false))]
    fn wrap_layer<'p>(
        &self,
        py: Python<'p>,
        layer: Py<PyAny>,
        server_side: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
        let io = self.take()?;
        future_into_py(py, async move {
            let io = layer::wrap(io, layer, server_side, locals)
                .await
                .map_err(io_err)?;
            Ok(PipeIo::wrap(io))
        })
    }
}

/// The far end of `pipe_pair()`: bytes written here are what the pipe reads.
#[pyclass(frozen, module = "zmux")]
struct PipeEnd {
    r: Arc<Mutex<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    /// Bytes of reads cancelled as they completed.
    unread: Returned<Bytes>,
    w: Arc<Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
}

#[pymethods]
impl PipeEnd {
    /// Up to `n` bytes the session wrote; `b""` once the session side closed.
    #[pyo3(signature = (n=65536))]
    fn read<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let (r, unread) = (self.r.clone(), self.unread.queue());
        let undo = self.unread.undo(py)?;
        rt::undoable_future_into_py(
            py,
            async move {
                // Held until the result is settled: bytes taken back come first.
                let mut r = r.lock_owned().await;
                if let Some(b) = unread_take(&unread, n) {
                    return Ok((pyb(&b), r));
                }
                let mut buf = vec![0u8; n];
                let k = r.read(&mut buf).await.unwrap_or(0);
                buf.truncate(k);
                Ok((pyb(&buf), r))
            },
            undo,
        )
    }
    /// Feeds `data` to the session; `b""` signals end of input.
    fn write<'p>(&self, py: Python<'p>, data: Vec<u8>) -> PyResult<Bound<'p, PyAny>> {
        let w = self.w.clone();
        future_into_py(py, async move {
            let mut w = w.lock().await;
            let r = if data.is_empty() {
                w.shutdown().await
            } else {
                w.write_all(&data).await
            };
            r.map_err(io_err)
        })
    }
}

/// An in-memory pipe whose other end Python drives (the stream-pair entry).
/// `carrier_kind`: the pipe's carrier kind (`PipeIo.carrier_kind`); `unsent`,
/// the carrier's unsent count the application keeps up to date; `max_record`,
/// the largest record plaintext (at least 1) the carrier takes, applied
/// beside the peer's `max_record_size`; `exporter(label, context, length)`,
/// the exporter of the carrier's innermost end-to-end handshake.
#[pyfunction]
#[pyo3(signature = (*, carrier_kind=None, unsent=None, max_record=None, exporter=None))]
fn pipe_pair(
    carrier_kind: Option<Bound<'_, PyAny>>,
    unsent: Option<PyRef<'_, UnsentCount>>,
    max_record: Option<usize>,
    exporter: Option<Py<PyAny>>,
) -> PyResult<(PipeIo, PipeEnd)> {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (r, w) = tokio::io::split(b);
    let mut io = zmux::PipeIo::new(a);
    if let Some(k) = carrier_kind {
        io = io.with_carrier(shaping::carrier_kind(&k)?);
    }
    if let Some(count) = unsent {
        let c = count.0.clone();
        io = io.with_unsent(move || UnsentCount::decode(&c));
    }
    if let Some(size) = max_record {
        if size == 0 {
            return Err(PyValueError::new_err("max_record is at least 1"));
        }
        io = io.with_max_record(size);
    }
    if let Some(export) = exporter {
        let export = Arc::new(export);
        io = io
            .with_exporter(move |label, context, out| call_exporter(&export, label, context, out));
    }
    Ok((
        PipeIo::wrap(io),
        PipeEnd {
            r: Arc::new(Mutex::new(r)),
            unread: Returned::default(),
            w: Arc::new(Mutex::new(w)),
        },
    ))
}

async fn resolve(addr: &str) -> PyResult<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await
        .map_err(io_err)?
        .next()
        .ok_or_else(|| PyValueError::new_err("no address"))
}

/// [`resolve`] inside a carrier's dial, where errors are I/O errors.
async fn lookup(addr: &str) -> std::io::Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address"))
}

#[pyfunction]
#[pyo3(signature = (host, port, *, carrier_credential=None))]
fn dial_tcp<'p>(
    py: Python<'p>,
    host: String,
    port: u16,
    carrier_credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let credential = admission::carrier_credential(carrier_credential)?;
    future_into_py(py, async move {
        let mut tcp = tokio::net::TcpStream::connect(addr).await.map_err(io_err)?;
        if let Some(c) = credential {
            let prefix = {
                let mut info = zmux::CarrierInfo::new();
                if let Ok(peer) = tcp.peer_addr() {
                    info = info.with_source(peer).with_peer(peer);
                }
                c.prefix(&info).map_err(io_err)?
            };
            tcp.write_all(&prefix).await.map_err(io_err)?;
        }
        Ok(PipeIo::wrap(zmux::PipeIo::from_tcp(tcp)))
    })
}

/// The client TLS settings, by default the bundled web roots.
fn client_tls(tls: Option<PyRef<'_, TlsConfig>>) -> TlsConfig {
    tls.map_or_else(TlsConfig::web, |t| t.clone())
}

#[pyfunction]
#[pyo3(signature = (host, port, *, tls=None, server_name=None, carrier_credential=None))]
fn dial_tls<'p>(
    py: Python<'p>,
    host: String,
    port: u16,
    tls: Option<PyRef<'_, TlsConfig>>,
    server_name: Option<String>,
    carrier_credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let c = Arc::new(client_tls(tls).client_zmux()?);
    let server_name = server_name.unwrap_or_else(|| host_of(&addr));
    let credential = admission::carrier_credential(carrier_credential)?;
    future_into_py(py, async move {
        let mut options = zmux_rustls::Options::new();
        if let Some(c) = credential {
            options = options.with_carrier_credential(c);
        }
        let io = zmux_rustls::dial(addr, &server_name, c, &options).await;
        Ok(PipeIo::wrap(io.map_err(io_err)?))
    })
}

fn quic_options(lanes: u32) -> zmux_quinn::Options {
    zmux_quinn::Options::default().with_windows(zmux_quinn::LaneWindows::new().with_lanes(lanes))
}

/// How a QUIC carrier to one server is opened: by `dial_quic`, and by
/// every dial of `Candidate.quic`.
#[derive(Clone)]
pub(crate) struct QuicDial {
    addr: String,
    server_name: String,
    qc: quinn::ClientConfig,
    opts: zmux_quinn::Options,
}

impl QuicDial {
    pub(crate) fn new(
        addr: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut opts = quic_options(lanes);
        if let Some(c) = admission::carrier_credential(carrier_credential)? {
            opts = opts.with_carrier_credential(c);
        }
        let server_name = server_name.unwrap_or_else(|| host_of(&addr));
        let qc = zmux_quinn::client_config(client_tls(tls).client_zmux()?, &opts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            addr,
            server_name,
            qc,
            opts,
        })
    }

    /// A pipe on a new connection, from an endpoint of its own.
    pub(crate) async fn open(&self) -> std::io::Result<zmux::PipeIo> {
        let addr = lookup(&self.addr).await?;
        let mut ep = quinn::Endpoint::client(bind_for(&addr))?;
        ep.set_default_client_config(self.qc.clone());
        zmux_quinn::dial(&ep, addr, &self.server_name, &self.opts).await
    }
}

#[pyfunction]
#[pyo3(signature = (host, port, *, tls=None, server_name=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
fn dial_quic<'p>(
    py: Python<'p>,
    host: String,
    port: u16,
    tls: Option<PyRef<'_, TlsConfig>>,
    server_name: Option<String>,
    lanes: u32,
    carrier_credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let d = QuicDial::new(addr, tls, server_name, lanes, carrier_credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(d.open().await.map_err(io_err)?))
    })
}

/// A configuration or argument error of the core: a `ValueError` of zmux.
fn value_err(e: impl Display) -> PyErr {
    new_err("InvalidArgumentError", e.to_string())
}

const HTTP1: &[u8] = b"http/1.1";

/// `ws://` or `wss://` (TLS with `tls`, by default the bundled web roots);
/// `headers` are added to the upgrade request, with the credential's
/// header field. With `no_subprotocol` the request offers no subprotocol.
#[pyfunction]
#[pyo3(signature = (url, *, tls=None, headers=None, carrier_credential=None, no_subprotocol=false))]
fn dial_websocket<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    headers: Option<Bound<'p, PyAny>>,
    carrier_credential: Option<Bound<'p, PyAny>>,
    no_subprotocol: bool,
) -> PyResult<Bound<'p, PyAny>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
    let mut opts = zmux_websocket::Options::default().with_no_subprotocol(no_subprotocol);
    if let Some(c) = admission::carrier_credential(carrier_credential)? {
        opts = opts.with_carrier_credential(c);
    }
    let headers: Option<Vec<(String, String)>> = match headers {
        Some(h) if h.hasattr("items")? => Some(
            py.import("builtins")?
                .getattr("list")?
                .call1((h.call_method0("items")?,))?
                .extract()?,
        ),
        Some(h) => Some(h.extract()?),
        None => None,
    };
    let mut req = url.as_str().into_client_request().map_err(value_err)?;
    for (k, v) in headers.unwrap_or_default() {
        req.headers_mut().insert(
            HeaderName::from_bytes(k.as_bytes()).map_err(value_err)?,
            HeaderValue::from_str(&v).map_err(value_err)?,
        );
    }
    let connector = if req.uri().scheme_str() == Some("wss") {
        let c = match tls {
            Some(t) => t.client_alpn(http1)?,
            None => TlsConfig::web().client_alpn(http1)?,
        };
        Some(tokio_rustls::TlsConnector::from(Arc::new(c)))
    } else {
        None
    };
    future_into_py(py, async move {
        let io = match connector {
            Some(c) => zmux_websocket::dial_tls(req, &c, &opts).await,
            None => zmux_websocket::dial(req, &opts).await,
        }
        .map_err(io_err)?;
        Ok(PipeIo::wrap(io))
    })
}

/// An HTTP/2 connection whose exchanges carry pipes: prior knowledge
/// without `tls`, ALPN `h2` with it.
#[pyclass(frozen, module = "zmux")]
struct Http2Connection(zmux_http::Http2Connection);

#[pymethods]
impl Http2Connection {
    #[staticmethod]
    #[pyo3(signature = (host, port, *, path="/zmux".to_owned(), tls=None, server_name=None, carrier_credential=None, pair_field=None))]
    #[allow(clippy::too_many_arguments)]
    fn dial<'p>(
        py: Python<'p>,
        host: String,
        port: u16,
        path: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        carrier_credential: Option<Bound<'p, PyAny>>,
        pair_field: Option<String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let opts = http_client_options(path, carrier_credential, pair_field)?;
        let tls = tls
            .map(|t| t.client_alpn(|| vec![b"h2".to_vec()]))
            .transpose()?
            .map(|c| tokio_rustls::TlsConnector::from(Arc::new(c)));
        future_into_py(py, async move {
            let conn = match tls {
                None => zmux_http::Http2Connection::connect(&addr, opts).await,
                Some(c) => {
                    let host = server_name.unwrap_or_else(|| host_of(&addr));
                    let name = rustls::pki_types::ServerName::try_from(host).map_err(value_err)?;
                    let tcp = tokio::net::TcpStream::connect(&addr)
                        .await
                        .map_err(io_err)?;
                    let _ = tcp.set_nodelay(true);
                    let io = c.connect(name, tcp).await.map_err(io_err)?;
                    let io = zmux_rustls::TlsConnection::new(io);
                    zmux_http::Http2Connection::handshake(io, &addr, opts.with_https(true)).await
                }
            }
            .map_err(io_err)?;
            Ok(Http2Connection(conn))
        })
    }

    /// A pipe input on a new request of the connection, of `direction`
    /// (`Direction`; see `dial_streaming`).
    #[pyo3(signature = (*, direction="bidi".to_owned()))]
    fn open_pipe<'p>(&self, py: Python<'p>, direction: String) -> PyResult<Bound<'p, PyAny>> {
        let request = dial_request(&direction)?;
        let c = self.0.clone();
        future_into_py(py, async move {
            Ok(PipeIo::wrap(
                c.open_carrier(&request).await.map_err(io_err)?,
            ))
        })
    }

    /// A split bootstrap on two new requests of the connection.
    fn open_split<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let c = self.0.clone();
        future_into_py(py, async move {
            Ok(PipeIo::wrap(c.open_split().await.map_err(io_err)?))
        })
    }

    /// Joins a split carrier on two new requests of the connection to
    /// `session` as two further pipes (see `join_split`).
    #[pyo3(signature = (session, *, options=None))]
    fn join_split<'p>(
        &self,
        py: Python<'p>,
        session: Bound<'p, Session>,
        options: Option<Bound<'p, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let po = pipe_options(options)?;
        let (c, s) = (self.0.clone(), session.get().0.clone());
        let owner = session.unbind();
        future_into_py(py, async move {
            let pipes = c.join_split(&s, po).await.map_err(io_err)?;
            Ok(pipes_of(pipes, &owner))
        })
    }
}

/// `host:port` as the standard library takes it: an IPv6 host in brackets.
pub(crate) fn hostport(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A reported address as `(host, port)`.
pub(crate) fn host_port(a: SocketAddr) -> (String, u16) {
    (a.ip().to_string(), a.port())
}

/// The host part of `host:port`, without IPv6 brackets.
fn host_of(addr: &str) -> String {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned()
}

fn bind_for(addr: &SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// The `host:port` of an `https://` URL.
fn authority_of(uri: &http::Uri) -> PyResult<String> {
    let host = uri
        .host()
        .ok_or_else(|| PyValueError::new_err("URL without a host"))?;
    Ok(format!("{host}:{}", uri.port_u16().unwrap_or(443)))
}

/// How an HTTP/3 carrier is opened: a request to `url` (`https://`) on a
/// new connection to `addr` when given, else to the URL's host and port;
/// by `dial_http3`, and by every dial of `Candidate.http3`.
#[derive(Clone)]
pub(crate) struct H3Dial {
    uri: http::Uri,
    addr: String,
    qc: quinn::ClientConfig,
    opts: zmux_h3::Options,
}

impl H3Dial {
    pub(crate) fn new(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        addr: Option<(String, u16)>,
        lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let uri: http::Uri = url.parse().map_err(value_err)?;
        let addr = match addr {
            Some((h, p)) => hostport(&h, p),
            None => authority_of(&uri)?,
        };
        let mut opts =
            zmux_h3::Options::new().with_windows(zmux_h3::LaneWindows::new().with_lanes(lanes));
        if let Some(c) = admission::carrier_credential(carrier_credential)? {
            opts = opts.with_carrier_credential(c);
        }
        let qc = zmux_h3::client_config(client_tls(tls).client()?, &opts).map_err(value_err)?;
        Ok(Self {
            uri,
            addr,
            qc,
            opts,
        })
    }

    /// A pipe on a new connection, from an endpoint of its own.
    pub(crate) async fn open(&self) -> std::io::Result<zmux::PipeIo> {
        let addr = lookup(&self.addr).await?;
        let mut ep = quinn::Endpoint::client(bind_for(&addr))?;
        ep.set_default_client_config(self.qc.clone());
        zmux_h3::dial(&ep, addr, self.uri.clone(), &self.opts).await
    }
}

/// A pipe on a new HTTP/3 connection: a request to `url` (`https://`),
/// to `addr` when given, else to the URL's host and port.
#[pyfunction]
#[pyo3(signature = (url, *, tls=None, addr=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
fn dial_http3<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    addr: Option<(String, u16)>,
    lanes: u32,
    carrier_credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let d = H3Dial::new(url, tls, addr, lanes, carrier_credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(d.open().await.map_err(io_err)?))
    })
}

use zmux_webtransport::web_transport_quinn as wt;

/// How a WebTransport carrier is opened: a session to `url` (`https://`),
/// on a new QUIC connection to the URL's host, whose exporter a bound
/// credential is given; by `dial_webtransport`, and by every dial of
/// `Candidate.webtransport`.
#[derive(Clone)]
pub(crate) struct WebTransportDial {
    url: zmux_webtransport::Url,
    host: String,
    authority: String,
    qc: quinn::ClientConfig,
    opts: zmux_webtransport::Options,
}

impl WebTransportDial {
    pub(crate) fn new(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let url: zmux_webtransport::Url = url.parse().map_err(value_err)?;
        let host = url
            .host_str()
            .ok_or_else(|| PyValueError::new_err("URL without a host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let authority = format!(
            "{}:{}",
            url.host_str().unwrap_or_default(),
            url.port_or_known_default().unwrap_or(443)
        );
        let mut opts = zmux_webtransport::Options::new()
            .with_windows(zmux_webtransport::LaneWindows::new().with_lanes(lanes));
        if let Some(c) = admission::carrier_credential(carrier_credential)? {
            opts = opts.with_carrier_credential(c);
        }
        let mut c = client_tls(tls).client()?;
        c.alpn_protocols = vec![wt::ALPN.as_bytes().to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(c).map_err(value_err)?;
        let mut qc = quinn::ClientConfig::new(Arc::new(crypto));
        qc.transport_config(Arc::new(opts.transport_config()));
        Ok(Self {
            url,
            host,
            authority,
            qc,
            opts,
        })
    }

    /// A pipe on a new connection, from an endpoint of its own.
    pub(crate) async fn open(&self) -> std::io::Result<zmux::PipeIo> {
        let addr = lookup(&self.authority).await?;
        let ep = quinn::Endpoint::client(bind_for(&addr))?;
        let conn = ep
            .connect_with(self.qc.clone(), addr, &self.host)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .await
            .map_err(std::io::Error::other)?;
        zmux_webtransport::dial_over(conn, self.url.clone(), &self.opts).await
    }
}

/// A pipe on a new WebTransport session to `url` (`https://`), on a QUIC
/// connection to the URL's host, whose exporter a bound credential is
/// given.
#[pyfunction]
#[pyo3(signature = (url, *, tls=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
fn dial_webtransport<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    lanes: u32,
    carrier_credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let d = WebTransportDial::new(url, tls, lanes, carrier_credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(d.open().await.map_err(io_err)?))
    })
}

/// A QUIC client endpoint kept across connections, so that TLS sessions
/// resume; with `zero_rtt` it remembers each server's parameters and
/// sends a session's first records as 0-RTT data when the session's
/// `Config(carrier_early_data=True)` allows it.
#[pyclass(frozen, module = "zmux")]
struct QuicClient {
    ep: quinn::Endpoint,
    opts: zmux_quinn::Options,
    memory: Option<zmux_quinn::ParameterMemory>,
}

#[pymethods]
impl QuicClient {
    #[new]
    #[pyo3(signature = (tls=None, *, lanes=zmux_quinn::LaneWindows::default().lanes, zero_rtt=false, memory_capacity=None, bind=("0.0.0.0".to_owned(), 0), carrier_credential=None))]
    fn new(
        tls: Option<PyRef<'_, TlsConfig>>,
        lanes: u32,
        zero_rtt: bool,
        memory_capacity: Option<usize>,
        bind: (String, u16),
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let memory = zero_rtt.then(|| match memory_capacity {
            Some(n) => zmux_quinn::ParameterMemory::with_capacity(n),
            None => zmux_quinn::ParameterMemory::new(),
        });
        let mut opts = quic_options(lanes);
        if let Some(m) = &memory {
            opts = opts.with_zero_rtt(m.clone());
        }
        if let Some(c) = admission::carrier_credential(carrier_credential)? {
            opts = opts.with_carrier_credential(c);
        }
        let qc =
            zmux_quinn::client_config(client_tls(tls).client_zmux()?, &opts).map_err(value_err)?;
        let bind: SocketAddr = hostport(&bind.0, bind.1).parse().map_err(value_err)?;
        let _g = get_runtime().enter();
        let mut ep = quinn::Endpoint::client(bind).map_err(io_err)?;
        ep.set_default_client_config(qc);
        Ok(QuicClient { ep, opts, memory })
    }

    /// A pipe on a new connection.
    #[pyo3(signature = (host, port, *, server_name=None))]
    fn dial<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        server_name: Option<String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let server_name = server_name.unwrap_or_else(|| host_of(&addr));
        let (ep, opts) = (self.ep.clone(), self.opts.clone());
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            Ok(PipeIo::wrap(
                zmux_quinn::dial(&ep, addr, &server_name, &opts)
                    .await
                    .map_err(io_err)?,
            ))
        })
    }

    /// A session on a new connection, with what became of its 0-RTT data:
    /// `(Session, ZeroRtt)`.
    #[pyo3(signature = (host, port, *, server_name=None, config=None))]
    fn connect<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        server_name: Option<String>,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let (ep, opts, c) = (self.ep.clone(), self.opts.clone(), cfg(config)?);
        let server_name = server_name.unwrap_or_else(|| host_of(&addr));
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let (s, z) = zmux_quinn::connect_with_report(&ep, addr, &server_name, &opts, c)
                .await
                .map_err(connect_err)?;
            rt::attach(|py| Ok(Session(s, Some(Py::new(py, ZeroRtt(z))?), Arc::default())))
        })
    }

    /// Forgets the parameters remembered for `server_name`, for example
    /// after `EarlyDataRejectedError`.
    fn forget(&self, server_name: &str) {
        if let Some(m) = &self.memory {
            m.forget(server_name);
        }
    }

    /// Forgets every remembered server.
    fn clear(&self) {
        if let Some(m) = &self.memory {
            m.clear();
        }
    }

    /// Whether parameters are remembered for `server_name`.
    fn remembers(&self, server_name: &str) -> bool {
        self.memory
            .as_ref()
            .is_some_and(|m| m.get(server_name).is_some())
    }
}

/// What became of a session's 0-RTT data.
#[pyclass(frozen, module = "zmux")]
struct ZeroRtt(zmux_quinn::ZeroRtt);

#[pymethods]
impl ZeroRtt {
    #[getter]
    fn sent(&self) -> bool {
        self.0.sent()
    }
    /// `None` while unknown or when none was sent.
    #[getter]
    fn accepted(&self) -> Option<bool> {
        self.0.accepted()
    }
    #[getter]
    fn rewritten(&self) -> bool {
        self.0.rewritten()
    }
}

/// The request field that pairs a split bootstrap's halves, by name
/// (`None`: the default one). Both ends must agree.
pub(crate) fn pair_field_of(name: Option<String>) -> PyResult<Option<zmux_http::PairField>> {
    name.map(|n| zmux_http::PairField::new(&n).map_err(value_err))
        .transpose()
}

/// A client's HTTP options: `path`, and the credential whose prefix goes
/// first on each request body. The adapter does not see the TLS layer, so
/// a credential bound to it is refused here.
fn http_client_options(
    path: String,
    carrier_credential: Option<Bound<'_, PyAny>>,
    pair_field: Option<String>,
) -> PyResult<zmux_http::Options> {
    let mut opts = zmux_http::Options::new().with_path(path);
    if let Some(f) = pair_field_of(pair_field)? {
        opts = opts.with_pair_field(f);
    }
    if let Some(c) = &carrier_credential
        && c.cast::<admission::PrefixAuth>()
            .is_ok_and(|p| p.get().binds_tls())
    {
        return Err(PyValueError::new_err(
            "HTTP carriers take tokens without bind_tls",
        ));
    }
    if let Some(c) = admission::carrier_credential(carrier_credential)? {
        opts = opts.with_carrier_credential(c);
    }
    Ok(opts)
}

/// The request of an HTTP carrier of `direction` (a `Direction`): `bidi`
/// (a `POST` whose bodies carry both directions), `out` (an uplink `POST`
/// whose request body is the only direction) or `in` (a downlink `GET`
/// whose response body is).
fn dial_request(direction: &str) -> PyResult<zmux::DialRequest> {
    Ok(zmux::DialRequest::new(direction_named(direction)?))
}

#[pyfunction]
#[pyo3(signature = (host, port, *, path="/zmux".to_owned(), carrier_credential=None,
    direction="bidi".to_owned(), pair_field=None))]
fn dial_streaming<'p>(
    py: Python<'p>,
    host: String,
    port: u16,
    path: String,
    carrier_credential: Option<Bound<'p, PyAny>>,
    direction: String,
    pair_field: Option<String>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let opts = http_client_options(path, carrier_credential, pair_field)?;
    let request = dial_request(&direction)?;
    future_into_py(py, async move {
        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(io_err)?;
        let _ = tcp.set_nodelay(true);
        Ok(PipeIo::wrap(
            zmux_http::dial_http1_carrier_over(tcp, &addr, &opts, &request)
                .await
                .map_err(io_err)?,
        ))
    })
}

/// A split bootstrap over two HTTP/1.1 connections: an uplink `POST` and
/// a downlink `GET` paired by a fresh token.
#[pyfunction]
#[pyo3(signature = (host, port, *, path="/zmux".to_owned(), carrier_credential=None, pair_field=None))]
fn dial_split<'p>(
    py: Python<'p>,
    host: String,
    port: u16,
    path: String,
    carrier_credential: Option<Bound<'p, PyAny>>,
    pair_field: Option<String>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let opts = http_client_options(path, carrier_credential, pair_field)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(
            zmux_http::dial_http1_split(&addr, &opts)
                .await
                .map_err(io_err)?,
        ))
    })
}

/// Joins a split carrier over two HTTP/1.1 connections to `session`: one
/// join across a `POST` and a `GET` paired by a token, one further pipe of
/// the two directions, `options` choosing its direction; returns `[pipe]`
/// as `add_pipe` does (a split bootstrap's carrier joins no session). A `PipePool(join=...)` keeps such pairs up.
#[pyfunction]
#[pyo3(signature = (session, host, port, *, path="/zmux".to_owned(), carrier_credential=None, pair_field=None,
    options=None))]
#[allow(clippy::too_many_arguments)]
fn join_split<'p>(
    py: Python<'p>,
    session: Bound<'p, Session>,
    host: String,
    port: u16,
    path: String,
    carrier_credential: Option<Bound<'p, PyAny>>,
    pair_field: Option<String>,
    options: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let opts = http_client_options(path, carrier_credential, pair_field)?;
    let po = pipe_options(options)?;
    let s = session.get().0.clone();
    let owner = session.unbind();
    future_into_py(py, async move {
        let to: Arc<str> = addr.as_str().into();
        let connect = move || {
            let to = to.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(&*to).await?;
                let _ = tcp.set_nodelay(true);
                Ok::<_, std::io::Error>(tcp)
            }
        };
        let pipes = zmux_http::join_http1_split_with(&s, connect, &addr, &opts, po)
            .await
            .map_err(io_err)?;
        Ok(pipes_of(pipes, &owner))
    })
}

/// The HTTP exchange carrier's options, for `dial_exchange` and
/// `Listener.serve_http(exchange=...)`.
#[pyclass(frozen, module = "zmux")]
struct ExchangeOptions(zmux_http::ExchangeOptions);

#[pymethods]
impl ExchangeOptions {
    /// Every keyword left out keeps the library's default; the piece sizes
    /// and `down_path` take `zmux.AUTO` (the default: from the encoding,
    /// `path`), `max_carriers` `None` (the default: no bound but the
    /// listener's memory budget). Durations are seconds.
    #[new]
    #[pyo3(signature = (*, psk=Vec::new(), unauthenticated=false, encoding="binary".to_owned(),
        path=zmux_http::ExchangeOptions::default().path, down_path=None, query=zmux_http::ExchangeOptions::default().query, down_requests=zmux_http::ExchangeOptions::default().down_requests,
        up_requests=zmux_http::ExchangeOptions::default().up_requests, up_piece=None, max_down_piece=None,
        backoff=None,
        request_timeout=zmux_http::ExchangeOptions::default().request_timeout.as_secs_f64(), deadline=zmux_http::ExchangeOptions::default().deadline.as_secs_f64(),
        hold=zmux_http::ExchangeOptions::default().hold.as_secs_f64(), coalesce=zmux_http::ExchangeOptions::default().coalesce.as_secs_f64(), down_piece=None,
        down_window=zmux_http::ExchangeOptions::default().down_window, max_up_piece=None, up_store=zmux_http::ExchangeOptions::default().up_store,
        idle_timeout=zmux_http::ExchangeOptions::default().idle_timeout.as_secs_f64(), gone_memory=zmux_http::ExchangeOptions::default().gone_memory.as_secs_f64(),
        max_carriers=None, time_window=zmux_http::ExchangeOptions::default().time_window.as_secs_f64(),
        max_recorded=zmux_http::ExchangeOptions::default().max_recorded))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        psk: Vec<u8>,
        unauthenticated: bool,
        encoding: String,
        path: String,
        down_path: Option<Bound<'_, PyAny>>,
        query: String,
        down_requests: usize,
        up_requests: usize,
        up_piece: Option<Bound<'_, PyAny>>,
        max_down_piece: Option<Bound<'_, PyAny>>,
        backoff: Option<Bound<'_, PyAny>>,
        request_timeout: f64,
        deadline: f64,
        hold: f64,
        coalesce: f64,
        down_piece: Option<Bound<'_, PyAny>>,
        down_window: u64,
        max_up_piece: Option<Bound<'_, PyAny>>,
        up_store: usize,
        idle_timeout: f64,
        gone_memory: f64,
        max_carriers: Option<usize>,
        time_window: f64,
        max_recorded: usize,
    ) -> PyResult<Self> {
        // AUTO, or a fixed value.
        fn auto<'py, T: FromPyObjectOwned<'py>>(
            v: Option<Bound<'py, PyAny>>,
        ) -> PyResult<zmux::Cap<T>> {
            match v {
                Some(v) if !is_setting(&v, "AUTO")? => {
                    Ok(zmux::Cap::Fixed(v.extract().map_err(Into::into)?))
                }
                _ => Ok(zmux::Cap::Auto),
            }
        }
        let mut o = zmux_http::ExchangeOptions::new();
        o.encoding = match encoding.as_str() {
            "binary" => zmux_http::BodyEncoding::Binary,
            "base64" => zmux_http::BodyEncoding::Base64,
            e => return Err(PyValueError::new_err(format!("unknown encoding {e:?}"))),
        };
        o.psk = psk;
        o.unauthenticated = unauthenticated;
        o.path = path;
        o.down_path = auto(down_path)?;
        o.query = query;
        o.down_requests = down_requests;
        o.up_requests = up_requests;
        o.up_piece = auto(up_piece)?;
        o.max_down_piece = auto(max_down_piece)?;
        o.down_piece = auto(down_piece)?;
        o.max_up_piece = auto(max_up_piece)?;
        o.down_window = down_window;
        o.up_store = up_store;
        o.max_carriers = max_carriers;
        o.max_recorded = max_recorded;
        if let Some(b) = backoff {
            o.backoff = backoff_of(&b)?;
        }
        o.request_timeout = seconds("request_timeout", request_timeout)?;
        o.deadline = seconds("deadline", deadline)?;
        o.hold = seconds("hold", hold)?;
        o.coalesce = seconds("coalesce", coalesce)?;
        o.idle_timeout = seconds("idle_timeout", idle_timeout)?;
        o.gone_memory = seconds("gone_memory", gone_memory)?;
        o.time_window = seconds("time_window", time_window)?;
        Ok(ExchangeOptions(o))
    }

    #[getter]
    fn encoding(&self) -> &'static str {
        match self.0.encoding {
            zmux_http::BodyEncoding::Base64 => "base64",
            _ => "binary",
        }
    }
    #[getter]
    fn path(&self) -> &str {
        &self.0.path
    }
    #[getter]
    fn down_path<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        auto_obj(
            py,
            match &self.0.down_path {
                zmux::Cap::Fixed(p) => Some(p.as_str()),
                zmux::Cap::Auto => None,
            },
        )
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// An endpoint of the exchange carrier: plain TCP, or TLS whose ALPN
/// chooses `http/1.1`.
fn exchange_endpoint(
    addr: String,
    tls: Option<&tokio_rustls::TlsConnector>,
    server_name: Option<&str>,
) -> PyResult<zmux_http::ExchangeEndpoint> {
    let Some(tls) = tls.cloned() else {
        return Ok(zmux_http::ExchangeEndpoint::tcp(&addr));
    };
    let host = server_name.map_or_else(|| host_of(&addr), str::to_owned);
    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(value_err)?;
    let port = addr.rsplit_once(':').map_or("443", |(_, p)| p);
    let authority = if port == "443" {
        host
    } else {
        format!("{host}:{port}")
    };
    Ok(zmux_http::ExchangeEndpoint::new(
        move || {
            let (tls, name, addr) = (tls.clone(), name.clone(), addr.clone());
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                let _ = tcp.set_nodelay(true);
                tls.connect(name, tcp).await
            }
        },
        &authority,
    ))
}

/// An exchange carrier: HTTP/1.1 requests to `addr` (and DOWN requests to
/// `down_addr` when given), over TLS with `tls`; with `credential`, its
/// prefix starts the uplink, for a server's admission.
#[pyfunction]
#[pyo3(signature = (host, port, *, options=None, down_addr=None, tls=None, server_name=None,
    carrier_credential=None))]
#[allow(clippy::too_many_arguments)]
fn dial_exchange<'p>(
    py: Python<'p>,
    host: String,
    port: u16,
    options: Option<PyRef<'_, ExchangeOptions>>,
    down_addr: Option<(String, u16)>,
    tls: Option<PyRef<'_, TlsConfig>>,
    server_name: Option<String>,
    carrier_credential: Option<Bound<'_, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let addr = hostport(&host, port);
    let mut opts = options.map(|o| o.0.clone()).unwrap_or_default();
    if let Some(c) = admission::carrier_credential(carrier_credential)? {
        opts = opts.with_carrier_credential(c);
    }
    let tls = tls
        .map(|t| t.client_alpn(http1))
        .transpose()?
        .map(|c| tokio_rustls::TlsConnector::from(Arc::new(c)));
    let up = exchange_endpoint(addr, tls.as_ref(), server_name.as_deref())?;
    let down = match down_addr {
        Some((h, p)) => exchange_endpoint(hostport(&h, p), tls.as_ref(), server_name.as_deref())?,
        None => up.clone(),
    };
    future_into_py(py, async move {
        Ok(PipeIo::wrap(
            zmux_http::dial_exchange_split(up, down, &opts).map_err(value_err)?,
        ))
    })
}

// ---- session --------------------------------------------------------------------------

fn preamble(
    info: Option<Vec<u8>>,
    tlvs: Option<Vec<(u64, Vec<u8>)>>,
    pipe_carrier: bool,
) -> Option<zmux::Preamble> {
    if info.is_none() && tlvs.as_ref().is_none_or(Vec::is_empty) && !pipe_carrier {
        return None;
    }
    let mut p = zmux::Preamble::new();
    if pipe_carrier {
        p = p.with_pipe_carrier();
    }
    if let Some(i) = info {
        p = p.with_info(i);
    }
    for (t, v) in tlvs.unwrap_or_default() {
        p = p.with_tlv(t, v);
    }
    Some(p)
}

/// The priorities `open_bi` sets on the parts it opened.
struct Prios(Option<zmux::Priority>, Option<zmux::Priority>);

impl Prios {
    fn new(local: Option<(u8, bool)>, peer: Option<(u8, bool)>) -> PyResult<Self> {
        let p = |v: Option<(u8, bool)>| v.map(|(u, i)| priority(u, i)).transpose();
        Ok(Prios(p(local)?, p(peer)?))
    }
    fn apply(&self, (send, recv): &(zmux::SendStream, zmux::RecvStream)) -> PyResult<()> {
        if let Some(p) = self.0 {
            send.set_priority(p).map_err(stream_err)?;
        }
        if let Some(p) = self.1 {
            recv.set_peer_priority(p).map_err(stream_err)?;
        }
        Ok(())
    }
}

/// A `zmux.QualityBand`.
fn quality_band(b: &Bound<'_, PyAny>) -> PyResult<zmux::QualityBand> {
    let rtt: Option<f64> = b.getattr("rtt")?.extract()?;
    Ok(zmux::QualityBand {
        rtt: rtt.map(|v| seconds("rtt", v)).transpose()?,
        rate_ratio: b.getattr("rate_ratio")?.extract()?,
        min_interval: seconds("min_interval", b.getattr("min_interval")?.extract()?)?,
    })
}

/// The `zmux.QualityBand` of a native band.
fn quality_band_obj(py: Python<'_>, b: zmux::QualityBand) -> PyResult<Bound<'_, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("rtt", dur(b.rtt))?;
    d.set_item("rate_ratio", b.rate_ratio)?;
    d.set_item("min_interval", b.min_interval.as_secs_f64())?;
    types(py)?.getattr("QualityBand")?.call((), Some(&d))
}

/// The `zmux.CapacityFloor` of a native floor.
fn capacity_floor_obj(py: Python<'_>, f: zmux::CapacityFloor) -> PyResult<Bound<'_, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("rate", f.rate)?;
    d.set_item("rate_ratio", f.rate_ratio)?;
    types(py)?.getattr("CapacityFloor")?.call((), Some(&d))
}

/// A `zmux.CapacityFloor`.
fn capacity_floor(f: &Bound<'_, PyAny>) -> PyResult<zmux::CapacityFloor> {
    Ok(zmux::CapacityFloor {
        rate: f.getattr("rate")?.extract()?,
        rate_ratio: f.getattr("rate_ratio")?.extract()?,
    })
}

fn priority(urgency: u8, incremental: bool) -> PyResult<zmux::Priority> {
    zmux::Priority::new(urgency, incremental)
        .ok_or_else(|| PyValueError::new_err("urgency out of range"))
}

/// A listener's source prefix length: 1 to `max` bits.
fn prefix_bits(name: &str, v: i64, max: u8) -> PyResult<u8> {
    u8::try_from(v)
        .ok()
        .filter(|n| (1..=max).contains(n))
        .ok_or_else(|| PyValueError::new_err(format!("{name} is from 1 to {max}")))
}

fn varint(v: u64) -> PyResult<zmux::VarInt> {
    zmux::VarInt::from_u64(v).map_err(|_| PyValueError::new_err("code exceeds 2**62-1"))
}

/// A zmux session. Cheap handle; the session runs on the binding's runtime.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Session(
    pub(crate) zmux::Session,
    Option<Py<ZeroRtt>>,
    Arc<SessionReturned>,
);

/// What a session's accepts and datagram reads took back.
#[derive(Default)]
struct SessionReturned {
    bi: Returned<Py<PyAny>>,
    uni: Returned<Py<PyAny>>,
    datagrams: Returned<Py<PyAny>>,
    events: Returned<Py<PyAny>>,
}

impl Session {
    pub(crate) fn new(s: zmux::Session) -> Self {
        Session(s, None, Arc::default())
    }
}

fn start<'p>(
    py: Python<'p>,
    pipe: &PipeIo,
    config: Option<Bound<'_, PyAny>>,
    how: u8,
) -> PyResult<Bound<'p, PyAny>> {
    let io = pipe.take()?;
    let c = cfg(config)?;
    future_into_py(py, async move {
        let s = match how {
            0 => zmux::Session::connect(io, c).await,
            1 => zmux::Session::accept(io, c).await,
            _ => zmux::Session::peer(io, c).await,
        };
        s.map(Session::new).map_err(connect_err)
    })
}

/// The application error code of an abandoned stream or session
/// (`ZMUX_CANCELLED`).
const ZMUX_CANCELLED: u32 = 0x5a4d_0001;

/// A `zmux.BiStream` of the two parts of a bidirectional stream.
fn bi(py: Python<'_>, (s, r): (zmux::SendStream, zmux::RecvStream)) -> PyResult<Py<PyAny>> {
    Ok(types(py)?
        .getattr("BiStream")?
        .call1((SendStream::wrap(s), RecvStream::wrap(r)))?
        .unbind())
}

#[pymethods]
impl Session {
    /// Establishes a session as the dialling side of `pipe`.
    #[staticmethod]
    #[pyo3(signature = (pipe, *, config=None))]
    fn connect<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 0)
    }
    /// Establishes a single-pipe session as the accepting side of `pipe`.
    #[staticmethod]
    #[pyo3(signature = (pipe, *, config=None))]
    fn accept<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 1)
    }
    /// Establishes a session over a symmetric carrier: the roles are
    /// negotiated (role auto).
    #[staticmethod]
    #[pyo3(signature = (pipe, *, config=None))]
    fn symmetric<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 2)
    }

    /// The value the listener's admission gave the carrier that started
    /// the session (`AdmissionVerdict.accept(value=...)`; a split bootstrap's
    /// uplink's), for the session's lifetime; `None` without one and on a
    /// client.
    #[getter]
    fn admitted(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        admission::admitted_obj(py, self.0.admitted().as_ref())
    }

    #[pyo3(signature = (*, info=None, tlvs=None, pipe_carrier=false, priority=None, peer_priority=None))]
    fn open_bi<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        pipe_carrier: bool,
        priority: Option<(u8, bool)>,
        peer_priority: Option<(u8, bool)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, pipe_carrier);
        let prios = Prios::new(priority, peer_priority)?;
        future_into_py(py, async move {
            let pair = match p {
                Some(p) => s.open_bi_with(&p).await,
                None => s.open_bi().await,
            }
            .map_err(open_err)?;
            prios.apply(&pair)?;
            rt::attach(|py| bi(py, pair))
        })
    }

    /// Opens a bidirectional stream with the preamble (`info`, `tlvs`) and
    /// wraps it as a `zmux.helpers.PacketStream`.
    #[pyo3(signature = (*, info=None, tlvs=None, policy="prefer_datagram",
        max_packet=zmux::helpers::DEFAULT_MAX_PACKET))]
    fn open_packet_stream<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        policy: &str,
        max_packet: usize,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, false).unwrap_or_default();
        let opts = packet::options(policy, max_packet)?;
        future_into_py(py, async move {
            let ps = s.open_packet_stream(&p, opts).await.map_err(open_err)?;
            Ok(packet::PacketStream::from(ps))
        })
    }

    /// Opens a bidirectional stream as an asyncio-style pair
    /// `(StreamPairReader, StreamPairWriter)`: the reader offers
    /// `asyncio.StreamReader`'s reads, the writer `asyncio.StreamWriter`'s
    /// writes (`high_water` the queued bytes above which `drain` waits,
    /// `limit` the reader's buffer limit). The other keywords are those of
    /// `open_bi`.
    #[pyo3(signature = (*, info=None, tlvs=None, priority=None, peer_priority=None,
        high_water=65536, limit=65536))]
    #[allow(clippy::too_many_arguments)]
    fn open_stream_pair<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        priority: Option<(u8, bool)>,
        peer_priority: Option<(u8, bool)>,
        high_water: usize,
        limit: usize,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, false);
        let prios = Prios::new(priority, peer_priority)?;
        future_into_py(py, async move {
            let pair = match p {
                Some(p) => s.open_bi_with(&p).await,
                None => s.open_bi().await,
            }
            .map_err(open_err)?;
            prios.apply(&pair)?;
            rt::attach(|py| {
                let (send, recv) = pair;
                let pair = py
                    .import("zmux._streams")?
                    .getattr("_stream_pair")?
                    .call1((
                        SendStream::wrap(send),
                        RecvStream::wrap(recv),
                        high_water,
                        limit,
                    ))?;
                Ok(pair.unbind())
            })
        })
    }

    /// Opens a bidirectional stream if stream credit is available now;
    /// `OpenError` otherwise. Never waits.
    #[pyo3(signature = (*, info=None, tlvs=None, pipe_carrier=false, priority=None, peer_priority=None))]
    fn try_open_bi(
        &self,
        py: Python<'_>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        pipe_carrier: bool,
        priority: Option<(u8, bool)>,
        peer_priority: Option<(u8, bool)>,
    ) -> PyResult<Py<PyAny>> {
        let prios = Prios::new(priority, peer_priority)?;
        let pair = match preamble(info, tlvs, pipe_carrier) {
            Some(p) => self.0.try_open_bi_with(&p),
            None => self.0.try_open_bi(),
        }
        .map_err(open_err)?;
        prios.apply(&pair)?;
        bi(py, pair)
    }

    /// Opens a carrier stream (`PIPE_CARRIER`) for a nested session, with the
    /// open info `info` and the application TLVs `tlvs`; returns its
    /// `PipeIo`.
    #[pyo3(signature = (*, info=None, tlvs=None))]
    fn open_pipe_stream<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, false).unwrap_or_default();
        future_into_py(py, async move {
            s.open_pipe_stream(&p)
                .await
                .map(PipeIo::wrap)
                .map_err(open_err)
        })
    }

    /// Supplies the deferred pre-shared key (`PipeAuth.deferred_psk`), once;
    /// after establishment it derives the join keys and releases the peer's
    /// held joins.
    fn set_join_secret(&self, psk: Vec<u8>) -> PyResult<()> {
        self.0.set_join_secret(&psk).map_err(pipe_err)
    }

    /// Whether the joins wait for the deferred pre-shared key.
    #[getter]
    fn join_pending(&self) -> bool {
        self.0.join_pending()
    }

    /// States that the host has proven pipe 0 end to end, for a session whose first pipe is
    /// outside the secure carrier: the join keys are derived from then on.
    fn declare_end_to_end(&self) {
        self.0.declare_end_to_end();
    }

    /// The session epoch new local joins use; `None` outside a multipath session.
    #[getter]
    fn epoch(&self) -> Option<u64> {
        self.0.epoch()
    }

    /// The weakest record mode among the session's pipes.
    #[getter]
    fn weakest_record_mode<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        record_mode_obj(py, self.0.weakest_record_mode())
    }

    /// The shaping limits in effect. Assigning replaces them; invalid ones
    /// raise `ValueError` and change nothing.
    #[getter]
    fn shaping_limits<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        shaping::limits_obj(py, &self.0.shaping_limits())
    }

    #[setter]
    fn set_shaping_limits(&self, limits: &Bound<'_, PyAny>) -> PyResult<()> {
        self.0
            .set_shaping_limits(shaping::limits_of(limits)?)
            .map_err(value_err)
    }

    /// `length` bytes exported from the innermost end-to-end handshake of
    /// the bootstrap carrier.
    #[pyo3(signature = (label, *, context=b"".to_vec(), length=32))]
    fn export_keying_material<'p>(
        &self,
        py: Python<'p>,
        label: &str,
        context: Vec<u8>,
        length: usize,
    ) -> PyResult<Bound<'p, PyBytes>> {
        let v = self
            .0
            .export_keying_material(label, &context, length)
            .map_err(export_err)?;
        Ok(PyBytes::new(py, &v))
    }

    /// The 32-byte public value that identifies this session at both ends;
    /// `None` before establishment and without multipath.
    #[getter]
    fn session_binding<'p>(&self, py: Python<'p>) -> Option<Bound<'p, PyBytes>> {
        self.0.session_binding().map(|b| PyBytes::new(py, &b))
    }

    /// The liveness settings in effect, defaults filled in. Assigning a
    /// `Liveness` replaces them as a whole (a field left at its default is
    /// the default); invalid ones raise `ValueError` and change nothing.
    #[getter]
    fn liveness<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        liveness_obj(py, &self.0.liveness())
    }

    #[setter]
    fn set_liveness(&self, liveness: &Bound<'_, PyAny>) -> PyResult<()> {
        self.0
            .set_liveness(&self::liveness(liveness)?)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Raises the streams the peer may have open and sends the credit; the
    /// credit only grows, so 0 raises nothing.
    #[pyo3(signature = (*, bidi=0, uni=0))]
    fn raise_incoming_streams(&self, bidi: i128, uni: i128) -> PyResult<()> {
        let count = |n: &str, v: i128| {
            u64::try_from(v)
                .map_err(|_| PyValueError::new_err(format!("{n} is a non-negative integer")))
        };
        self.0
            .raise_incoming_streams(count("bidi", bidi)?, count("uni", uni)?)
            .map_err(value_err)
    }

    /// The default quality band of the session's pipes (`None`: no
    /// reports).
    #[getter]
    fn quality_band<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0
            .quality_band()
            .map(|b| quality_band_obj(py, b))
            .transpose()
    }
    #[setter]
    fn set_quality_band(&self, band: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let native = band.as_ref().map(quality_band).transpose()?;
        self.0.set_quality_band(native).map_err(pipe_err)
    }

    /// The floor under the session's outbound capacity (`None`: none).
    #[getter]
    fn capacity_floor<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0
            .capacity_floor()
            .map(|f| capacity_floor_obj(py, f))
            .transpose()
    }
    #[setter]
    fn set_capacity_floor(&self, floor: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let native = floor.as_ref().map(capacity_floor).transpose()?;
        self.0.set_capacity_floor(native).map_err(pipe_err)
    }

    /// The default scheduling policy of new stream data.
    #[getter]
    fn scheduler<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        typed(py, "Scheduler", policy_name(&self.0.scheduler()).to_owned())
    }
    #[setter]
    fn set_scheduler(&self, scheduler: &Bound<'_, PyAny>) -> PyResult<()> {
        let p = scheduler_of(Some(scheduler))?
            .ok_or_else(|| PyValueError::new_err("scheduler has no off setting"))?;
        self.0.set_scheduler(p);
        Ok(())
    }

    #[pyo3(signature = (*, info=None, tlvs=None, priority=None))]
    fn open_uni<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        priority: Option<(u8, bool)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, false);
        let prio = priority.map(|(u, i)| self::priority(u, i)).transpose()?;
        future_into_py(py, async move {
            let send = match p {
                Some(p) => s.open_uni_with(&p).await,
                None => s.open_uni().await,
            }
            .map_err(open_err)?;
            if let Some(pr) = prio {
                send.set_priority(pr).map_err(stream_err)?;
            }
            Ok(SendStream::wrap(send))
        })
    }

    fn accept_bi<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.2.bi, async move {
            let pair = s.accept_bi().await.map_err(session_err)?;
            rt::attach(|py| bi(py, pair))
        })
    }

    fn accept_uni<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.2.uni, async move {
            Ok(RecvStream::wrap(s.accept_uni().await.map_err(session_err)?))
        })
    }

    fn send_datagram(&self, data: Vec<u8>) -> PyResult<()> {
        self.0
            .send_datagram(Bytes::from(data))
            .map_err(datagram_err)
    }

    fn read_datagram<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.2.datagrams, async move {
            s.read_datagram()
                .await
                .map(|b| pyb(&b))
                .map_err(session_err)
        })
    }

    #[getter]
    fn max_datagram_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }

    /// Starts the graceful close with the application error `code` and
    /// `reason` (0 and empty: a close without error) and returns without
    /// blocking: the data the streams wrote is sent first, so that the peer
    /// reads it ahead of the code, then `CONNECTION_CLOSE` is handed to every
    /// usable carrier, all within 1 s; streams still open are not waited
    /// for and fail with the session's error. `wait_closed` waits for the
    /// end. Idempotent with `abort`: the first call of either decides what
    /// is sent, code and reason included; an `abort` while the close is
    /// still flushing ends it at once.
    #[pyo3(signature = (code=0, reason=b"".to_vec()))]
    fn close(&self, code: u64, reason: Vec<u8>) -> PyResult<()> {
        // The close starts with the call; its future only waits.
        drop(self.0.close_with_error(varint(code)?, &reason));
        Ok(())
    }

    /// Ends the session at once with the application error `code` and
    /// `reason`, draining nothing: data not yet sent is discarded and
    /// `CONNECTION_CLOSE` goes in the background. Returns at once. An abort
    /// while a close is still flushing discards what remains unsent.
    #[pyo3(signature = (code, reason=b"".to_vec()))]
    fn abort(&self, code: u64, reason: Vec<u8>) -> PyResult<()> {
        self.0.abort(varint(code)?, &reason);
        Ok(())
    }

    /// Graceful shutdown: GOAWAY, then close once the streams ended.
    #[pyo3(signature = (code=0, reason=b"".to_vec()))]
    fn shutdown<'p>(
        &self,
        py: Python<'p>,
        code: u64,
        reason: Vec<u8>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let code = varint(code)?;
        future_into_py(py, async move {
            s.shutdown(code, &reason).await.map_err(session_err)
        })
    }

    /// Waits for the session's whole end and returns the
    /// `SessionClosedError` that describes it (it is not raised). It
    /// returns once every pipe's inbound side has ended (the peer read the
    /// close and ended its side) or the linger timeout has passed, so a
    /// return before the linger confirms that the peer read the close.
    /// "Delivered, or given up after d" is `async with asyncio.timeout(d):
    /// await s.wait_closed()`; a timeout changes nothing in the session.
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let e = s.closed().await;
            rt::attach(|py| Ok(session_err(e).into_value(py)))
        })
    }

    fn ping<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            s.ping().await.map(|d| d.as_secs_f64()).map_err(session_err)
        })
    }

    /// The next session event, or `None` once the session ended.
    fn next_event<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.2.events, async move {
            match s.next_event().await {
                Some(e) => rt::attach(|py| event_obj(py, &e).map(Some)),
                None => Ok(None),
            }
        })
    }

    /// Session events as an async iterator.
    fn events(&self) -> EventStream {
        EventStream(self.0.clone(), self.2.clone())
    }

    /// Received datagrams as an async iterator.
    fn datagrams(&self) -> DatagramStream {
        DatagramStream(self.0.clone(), self.2.clone())
    }

    /// The shaper in force on every outbound pipe, as an opaque
    /// `InstalledShaper` (the configuration's or the last one assigned);
    /// `None` for no shaping.
    #[getter]
    fn shaper(&self) -> Option<shaping::InstalledShaper> {
        self.0.shaper().map(shaping::InstalledShaper)
    }
    #[setter]
    fn set_shaper(&self, shaper: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let Some(v) = &shaper else {
            self.0.set_shaper(None, None);
            return Ok(());
        };
        if let Ok(i) = v.cast::<shaping::InstalledShaper>() {
            self.0.set_shaper(Some(i.get().0.clone()), None);
            return Ok(());
        }
        if let Ok(b) = v.cast::<shaping::ShapingBundle>() {
            let b = b.get().0.clone();
            let budget = b
                .resolve("default")
                .and_then(zmux_shaping::Compiled::budget);
            self.0.set_shaper(Some(b), budget);
            return Ok(());
        }
        let get = |n: &str| v.getattr(n);
        let definition: Option<String> = get("definition")?.extract()?;
        let by_kind = Some(get("by_kind")?).filter(|x| !x.is_none());
        let by_variant = Some(get("by_variant")?).filter(|x| !x.is_none());
        let limits = Some(get("limits")?).filter(|x| !x.is_none());
        let seed: Option<Vec<u8>> = get("seed")?.extract()?;
        let budget = Some(get("budget")?)
            .filter(|x| !x.is_none())
            .map(|b| shaping::budget_hook(b.unbind()));
        let o = shaping::options(limits.as_ref(), seed)?;
        let factory: Option<Arc<dyn Factory>> =
            match (definition, by_kind.is_some() || by_variant.is_some()) {
                (Some(j), false) => Some(Arc::new(
                    zmux_shaping::MachineFactory::from_json(j.as_bytes(), o).map_err(value_err)?,
                )),
                (None, true) => Some(Arc::new(shaping::by_carrier(
                    by_kind.as_ref(),
                    by_variant.as_ref(),
                    &o,
                )?)),
                (None, false) => None,
                _ => {
                    return Err(PyValueError::new_err(
                        "definition and by_kind or by_variant exclude each other",
                    ));
                }
            };
        self.0.set_shaper(factory, budget);
        Ok(())
    }

    /// The session's shaping readings.
    fn shaping_meters<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let m = self.0.shaping_meters();
        let d = PyDict::new(py);
        d.set_item("wire_left", m.wire_left)?;
        d.set_item("stall_left", m.stall_left)?;
        d.set_item("wire_spent", m.wire_spent)?;
        d.set_item("stall_spent", m.stall_spent)?;
        d.set_item("sent_bytes", m.sent_bytes)?;
        Ok(d.into_any())
    }

    /// The shaping counters of the session.
    fn shaping_stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = self.0.shaping_stats();
        let d = PyDict::new(py);
        d.set_item("wire_spent", st.wire_spent)?;
        d.set_item("injected", st.injected)?;
        d.set_item("inject_dropped", st.inject_dropped)?;
        d.set_item("clamped", st.clamped)?;
        d.set_item("stall_spent", st.stall_spent.as_secs_f64())?;
        d.set_item("faults", st.faults)?;
        d.set_item("handshake_unplanned", st.handshake_unplanned)?;
        Ok(d.into_any())
    }

    /// A statistics snapshot.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = self.0.stats();
        let d = PyDict::new(py);
        macro_rules! put {
            ($($f:ident),*) => { $(d.set_item(stringify!($f), st.$f)?;)* };
        }
        put!(
            bytes_sent,
            bytes_received,
            records_sent,
            records_received,
            bytes_written,
            bytes_read,
            datagram_bytes_sent,
            datagram_bytes_received,
            streams_opened_local,
            streams_opened_remote,
            streams_active,
            stream_credit_waits,
            datagrams_sent,
            datagrams_received,
            datagrams_sent_channel,
            datagrams_received_channel,
            datagrams_dropped_send,
            datagrams_dropped_recv,
            datagrams_dropped_limit,
            no_effect_budget,
            bytes_reinjected,
            bytes_opportunistic,
            penalties,
            reinjections,
            bytes_redundant,
            bytes_duplicate_received,
            send_buffered,
            recv_buffered,
            retained,
            pipes_active,
            pipes_added,
            pipe_failures,
            join_auth_failures,
            join_pending,
            join_batch_dropped,
            join_failures,
            join_replays,
            join_refusals,
            suspensions,
            scheduler_answers,
            scheduler_fallbacks,
            first_flight_timeouts
        );
        d.set_item("smoothed_rtt", dur(st.smoothed_rtt))?;
        d.set_item("min_rtt", dur(st.min_rtt))?;
        d.set_item("latest_rtt", dur(st.latest_rtt))?;
        d.set_item("mean_deviation", dur(st.mean_deviation))?;
        d.set_item("suspended_time", st.suspended_time.as_secs_f64())?;
        d.set_item("carrier", st.carrier.map(zmux::CarrierKind::name))?;
        let tries = st
            .carrier_candidates
            .iter()
            .map(choice::result_obj)
            .map(|r| r(py))
            .collect::<PyResult<Vec<_>>>()?;
        d.set_item("carrier_candidates", tries)?;
        types(py)?.getattr("SessionStats")?.call((), Some(&d))
    }

    /// How the transport's 0-RTT went, for sessions from `QuicClient.connect`.
    #[getter]
    fn zero_rtt(&self, py: Python<'_>) -> Option<Py<ZeroRtt>> {
        self.1.as_ref().map(|z| z.clone_ref(py))
    }

    /// Adds a carrier as a further pipe (multipath): returns once the peer
    /// attached it, or with `options.no_wait_attached` once its Reply was
    /// verified; the handshake timeout bounds the call, and a failed or
    /// cancelled call aborts the pipe.
    #[pyo3(signature = (pipe, *, options=None))]
    fn add_pipe<'p>(
        slf: &Bound<'p, Self>,
        pipe: &PipeIo,
        options: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let o = pipe_options(options)?;
        let io = pipe.take()?;
        let s = slf.get().0.clone();
        let owner = slf.clone().unbind();
        future_into_py(slf.py(), async move {
            let p = s.add_pipe(io, o).await.map_err(pipe_err)?;
            Ok(Pipe(p, owner))
        })
    }

    /// Keeps `pool`'s pipes up (dials, redials with backoff, rotation
    /// make before break, its policy's decisions) until the handle is
    /// stopped or collected or the session ends; needs a running event loop.
    fn maintain_pipes(
        &self,
        py: Python<'_>,
        pool: PyRef<'_, pool::PipePool>,
    ) -> PyResult<pool::MaintainHandle> {
        pool::maintain(py, self, &pool)
    }

    /// Revalidates every live outbound pipe after a network change.
    fn revalidate_pipes(&self) -> PyResult<()> {
        self.0.revalidate_pipes().map_err(pipe_err)
    }

    /// Starts a session epoch exchange as soon as this end is Stable.
    fn advance_epoch(&self) -> PyResult<()> {
        self.0.advance_epoch().map_err(pipe_err)
    }

    /// Replaces every pipe after a suspected leak of a session-level
    /// secret: advances the epoch, waits until new joins use it, then
    /// replaces each pipe that existed when called through the `redial`
    /// hook, make before break. Unbounded: bound it with
    /// `asyncio.timeout(seconds)`, a relative bound; cancelled, it stops
    /// where it is, the pipes already replaced staying replaced.
    fn replace_pipes<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move { s.replace_pipes().await.map_err(pipe_err) })
    }

    fn pipes(slf: &Bound<'_, Self>) -> Vec<Pipe> {
        let owner = slf.clone().unbind();
        pipes_of(slf.get().0.pipes(), &owner)
    }

    fn pipe_stats<'p>(&self, py: Python<'p>) -> PyResult<Vec<Bound<'p, PyAny>>> {
        self.0
            .pipe_stats()
            .iter()
            .map(|s| stats_dict(py, s))
            .collect()
    }

    /// The session's role: `Role.CLIENT` or `Role.SERVER`, negotiated when
    /// it was started as auto.
    #[getter]
    fn role<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        role_obj(py, self.0.role())
    }
    #[getter]
    fn rtt(&self) -> Option<f64> {
        self.0.rtt().map(|d| d.as_secs_f64())
    }
    #[getter]
    fn protocol(&self) -> Option<String> {
        self.0.protocol()
    }
    #[getter]
    fn is_plain_qmux_peer(&self) -> bool {
        self.0.is_plain_qmux_peer()
    }
    /// Whether establishment has completed.
    #[getter]
    fn is_established(&self) -> bool {
        self.0.is_established()
    }
    /// The `QMux` version in use (`"draft-02"`, the only one).
    #[getter]
    fn qmux_version(&self) -> &'static str {
        self.0.qmux_version()
    }
    /// The TLS or QUIC handshake this process ran for the bootstrap carrier
    /// (`TlsState`), or `None` where TLS ends outside the process or the
    /// carrier has none.
    #[getter]
    fn tls<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0.tls().map(|s| tls_state_obj(py, &s)).transpose()
    }
    /// DATAGRAM support of each side (`Support`).
    #[getter]
    fn datagram_support<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        support_obj(py, self.0.datagram_support())
    }
    /// `RESET_STREAM_AT` support of each side (`Support`).
    #[getter]
    fn reset_stream_at_support<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        support_obj(py, self.0.reset_stream_at_support())
    }
    /// What became of multipath (`Multipath`).
    #[getter]
    fn multipath<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        let v = match self.0.multipath() {
            zmux::Multipath::InUse => "in_use",
            zmux::Multipath::PeerDeclined => "peer_declined",
            zmux::Multipath::JoinSecurityUnavailable => "join_security_unavailable",
            _ => "off",
        };
        typed(py, "Multipath", v.to_owned())
    }
    /// Whether pipe acknowledgements are in use.
    #[getter]
    fn pipe_ack_in_use(&self) -> bool {
        self.0.pipe_ack_in_use()
    }
    /// Whether resume is in use.
    #[getter]
    fn resume_in_use(&self) -> bool {
        self.0.resume_in_use()
    }
    /// The watermarks of the latest GOAWAY received (`GoAwayReceived`), or
    /// `None`.
    #[getter]
    fn goaway(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let Some(g) = self.0.goaway() else {
            return Ok(None);
        };
        let d = PyDict::new(py);
        goaway_fields(&d, &g)?;
        Ok(Some(
            types(py)?
                .getattr("_event")?
                .call1(("GoAwayReceived", d))?
                .unbind(),
        ))
    }
    #[getter]
    fn state<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        typed(py, "SessionState", kind_of(&self.0.state()))
    }
    /// Ends `Config(hold_first_flight=True)`: what is queued goes in one
    /// carrier write, as far as one batch holds it. Never blocks.
    fn release_first_flight(&self) {
        self.0.release_first_flight();
    }
    /// What became of the session's early data.
    #[getter]
    fn early_data<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        typed(py, "EarlyDataState", kind_of(&self.0.early_data()))
    }

    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    /// A normal exit closes and waits for the end (`close`, then
    /// `wait_closed`); an exit by an exception starts a close with
    /// `ZMUX_CANCELLED` and an empty reason and returns at once.
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        if !t.is_none() {
            // The close starts with the call; its future only waits.
            drop(s.close_with_error(zmux::VarInt::from_u32(ZMUX_CANCELLED), b""));
            return future_into_py(py, async move { Ok(false) });
        }
        future_into_py(py, async move {
            s.close().await;
            s.closed().await;
            Ok(false)
        })
    }
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    /// Iterates accepted bidirectional streams until the session ends.
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.2.bi, async move {
            match s.accept_bi().await {
                Ok(pair) => rt::attach(|py| bi(py, pair)),
                Err(e) => Err(iteration_end(e)),
            }
        })
    }
}

/// Whether the session ended cleanly: closed by either application with
/// code 0.
fn clean_end(e: &zmux::SessionError) -> bool {
    matches!(e, zmux::SessionError::ApplicationClosed { code, .. } if code.into_inner() == 0)
}

/// The end of an iteration over a session's streams or datagrams: the
/// iteration stops on a clean end and raises any other error.
fn iteration_end(e: zmux::SessionError) -> PyErr {
    if clean_end(&e) {
        PyStopAsyncIteration::new_err(())
    } else {
        session_err(e)
    }
}

fn dur(d: Option<Duration>) -> Option<f64> {
    d.map(|d| d.as_secs_f64())
}

fn support_obj(py: Python<'_>, s: zmux::Support) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("Support")?.call1((s.local, s.peer))
}

fn goaway_fields(d: &Bound<'_, PyDict>, g: &zmux::GoAway) -> PyResult<()> {
    d.set_item("max_bidi", g.max_bidi)?;
    d.set_item("max_uni", g.max_uni)?;
    d.set_item("code", g.code)
}

fn event_obj(py: Python<'_>, e: &zmux::SessionEvent) -> PyResult<Py<PyAny>> {
    use zmux::SessionEvent as E;
    let d = PyDict::new(py);
    let kind = match e {
        E::PipeAdded { pipe, carrier }
        | E::PipeJoined { pipe, carrier }
        | E::PipeSuspect { pipe, carrier }
        | E::PipeRecovered { pipe, carrier } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("carrier", carrier.map(zmux::CarrierKind::name))?;
            match e {
                E::PipeAdded { .. } => "PipeAdded",
                E::PipeJoined { .. } => "PipeJoined",
                E::PipeSuspect { .. } => "PipeSuspect",
                _ => "PipeRecovered",
            }
        }
        E::PipeFailed {
            pipe,
            failure,
            carrier,
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("failure", failure.map(|f| f.to_string()))?;
            d.set_item("carrier", carrier.map(zmux::CarrierKind::name))?;
            "PipeFailed"
        }
        E::PipeClosed {
            pipe,
            half,
            carrier,
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("half", format!("{half:?}"))?;
            d.set_item("carrier", carrier.map(zmux::CarrierKind::name))?;
            "PipeClosed"
        }
        E::JoinAuthFailed { reason, count, .. } => {
            d.set_item("reason", reason)?;
            d.set_item("count", count)?;
            "JoinAuthFailed"
        }
        E::PipePriorityChanged {
            pipe,
            send_priority,
            standby,
            weight,
            source,
            ..
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("send_priority", send_priority)?;
            d.set_item("standby", standby)?;
            d.set_item("weight", weight)?;
            d.set_item("source", format!("{source:?}"))?;
            "PipePriorityChanged"
        }
        E::PipeQualityChanged {
            pipe,
            smoothed_rtt,
            delivery_rate,
            ..
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("smoothed_rtt", dur(*smoothed_rtt))?;
            d.set_item("delivery_rate", delivery_rate)?;
            "PipeQualityChanged"
        }
        E::TierSaturation {
            priority,
            saturated,
            ..
        } => {
            d.set_item("priority", priority)?;
            d.set_item("saturated", saturated)?;
            "TierSaturation"
        }
        E::CapacityBelow { rate, .. } => {
            d.set_item("rate", rate)?;
            "CapacityBelow"
        }
        E::CapacityRestored { rate, .. } => {
            d.set_item("rate", rate)?;
            "CapacityRestored"
        }
        E::GoAwayReceived(g) => {
            goaway_fields(&d, g)?;
            "GoAwayReceived"
        }
        E::SessionSuspended => "SessionSuspended",
        E::SessionResumed => "SessionResumed",
        E::ResumeUnattended => "ResumeUnattended",
        E::PipesRetired {
            retired,
            failed,
            closed,
            dropped,
            last,
            ..
        } => {
            d.set_item("retired", retired)?;
            d.set_item("failed", failed)?;
            d.set_item("closed", closed)?;
            d.set_item("dropped", dropped)?;
            d.set_item("last", last.iter().map(|p| p.get()).collect::<Vec<_>>())?;
            "PipesRetired"
        }
        E::CarrierCandidate {
            kind,
            variant,
            outcome,
            joined,
            ..
        } => {
            d.set_item("carrier", kind.name())?;
            d.set_item("variant", variant.as_deref())?;
            d.set_item("outcome", outcome.name())?;
            d.set_item("joined", joined)?;
            "CarrierCandidate"
        }
        E::CarrierChosen(kind, variant) => {
            d.set_item("carrier", kind.name())?;
            d.set_item("variant", variant.as_deref())?;
            "CarrierChosen"
        }
        E::EpochCommitted { epoch } => {
            d.set_item("epoch", epoch)?;
            "EpochCommitted"
        }
        E::EpochDeleted { epoch } => {
            d.set_item("epoch", epoch)?;
            "EpochDeleted"
        }
        _ => {
            d.set_item("detail", format!("{e:?}"))?;
            "Unknown"
        }
    };
    Ok(types(py)?.getattr("_event")?.call1((kind, d))?.unbind())
}

/// `Session.events()`: session events until the session ended.
#[pyclass(frozen, module = "zmux")]
struct EventStream(zmux::Session, Arc<SessionReturned>);

#[pymethods]
impl EventStream {
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.1.events, async move {
            match s.next_event().await {
                Some(e) => rt::attach(|py| event_obj(py, &e)),
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

/// `Session.datagrams()`: received datagrams until the session ended.
#[pyclass(frozen, module = "zmux")]
struct DatagramStream(zmux::Session, Arc<SessionReturned>);

#[pymethods]
impl DatagramStream {
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        returned_first(py, &self.1.datagrams, async move {
            match s.read_datagram().await {
                Ok(b) => Ok(pyb(&b)),
                Err(e) => Err(iteration_end(e)),
            }
        })
    }
}

/// A duration in seconds from Python: finite and non-negative, else
/// `ValueError`.
pub(crate) fn seconds(name: &str, v: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(v)
        .map_err(|_| PyValueError::new_err(format!("{name} is a non-negative number of seconds")))
}

/// A pipe direction of a `zmux.Direction` or its name.
pub(crate) fn direction_of(v: &Bound<'_, PyAny>) -> PyResult<zmux::PipeDirection> {
    direction_named(&v.str()?.extract::<String>()?)
}

/// The pipe direction of a name.
fn direction_named(name: &str) -> PyResult<zmux::PipeDirection> {
    Ok(match name {
        "bidi" => zmux::PipeDirection::Bidi,
        "out" => zmux::PipeDirection::Out,
        "in" => zmux::PipeDirection::In,
        d => {
            return Err(PyValueError::new_err(format!(
                "a direction is bidi, out or in, not {d:?}"
            )));
        }
    })
}

/// The `zmux.Direction` of a pipe direction.
pub(crate) fn direction_obj(py: Python<'_>, d: zmux::PipeDirection) -> Bound<'_, PyAny> {
    let name = match d {
        zmux::PipeDirection::In => "in",
        zmux::PipeDirection::Out => "out",
        zmux::PipeDirection::Bidi => "bidi",
    };
    typed(py, "Direction", name.to_owned())
}

/// The Python value of a local setting that follows the peer's request
/// unless set.
fn auto_obj<'p, T: IntoPyObject<'p>>(py: Python<'p>, v: Option<T>) -> PyResult<Bound<'p, PyAny>> {
    match v {
        None => setting(py, "AUTO"),
        Some(v) => v.into_bound_py_any(py),
    }
}

/// The native options of a pipe from a `PipeOptions` (`None`: the
/// defaults); invalid values raise `ValueError`.
pub(crate) fn pipe_options(options: Option<Bound<'_, PyAny>>) -> PyResult<zmux::PipeOptions> {
    let mut o = zmux::PipeOptions::new();
    let Some(opts) = options else {
        return Ok(o);
    };
    let get = |n: &str| opts.getattr(n);
    o.direction = direction_of(&get("direction")?)?;
    o.record_mode = inherit(&get("record_mode")?, seal::record_mode_of)?;
    o.key_group = inherit(&get("key_group")?, |x| field_count("key_group", x))?;
    o.send_priority = change(&get("send_priority")?, |x| field_count("send_priority", x))?;
    o.receive_priority = change(&get("receive_priority")?, |x| {
        field_count("receive_priority", x)
    })?;
    o.send_standby = change(&get("send_standby")?, |x| {
        required("send_standby", x)?.extract()
    })?;
    o.receive_standby = change(&get("receive_standby")?, |x| {
        required("receive_standby", x)?.extract()
    })?;
    o.weight = change(&get("weight")?, |x| field_count("weight", x))?;
    o.probation = change(&get("probation")?, |x| probation_of("probation", x))?;
    o.label = get("label")?.extract::<Option<String>>()?.map(Into::into);
    o.fate_group = field_count("fate_group", &get("fate_group")?)?;
    o.liveness = change(&get("liveness")?, |x| {
        pipe_liveness(required("liveness", x)?)
    })?;
    o.quality_band = change(&get("quality_band")?, quality_band)?;
    o.return_on_reply = required("return_on_reply", &get("return_on_reply")?)?.extract()?;
    o.validate().map_err(pipe_err)?;
    Ok(o)
}

/// The Python `PipeOptions` of native options.
pub(crate) fn options_obj<'p>(py: Python<'p>, o: &zmux::PipeOptions) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("direction", direction_obj(py, o.direction))?;
    d.set_item(
        "record_mode",
        inherit_obj(py, o.record_mode, |m| record_mode_obj(py, m))?,
    )?;
    d.set_item(
        "key_group",
        inherit_obj(py, o.key_group, |g| typed_int(py, "KeyGroup", g))?,
    )?;
    let plain = |v: u64| Ok(v.into_pyobject(py)?.into_any());
    d.set_item("send_priority", change_obj(py, o.send_priority, plain)?)?;
    d.set_item(
        "receive_priority",
        change_obj(py, o.receive_priority, plain)?,
    )?;
    d.set_item(
        "send_standby",
        change_obj(py, o.send_standby, |b| b.into_bound_py_any(py))?,
    )?;
    d.set_item(
        "receive_standby",
        change_obj(py, o.receive_standby, |b| b.into_bound_py_any(py))?,
    )?;
    d.set_item("weight", change_obj(py, o.weight, plain)?)?;
    d.set_item(
        "probation",
        change_obj(py, o.probation, |p| probation_obj(py, p))?,
    )?;
    d.set_item("label", o.label.as_deref())?;
    d.set_item("fate_group", o.fate_group)?;
    d.set_item(
        "liveness",
        change_obj(py, o.liveness, |l| pipe_liveness_obj(py, &l))?,
    )?;
    d.set_item(
        "quality_band",
        change_obj(py, o.quality_band, |b| quality_band_obj(py, b))?,
    )?;
    d.set_item("return_on_reply", o.return_on_reply)?;
    types(py)?.getattr("PipeOptions")?.call((), Some(&d))
}

/// A `zmux._types` integer enum member for `v`, or `v` itself when
/// unknown.
fn typed_int<'p>(py: Python<'p>, enum_name: &str, v: u64) -> PyResult<Bound<'p, PyAny>> {
    let cls = types(py)?.getattr(enum_name)?;
    match cls.call1((v,)) {
        Ok(m) => Ok(m),
        Err(_) => v.into_bound_py_any(py),
    }
}

/// The options of a live pipe that `Pipe.update` changes, and those fixed
/// when it is added.
const UPDATABLE: [&str; 8] = [
    "send_priority",
    "receive_priority",
    "send_standby",
    "receive_standby",
    "weight",
    "probation",
    "liveness",
    "quality_band",
];
const FIXED: [&str; 6] = [
    "direction",
    "record_mode",
    "key_group",
    "label",
    "fate_group",
    "return_on_reply",
];

/// One field of `Pipe.update`: `zmux.CLEAR` clears, a value sets.
fn change<T>(
    v: &Bound<'_, PyAny>,
    set: impl FnOnce(&Bound<'_, PyAny>) -> PyResult<T>,
) -> PyResult<zmux::Change<T>> {
    if is_setting(v, "CLEAR")? {
        return Ok(zmux::Change::Clear);
    }
    set(v).map(zmux::Change::Set)
}

/// The Python value of a pipe setting: `zmux.CLEAR` when it is the
/// default, else its value.
fn change_obj<'p, T>(
    py: Python<'p>,
    v: zmux::Change<T>,
    set: impl FnOnce(T) -> PyResult<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    match v {
        zmux::Change::Set(t) => set(t),
        _ => setting(py, "CLEAR"),
    }
}

/// The native update of `Pipe.update(**fields)`.
fn pipe_update(kw: Option<&Bound<'_, PyDict>>) -> PyResult<zmux::PipeUpdate> {
    let mut u = zmux::PipeUpdate::default();
    let Some(kw) = kw else {
        return Ok(u);
    };
    for (k, v) in kw.iter() {
        let k: String = k.extract()?;
        if FIXED.contains(&k.as_str()) {
            return Err(PyTypeError::new_err(format!(
                "{k} is fixed when the pipe is added"
            )));
        }
        if !UPDATABLE.contains(&k.as_str()) {
            return Err(PyTypeError::new_err(format!("no pipe option {k}")));
        }
        let v = &v;
        match k.as_str() {
            "send_priority" => u.send_priority = change(v, |x| field_count(&k, x))?,
            "receive_priority" => u.receive_priority = change(v, |x| field_count(&k, x))?,
            "send_standby" => {
                u.send_standby = change(v, |x| required(&k, x)?.extract())?;
            }
            "receive_standby" => {
                u.receive_standby = change(v, |x| required(&k, x)?.extract())?;
            }
            "weight" => u.weight = change(v, |x| field_count(&k, x))?,
            "probation" => u.probation = change(v, |x| probation_of(&k, x))?,
            "liveness" => u.liveness = change(v, |x| pipe_liveness(required(&k, x)?))?,
            _ => u.quality_band = change(v, quality_band)?,
        }
    }
    Ok(u)
}

/// A point in time of the Rust clock on Python's `time.monotonic()`
/// clock: the offset from now on both.
fn monotonic(py: Python<'_>, t: std::time::Instant) -> PyResult<f64> {
    let now = std::time::Instant::now();
    let py_now: f64 = py.import("time")?.call_method0("monotonic")?.extract()?;
    Ok(if t >= now {
        py_now + (t - now).as_secs_f64()
    } else {
        py_now - (now - t).as_secs_f64()
    })
}

/// The `zmux.Role` of a role.
pub(crate) fn role_obj(py: Python<'_>, r: zmux::Role) -> PyResult<Bound<'_, PyAny>> {
    let name = match r {
        zmux::Role::Client => "CLIENT",
        zmux::Role::Server => "SERVER",
        zmux::Role::Auto => "AUTO",
    };
    types(py)?.getattr("Role")?.getattr(name)
}

fn record_mode_obj(py: Python<'_>, m: zmux::RecordMode) -> PyResult<Bound<'_, PyAny>> {
    let name = match m {
        zmux::RecordMode::Sealed => "SEALED",
        zmux::RecordMode::Bound => "BOUND",
        zmux::RecordMode::Trusted => "TRUSTED",
        zmux::RecordMode::Unmanaged => "UNMANAGED",
    };
    types(py)?.getattr("RecordMode")?.getattr(name)
}

fn stats_dict<'p>(py: Python<'p>, s: &zmux::PipeStats) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    macro_rules! put {
        ($($f:ident),*) => { $(d.set_item(stringify!($f), s.$f)?;)* };
    }
    put!(
        local,
        peer_attached,
        fate_group,
        suspect_count,
        failure_count,
        send_priority,
        standby,
        receive_priority,
        receive_standby,
        request_seq,
        weight,
        in_probation,
        revalidating,
        eligible,
        writable,
        saturated,
        delivery_rate,
        queued_bytes,
        bytes_in_flight,
        bytes_sent,
        bytes_received,
        bytes_acked,
        records_sent,
        records_received,
        bytes_reinjected,
        bytes_lost,
        records_lost,
        bytes_retransmitted,
        loss_rate,
        bytes_opportunistic,
        bytes_redundant,
        bytes_duplicate_received,
        pings_sent,
        pings_answered,
        lanes_out,
        lanes_in,
        lanes_refused
    );
    d.set_item("pipe", s.pipe.get())?;
    d.set_item(
        "record_mode",
        s.record_mode.map(|m| record_mode_obj(py, m)).transpose()?,
    )?;
    d.set_item("label", s.label.as_deref())?;
    d.set_item("carrier", s.carrier.map(zmux::CarrierKind::name))?;
    d.set_item("variant", s.variant.as_deref())?;
    d.set_item("inbound", s.inbound.map(|x| kind_of(&x)))?;
    d.set_item("outbound", s.outbound.map(|x| kind_of(&x)))?;
    d.set_item("attached_for", s.attached_for.as_secs_f64())?;
    d.set_item("epoch", s.epoch)?;
    d.set_item("failure", s.failure.map(|x| x.to_string()))?;
    d.set_item("send_priority_source", kind_of(&s.send_priority_source))?;
    d.set_item("standby_source", kind_of(&s.standby_source))?;
    d.set_item(
        "peer_request",
        s.peer_request.map(|r| (r.priority, r.standby)),
    )?;
    d.set_item(
        "probation_until",
        s.probation_until.map(|t| monotonic(py, t)).transpose()?,
    )?;
    d.set_item(
        "replace_by",
        s.replace_by.map(|t| monotonic(py, t)).transpose()?,
    )?;
    d.set_item(
        "rtt_source",
        s.rtt_source.map(|r| kind_of(&r).to_lowercase()),
    )?;
    d.set_item("smoothed_rtt", dur(s.smoothed_rtt))?;
    d.set_item("min_rtt", dur(s.min_rtt))?;
    d.set_item("rttvar", dur(s.rttvar))?;
    d.set_item("one_way_delay", dur(s.one_way_delay))?;
    d.set_item("queue_delay", dur(s.queue_delay))?;
    d.set_item("since_last_ack", dur(s.since_last_ack))?;
    d.set_item("since_last_receive", dur(s.since_last_receive))?;
    d.set_item("since_last_traffic", dur(s.since_last_traffic))?;
    let lanes = s
        .lanes
        .iter()
        .map(|l| {
            (
                l.lane.get(),
                l.position_sent,
                l.position_acked,
                l.position_received,
            )
        })
        .collect::<Vec<_>>();
    d.set_item("lanes", lanes)?;
    types(py)?.getattr("_pipe_stats")?.call1((d,))
}

/// One pipe of a session. The Python session it was given by is
/// `Pipe.session`, with what that object's calls took back.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Pipe(pub(crate) zmux::Pipe, Py<Session>);

/// `pipes` as Python pipes of the session `owner`.
fn pipes_of(pipes: Vec<zmux::Pipe>, owner: &Py<Session>) -> Vec<Pipe> {
    rt::attach(|py| {
        pipes
            .into_iter()
            .map(|p| Pipe(p, owner.clone_ref(py)))
            .collect()
    })
}

#[pymethods]
impl Pipe {
    /// The pipe's ID (`PipeId`).
    #[getter]
    fn id(&self) -> u64 {
        self.0.id().get()
    }
    /// The value the listener's admission gave the carrier that brought
    /// the pipe (`AdmissionVerdict.accept(value=...)`): its join's carrier, the
    /// session's for pipe 0; `None` without one and once the session
    /// forgot the pipe.
    #[getter]
    fn admitted(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        admission::admitted_obj(py, self.0.admitted().as_ref())
    }
    /// Waits until the join is confirmed.
    fn joined<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = self.0.clone();
        future_into_py(py, async move { p.joined().await.map_err(pipe_err) })
    }
    /// Waits until the peer attached the pipe.
    fn attached<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = self.0.clone();
        future_into_py(py, async move { p.attached().await.map_err(pipe_err) })
    }
    /// Waits until the pipe ended.
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = self.0.clone();
        future_into_py(py, async move { p.closed().await.map_err(pipe_err) })
    }
    /// The session the pipe belongs to.
    #[getter]
    fn session(&self, py: Python<'_>) -> Py<Session> {
        self.1.clone_ref(py)
    }
    /// Changes the settings a live pipe changes, together: a keyword left
    /// out keeps its value, `zmux.CLEAR` clears it (the `send_*` fields
    /// then follow the peer's request, the `receive_*` fields request the
    /// default, `weight` is 1, `probation` and `liveness` follow the
    /// session's), and a value sets it (`probation=None` turns probation
    /// off). A field fixed when the pipe is added or an unknown name
    /// raises `TypeError`; an invalid value raises `ValueError` and
    /// changes nothing.
    #[pyo3(signature = (**fields))]
    fn update(&self, fields: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
        let u = pipe_update(fields)?;
        self.0.update(&u).map_err(pipe_err)
    }
    /// The options in force, with the fields `update` set; `None` once the
    /// pipe's state is released.
    #[getter]
    fn options<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0.options().map(|o| options_obj(py, &o)).transpose()
    }
    /// The outbound direction's state (else the inbound one's).
    #[getter]
    fn state<'p>(&self, py: Python<'p>) -> Option<Bound<'p, PyAny>> {
        let s = self.0.stats()?;
        match (s.outbound, s.inbound) {
            (Some(o), _) => Some(typed(py, "OutboundState", kind_of(&o))),
            (None, Some(i)) => Some(typed(py, "InboundState", kind_of(&i))),
            (None, None) => None,
        }
    }
    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    /// A normal exit closes the pipe gracefully, an exit by an exception
    /// aborts it.
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let _ = if t.is_none() {
            self.0.close()
        } else {
            self.0.abort()
        };
        future_into_py(py, async move { Ok(false) })
    }
    fn close(&self) -> PyResult<()> {
        self.0.close().map_err(pipe_err)
    }
    fn abort(&self) -> PyResult<()> {
        self.0.abort().map_err(pipe_err)
    }
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0.stats().map(|s| stats_dict(py, &s)).transpose()
    }
}

type PreambleTuple<'p> = (
    Option<Bound<'p, PyBytes>>,
    Vec<(u64, Bound<'p, PyBytes>)>,
    bool,
);

// ---- streams --------------------------------------------------------------------------

/// A stream part a Python handle holds: taken out by the calls that consume
/// it (`reject`, `stream_pipe`, `splice`).
pub(crate) type Part<T> = Arc<Mutex<Option<T>>>;

/// The error of a part another call took.
fn taken() -> PyErr {
    stream_err(zmux::StreamError::ClosedLocally)
}

/// The part, waiting for an operation in progress.
async fn held<T>(p: &Part<T>) -> PyResult<MappedMutexGuard<'_, T>> {
    MutexGuard::try_map(p.lock().await, Option::as_mut).map_err(|_| taken())
}

/// The part now, for the calls that never wait; `StreamBusyError` while an
/// operation is in progress.
fn held_now<T>(p: &Part<T>) -> PyResult<MappedMutexGuard<'_, T>> {
    MutexGuard::try_map(p.try_lock().map_err(|_| busy())?, Option::as_mut).map_err(|_| taken())
}

/// Runs `f` on the part now, or, while an operation holds it, on the
/// runtime once that operation released it.
fn later<T: Send + 'static>(
    p: &Part<T>,
    f: impl FnOnce(&mut T) -> Result<(), zmux::StreamError> + Send + 'static,
) -> PyResult<()> {
    if let Ok(mut g) = p.try_lock() {
        match g.as_mut() {
            Some(s) => f(s).map_err(stream_err),
            None => Err(taken()),
        }
    } else {
        let p = p.clone();
        get_runtime().spawn(async move {
            if let Some(s) = p.lock().await.as_mut() {
                let _ = f(s);
            }
        });
        Ok(())
    }
}

/// Takes the part out of its handle, which fails from then on.
pub(crate) fn take_now<T>(p: &Part<T>) -> PyResult<T> {
    p.try_lock().map_err(|_| busy())?.take().ok_or_else(taken)
}

/// A received buffer lent to Python without a copy (`memoryview(chunk)`).
#[pyclass(frozen, module = "zmux")]
struct Chunk(Bytes);

#[pymethods]
impl Chunk {
    unsafe fn __getbuffer__(
        slf: Bound<'_, Self>,
        view: *mut pyo3::ffi::Py_buffer,
        flags: std::os::raw::c_int,
    ) -> PyResult<()> {
        if flags & pyo3::ffi::PyBUF_WRITABLE != 0 {
            return Err(pyo3::exceptions::PyBufferError::new_err(
                "the chunk is read-only",
            ));
        }
        let b = &slf.get().0;
        // SAFETY: the view exports the immutable bytes of the chunk, which the
        // exporter object `slf` keeps alive for the view's lifetime.
        unsafe {
            let r = pyo3::ffi::PyBuffer_FillInfo(
                view,
                slf.as_ptr(),
                b.as_ptr().cast_mut().cast(),
                b.len().cast_signed(),
                1,
                flags,
            );
            if r == -1 {
                return Err(PyErr::fetch(slf.py()));
            }
        }
        Ok(())
    }
    unsafe fn __releasebuffer__(&self, _view: *mut pyo3::ffi::Py_buffer) {}
}

/// A Python buffer handed to a sending part without a copy: the caller
/// does not modify it afterwards.
struct Lent(Option<pyo3::buffer::PyBuffer<u8>>);

impl AsRef<[u8]> for Lent {
    fn as_ref(&self) -> &[u8] {
        let b = self.0.as_ref().expect("held until dropped");
        // SAFETY: the buffer is C-contiguous (checked when lent) and stays
        // exported while `self` holds it.
        unsafe { std::slice::from_raw_parts(b.buf_ptr().cast::<u8>(), b.len_bytes()) }
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        if let Some(b) = self.0.take() {
            rt::release_buffer(b);
        }
    }
}

fn lend(data: &Bound<'_, PyAny>) -> PyResult<Bytes> {
    let buf = pyo3::buffer::PyBuffer::<u8>::get(data)?;
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err("the buffer is not contiguous"));
    }
    Ok(Bytes::from_owner(Lent(Some(buf))))
}

fn stream_stats<'p>(py: Python<'p>, st: &zmux::StreamStats) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    macro_rules! put {
        ($($f:ident),*) => { $(d.set_item(stringify!($f), st.$f)?;)* };
    }
    put!(
        bytes_written,
        bytes_sent,
        bytes_acknowledged,
        bytes_received,
        bytes_read,
        datagrams_sent,
        datagrams_received,
        datagrams_dropped_recv,
        datagram_bytes_sent,
        datagram_bytes_received,
        send_buffered,
        recv_buffered,
        recv_window
    );
    d.set_item("pipe_id", st.pipe_id.map(zmux::PipeId::get))?;
    types(py)?.getattr("StreamStats")?.call((), Some(&d))
}

/// The sending part of a stream.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct SendStream(pub(crate) Part<zmux::SendStream>);

impl SendStream {
    fn wrap(s: zmux::SendStream) -> Self {
        SendStream(Arc::new(Mutex::new(Some(s))))
    }
}

#[pymethods]
impl SendStream {
    /// Writes all of `data`, waiting for flow control.
    fn write<'p>(
        &self,
        py: Python<'p>,
        data: pyo3::pybacked::PyBackedBytes,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let n = data.len();
        // Zero-copy for `bytes`: the chunk keeps the Python object alive.
        future_into_py(py, async move {
            held(&s)
                .await?
                .write_chunk(Bytes::from_owner(data))
                .await
                .map_err(stream_err)?;
            Ok(n)
        })
    }
    /// Writes the buffer without copying it; the caller does not modify it
    /// afterwards.
    fn write_chunk<'p>(
        &self,
        py: Python<'p>,
        buffer: &Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let data = lend(buffer)?;
        let n = data.len();
        future_into_py(py, async move {
            held(&s)
                .await?
                .write_chunk(data)
                .await
                .map_err(stream_err)?;
            Ok(n)
        })
    }
    /// Opens the stream now and waits until the opening frame and the data
    /// written so far left for a carrier: the peer sees the stream even with
    /// nothing written. A cancelled call leaves the frame owed.
    fn flush<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            {
                use tokio::io::AsyncWriteExt;
                held(&s).await?.flush().await.map_err(io_err)
            }
        })
    }
    /// Ends the stream cleanly (FIN).
    /// Waits for an operation in progress (a cancelled one releases at once).
    fn finish<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(
            py,
            async move { held(&s).await?.finish().map_err(stream_err) },
        )
    }
    /// Abandons the stream with an application error code; never blocks.
    /// While a write is in progress the reset follows once that write
    /// returns or is cancelled. During the read drain after the peer's
    /// close it raises the session's error; the exit of `async with`
    /// ignores it.
    fn reset(&self, code: u64) -> PyResult<()> {
        let code = varint(code)?;
        later(&self.0, move |s| s.reset(code))
    }
    /// Marks the bytes written so far as delivered even if the stream is
    /// reset later (`RESET_STREAM_AT`).
    fn set_reliable_boundary(&self) -> PyResult<()> {
        held_now(&self.0)?
            .set_reliable_boundary()
            .map_err(stream_err)
    }
    /// The stream's `Priority`; assigning a `Priority` (or an
    /// `(urgency, incremental)` pair) changes it.
    #[getter]
    fn priority<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = held_now(&self.0)?.priority().map_err(stream_err)?;
        types(py)?
            .getattr("Priority")?
            .call1((p.urgency(), p.incremental()))
    }
    #[setter]
    fn set_priority(&self, priority: (u8, bool)) -> PyResult<()> {
        held_now(&self.0)?
            .set_priority(self::priority(priority.0, priority.1)?)
            .map_err(stream_err)
    }
    /// The bytes the part could transmit now.
    fn send_capacity(&self) -> PyResult<u64> {
        Ok(held_now(&self.0)?.send_capacity())
    }
    /// Waits until the send capacity is at least `minimum` (or above 0 while
    /// nothing is unsent) and returns it.
    fn wait_send_capacity<'p>(&self, py: Python<'p>, minimum: u64) -> PyResult<Bound<'p, PyAny>> {
        if minimum == 0 {
            return Err(PyValueError::new_err("minimum is at least 1"));
        }
        let s = self.0.clone();
        future_into_py(py, async move {
            held(&s)
                .await?
                .wait_send_capacity(minimum)
                .await
                .map_err(stream_err)
        })
    }
    /// The bytes written and not yet released that the part may hold: the
    /// last assignment, else the session's `Config.send_buffer`.
    #[getter]
    fn send_buffer(&self) -> PyResult<u64> {
        held_now(&self.0)?.send_buffer().map_err(stream_err)
    }
    #[setter]
    fn set_send_buffer(&self, n: u64) -> PyResult<()> {
        held_now(&self.0)?.set_send_buffer(n).map_err(stream_err)
    }
    /// The part's scheduling policy; `None` follows the session's.
    #[getter]
    fn scheduler<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        let p = held_now(&self.0)?.scheduler().map_err(stream_err)?;
        Ok(p.map(|p| typed(py, "Scheduler", policy_name(&p).to_owned())))
    }
    #[setter]
    fn set_scheduler(&self, scheduler: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        let p = scheduler_of(scheduler)?;
        held_now(&self.0)?.set_scheduler(p).map_err(stream_err)
    }
    /// Sends the part's chunks redundantly on a second pipe (multipath):
    /// `True` on, `False` off, `None` following the session's `redundancy`.
    #[getter]
    fn redundant(&self) -> PyResult<Option<bool>> {
        held_now(&self.0)?.redundant().map_err(stream_err)
    }
    #[setter]
    fn set_redundant(&self, on: Option<bool>) -> PyResult<()> {
        held_now(&self.0)?.set_redundant(on).map_err(stream_err)
    }
    /// The largest datagram payload the peer accepts on this stream with
    /// the context ID `context`, or `None` without datagram flows.
    #[pyo3(signature = (context=0))]
    fn max_datagram_size(&self, context: u64) -> PyResult<Option<usize>> {
        Ok(held_now(&self.0)?.max_datagram_size(context))
    }
    /// Sends a datagram of the stream with the context ID `context`.
    #[pyo3(signature = (payload, context=0))]
    fn send_datagram(&self, payload: Vec<u8>, context: u64) -> PyResult<()> {
        held_now(&self.0)?
            .send_datagram(context, Bytes::from(payload))
            .map_err(datagram_err)
    }
    /// A snapshot of the stream's statistics.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = held_now(&self.0)?.stats();
        stream_stats(py, &st)
    }
    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    /// Finishes on a normal exit (unless already ended), resets with
    /// `ZMUX_CANCELLED` on an exception.
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let ok = t.is_none();
        let s = self.0.clone();
        future_into_py(py, async move {
            if !ok {
                // At once, as `reset()`: a write another task has blocked on
                // flow control does not hold the exit.
                let _ = later(&s, |g| g.reset(zmux::VarInt::from_u32(ZMUX_CANCELLED)));
                return Ok(false);
            }
            let mut g = s.lock().await;
            let Some(g) = g.as_mut() else {
                return Ok(false);
            };
            match g.finish() {
                Err(e) if kind_of(&e) == "ClosedLocally" => Ok(false),
                r => r.map(|()| false).map_err(stream_err),
            }
        })
    }
    /// Waits until the peer stops the stream; returns its code or `None` once all data was acknowledged.
    fn stopped<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            // Holds nothing of the part: a write goes on while this waits.
            let fut = held(&s).await?.stopped_owned();
            fut.await
                .map(|c| c.map(zmux::VarInt::into_inner))
                .map_err(stream_err)
        })
    }
    #[getter]
    fn id(&self) -> PyResult<Option<u64>> {
        Ok(held_now(&self.0)?.id().map(zmux::StreamId::into_inner))
    }
}

/// Bytes read from a stream and not yet given to an awaiter: reads that take many chunks
/// collect them here, and a read cancelled as it completed returns its result here.
pub(crate) type Unread = Arc<StdMutex<VecDeque<Bytes>>>;

/// Takes a result back to the front of the stream.
#[pyclass(frozen)]
pub(crate) struct PutBack(Unread);

/// Results of one kind of operation that were cancelled as they completed,
/// for the next call of that kind, ahead of new ones; the callable that
/// takes them back is made once, on the first call.
pub(crate) struct Returned<T> {
    q: Arc<StdMutex<VecDeque<T>>>,
    undo: PyOnceLock<Py<PyAny>>,
}

impl<T> Default for Returned<T> {
    fn default() -> Self {
        Returned {
            q: Arc::default(),
            undo: PyOnceLock::new(),
        }
    }
}

impl<T> Returned<T> {
    pub(crate) fn queue(&self) -> Arc<StdMutex<VecDeque<T>>> {
        self.q.clone()
    }
}

impl Returned<Py<PyAny>> {
    pub(crate) fn undo(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let u = self.undo.get_or_try_init(py, || {
            Ok::<_, PyErr>(Py::new(py, Requeue(self.q.clone()))?.into_any())
        })?;
        Ok(Some(u.clone_ref(py)))
    }
}

impl Returned<Bytes> {
    pub(crate) fn undo(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let u = self.undo.get_or_try_init(py, || {
            Ok::<_, PyErr>(Py::new(py, PutBack(self.q.clone()))?.into_any())
        })?;
        Ok(Some(u.clone_ref(py)))
    }
}

/// Takes a result back for the next call.
#[pyclass(frozen)]
pub(crate) struct Requeue(pub(crate) Arc<StdMutex<VecDeque<Py<PyAny>>>>);

#[pymethods]
impl Requeue {
    fn __call__(&self, value: Bound<'_, PyAny>) {
        self.0.lock().unwrap().push_back(value.unbind());
    }
}

/// A result taken back earlier, or a new one.
pub(crate) enum Next<T> {
    Again(Py<PyAny>),
    New(T),
}

impl<'py, T: IntoPyObject<'py>> IntoPyObject<'py> for Next<T> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;
    fn into_pyobject(self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match self {
            Next::Again(o) => Ok(o.into_bound(py)),
            Next::New(t) => t.into_bound_py_any(py),
        }
    }
}

/// `fut`'s result, unless a result of the same kind was taken back: that
/// one first. A result cancelled as it completed is taken back.
fn returned_first<'p, F, T>(
    py: Python<'p>,
    r: &Returned<Py<PyAny>>,
    fut: F,
) -> PyResult<Bound<'p, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
{
    let q = r.queue();
    let undo = r.undo(py)?;
    rt::undoable_future_into_py(
        py,
        async move {
            let again = q.lock().unwrap().pop_front();
            match again {
                Some(o) => Ok((Next::Again(o), ())),
                None => Ok((Next::New(fut.await?), ())),
            }
        },
        undo,
    )
}

#[pymethods]
impl PutBack {
    fn __call__(&self, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let buf = pyo3::buffer::PyBuffer::<u8>::get(value)?;
        let data = buf.to_vec(value.py())?;
        if !data.is_empty() {
            self.0.lock().unwrap().push_front(data.into());
        }
        Ok(())
    }
}

pub(crate) fn unread_take(unread: &Unread, max: usize) -> Option<Bytes> {
    let mut q = unread.lock().unwrap();
    let front = q.front_mut()?;
    if front.len() > max {
        return Some(front.split_to(max));
    }
    q.pop_front()
}

/// The receiving part, held until a read's result is settled: a read cancelled as it
/// completes takes its result back before the next read begins.
type HeldRecv = tokio::sync::OwnedMutexGuard<Option<zmux::RecvStream>>;

async fn held_recv(s: &Part<zmux::RecvStream>) -> PyResult<HeldRecv> {
    let part = s.clone().lock_owned().await;
    if part.is_none() {
        return Err(taken());
    }
    Ok(part)
}

/// Up to `max` bytes, those set aside first; `None` at the end of the stream.
async fn next_chunk(
    s: &Part<zmux::RecvStream>,
    unread: &Unread,
    max: usize,
) -> PyResult<(Option<Bytes>, HeldRecv)> {
    let mut part = held_recv(s).await?;
    if let Some(b) = unread_take(unread, max) {
        return Ok((Some(b), part));
    }
    let r = part.as_mut().ok_or_else(taken)?;
    let b = r.read_chunk(max).await.map_err(stream_err)?;
    Ok((b, part))
}

/// Moves chunks to the unread bytes until they hold `want` or the stream ends; how many they
/// hold. A cancellation leaves everything read in place.
async fn collect(
    s: &Part<zmux::RecvStream>,
    unread: &Unread,
    want: usize,
) -> PyResult<(usize, HeldRecv)> {
    let mut part = held_recv(s).await?;
    loop {
        let have: usize = unread.lock().unwrap().iter().map(Bytes::len).sum();
        if have >= want {
            return Ok((have, part));
        }
        let r = part.as_mut().ok_or_else(taken)?;
        match r.read_chunk(want - have).await.map_err(stream_err)? {
            Some(b) if !b.is_empty() => unread.lock().unwrap().push_back(b),
            _ => return Ok((have, part)),
        }
    }
}

fn unread_drain(unread: &Unread, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        match unread_take(unread, n - out.len()) {
            Some(b) => out.extend_from_slice(&b),
            None => break,
        }
    }
    out
}

/// The receiving part of a stream.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct RecvStream(pub(crate) Part<zmux::RecvStream>, Unread);

impl RecvStream {
    fn wrap(s: zmux::RecvStream) -> Self {
        RecvStream(Arc::new(Mutex::new(Some(s))), Unread::default())
    }
    fn undo(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        Ok(Some(Py::new(py, PutBack(self.1.clone()))?.into_any()))
    }
}

#[pymethods]
impl RecvStream {
    /// Up to `n` bytes; `b""` at the end of the stream.
    #[pyo3(signature = (n=65536))]
    fn read<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let (s, unread) = (self.0.clone(), self.1.clone());
        let undo = self.undo(py)?;
        rt::undoable_future_into_py(
            py,
            async move {
                let (b, part) = next_chunk(&s, &unread, n).await?;
                Ok((b.as_deref().map_or_else(|| pyb(b""), pyb), part))
            },
            undo,
        )
    }
    /// Up to `n` bytes as a `memoryview` of the received buffer, without
    /// a copy; an empty one at the end of the stream.
    #[pyo3(signature = (n=65536))]
    fn read_chunk<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let (s, unread) = (self.0.clone(), self.1.clone());
        let undo = self.undo(py)?;
        rt::undoable_future_into_py(
            py,
            async move {
                let (b, part) = next_chunk(&s, &unread, n).await?;
                let view: PyResult<Py<PyAny>> = rt::attach(|py| {
                    let c = Bound::new(py, Chunk(b.unwrap_or_default()))?;
                    Ok(pyo3::types::PyMemoryView::from(&c)?.into_any().unbind())
                });
                Ok((view?, part))
            },
            undo,
        )
    }
    /// Exactly `n` bytes, or `IncompleteReadError` (its `partial` the bytes
    /// read) when the stream ends first.
    fn read_exact<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let (s, unread) = (self.0.clone(), self.1.clone());
        let undo = self.undo(py)?;
        rt::undoable_future_into_py(
            py,
            async move {
                let (have, part) = collect(&s, &unread, n).await?;
                if have < n {
                    let partial = unread_drain(&unread, have);
                    return Err(incomplete_read(&partial, n));
                }
                Ok((pyb(&unread_drain(&unread, n)), part))
            },
            undo,
        )
    }
    /// The rest of the stream, at most `limit` bytes.
    #[pyo3(signature = (limit=16 * 1024 * 1024))]
    fn read_to_end<'p>(&self, py: Python<'p>, limit: usize) -> PyResult<Bound<'p, PyAny>> {
        let (s, unread) = (self.0.clone(), self.1.clone());
        let undo = self.undo(py)?;
        rt::undoable_future_into_py(
            py,
            async move {
                let (have, part) = collect(&s, &unread, limit.saturating_add(1)).await?;
                if have > limit {
                    let e = zmux::ReadToEndError::TooLong;
                    return Err(raise("LimitExceededError", &e, false, None));
                }
                Ok((pyb(&unread_drain(&unread, have)), part))
            },
            undo,
        )
    }
    /// Asks the peer to stop sending (`STOP_SENDING`); never blocks. While a
    /// read is in progress the stop follows once that read returns or is
    /// cancelled. During the read drain after the peer's close it discards
    /// the unread data and raises the session's error; the exit of
    /// `async with` ignores it.
    fn stop(&self, code: u64) -> PyResult<()> {
        let code = varint(code)?;
        later(&self.0, move |r| r.stop(code))
    }
    /// Declines the stream before reading it (`ZMUX_REJECTED`); the handle
    /// is used up.
    fn reject(&self) -> PyResult<()> {
        take_now(&self.0)?.reject().map_err(stream_err)
    }
    /// The receive window of the stream, `(window, maximum)`: the window
    /// now advertised, which auto-tuning raises up to `maximum`.
    #[getter]
    fn receive_window(&self) -> PyResult<(u64, u64)> {
        held_now(&self.0)?.receive_window().map_err(stream_err)
    }
    #[setter]
    fn set_receive_window(&self, window: (u64, u64)) -> PyResult<()> {
        held_now(&self.0)?
            .set_receive_window(window.0, window.1)
            .map_err(stream_err)
    }
    /// The priority last asked of the peer for the stream; `None` when
    /// none was asked.
    #[getter]
    fn peer_priority<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        let Some(p) = held_now(&self.0)?.peer_priority().map_err(stream_err)? else {
            return Ok(None);
        };
        types(py)?
            .getattr("Priority")?
            .call1((p.urgency(), p.incremental()))
            .map(Some)
    }
    #[setter]
    fn set_peer_priority(&self, priority: (u8, bool)) -> PyResult<()> {
        held_now(&self.0)?
            .set_peer_priority(self::priority(priority.0, priority.1)?)
            .map_err(stream_err)
    }
    /// The next datagram of the stream: `(context, payload)`.
    fn read_datagram<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            // Holds nothing of the part: a read goes on while this waits.
            let fut = held(&s).await?.read_datagram_owned();
            let d = fut.await.map_err(stream_err)?;
            rt::attach(|py| {
                Ok(types(py)?
                    .getattr("StreamDatagram")?
                    .call1((d.context, PyBytes::new(py, &d.payload)))?
                    .unbind())
            })
        })
    }
    /// A snapshot of the stream's statistics.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = held_now(&self.0)?.stats();
        stream_stats(py, &st)
    }
    /// The stream's `Preamble`.
    #[getter]
    fn preamble<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = held_now(&self.0)?.preamble();
        let t: PreambleTuple<'p> = (
            p.info().map(|b| PyBytes::new(py, b)),
            p.tlvs().map(|(t, v)| (t, PyBytes::new(py, &v))).collect(),
            p.is_pipe_carrier(),
        );
        types(py)?.getattr("_preamble")?.call1(t)
    }
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    /// Chunks until the end of the stream.
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let (s, unread) = (self.0.clone(), self.1.clone());
        let undo = self.undo(py)?;
        rt::undoable_future_into_py(
            py,
            async move {
                match next_chunk(&s, &unread, 65536).await? {
                    (Some(b), part) if !b.is_empty() => Ok((pyb(&b), part)),
                    _ => Err(PyStopAsyncIteration::new_err(())),
                }
            },
            undo,
        )
    }
    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    /// Releases the stream with `stop(0)` on exit, an exception or not
    /// (automatic release): it returns at once, and is a no-op once the
    /// stream ended.
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let _ = t;
        let s = self.0.clone();
        future_into_py(py, async move {
            let _ = later(&s, |r| r.stop(zmux::VarInt::from_u32(0)));
            Ok(false)
        })
    }
    #[getter]
    fn is_replayable(&self) -> PyResult<bool> {
        Ok(held_now(&self.0)?.is_replayable())
    }
    /// The PRIORITY the peer put in the stream's opening preamble, as a
    /// `Priority`; `None` when it sent none or the stream is a local one.
    /// Later priority updates are not reflected.
    #[getter]
    fn requested_priority<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        held_now(&self.0)?
            .requested_priority()
            .map(|p| {
                types(py)?
                    .getattr("Priority")?
                    .call1((p.urgency(), p.incremental()))
            })
            .transpose()
    }
    #[getter]
    fn id(&self) -> PyResult<Option<u64>> {
        Ok(held_now(&self.0)?.id().map(zmux::StreamId::into_inner))
    }
}

// ---- listener -------------------------------------------------------------------------

/// A listener's choice of a session's configuration written in Python:
/// `f(carrier)` returning a `zmux.Config` or `None`. An exception or another
/// value is reported as unraisable and closes the carrier.
fn session_config_fn(f: Py<PyAny>) -> zmux::SessionConfigFn {
    zmux::SessionConfigFn::new(move |c| {
        rt::attach(|py| {
            let r = (|| -> PyResult<Option<zmux::Config>> {
                let addr = |a: Option<SocketAddr>| a.map(|a| (a.ip().to_string(), a.port()));
                let carrier = types(py)?.getattr("SessionCarrier")?.call1((
                    addr(c.source),
                    addr(c.peer),
                    c.tls.map(|s| tls_state_obj(py, s)).transpose()?,
                    admission::admitted_obj(py, c.admitted),
                ))?;
                let v = f.bind(py).call1((carrier,))?;
                if v.is_none() {
                    return Ok(None);
                }
                Ok(Some((*cfg(Some(v))?).clone()))
            })();
            r.map_err(|e| {
                let text = e.to_string();
                e.write_unraisable(py, Some(f.bind(py)));
                text
            })
        })
    })
}

/// A time-windowed single-use filter: each key is accepted once while its
/// stamp is within the window of the clock.
#[pyclass(frozen, module = "zmux")]
struct ReplayFilter(zmux::ReplayFilter);

fn replay_verdict(py: Python<'_>, v: zmux::ReplayVerdict) -> Bound<'_, PyAny> {
    use zmux::ReplayVerdict as V;
    let name = match v {
        V::Fresh => "fresh",
        V::Seen => "seen",
        V::Outside => "outside",
        V::Full => "full",
    };
    typed(py, "ReplayVerdict", name.to_owned())
}

#[pymethods]
impl ReplayFilter {
    /// A filter of `window` seconds (at least 0.001) holding at most
    /// `capacity` keys (at least 1); `not_before` (Unix seconds) rejects
    /// earlier stamps.
    #[new]
    #[pyo3(signature = (window, capacity, *, not_before=None))]
    fn new(window: f64, capacity: usize, not_before: Option<f64>) -> PyResult<Self> {
        let f = zmux::ReplayFilter::new(seconds("window", window)?, capacity).map_err(value_err)?;
        Ok(Self(match not_before {
            Some(t) => {
                let t = std::time::UNIX_EPOCH
                    .checked_add(seconds("not_before", t)?)
                    .ok_or_else(|| PyValueError::new_err("not_before is out of range"))?;
                f.with_not_before(t)
            }
            None => f,
        }))
    }
    /// Checks `key` stamped `stamp` (Unix milliseconds) by the system clock.
    fn check<'p>(&self, py: Python<'p>, key: &[u8], stamp: i64) -> Bound<'p, PyAny> {
        replay_verdict(py, self.0.check(key, stamp))
    }
    /// Checks `key` stamped `stamp` with the clock at `now` (Unix
    /// milliseconds).
    fn check_at<'p>(&self, py: Python<'p>, key: &[u8], stamp: i64, now: i64) -> Bound<'p, PyAny> {
        replay_verdict(py, self.0.check_at(key, stamp, now))
    }
    fn __len__(&self) -> usize {
        self.0.len()
    }
}

/// Whether `data`, a carrier's first bytes, can begin a first record:
/// `(FirstBytes, need)`, `need` the bytes wanted in all for `NEED_MORE` and 0
/// otherwise.
#[pyfunction]
#[pyo3(signature = (data, *, framing="byte_stream"))]
fn classify_first_bytes<'p>(
    py: Python<'p>,
    data: &[u8],
    framing: &str,
) -> PyResult<(Bound<'p, PyAny>, usize)> {
    use zmux::adapter::{FirstBytes as F, Framing};
    let framing = match framing {
        "byte_stream" => Framing::ByteStream,
        "records" => Framing::Records,
        f => return Err(PyValueError::new_err(format!("unknown framing {f:?}"))),
    };
    let (name, need) = match zmux::adapter::classify_first_bytes(data, framing) {
        F::NeedMore(n) => ("need_more", n),
        F::Record => ("record", 0),
        F::Other => ("other", 0),
    };
    Ok((typed(py, "FirstBytes", name.to_owned()), need))
}

/// For an admission's `decide`: whether `prefix`, a byte-stream carrier's
/// first bytes, begins a Join of a session of `listener`: `(JoinPrefix,
/// need)`, `need` the bytes wanted in all for `NEED_MORE` (ask for them
/// with `AdmissionVerdict.more`, within `max_peek`) and 0 otherwise.
/// Advisory: the join still authenticates.
#[pyfunction]
fn join_prefix<'p>(
    py: Python<'p>,
    listener: &Listener,
    prefix: &[u8],
) -> PyResult<(Bound<'p, PyAny>, usize)> {
    use zmux::adapter::JoinPrefix as J;
    let (name, need) = match listener.inner.adapter().join_prefix(prefix) {
        J::Known => ("known", 0),
        J::Unknown => ("unknown", 0),
        J::NotJoin => ("not_join", 0),
        J::Need(n) => ("need_more", n),
    };
    Ok((typed(py, "JoinPrefix", name.to_owned()), need))
}

/// Whether a pipe added to `session` now would join at once rather than
/// wait: join keys in place, room for a join and no join backoff running.
#[pyfunction]
fn join_ready(session: &Session) -> bool {
    session.0.adapter().join_ready()
}

/// Accepts sessions (and multipath joins) from any number of carriers.
#[pyclass(frozen, module = "zmux")]
struct Listener {
    inner: zmux::Listener,
    /// The carrier servers; `None` once the listener closed, when a server
    /// that finished binding after the close is aborted at once.
    tasks: Arc<StdMutex<Option<Vec<tokio::task::JoinHandle<()>>>>>,
    /// Sessions accepted as their accept was cancelled.
    returned: Returned<Py<PyAny>>,
}

impl Listener {
    fn serve<'p, F, Fut>(&self, py: Python<'p>, addr: String, run: F) -> PyResult<Bound<'p, PyAny>>
    where
        F: FnOnce(zmux::Listener, tokio::net::TcpListener) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let tcp = tokio::net::TcpListener::bind(addr).await.map_err(io_err)?;
            let local = host_port(tcp.local_addr().map_err(io_err)?);
            tasks(tokio::spawn(run(l, tcp)));
            Ok(local)
        })
    }
    fn spawner(&self) -> impl FnOnce(tokio::task::JoinHandle<()>) + Send + 'static {
        let tasks = self.tasks.clone();
        move |h| match tasks.lock().unwrap().as_mut() {
            Some(t) => t.push(h),
            None => h.abort(),
        }
    }
    fn stop_servers(tasks: &StdMutex<Option<Vec<tokio::task::JoinHandle<()>>>>) {
        for t in tasks.lock().unwrap().take().into_iter().flatten() {
            t.abort();
        }
    }
}

#[pymethods]
impl Listener {
    #[new]
    #[pyo3(signature = (*, config=None, listener_config=None))]
    fn new(
        py: Python<'_>,
        config: Option<Bound<'_, PyAny>>,
        listener_config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let lc = match listener_config {
            Some(c) => c,
            None => types(py)?.getattr("ListenerConfig")?.call0()?,
        };
        let get = |n: &str| lc.getattr(n);
        let max_pending: Option<usize> = get("max_pending")?.extract()?;
        let max_pending_per_source: usize = get("max_pending_per_source")?.extract()?;
        let source_prefix_v4: i64 = get("source_prefix_v4")?.extract()?;
        let source_prefix_v6: i64 = get("source_prefix_v6")?.extract()?;
        let max_pending_per_session: usize = get("max_pending_per_session")?.extract()?;
        let first_record_timeout: Option<f64> = get("first_record_timeout")?.extract()?;
        let handshake_timeout: Option<f64> = get("handshake_timeout")?.extract()?;
        let max_record_size: u64 = get("max_record_size")?.extract()?;
        let accept_sessions: bool = get("accept_sessions")?.extract()?;
        let max_suspended: usize = get("max_suspended")?.extract()?;
        let memory_budget: Option<u64> = get("memory_budget")?.extract()?;
        let instance_id: Vec<u8> = get("instance_id")?.extract()?;
        let on_memory_pressure = Some(get("on_memory_pressure")?)
            .filter(|f| !f.is_none())
            .map(Bound::unbind);
        let trusted_proxies: Option<Vec<String>> = get("trusted_proxies")?.extract()?;
        let forwarded_header: Option<String> = get("forwarded_header")?.extract()?;
        let proxy_protocol: bool = get("proxy_protocol")?.extract()?;
        let admission: Option<PyRef<'_, Admission>> = get("admission")?.extract()?;
        let inbound_transform = Some(get("inbound_transform")?)
            .filter(|f| !f.is_none())
            .map(Bound::unbind);
        let on_reject = Some(get("on_reject")?)
            .filter(|f| !f.is_none())
            .map(Bound::unbind);
        let secure_server: Option<PyRef<'_, seal::SecureServer>> =
            get("secure_server")?.extract()?;
        let session_config = Some(get("session_config")?)
            .filter(|f| !f.is_none())
            .map(Bound::unbind);
        let logger = Some(get("logger")?).filter(|f| !f.is_none());
        let mut l = zmux::ListenerConfig::default();
        l.logger = logger.as_ref().map(logger_of);
        let mut trusted = zmux::TrustedProxies::new().with_proxy_protocol(proxy_protocol);
        for net in trusted_proxies.unwrap_or_default() {
            trusted = trusted.with_net(net.parse().map_err(value_err)?);
        }
        if let Some(h) = forwarded_header {
            trusted = trusted.with_forwarded_header(h);
        }
        l.trusted_proxies = trusted;
        l.max_pending = max_pending;
        l.max_pending_per_source = max_pending_per_source;
        l.source_prefix_v4 = prefix_bits("source_prefix_v4", source_prefix_v4, 32)?;
        l.source_prefix_v6 = prefix_bits("source_prefix_v6", source_prefix_v6, 128)?;
        l.max_pending_per_session = max_pending_per_session;
        let timeout = |name: &str, v: Option<f64>| {
            v.ok_or_else(|| {
                PyValueError::new_err(format!("{name} has no off setting: give a value"))
            })
            .and_then(|v| seconds(name, v))
        };
        l.first_record_timeout = timeout("first_record_timeout", first_record_timeout)?;
        l.handshake_timeout = timeout("handshake_timeout", handshake_timeout)?;
        l.max_record_size = max_record_size;
        l.accept_sessions = accept_sessions;
        l.max_suspended = max_suspended;
        l.memory_budget = memory_budget;
        l.instance_id = instance_id;
        if l.instance_id.len() > zmux::MAX_INSTANCE_ID_LEN {
            return Err(PyValueError::new_err(format!(
                "instance_id is longer than {} bytes",
                zmux::MAX_INSTANCE_ID_LEN
            )));
        }
        if let Some(f) = on_memory_pressure {
            l.on_memory_pressure = Some(zmux::OnMemoryPressure::new(move |m| {
                rt::attach(|py| {
                    if let Err(e) = f.call1(py, (m.used, m.budget, m.active)) {
                        e.write_unraisable(py, Some(f.bind(py)));
                    }
                });
            }));
        }
        l.admission = admission.map(|a| a.for_listener(py));
        if let Some(f) = inbound_transform {
            let locals = pyo3_async_runtimes::tokio::get_current_locals(py).map_err(|_| {
                new_err(
                    "NoRunningLoopError",
                    "inbound_transform needs the Listener made inside a running event loop",
                )
            })?;
            l.inbound_transform = Some(layer::transform(f, locals));
        }
        if let Some(server) = secure_server {
            if l.inbound_transform.is_some() {
                return Err(PyValueError::new_err(
                    "secure_server is a transform: give it or inbound_transform",
                ));
            }
            let locals = pyo3_async_runtimes::tokio::get_current_locals(py).map_err(|_| {
                new_err(
                    "NoRunningLoopError",
                    "secure_server needs the Listener made inside a running event loop",
                )
            })?;
            l.inbound_transform = Some(server.transform(py, locals)?);
        }
        l.on_reject = on_reject.map(seal::on_reject);
        l.session_config = session_config.map(session_config_fn);
        let config = cfg(config)?;
        let _g = get_runtime().enter();
        Ok(Listener {
            inner: zmux::Listener::new(config, l).map_err(connect_err)?,
            tasks: Arc::new(StdMutex::new(Some(Vec::new()))),
            returned: Returned::default(),
        })
    }

    /// Serves plain TCP on `addr`; returns the bound address. With the
    /// listener's `admission`, a connection reaches it only once admitted.
    #[pyo3(signature = (host, port))]
    fn serve_tcp<'p>(&self, py: Python<'p>, host: String, port: u16) -> PyResult<Bound<'p, PyAny>> {
        self.serve(py, hostport(&host, port), zmux::Listener::serve)
    }
    #[pyo3(signature = (host, port, *, tls))]
    fn serve_tls<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        tls: PyRef<'_, TlsConfig>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let c = Arc::new(tls.server_zmux()?);
        self.serve(py, addr, move |l, tcp| zmux_rustls::serve(l, tcp, c))
    }
    /// HTTP/1.1 and HTTP/2 (prior knowledge, or ALPN with `tls`).
    /// With `exchange`, requests to its path are the exchange carrier's.
    ///
    /// Every carrier kind shares `path` (one endpoint, each request
    /// classified by its head): bidirectional, uplink and downlink requests
    /// and split bootstraps, the exchange (with `exchange`), and WebSocket
    /// upgrades (with `websocket`). A connection from a trusted
    /// intermediary configured for the PROXY protocol reads its header
    /// first.
    #[pyo3(signature = (host, port, *, path="/zmux".to_owned(), tls=None, exchange=None,
        websocket=false, websocket_no_subprotocol=false, pair_field=None))]
    #[allow(clippy::too_many_arguments)]
    fn serve_http<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        path: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        exchange: Option<PyRef<'_, ExchangeOptions>>,
        websocket: bool,
        websocket_no_subprotocol: bool,
        pair_field: Option<String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let mut opts = zmux_http::Options::new().with_path(path);
        if let Some(f) = pair_field_of(pair_field)? {
            opts = opts.with_pair_field(f);
        }
        if let Some(x) = exchange {
            let server =
                zmux_http::ExchangeServer::new(&self.inner, x.0.clone()).map_err(value_err)?;
            opts = opts.with_exchange(server);
        }
        let mut endpoint = zmux_http::Endpoint::new(self.inner.clone(), opts);
        if websocket {
            endpoint = endpoint.with_websocket(
                zmux_websocket::Options::default().with_no_subprotocol(websocket_no_subprotocol),
            );
        }
        let Some(tls) = tls else {
            return self.serve(py, addr, move |_, tcp| endpoint.serve(tcp));
        };
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(
            tls.server_alpn(|| vec![b"h2".to_vec(), HTTP1.to_vec()])?,
        ));
        self.serve(py, addr, move |l, tcp| async move {
            let trusted = Arc::new(l.adapter().trusted_proxies().clone());
            endpoint
                .serve_proxied(
                    || tcp.accept(),
                    move |mut conn, peer| {
                        let (acc, trusted) = (acc.clone(), trusted.clone());
                        async move {
                            let source =
                                zmux::adapter::proxied_source(&mut conn, peer, &trusted).await?;
                            let conn = acc.accept(conn).await?;
                            Ok((zmux_rustls::TlsConnection::new(conn), source))
                        }
                    },
                )
                .await;
        })
    }
    /// `ws://`, or `wss://` with `tls`. With the listener's `admission`, an
    /// upgrade is decided on its request head (no prefix), over TLS with
    /// the connection's exporter.
    #[pyo3(signature = (host, port, *, tls=None))]
    fn serve_websocket<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        tls: Option<PyRef<'_, TlsConfig>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let options = zmux_websocket::Options::default();
        let Some(tls) = tls else {
            return self.serve(py, addr, |l, tcp| zmux_websocket::serve(l, tcp, options));
        };
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(tls.server_alpn(http1)?));
        self.serve(py, addr, move |l, tcp| {
            zmux_websocket::serve_tls(l, tcp, acc, options)
        })
    }
    /// HTTP/3 requests to any path carry pipes. With the listener's
    /// `admission`, each request is decided on the first bytes of its body.
    #[pyo3(signature = (host, port, *, tls, lanes=zmux_quinn::LaneWindows::default().lanes))]
    fn serve_http3<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let opts =
            zmux_h3::Options::new().with_windows(zmux_h3::LaneWindows::new().with_lanes(lanes));
        let sc = zmux_h3::server_config(tls.server()?, &opts).map_err(value_err)?;
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = host_port(ep.local_addr().map_err(io_err)?);
            tasks(tokio::spawn(zmux_h3::serve(l, ep, opts)));
            Ok(local)
        })
    }
    /// WebTransport sessions carry pipes. With the listener's `admission`, a
    /// session request is decided on its request head (no prefix), with the
    /// QUIC connection's exporter.
    #[pyo3(signature = (host, port, *, tls, lanes=zmux_quinn::LaneWindows::default().lanes))]
    fn serve_webtransport<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        let opts = zmux_webtransport::Options::new()
            .with_windows(zmux_webtransport::LaneWindows::new().with_lanes(lanes));
        let mut c = tls.server()?;
        c.alpn_protocols = vec![wt::ALPN.as_bytes().to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(c).map_err(value_err)?;
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        sc.transport_config(Arc::new(opts.transport_config()));
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = host_port(ep.local_addr().map_err(io_err)?);
            tasks(tokio::spawn(zmux_webtransport::serve(l, ep, opts)));
            Ok(local)
        })
    }
    /// QUIC; with `zero_rtt`, 0-RTT data is accepted when the listener's
    /// `Config(carrier_early_data=True)` allows it.
    /// With the listener's `admission`, a connection reaches the listener
    /// only once the first bytes of its first stream are admitted; it
    /// excludes `zero_rtt`.
    #[pyo3(signature = (host, port, *, tls, lanes=zmux_quinn::LaneWindows::default().lanes, zero_rtt=false))]
    fn serve_quic<'p>(
        &self,
        py: Python<'p>,
        host: String,
        port: u16,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
        zero_rtt: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let addr = hostport(&host, port);
        if zero_rtt && self.inner.adapter().admission().is_some() {
            return Err(PyValueError::new_err(
                "zero_rtt and admission are mutually exclusive",
            ));
        }
        let mut opts = quic_options(lanes);
        if zero_rtt {
            opts = opts.with_zero_rtt(zmux_quinn::ParameterMemory::new());
        }
        let sc = zmux_quinn::server_config(tls.server_zmux()?, &opts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = host_port(ep.local_addr().map_err(io_err)?);
            tasks(tokio::spawn(zmux_quinn::serve(l, ep, opts, None)));
            Ok(local)
        })
    }

    /// Hands over a carrier accepted by the application (for example
    /// `pipe_pair()`): `peer` is its directly connected peer and `source`
    /// the client the application resolved (both `(host, port)`; unset, the
    /// source is the peer, and the peer `127.0.0.1:0`). It takes a source
    /// slot and goes through the listener's admission, joins and
    /// resumptions too.
    #[pyo3(signature = (pipe, *, peer=None, source=None))]
    fn handle_pipe<'p>(
        &self,
        py: Python<'p>,
        pipe: &PipeIo,
        peer: Option<(String, u16)>,
        source: Option<(String, u16)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        let addr = |a: Option<(String, u16)>| -> PyResult<Option<SocketAddr>> {
            a.map(|(h, p)| {
                h.parse::<std::net::IpAddr>()
                    .map(|ip| SocketAddr::new(ip, p))
                    .map_err(value_err)
            })
            .transpose()
        };
        let peer = addr(peer)?.unwrap_or((std::net::Ipv4Addr::LOCALHOST, 0).into());
        let source = addr(source)?;
        let io = pipe.take()?;
        future_into_py(py, async move {
            let mut hint = zmux::PipeHint::from_peer(peer);
            if let Some(s) = source {
                hint = hint.with_source(s);
            }
            l.handle_pipe(io, hint)
                .await
                .map_err(|e| raise("ConnectError", &e, false, None))
        })
    }

    /// The next established session; `ListenerClosedError` once closed.
    fn accept<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        returned_first(py, &self.returned, async move {
            l.accept().await.map(Session::new).ok_or_else(|| {
                rt::attach(|py| {
                    let e = new_err("ListenerClosedError", "listener closed");
                    let v = e.value(py);
                    let _ = v.setattr("kind", typed(py, "ErrorKind", "ListenerClosed".into()));
                    let _ = v.setattr("retryable", false);
                    let _ = v.setattr("code", py.None());
                    e
                })
            })
        })
    }

    /// Closes gracefully: new sessions are refused at once while the joins
    /// and resumptions of the live sessions are taken; every session is
    /// shut down with `code` and `reason`, and once they all ended the
    /// listener closes. Cancelled (a timeout at a deadline), it closes at
    /// once.
    #[pyo3(signature = (code=0, reason=b"".to_vec()))]
    fn shutdown<'p>(
        &self,
        py: Python<'p>,
        code: u64,
        reason: Vec<u8>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        let code = zmux::VarInt::from_u64(code).map_err(value_err)?;
        let tasks = self.tasks.clone();
        future_into_py(py, async move {
            l.shutdown(code, &reason).await;
            Listener::stop_servers(&tasks);
            Ok(())
        })
    }

    fn close(&self) {
        self.inner.close();
        Listener::stop_servers(&self.tasks);
    }

    /// The admission's verdicts on the carriers it labelled, per label.
    fn variant_stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let v = self.inner.variant_stats();
        let variant_stats = types(py)?.getattr("VariantStats")?;
        let of = |s: &zmux::VariantStats| {
            variant_stats.call1((s.accepted, s.fallback, s.stalled, s.closed))
        };
        let variants = PyDict::new(py);
        for (name, s) in &v.variants {
            variants.set_item(&**name, of(s)?)?;
        }
        types(py)?
            .getattr("AdmissionVariants")?
            .call1((variants, of(&v.overflow)?))
    }

    /// What happened to the listener's carriers: counts since it was made.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = self.inner.stats();
        let d = PyDict::new(py);
        d.set_item("sessions", st.sessions)?;
        d.set_item("joins", st.joins)?;
        d.set_item("setup_failures", st.setup_failures)?;
        d.set_item("rejected", st.rejected)?;
        d.set_item("refused", st.refused)?;
        d.set_item("timed_out", st.timed_out)?;
        let a = &st.admission;
        let ad = PyDict::new(py);
        ad.set_item("accepted", a.accepted)?;
        ad.set_item("fallback", a.fallback)?;
        ad.set_item("stalled", a.stalled)?;
        ad.set_item("closed", a.closed)?;
        ad.set_item("stall_overflow", a.stall_overflow)?;
        ad.set_item("peek_timed_out", a.peek_timed_out)?;
        ad.set_item("handshake_failed", a.handshake_failed)?;
        d.set_item(
            "admission",
            types(py)?.getattr("AdmissionStats")?.call((), Some(&ad))?,
        )?;
        types(py)?.getattr("ListenerStats")?.call((), Some(&d))
    }

    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        _t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        self.close();
        future_into_py(py, async move { Ok(false) })
    }
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        returned_first(py, &self.returned, async move {
            l.accept()
                .await
                .map(Session::new)
                .ok_or_else(|| PyStopAsyncIteration::new_err(()))
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.inner.close();
        Listener::stop_servers(&self.tasks);
    }
}

#[pymodule(gil_used = false)]
fn _zmux(m: &Bound<'_, PyModule>) -> PyResult<()> {
    rt::register(m)?;
    m.add_class::<Config>()?;
    m.add_function(wrap_pyfunction!(_config_defaults, m)?)?;
    m.add_class::<shaping::ShapingBundle>()?;
    m.add_class::<shaping::InstalledShaper>()?;
    m.add_class::<TlsConfig>()?;
    m.add_class::<PipeIo>()?;
    m.add_class::<UnsentCount>()?;
    m.add_class::<PipeEnd>()?;
    m.add_class::<Session>()?;
    m.add_class::<Pipe>()?;
    m.add_class::<SendStream>()?;
    m.add_class::<RecvStream>()?;
    m.add_class::<Chunk>()?;
    helpers::register(m)?;
    packet::register(m)?;
    m.add_class::<Listener>()?;
    m.add_class::<ReplayFilter>()?;
    m.add_function(wrap_pyfunction!(classify_first_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(join_prefix, m)?)?;
    m.add_function(wrap_pyfunction!(join_ready, m)?)?;
    m.add_function(wrap_pyfunction!(_listener_defaults, m)?)?;
    m.add_class::<Http2Connection>()?;
    m.add_class::<ExchangeOptions>()?;
    admission::register(m)?;
    layer::register(m)?;
    pool::register(m)?;
    m.add_class::<QuicClient>()?;
    m.add_class::<ZeroRtt>()?;
    m.add_class::<EventStream>()?;
    m.add_class::<DatagramStream>()?;
    m.add_function(wrap_pyfunction!(dial_http3, m)?)?;
    m.add_function(wrap_pyfunction!(dial_webtransport, m)?)?;
    m.add_function(wrap_pyfunction!(pipe_pair, m)?)?;
    m.add_function(wrap_pyfunction!(dial_tcp, m)?)?;
    m.add_function(wrap_pyfunction!(dial_tls, m)?)?;
    m.add_function(wrap_pyfunction!(dial_quic, m)?)?;
    m.add_function(wrap_pyfunction!(dial_websocket, m)?)?;
    m.add_function(wrap_pyfunction!(dial_streaming, m)?)?;
    m.add_function(wrap_pyfunction!(dial_split, m)?)?;
    m.add_function(wrap_pyfunction!(join_split, m)?)?;
    choice::register(m)?;
    seal::register(m)?;
    defaults(m)?;
    m.add_function(wrap_pyfunction!(dial_exchange, m)?)?;
    Ok(())
}

/// The library defaults, durations in seconds.
fn defaults(m: &Bound<'_, PyModule>) -> PyResult<()> {
    use zmux::proto::session as s;
    m.add(
        "DEFAULT_KEEP_ALIVE_PERIOD",
        s::DEFAULT_KEEP_ALIVE_PERIOD.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_IDLE_TIMEOUT",
        s::DEFAULT_IDLE_TIMEOUT.as_secs_f64(),
    )?;
    m.add("DEFAULT_PROBE_JITTER", s::DEFAULT_PROBE_JITTER)?;
    m.add(
        "DEFAULT_STANDBY_PROBE",
        s::DEFAULT_STANDBY_PROBE.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_MAX_RECORD_SIZE",
        zmux::proto::params::DEFAULT_MAX_RECORD_SIZE,
    )?;
    m.add(
        "DEFAULT_MIN_BACKOFF",
        zmux::DEFAULT_MIN_BACKOFF.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_MAX_BACKOFF",
        zmux::DEFAULT_MAX_BACKOFF.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_JOIN_TIMEOUT",
        zmux::DEFAULT_JOIN_TIMEOUT.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_SUSPECT_FLOOR",
        zmux::Liveness::default().suspect_floor.as_secs_f64(),
    )?;
    m.add("DEFAULT_BACKOFF_JITTER", zmux::DEFAULT_BACKOFF_JITTER)?;
    m.add("DEFAULT_LANES", zmux_quinn::LaneWindows::default().lanes)?;
    m.add("MAX_FIRST_BYTES", zmux::adapter::MAX_FIRST_BYTES)?;
    m.add("MAX_STREAM_CREDIT", zmux::MAX_STREAM_CREDIT)?;
    m.add(
        "RESERVED_EXPORTER_PREFIX",
        zmux::adapter::RESERVED_EXPORTER_PREFIX,
    )?;
    m.add("MIN_MAX_LEN", zmux::shaping::MIN_MAX_LEN)?;
    m.add("DEFAULT_MAX_SLOTS", zmux_shaping::DEFAULT_MAX_SLOTS)?;
    m.add(
        "DEFAULT_MAX_DELAY",
        zmux::shaping::DEFAULT_MAX_DELAY.as_secs_f64(),
    )?;
    m.add_function(wrap_pyfunction!(shaping::shaping_limits_from_json, m)?)?;
    Ok(())
}
