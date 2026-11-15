//! Keeping pipes up: `PipePool`, `PoolPolicy`, `MaintainHandle`.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString};
use pyo3_async_runtimes::TaskLocals;
use zmux::helpers::{PoolDecision, PoolView};

use zmux_shaping::{MachinePoolPolicy, MemberDecision, PoolMember};

use crate::rt::get_runtime;
use crate::{Pipe, PipeIo, Session, options_obj, pipe_options};

/// The JSON text of `json`: `str`, `bytes` or a `dict` (serialised).
fn json_bytes(json: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(s) = json.cast::<PyString>() {
        return Ok(s.to_str()?.as_bytes().to_vec());
    }
    if let Ok(b) = json.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if json.cast::<PyDict>().is_ok() {
        let s = json.py().import("json")?.call_method1("dumps", (json,))?;
        return Ok(s.extract::<String>()?.into_bytes());
    }
    Err(PyValueError::new_err(
        "pool policy JSON is str, bytes or dict",
    ))
}

/// A pool policy read from JSON; its decisions run natively. Pools given
/// the same object share its state.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PoolPolicy(Arc<StdMutex<MachinePoolPolicy>>);

impl PoolPolicy {
    fn parse(json: &Bound<'_, PyAny>) -> PyResult<Self> {
        let b = json_bytes(json)?;
        let p = zmux_shaping::pool_policy(&b, zmux_shaping::Options::default())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Arc::new(StdMutex::new(p))))
    }

    /// `p` itself when it is a `PoolPolicy`, else `p` read as JSON.
    fn of(p: &Bound<'_, PyAny>) -> PyResult<Shared> {
        if let Ok(p) = p.cast::<PoolPolicy>() {
            return Ok(Shared(p.get().0.clone()));
        }
        Ok(Shared(Self::parse(p)?.0))
    }
}

/// A member metric, absent 0; negative or not finite raises `ValueError`.
fn metric(d: &Bound<'_, PyDict>, k: &str) -> PyResult<f64> {
    let x: f64 = match d.get_item(k)? {
        Some(v) => v.extract()?,
        None => return Ok(0.0),
    };
    if !x.is_finite() || x < 0.0 {
        return Err(PyValueError::new_err(format!(
            "member {k} is a finite non-negative number"
        )));
    }
    Ok(x)
}

/// Seconds as microseconds.
fn micros(x: f64) -> u64 {
    (x * 1e6).round().clamp(0.0, u64::MAX as f64) as u64
}

fn secs(x: u64) -> f64 {
    x as f64 / 1e6
}

fn count(x: f64) -> u64 {
    x.clamp(0.0, u64::MAX as f64) as u64
}

#[pymethods]
impl PoolPolicy {
    /// Reads a policy from its JSON `definition` (`str`, `bytes` or
    /// `dict`).
    #[new]
    fn new(definition: &Bound<'_, PyAny>) -> PyResult<Self> {
        Self::parse(definition)
    }

    /// One decision for a pool whose dials failed `failures` times in a
    /// row, whose members are `members` (dicts with `id` and optional
    /// `age`, `idle` in seconds, `pipes`, `bytes_sent`, `bytes_received`)
    /// and whose last dial started `since_dial` seconds ago (`None`: none).
    #[pyo3(signature = (failures=0, members=Vec::new(), *, since_dial=None))]
    fn decide(
        &self,
        failures: u32,
        members: Vec<Bound<'_, PyDict>>,
        since_dial: Option<f64>,
    ) -> PyResult<PoolPolicyDecision> {
        let mut ms = Vec::with_capacity(members.len());
        for d in &members {
            let id: u64 = d
                .get_item("id")?
                .ok_or_else(|| PyValueError::new_err("member without an id"))?
                .extract()?;
            let mut m = PoolMember::new(id);
            m.age = micros(metric(d, "age")?);
            m.idle = micros(metric(d, "idle")?);
            m.pipes = count(metric(d, "pipes")?);
            m.bytes_sent = count(metric(d, "bytes_sent")?);
            m.bytes_received = count(metric(d, "bytes_received")?);
            ms.push(m);
        }
        let since = match since_dial {
            Some(s) if !s.is_finite() || s < 0.0 => {
                return Err(PyValueError::new_err(
                    "since_dial is a finite non-negative number",
                ));
            }
            s => s.map(micros),
        };
        let mut out = MemberDecision::default();
        self.0
            .lock()
            .unwrap()
            .decide_members(failures, since, &ms, &mut out);
        Ok(PoolPolicyDecision {
            count: out.count.map(|c| usize::try_from(c).unwrap_or(usize::MAX)),
            dial_after: out.dial_after.map(secs),
            retire: out.retire,
            recheck: out.recheck.map(secs),
            probe_interval: out.probe_interval.map(secs),
            probe_jitter: out.probe_jitter.map(|j| f64::from(j) / 1e6),
        })
    }
}

/// One answer of `PoolPolicy.decide`.
#[pyclass(frozen, eq, get_all, module = "zmux")]
#[derive(Clone, PartialEq)]
pub(crate) struct PoolPolicyDecision {
    count: Option<usize>,
    dial_after: Option<f64>,
    retire: Vec<u64>,
    recheck: Option<f64>,
    probe_interval: Option<f64>,
    probe_jitter: Option<f64>,
}

#[pymethods]
impl PoolPolicyDecision {
    /// A decision of its own; `probe_interval` neither 0 nor at least 1 s, `probe_jitter`
    /// outside [0, 1) or a negative time raise `ValueError`.
    #[new]
    #[pyo3(signature = (*, count=None, dial_after=None, retire=Vec::new(), recheck=None,
        probe_interval=None, probe_jitter=None))]
    fn new(
        count: Option<usize>,
        dial_after: Option<f64>,
        retire: Vec<u64>,
        recheck: Option<f64>,
        probe_interval: Option<f64>,
        probe_jitter: Option<f64>,
    ) -> PyResult<Self> {
        for (name, v) in [("dial_after", dial_after), ("recheck", recheck)] {
            if v.is_some_and(|v| !v.is_finite() || v < 0.0) {
                return Err(PyValueError::new_err(format!(
                    "{name} is a non-negative number of seconds"
                )));
            }
        }
        // As in a policy file, a probe interval of 0 turns the idle probes off.
        let mut l = zmux::PipeLiveness::default();
        if let Some(i) = probe_interval {
            let bad = || PyValueError::new_err("probe_interval is 0 or at least 1 s");
            let i = Duration::try_from_secs_f64(i).map_err(|_| bad())?;
            l.probe_interval = zmux::Inherit::Set((!i.is_zero()).then_some(i));
            l.validate().map_err(|_| bad())?;
        }
        if let Some(j) = probe_jitter {
            l.probe_jitter = zmux::Inherit::Set(j);
            l.validate()
                .map_err(|_| PyValueError::new_err("probe_jitter is in [0, 1)"))?;
        }
        Ok(Self {
            count,
            dial_after,
            retire,
            recheck,
            probe_interval,
            probe_jitter,
        })
    }

    fn __repr__(&self) -> String {
        fn opt<T: std::fmt::Display>(v: Option<&T>) -> String {
            v.map_or("None".into(), ToString::to_string)
        }
        format!(
            "PoolPolicyDecision(count={}, dial_after={}, retire={:?}, recheck={}, \
             probe_interval={}, probe_jitter={})",
            opt(self.count.as_ref()),
            opt(self.dial_after.as_ref()),
            self.retire,
            opt(self.recheck.as_ref()),
            opt(self.probe_interval.as_ref()),
            opt(self.probe_jitter.as_ref())
        )
    }
}

/// A policy shared between the Python object and its pools.
struct Shared(Arc<StdMutex<MachinePoolPolicy>>);

impl zmux::helpers::PoolPolicy for Shared {
    fn decide(&mut self, view: &PoolView<'_>, out: &mut PoolDecision) {
        let mut p = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        zmux::helpers::PoolPolicy::decide(&mut *p, view, out);
    }
}

fn dial_err(e: PyErr) -> std::io::Error {
    std::io::Error::other(e)
}

/// Members to keep up over one path: pipes on the carriers an async
/// callable `dial()` returns, or the groups of pipes an async callable
/// `join(session, options)` joins itself.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PipePool {
    count: usize,
    dial: Option<Arc<Py<PyAny>>>,
    join: Option<Arc<Py<PyAny>>>,
    /// Members dialed through a carrier choice, under its policy.
    choice: Option<(zmux::CarrierChoice, zmux::CarrierChoicePolicy)>,
    options: zmux::PipeOptions,
    rotate: Option<zmux::helpers::RotatePolicy>,
    backoff: Option<zmux::Backoff>,
    policy: Option<Arc<StdMutex<MachinePoolPolicy>>>,
    decision_rejected: Option<Arc<Py<PyAny>>>,
}

#[pymethods]
impl PipePool {
    /// Exactly one of `dial` (an async callable returning a `PipeIo`),
    /// `join` (an async callable `join(session, options)` returning the
    /// pipes it joined) and `choice` (a `CarrierChoice`, whose members are
    /// dialed most robust kind first and upgraded make before break to a
    /// preferred kind once one is usable, under `choice_policy`). Durations
    /// in seconds. An invalid choice or policy raises `ValueError`.
    #[new]
    #[pyo3(signature = (count=1, dial=None, *, join=None, choice=None, choice_policy=None,
        rotate_max_bytes=None, rotate_max_age=None, rotate_jitter=0.0, backoff=None,
        pool_policy=None, options=None, decision_rejected=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        count: usize,
        dial: Option<Py<PyAny>>,
        join: Option<Py<PyAny>>,
        choice: Option<PyRef<'_, crate::choice::CarrierChoice>>,
        choice_policy: Option<PyRef<'_, crate::choice::CarrierChoicePolicy>>,
        rotate_max_bytes: Option<u64>,
        rotate_max_age: Option<f64>,
        rotate_jitter: f64,
        backoff: Option<Bound<'_, PyAny>>,
        pool_policy: Option<Bound<'_, PyAny>>,
        options: Option<Bound<'_, PyAny>>,
        decision_rejected: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        let given = usize::from(dial.is_some())
            + usize::from(join.is_some())
            + usize::from(choice.is_some());
        if given != 1 {
            return Err(PyTypeError::new_err(
                "PipePool takes exactly one of dial, join and choice",
            ));
        }
        if choice.is_none() && choice_policy.is_some() {
            return Err(PyTypeError::new_err("choice_policy goes with choice"));
        }
        let choice = match choice {
            Some(c) => {
                let policy = choice_policy.map_or_else(Default::default, |p| p.0.clone());
                // Rejected now rather than when maintained.
                zmux::helpers::PipePool::choice(&c.0, &policy)
                    .map_err(|e| PyValueError::new_err(e.to_string()))?;
                Some((c.0.clone(), policy))
            }
            None => None,
        };
        Self::build(
            count,
            dial,
            join,
            choice,
            rotate_max_bytes,
            rotate_max_age,
            rotate_jitter,
            backoff,
            pool_policy,
            options,
            decision_rejected,
        )
    }

    /// Usable members to keep.
    #[getter]
    fn count(&self) -> usize {
        self.count
    }
}

impl PipePool {
    #[allow(clippy::too_many_arguments)]
    fn build(
        count: usize,
        dial: Option<Py<PyAny>>,
        join: Option<Py<PyAny>>,
        choice: Option<(zmux::CarrierChoice, zmux::CarrierChoicePolicy)>,
        rotate_max_bytes: Option<u64>,
        rotate_max_age: Option<f64>,
        rotate_jitter: f64,
        backoff: Option<Bound<'_, PyAny>>,
        pool_policy: Option<Bound<'_, PyAny>>,
        options: Option<Bound<'_, PyAny>>,
        decision_rejected: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        if !(0.0..=1.0).contains(&rotate_jitter) {
            return Err(PyValueError::new_err("rotate_jitter is between 0 and 1"));
        }
        let rotate_max_age = rotate_max_age
            .map(|a| {
                Duration::try_from_secs_f64(a).map_err(|_| {
                    PyValueError::new_err("rotate_max_age is a non-negative number of seconds")
                })
            })
            .transpose()?;
        let rotate = (rotate_max_bytes.is_some() || rotate_max_age.is_some()).then(|| {
            let mut r = zmux::helpers::RotatePolicy::new().with_jitter(rotate_jitter);
            if let Some(b) = rotate_max_bytes {
                r = r.with_max_bytes(b);
            }
            if let Some(a) = rotate_max_age {
                r = r.with_max_age(a);
            }
            r
        });
        Ok(Self {
            count,
            dial: dial.map(Arc::new),
            join: join.map(Arc::new),
            choice,
            options: pipe_options(options)?,
            backoff: backoff.as_ref().map(crate::backoff_of).transpose()?,
            rotate,
            policy: pool_policy
                .map(|p| PoolPolicy::of(&p))
                .transpose()?
                .map(|s| s.0),
            decision_rejected: decision_rejected.map(Arc::new),
        })
    }

    fn native(&self, locals: TaskLocals) -> zmux::helpers::PipePool {
        let locals = Arc::new(locals);
        let report = locals.clone();
        let mut p = if let Some((choice, policy)) = &self.choice {
            let mut p = zmux::helpers::PipePool::choice(choice, policy)
                .expect("checked when the pool was made");
            p.count = self.count;
            p
        } else if let Some(f) = self.join.clone() {
            zmux::helpers::PipePool::join(self.count, move |s: zmux::Session, o| {
                let (f, locals) = (f.clone(), locals.clone());
                async move {
                    let fut = crate::rt::attach(|py| {
                        let coro = f.bind(py).call1((Session::new(s), options_obj(py, &o)?))?;
                        crate::rt::into_future(&locals, coro)
                    })
                    .map_err(dial_err)?;
                    let obj = fut.await.map_err(dial_err)?;
                    crate::rt::attach(|py| {
                        let mut pipes = Vec::new();
                        for p in obj.bind(py).try_iter()? {
                            pipes.push(p?.cast::<Pipe>()?.get().0.clone());
                        }
                        Ok::<_, PyErr>(pipes)
                    })
                    .map_err(dial_err)
                }
            })
        } else {
            let f = self.dial.clone().expect("a dial or a join");
            zmux::helpers::PipePool::new(self.count, move |_req: zmux::DialRequest| {
                let (f, locals) = (f.clone(), locals.clone());
                async move {
                    let fut = crate::rt::attach(|py| {
                        let coro = f.bind(py).call0()?;
                        crate::rt::into_future(&locals, coro)
                    })
                    .map_err(dial_err)?;
                    let obj = fut.await.map_err(dial_err)?;
                    crate::rt::attach(|py| obj.bind(py).cast::<PipeIo>()?.get().take())
                        .map_err(dial_err)
                }
            })
        }
        .with_options(self.options.clone());
        if let Some(r) = self.rotate {
            p = p.with_rotate(r);
        }
        if let Some(b) = self.backoff {
            p = p.with_backoff(b);
        }
        if let Some(s) = &self.policy {
            p = p.with_policy(Shared(s.clone()));
        }
        if let Some(f) = self.decision_rejected.clone() {
            // Called on the event loop, as `dial` and `join` are.
            p = p.with_decision_rejected(move |reason: &str| {
                crate::rt::attach(|py| {
                    let lp = report.event_loop(py);
                    if let Err(e) = lp.call_method1("call_soon_threadsafe", (f.bind(py), reason)) {
                        e.write_unraisable(py, None);
                    }
                });
            });
        }
        p
    }
}

/// Stops a pool's maintainer on `stop()` or when collected; it also ends
/// with the session.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct MaintainHandle(zmux::helpers::MaintainHandle);

#[pymethods]
impl MaintainHandle {
    /// Stops the maintainer; pipes it added stay in the session.
    fn stop(&self) {
        self.0.stop();
    }

    /// Whether the maintainer has ended.
    #[getter]
    fn finished(&self) -> bool {
        self.0.is_finished()
    }
}

/// Keeps `pool`'s pipes of `session` up; called with a running event loop,
/// on which the pool's `dial` runs.
pub(crate) fn maintain(py: Python<'_>, s: &Session, pool: &PipePool) -> PyResult<MaintainHandle> {
    let locals = pyo3_async_runtimes::tokio::get_current_locals(py).map_err(|_| {
        crate::new_err(
            "NoRunningLoopError",
            "maintain_pipes needs a running event loop",
        )
    })?;
    let p = pool.native(locals);
    let _g = get_runtime().enter();
    Ok(MaintainHandle(
        zmux::helpers::maintain_pipes(&s.0, p).map_err(crate::connect_err)?,
    ))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PoolPolicy>()?;
    m.add_class::<PoolPolicyDecision>()?;
    m.add_class::<PipePool>()?;
    m.add_class::<MaintainHandle>()?;
    Ok(())
}
