//! Keeping pipes up: `PipePool`, `MachinePoolPolicy`, `MaintainHandle`.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString, PyTuple};
use zmux::helpers::{
    AsyncPoolPolicy, OwnedPoolView, PolicyError, PolicyFuture, PoolDecision, PoolMember, PoolView,
};
use zmux_shaping::MachinePoolPolicy as Machine;

use crate::helpers::lock;
use crate::rt::LoopRef;
use crate::{Pipe, Session, options_obj, pipe_options, seconds, types};
use crate::{ranged, ranged_opt};

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

/// A pool policy read from JSON, run natively: `decide(view)` answers a `PoolView` with a
/// `PoolDecision` without calling Python. Pools given the same object share its state.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct MachinePoolPolicy(Arc<StdMutex<Machine>>);

#[pymethods]
impl MachinePoolPolicy {
    /// Reads a policy from its JSON `definition` (`str`, `bytes` or `dict`); an invalid one
    /// raises `ValueError`.
    #[new]
    fn new(definition: &Bound<'_, PyAny>) -> PyResult<Self> {
        let b = json_bytes(definition)?;
        let p = zmux_shaping::pool_policy(&b, zmux_shaping::Options::default())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Arc::new(StdMutex::new(p))))
    }

    /// The decision for `view`, a `PoolView`: the policy's values, as `PoolDecision` takes
    /// them. A policy of a pool is asked this way at each look. `ValueError` for a value
    /// that `PoolDecision` refuses (a probe interval between 0 and 1 s), which rejects the
    /// look of a pool.
    fn decide<'p>(&self, py: Python<'p>, view: &Bound<'p, PyAny>) -> PyResult<Bound<'p, PyAny>> {
        let members = view_members(view)?;
        let mut v = PoolView::default();
        v.members = &members;
        v.failures = view.getattr("failures")?.extract()?;
        v.since_last_dial = view
            .getattr("since_last_dial")?
            .extract::<Option<f64>>()?
            .map(|s| seconds("since_last_dial", s))
            .transpose()?;
        v.dialing = view.getattr("dialing")?.extract()?;
        let mut out = PoolDecision::default();
        zmux::helpers::PoolPolicy::decide(&mut *lock(&self.0), &v, &mut out)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        decision_obj(py, &out)
    }

    /// The policy's values for `view` as it evaluates them, unchanged: a
    /// `PoolEvaluation`, out of range values included. How a policy file is tested;
    /// `decide` builds the `PoolDecision` from the same values and refuses one out of
    /// range.
    fn evaluate<'p>(&self, py: Python<'p>, view: &Bound<'p, PyAny>) -> PyResult<Bound<'p, PyAny>> {
        let micros = |d: Duration| u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        let members = view_members(view)?
            .iter()
            .map(|m| {
                let mut n = zmux_shaping::PoolMember::new(m.pipe.get());
                n.age = micros(m.age);
                n.idle = micros(m.idle);
                n.pipes = m.pipes as u64;
                n.bytes_sent = m.bytes_sent;
                n.bytes_received = m.bytes_received;
                n
            })
            .collect::<Vec<_>>();
        let since = view
            .getattr("since_last_dial")?
            .extract::<Option<f64>>()?
            .map(|s| seconds("since_last_dial", s))
            .transpose()?
            .map(micros);
        let mut out = zmux_shaping::MemberDecision::default();
        lock(&self.0).decide_members(
            view.getattr("failures")?.extract()?,
            since,
            &members,
            &mut out,
        );
        let secs = |us: u64| us as f64 / 1e6;
        let d = PyDict::new(py);
        d.set_item("count", out.count)?;
        d.set_item("dial_after", out.dial_after.map(secs))?;
        d.set_item("retire", out.retire)?;
        d.set_item("recheck", out.recheck.map(secs))?;
        d.set_item("probe_interval", out.probe_interval.map(secs))?;
        d.set_item("probe_jitter", out.probe_jitter.map(|j| f64::from(j) / 1e6))?;
        types(py)?.getattr("PoolEvaluation")?.call((), Some(&d))
    }
}

/// The native members of a `PoolView`'s `members`.
fn view_members(view: &Bound<'_, PyAny>) -> PyResult<Vec<PoolMember>> {
    let mut out = Vec::new();
    for m in view.getattr("members")?.try_iter()? {
        let m = m?;
        let mut n = PoolMember::default();
        n.pipe = zmux::PipeId::new(m.getattr("pipe")?.extract()?);
        n.age = seconds("age", m.getattr("age")?.extract()?)?;
        n.idle = seconds("idle", m.getattr("idle")?.extract()?)?;
        n.pipes = m.getattr("pipes")?.extract()?;
        n.bytes_sent = m.getattr("bytes_sent")?.extract()?;
        n.bytes_received = m.getattr("bytes_received")?.extract()?;
        n.usable = m.getattr("usable")?.extract()?;
        n.replacing = m.getattr("replacing")?.extract()?;
        out.push(n);
    }
    Ok(out)
}

/// The `PoolView` of a native one, built on the event loop.
fn view_obj<'p>(py: Python<'p>, v: &OwnedPoolView) -> PyResult<Bound<'p, PyAny>> {
    let t = types(py)?;
    let member = t.getattr("PoolMember")?;
    let mut members = Vec::with_capacity(v.members.len());
    for m in &v.members {
        let d = PyDict::new(py);
        d.set_item("pipe", m.pipe.get())?;
        d.set_item("age", m.age.as_secs_f64())?;
        d.set_item("idle", m.idle.as_secs_f64())?;
        d.set_item("pipes", m.pipes)?;
        d.set_item("bytes_sent", m.bytes_sent)?;
        d.set_item("bytes_received", m.bytes_received)?;
        d.set_item("usable", m.usable)?;
        d.set_item("replacing", m.replacing)?;
        members.push(member.call((), Some(&d))?);
    }
    let d = PyDict::new(py);
    d.set_item("members", PyTuple::new(py, members)?)?;
    d.set_item("failures", v.failures)?;
    d.set_item(
        "since_last_dial",
        v.since_last_dial.map(|s| s.as_secs_f64()),
    )?;
    d.set_item("dialing", v.dialing)?;
    t.getattr("PoolView")?.call((), Some(&d))
}

/// The `PoolDecision` of a native one.
fn decision_obj<'p>(py: Python<'p>, o: &PoolDecision) -> PyResult<Bound<'p, PyAny>> {
    let t = types(py)?;
    let d = PyDict::new(py);
    if let Some(c) = o.count() {
        d.set_item("count", c.get())?;
    }
    if let Some(a) = o.dial_after() {
        d.set_item("dial_after", a.as_secs_f64())?;
    }
    d.set_item(
        "retire_pipes",
        o.retire_pipes()
            .iter()
            .map(|p| p.get())
            .collect::<Vec<u64>>(),
    )?;
    d.set_item("recheck", o.recheck().map(|r| r.as_secs_f64()))?;
    if let Some(l) = o.liveness() {
        d.set_item("liveness", crate::pipe_liveness_obj(py, &l)?)?;
    }
    t.getattr("PoolDecision")?.call((), Some(&d))
}

/// The answer of a Python policy, read on the event loop.
#[derive(Default)]
struct Answer {
    count: Option<std::num::NonZeroUsize>,
    dial_after: Option<Duration>,
    retire_pipes: Vec<zmux::PipeId>,
    recheck: Option<Duration>,
    liveness: Option<zmux::PipeLiveness>,
}

impl Answer {
    /// Reads a `PoolDecision`; anything else, and a value out of range, is an error.
    fn of(d: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py = d.py();
        if !d.is_instance(&types(py)?.getattr("PoolDecision")?)? {
            return Err(PyTypeError::new_err(format!(
                "decide returns a PoolDecision, not {}",
                d.get_type().name()?
            )));
        }
        let unset = |v: &Bound<'_, PyAny>| crate::is_setting(v, "INHERIT");
        let count = d.getattr("count")?;
        let count = if unset(&count)? {
            None
        } else {
            // A `bool` is no count, whatever `int` it is.
            let n = if count.is_instance_of::<pyo3::types::PyBool>() {
                None
            } else {
                match count.extract::<usize>() {
                    Ok(n) => Some(n),
                    // No upper bound is documented: beyond the native
                    // range it is as large as a count gets.
                    Err(e) if e.is_instance_of::<pyo3::exceptions::PyOverflowError>(py) => {
                        count.gt(0)?.then_some(usize::MAX)
                    }
                    Err(_) => None,
                }
            };
            Some(n.and_then(std::num::NonZeroUsize::new).ok_or_else(|| {
                PyValueError::new_err("count is an integer of at least 1, or INHERIT")
            })?)
        };
        let dial_after = d.getattr("dial_after")?;
        let dial_after = if unset(&dial_after)? {
            None
        } else {
            Some(seconds("dial_after", dial_after.extract()?)?)
        };
        let retire_pipes = d
            .getattr("retire_pipes")?
            .try_iter()?
            .map(|p| Ok(zmux::PipeId::new(p?.extract()?)))
            .collect::<PyResult<_>>()?;
        let recheck = d
            .getattr("recheck")?
            .extract::<Option<f64>>()?
            .map(|r| seconds("recheck", r))
            .transpose()?;
        let liveness = crate::pipe_liveness(&d.getattr("liveness")?)?;
        Ok(Self {
            count,
            dial_after,
            retire_pipes,
            recheck,
            liveness: (liveness != zmux::PipeLiveness::default()).then_some(liveness),
        })
    }

    /// Writes the answer into `out`; a setter's refusal rejects the look.
    fn apply(self, out: &mut PoolDecision) -> Result<(), PolicyFailure> {
        if let Some(c) = self.count {
            out.set_count(c);
        }
        if let Some(a) = self.dial_after {
            out.set_dial_after(a);
        }
        out.set_retire_pipes(self.retire_pipes);
        if let Some(r) = self.recheck {
            out.set_recheck(r).map_err(PolicyFailure::value)?;
        }
        if let Some(l) = self.liveness {
            out.set_liveness(l).map_err(PolicyFailure::value)?;
        }
        Ok(())
    }
}

/// Whether `d`, a `PoolDecision`, is in range, as the pool applies it:
/// `ValueError` if not. The one check of the type, which its constructor runs.
#[pyfunction(name = "_check_pool_decision")]
pub(crate) fn check_pool_decision(d: &Bound<'_, PyAny>) -> PyResult<()> {
    Answer::of(d)?
        .apply(&mut PoolDecision::default())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Why a look was rejected: the exception that `decision_rejected` is handed, and its text
/// for the logger.
#[derive(Debug)]
struct PolicyFailure {
    err: Arc<PyErr>,
    text: String,
}

impl PolicyFailure {
    fn value(e: impl std::fmt::Display) -> Self {
        let text = e.to_string();
        Self {
            err: Arc::new(PyValueError::new_err(text.clone())),
            text,
        }
    }

    /// An exception of the policy, named for its type.
    fn of(py: Python<'_>, e: PyErr) -> Self {
        let v = e.value(py);
        let text = match v.str() {
            Ok(s) => format!(
                "{}: {s}",
                v.get_type()
                    .name()
                    .map_or_else(|_| "Exception".into(), |n| n.to_string())
            ),
            Err(_) => "an exception".to_owned(),
        };
        Self {
            err: Arc::new(e),
            text,
        }
    }
}

impl std::fmt::Display for PolicyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for PolicyFailure {}

/// A policy of an object in Python, asked on the event loop. The pool polls the future of
/// `decide` on its own maintainer task, so an answer that is slow, or never comes, occupies
/// no thread and no executor slot: only the look of its own pool waits for it, without a
/// bound. It is the loop, never a runtime thread, that runs the policy. A loop that closes
/// answers at once, as a rejection; a pool that stops drops the future, which cancels the
/// call on the loop.
struct PyPolicy {
    object: Arc<Py<PyAny>>,
    lp: LoopRef,
}

impl AsyncPoolPolicy for PyPolicy {
    fn decide(&self, view: OwnedPoolView) -> PolicyFuture {
        let object = self.object.clone();
        let asked = self.lp.settled(
            move |py| {
                object
                    .bind(py)
                    .call_method1(intern!(py, "decide"), (view_obj(py, &view)?,))
            },
            move |py, r| {
                // Read on the loop, where the answer's objects live.
                r.and_then(|v| Answer::of(&v))
                    .map_err(|e| PolicyFailure::of(py, e))
            },
            || {
                Err(PolicyFailure::value(
                    "the event loop of the pool's hooks closed",
                ))
            },
        );
        Box::pin(async move {
            let mut out = PoolDecision::default();
            asked.await?.apply(&mut out)?;
            Ok(out)
        })
    }
}

/// A policy shared between the Python object and its pools.
struct Shared(Arc<StdMutex<Machine>>);

impl zmux::helpers::PoolPolicy for Shared {
    fn decide(&mut self, view: &PoolView<'_>, out: &mut PoolDecision) -> Result<(), PolicyError> {
        let mut p = lock(&self.0);
        // An invalid decision of the machine policy is a rejection with a `ValueError`.
        zmux::helpers::PoolPolicy::decide(&mut *p, view, out)
            .map_err(|e| Box::new(PolicyFailure::value(e)) as PolicyError)
    }
}

/// The policy of a pool: a `MachinePoolPolicy`, run natively, or an object with `decide`.
#[derive(Clone)]
enum Policy {
    Machine(Arc<StdMutex<Machine>>),
    Object(Arc<Py<PyAny>>),
}

impl Policy {
    fn of(p: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(m) = p.cast::<MachinePoolPolicy>() {
            return Ok(Self::Machine(m.get().0.clone()));
        }
        if !p.getattr("decide").is_ok_and(|d| d.is_callable()) {
            return Err(PyTypeError::new_err(
                "policy is a MachinePoolPolicy or an object with decide(view)",
            ));
        }
        Ok(Self::Object(Arc::new(p.clone().unbind())))
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
    rotate: Option<zmux::helpers::Rotation>,
    backoff: Option<zmux::Backoff>,
    policy: Option<Policy>,
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
        policy=None, options=None, decision_rejected=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        #[pyo3(from_py_with = ranged)] count: usize,
        dial: Option<Py<PyAny>>,
        join: Option<Py<PyAny>>,
        choice: Option<PyRef<'_, crate::choice::CarrierChoice>>,
        choice_policy: Option<PyRef<'_, crate::choice::CarrierChoicePolicy>>,
        #[pyo3(from_py_with = ranged_opt)] rotate_max_bytes: Option<u64>,
        rotate_max_age: Option<f64>,
        rotate_jitter: f64,
        backoff: Option<Bound<'_, PyAny>>,
        policy: Option<Bound<'_, PyAny>>,
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
            policy,
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
        policy: Option<Bound<'_, PyAny>>,
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
            let mut r = zmux::helpers::Rotation::new().with_jitter(rotate_jitter);
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
            policy: policy.as_ref().map(Policy::of).transpose()?,
            decision_rejected: decision_rejected.map(Arc::new),
        })
    }

    fn native(&self, lp: LoopRef) -> zmux::helpers::PipePool {
        let report = lp.clone();
        let mut p = if let Some((choice, policy)) = &self.choice {
            let mut p = zmux::helpers::PipePool::choice(choice, policy)
                .expect("checked when the pool was made");
            p.count = self.count;
            p
        } else if let Some(f) = self.join.clone() {
            let lp = lp.clone();
            zmux::helpers::PipePool::join(self.count, move |s: zmux::Session, o| {
                let f = f.clone();
                let call = lp.call(
                    move |py| f.bind(py).call1((Session::new(s), options_obj(py, &o)?)),
                    |v| {
                        let mut pipes = Vec::new();
                        for p in v.try_iter()? {
                            pipes.push(p?.cast::<Pipe>()?.get().0.clone());
                        }
                        Ok(pipes)
                    },
                );
                async move { call.await.map_err(dial_err) }
            })
        } else {
            let f = self.dial.clone().expect("a dial or a join");
            let lp = lp.clone();
            zmux::helpers::PipePool::new(self.count, move |_req: zmux::DialRequest| {
                let f = f.clone();
                let call = crate::helpers::call_pipe(&lp, move |py| f.bind(py).call0());
                async move { call.await.map_err(dial_err) }
            })
        }
        .with_options(self.options.clone());
        if let Some(r) = self.rotate {
            p = p.with_rotate(r);
        }
        if let Some(b) = self.backoff {
            p = p.with_backoff(b);
        }
        match &self.policy {
            Some(Policy::Machine(m)) => p = p.with_policy(Shared(m.clone())),
            Some(Policy::Object(o)) => {
                p = p.with_async_policy(Arc::new(PyPolicy {
                    object: o.clone(),
                    lp: report.clone(),
                }));
            }
            None => {}
        }
        if let Some(f) = self.decision_rejected.clone() {
            // Called on the event loop, as `dial` and `join` are.
            p = p.with_decision_rejected(move |e: &(dyn std::error::Error + 'static)| {
                let f = f.clone();
                let why = e
                    .downcast_ref::<PolicyFailure>()
                    .map(|p| p.err.clone())
                    .ok_or_else(|| e.to_string());
                report.post(move |py| {
                    let exc = match why {
                        Ok(err) => err.clone_ref(py),
                        Err(text) => pyo3::exceptions::PyRuntimeError::new_err(text),
                    };
                    if let Err(e) = f.call1(py, (exc.into_value(py),)) {
                        e.write_unraisable(py, Some(f.bind(py)));
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
    let lp = LoopRef::current(py).map_err(|_| {
        crate::new_err(
            "NoRunningLoopError",
            "maintain_pipes needs a running event loop",
        )
    })?;
    let p = pool.native(lp);
    let _g = crate::rt::runtime()?.enter();
    Ok(MaintainHandle(
        zmux::helpers::maintain_pipes(&s.0, p).map_err(crate::connect_err)?,
    ))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MachinePoolPolicy>()?;
    m.add_class::<PipePool>()?;
    m.add_class::<MaintainHandle>()?;
    Ok(())
}
