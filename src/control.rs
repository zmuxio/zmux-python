//! The session controller and explicit capacity transactions.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

use crate::choice::{Candidate, CarrierCache};
use crate::host::{AccountingTicket, at, pipe_ids};
use crate::rt::{LoopRef, deferred, future_into_py, unit_future_into_py};
use crate::{PipeIo, Session, field_count, field_opt_secs, kind_of, monotonic, types};

fn nonzero(name: &str, value: usize) -> PyResult<NonZeroUsize> {
    NonZeroUsize::new(value)
        .ok_or_else(|| PyValueError::new_err(format!("{name} must be positive")))
}

fn sequence<T>(
    value: &Bound<'_, PyAny>,
    convert: impl Fn(&Bound<'_, PyAny>) -> PyResult<T>,
) -> PyResult<Vec<T>> {
    value.try_iter()?.map(|item| convert(&item?)).collect()
}

fn tuple<'py, T>(
    py: Python<'py>,
    values: &[T],
    convert: impl Fn(&T) -> PyResult<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyTuple>> {
    PyTuple::new(
        py,
        values.iter().map(convert).collect::<PyResult<Vec<_>>>()?,
    )
}

fn directions(value: &Bound<'_, PyAny>) -> PyResult<zmux::Directions> {
    use zmux::Directions as D;
    match value.extract::<u8>()? {
        0 => Ok(D::NONE),
        1 => Ok(D::SEND),
        2 => Ok(D::RECEIVE),
        3 => Ok(D::BOTH),
        _ => Err(PyValueError::new_err("unknown direction bits")),
    }
}

fn directions_obj(py: Python<'_>, dirs: zmux::Directions) -> PyResult<Bound<'_, PyAny>> {
    let send = u8::from(dirs.contains(zmux::Directions::SEND));
    let recv = u8::from(dirs.contains(zmux::Directions::RECEIVE));
    types(py)?
        .getattr("Directions")?
        .call1((send | (recv << 1),))
}

fn count<T: for<'a, 'py> FromPyObject<'a, 'py>>(v: &Bound<'_, PyAny>, name: &str) -> PyResult<T> {
    field_count(name, &v.getattr(name)?)
}

fn preference(value: &Bound<'_, PyAny>) -> PyResult<Option<zmux::PathPreference>> {
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(zmux::PathPreference {
        tier: count(value, "tier")?,
        standby: value.getattr("standby")?.extract()?,
        weight: count(value, "weight")?,
    }))
}

fn target_of(value: &Bound<'_, PyAny>) -> PyResult<zmux::SessionTarget> {
    let groups = sequence(&value.getattr("groups")?, |g| {
        let quotas = sequence(&g.getattr("quotas")?, |q| {
            let candidates = sequence(&q.getattr("candidates")?, |p| {
                Ok(zmux::TargetCandidate {
                    id: p.getattr("id")?.extract::<&str>()?.into(),
                    send: preference(&p.getattr("send")?)?,
                    receive: preference(&p.getattr("receive")?)?,
                })
            })?;
            Ok(zmux::MemberQuota {
                id: q.getattr("id")?.extract()?,
                count: count(q, "count")?,
                directions: directions(&q.getattr("directions")?)?,
                candidates,
            })
        })?;
        let rotation = g.getattr("rotation")?;
        let send = rotation.getattr("send_bytes")?;
        let receive = rotation.getattr("receive_bytes")?;
        Ok(zmux::GroupTarget {
            id: g.getattr("id")?.extract()?,
            quotas,
            rotation: zmux::RotationPolicy {
                max_age: field_opt_secs("max_age", &rotation.getattr("max_age")?)?,
                send_bytes: (!send.is_none())
                    .then(|| field_count("send_bytes", &send))
                    .transpose()?,
                receive_bytes: (!receive.is_none())
                    .then(|| field_count("receive_bytes", &receive))
                    .transpose()?,
            },
        })
    })?;
    let replace = sequence(&value.getattr("replace")?, |r| {
        Ok(zmux::ReplaceIntent {
            id: r.getattr("id")?.extract()?,
            members: member_ids(&r.getattr("members")?)?,
            min_epoch: count(r, "min_epoch")?,
            evidence: sequence(&r.getattr("evidence")?, |e| {
                Ok(e.cast::<QualityEvidence>()?.get().0.clone())
            })?,
        })
    })?;
    Ok(zmux::SessionTarget {
        revision: count(value, "revision")?,
        groups,
        replace,
    })
}

fn member_ids(value: &Bound<'_, PyAny>) -> PyResult<Vec<zmux::MemberId>> {
    sequence(value, |id| field_count("member", id).map(zmux::MemberId))
}

fn limits_of(v: &Bound<'_, PyAny>) -> PyResult<zmux::CapacityLimits> {
    let mut limits = zmux::CapacityLimits::default();
    limits.steady_attachments = count(v, "steady_attachments")?;
    limits.join_headroom = count(v, "join_headroom")?;
    let carriers = v.getattr("local_carriers")?;
    limits.local_carriers = (!carriers.is_none())
        .then(|| nonzero("local_carriers", field_count("local_carriers", &carriers)?))
        .transpose()?;
    limits.pending_peer_joins = nonzero("pending_peer_joins", count(v, "pending_peer_joins")?)?;
    limits.recovery_burst = nonzero("recovery_burst", count(v, "recovery_burst")?)?;
    Ok(limits)
}

fn limits_obj(py: Python<'_>, l: zmux::CapacityLimits) -> PyResult<Bound<'_, PyAny>> {
    let args = PyDict::new(py);
    args.set_item("steady_attachments", l.steady_attachments)?;
    args.set_item("join_headroom", l.join_headroom)?;
    args.set_item("local_carriers", l.local_carriers.map(NonZeroUsize::get))?;
    args.set_item("pending_peer_joins", l.pending_peer_joins.get())?;
    args.set_item("recovery_burst", l.recovery_burst.get())?;
    types(py)?.getattr("CapacityLimits")?.call((), Some(&args))
}

pub(crate) fn policy_of(v: &Bound<'_, PyAny>, lp: &LoopRef) -> PyResult<zmux::SessionPolicy> {
    let mut policy = zmux::SessionPolicy::default();
    policy.revision = count(v, "revision")?;
    policy.auth_generation = count(v, "auth_generation")?;
    policy.limits = limits_of(&v.getattr("limits")?)?;
    if let Some(f) = crate::optional(&v.getattr("authorize_join")?) {
        policy.authorize_join = Some(crate::authorize_join(f.clone().unbind(), lp.clone()));
    }
    let routes = v.getattr("join_source_routes")?;
    if !routes.is_none() {
        policy.join_source_routes = Some(Arc::new(
            sequence(&routes, |r| r.extract::<&str>().map(Arc::from))?
                .into_iter()
                .collect::<BTreeSet<_>>(),
        ));
    }
    let exclusions = v.getattr("candidate_exclusions")?;
    if !exclusions.is_none() {
        let pairs = sequence(&exclusions, |rule| {
            let (id, dirs) = rule.extract::<(String, Bound<'_, PyAny>)>()?;
            let dirs = directions(&dirs)?;
            Ok((
                zmux::CandidateId::from(id.as_str()),
                zmux::DirectionExclusion {
                    send: dirs.contains(zmux::Directions::SEND),
                    receive: dirs.contains(zmux::Directions::RECEIVE),
                },
            ))
        })?;
        policy.candidate_exclusions = Some(Arc::new(pairs.into_iter().collect::<BTreeMap<_, _>>()));
    }
    Ok(policy)
}

pub(crate) fn capacity_obj(
    py: Python<'_>,
    c: zmux::CapacitySnapshot,
) -> PyResult<Bound<'_, PyAny>> {
    let args = PyDict::new(py);
    macro_rules! field {
        ($($name:ident),* $(,)?) => {$(args.set_item(stringify!($name), c.$name)?;)*};
    }
    field!(
        observed,
        reserved_attachments,
        policy_revision,
        auth_generation,
        protocol_envelope,
        local_carrier_limit,
        local_attachments,
        peer_attachments,
        pending_peer_joins,
        authorizing_peer_joins,
        local_carriers
    );
    args.set_item("peer_retry_at", at(py, c.peer_retry_at)?)?;
    args.set_item("limits", limits_obj(py, c.limits)?)?;
    args.set_item("required", directions_obj(py, c.required)?)?;
    args.set_item("covered", directions_obj(py, c.covered)?)?;
    args.set_item("stable", directions_obj(py, c.stable)?)?;
    types(py)?
        .getattr("CapacitySnapshot")?
        .call((), Some(&args))
}

pub(crate) fn members_obj<'py>(
    py: Python<'py>,
    values: &[zmux::MemberSnapshot],
) -> PyResult<Bound<'py, PyTuple>> {
    tuple(py, values, |m| {
        types(py)?.getattr("MemberSnapshot")?.call1((
            m.id.0,
            m.candidate.as_ref().map(|id| id.0.as_ref()),
            directions_obj(py, m.expected)?,
            PyTuple::new(py, pipe_ids(&m.pipes))?,
            directions_obj(py, m.covered)?,
            directions_obj(py, m.stable)?,
            m.complete,
        ))
    })
}

fn attachment_of(v: &Bound<'_, PyAny>) -> PyResult<zmux::AttachmentSpec> {
    Ok(zmux::AttachmentSpec::new(
        directions(&v.getattr("directions")?)?,
        crate::pipe_options(Some(v.getattr("options")?))?,
    ))
}

fn attachments_obj<'py>(
    py: Python<'py>,
    values: &[zmux::AttachmentSpec],
) -> PyResult<Bound<'py, PyTuple>> {
    tuple(py, values, |a| {
        let args = PyDict::new(py);
        args.set_item("options", crate::options_obj(py, &a.options)?)?;
        types(py)?
            .getattr("AttachmentSpec")?
            .call((directions_obj(py, a.directions)?,), Some(&args))
    })
}

pub(crate) fn change_request(v: &Bound<'_, PyAny>) -> PyResult<zmux::ChangeRequest> {
    let add = sequence(&v.getattr("add")?, |m| {
        let name = m.getattr("candidate")?.extract::<Option<String>>()?;
        Ok(zmux::MemberSpec {
            candidate: name.as_deref().map(Into::into),
            attachments: sequence(&m.getattr("attachments")?, attachment_of)?,
        })
    })?;
    Ok(zmux::ChangeRequest {
        policy_revision: count(v, "policy_revision")?,
        observed: count(v, "observed")?,
        timeout: crate::field_secs("timeout", &v.getattr("timeout")?)?,
        add,
        drain: member_ids(&v.getattr("drain")?)?,
        min_epoch: count(v, "min_epoch")?,
    })
}

pub(crate) fn opener(f: Py<PyAny>, lp: LoopRef) -> zmux::CarrierOpener {
    let f = Arc::new(f);
    zmux::CarrierOpener::new(move |r: zmux::OpenRequest| {
        let f = f.clone();
        let call = lp.call(
            move |py| {
                let request = types(py)?.getattr("OpenRequest")?.call1((
                    r.attempt.0,
                    kind_of(&r.cause),
                    directions_obj(py, r.need)?,
                    kind_of(&r.stage),
                    attachments_obj(py, &r.layout)?,
                    monotonic(py, r.deadline)?,
                ))?;
                f.call1(py, (request,)).map(|value| value.into_bound(py))
            },
            |value| sequence(value, |pipe| pipe.cast::<PipeIo>()?.get().take()),
        );
        async move { call.await.map_err(crate::py_io) }
    })
}

pub(crate) fn layout(value: &Bound<'_, PyAny>) -> PyResult<Vec<zmux::AttachmentSpec>> {
    sequence(value, attachment_of)
}

pub(crate) fn change_error(e: zmux::ChangeError) -> PyErr {
    match e {
        zmux::ChangeError::Closed(e) => crate::session_err(e),
        zmux::ChangeError::Drain(e) => crate::pipe_err(e),
        zmux::ChangeError::NotNegotiated => crate::pipe_err(zmux::PipeError::NotNegotiated),
        zmux::ChangeError::Deadline => {
            crate::pipe_err(zmux::PipeError::Failed(zmux::PipeFailure::CallerDeadline))
        }
        zmux::ChangeError::Capacity => crate::raise("JoinPendingError", &e, true, None),
        _ => crate::raise("CapacityChangeError", &e, false, None),
    }
}

fn controller_error(e: zmux::ControllerError) -> PyErr {
    match e {
        zmux::ControllerError::Config(e) => crate::config_err(e),
        zmux::ControllerError::Bootstrap(e) => crate::rt::lazy_err(move |py| {
            let results = e
                .results
                .iter()
                .map(crate::choice::result_obj)
                .map(|convert| convert(py))
                .collect::<PyResult<Vec<_>>>();
            match results {
                Ok(results) => PyErr::from_type(
                    crate::err_type(py, "BootstrapError"),
                    (e.to_string(), results),
                ),
                Err(e) => e,
            }
        }),
        _ => crate::raise("SessionControllerError", &e, false, None),
    }
}

fn open_error(e: &std::io::Error) -> PyErr {
    if let Some(error) = e.get_ref().and_then(|inner| inner.downcast_ref::<PyErr>()) {
        return Python::attach(|py| error.clone_ref(py));
    }
    crate::raise_kind("ConnectError", e.to_string(), "Io", false, None)
}

fn attempt_result<'py>(py: Python<'py>, r: &zmux::AttemptResult) -> PyResult<Bound<'py, PyAny>> {
    types(py)?.getattr("AttemptResult")?.call1((
        r.id.0,
        r.generation,
        r.batch,
        kind_of(&r.reason),
        r.error.clone().map(|e| crate::pipe_err(e).into_value(py)),
        r.open_error
            .as_deref()
            .map(|e| open_error(e).into_value(py)),
        r.member.map(|id| id.0),
        PyTuple::new(py, pipe_ids(&r.pipes))?,
        PyTuple::new(py, r.tickets.iter().cloned().map(AccountingTicket))?,
    ))
}

pub(crate) async fn add_pipe(
    session: &zmux::Session,
    io: zmux::PipeIo,
    options: zmux::PipeOptions,
) -> PyResult<zmux::Pipe> {
    let dirs = match options.direction {
        zmux::PipeDirection::Out => zmux::Directions::SEND,
        zmux::PipeDirection::In => zmux::Directions::RECEIVE,
        zmux::PipeDirection::Bidi => zmux::Directions::BOTH,
    };
    let mut request = zmux::ChangeRequest::new(session.capacity(), Duration::ZERO);
    request.add.push(zmux::MemberSpec {
        candidate: None,
        attachments: vec![zmux::AttachmentSpec::new(dirs, options)],
    });
    let change = session
        .queue_change(request)
        .map_err(change_error)?
        .wait()
        .await
        .map_err(change_error)?;
    let attempt = change
        .start_member(0, zmux::CarrierOpener::prepared(vec![io]))
        .map_err(change_error)?;
    let result = attempt.wait().await;
    if let Some(e) = result.error {
        return Err(crate::pipe_err(e));
    }
    if let Some(e) = result.open_error {
        return Err(open_error(&e));
    }
    if result.reason == zmux::AttemptReason::Deadline {
        return Err(crate::pipe_err(zmux::PipeError::Failed(
            zmux::PipeFailure::CallerDeadline,
        )));
    }
    if result.reason != zmux::AttemptReason::Confirmed {
        return Err(crate::raise_kind(
            "CapacityChangeError",
            format!("Join ended with {:?}", result.reason),
            kind_of(&result.reason),
            false,
            None,
        ));
    }
    change.commit().map_err(change_error)?;
    result
        .pipes
        .first()
        .and_then(|id| session.pipe(*id))
        .ok_or_else(|| crate::pipe_err(zmux::PipeError::UnknownPipe))
}

/// An independently observable carrier opening and confirmation.
#[pyclass(frozen, module = "zmux")]
struct Attempt(zmux::Attempt);

#[pymethods]
impl Attempt {
    /// Reads the current attempt, including assigned and confirmed attachments.
    fn snapshot<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.snapshot();
        let batch = PyDict::new(py);
        batch.set_item("generation", s.generation)?;
        batch.set_item("batch", s.batch)?;
        types(py)?.getattr("AttemptSnapshot")?.call(
            (
                s.id.0,
                kind_of(&s.cause),
                directions_obj(py, s.need)?,
                s.candidate.as_ref().map(|id| id.0.as_ref()),
                s.member.0,
                PyTuple::new(py, pipe_ids(&s.pipes))?,
                PyTuple::new(py, pipe_ids(&s.replied))?,
                PyTuple::new(py, pipe_ids(&s.confirmed))?,
                at(py, s.started)?,
                at(py, s.ended)?,
                s.result
                    .as_ref()
                    .map(|r| attempt_result(py, r))
                    .transpose()?,
            ),
            Some(&batch),
        )
    }

    /// Waits for the terminal result. Cancelling this wait leaves the attempt running.
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let attempt = self.0.clone();
        future_into_py(py, async move {
            let result = attempt.wait().await;
            Ok(deferred(
                move |py| Ok(attempt_result(py, &result)?.unbind()),
            ))
        })
    }

    /// Requests cancellation before ownership of the carriers has committed.
    fn cancel(&self) {
        self.0.cancel();
    }
}

/// An admitted batch of member additions and retirements.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct CapacityChange(pub(crate) zmux::CapacityChange);

#[pymethods]
impl CapacityChange {
    /// Starts one reserved member's opener on the calling event loop.
    #[pyo3(signature = (index, *, open))]
    fn start_member(
        &self,
        py: Python<'_>,
        #[pyo3(from_py_with = crate::ranged)] index: usize,
        open: Py<PyAny>,
    ) -> PyResult<Attempt> {
        let lp = LoopRef::running(py, "start_member")?;
        self.0
            .start_member(index, opener(open, lp))
            .map(Attempt)
            .map_err(change_error)
    }

    /// Commits confirmed additions and drains replaced members after the native checks.
    fn commit<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let result = self.0.commit().map_err(change_error)?;
        types(py)?.getattr("ChangeResult")?.call1((
            PyTuple::new(py, result.draining.iter().map(|id| id.0))?,
            capacity_obj(py, result.capacity)?,
        ))
    }

    /// Cancels a batch that has not committed.
    fn cancel(&self) {
        self.0.cancel();
    }
}

/// One domain's carrier registrations, ranking and work bounds.
#[pyclass(frozen, module = "zmux")]
struct SessionController(zmux::SessionController);

#[pymethods]
impl SessionController {
    /// Registers candidates for this controller domain.
    #[new]
    #[pyo3(signature = (domain, *, candidates, choice="static", cache=None,
        concurrent_openers=None, attempt_timeout=None, clock_domain=None))]
    fn new(
        domain: String,
        candidates: &Bound<'_, PyAny>,
        choice: &str,
        cache: Option<&CarrierCache>,
        #[pyo3(from_py_with = crate::ranged_opt)] concurrent_openers: Option<usize>,
        attempt_timeout: Option<f64>,
        clock_domain: Option<&crate::host::ClockDomain>,
    ) -> PyResult<Self> {
        let candidates = sequence(candidates, |c| Ok(c.cast::<Candidate>()?.get().0.clone()))?;
        let mut options = zmux::ControllerOptions::new(domain, candidates);
        options.choice = match choice {
            "static" => zmux::ChoicePolicy::Static,
            "d160" => zmux::ChoicePolicy::D160,
            _ => return Err(PyValueError::new_err("unknown controller choice policy")),
        };
        if let Some(cache) = cache {
            options.clock_domain = cache.0.clock_domain().clone();
            options.cache = Some(cache.0.clone());
        }
        if let Some(domain) = clock_domain {
            options.clock_domain = domain.0.clone();
        }
        if let Some(n) = concurrent_openers {
            options.limits.concurrent_openers = nonzero("concurrent_openers", n)?;
        }
        if let Some(timeout) = attempt_timeout {
            options.limits.attempt_timeout = crate::seconds("attempt_timeout", timeout)?;
        }
        zmux::SessionController::new(options)
            .map(Self)
            .map_err(controller_error)
    }

    /// Establishes a session. With an empty target, the control is None
    /// when the peer and client did not negotiate multipath.
    #[pyo3(signature = (target, *, config=None))]
    fn open<'py>(
        &self,
        py: Python<'py>,
        target: &Bound<'_, PyAny>,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let target = target_of(target)?;
        let config = crate::cfg(config)?;
        let controller = self.0.clone();
        future_into_py(py, async move {
            let (session, control) = controller
                .open((*config).clone(), target)
                .await
                .map_err(controller_error)?;
            Ok((Session::new(session), control.map(SessionControl)))
        })
    }

    /// Takes ownership of convergence on an established session.
    #[pyo3(signature = (session, *, target, bootstrap=None))]
    fn manage(
        &self,
        session: &Session,
        target: &Bound<'_, PyAny>,
        bootstrap: Option<&str>,
    ) -> PyResult<SessionControl> {
        self.0
            .manage_with_bootstrap(
                &session.0,
                target_of(target)?,
                bootstrap.map(Into::into).as_ref(),
            )
            .map(SessionControl)
            .map_err(controller_error)
    }

    /// Replaces the exact current binding while retaining the session.
    #[pyo3(signature = (previous, *, target, bootstrap=None))]
    fn take_over(
        &self,
        previous: &SessionControl,
        target: &Bound<'_, PyAny>,
        bootstrap: Option<&str>,
    ) -> PyResult<SessionControl> {
        self.0
            .take_over_with_bootstrap(
                &previous.0,
                target_of(target)?,
                bootstrap.map(Into::into).as_ref(),
            )
            .map(SessionControl)
            .map_err(controller_error)
    }

    /// Requests shutdown of the controller and its bindings.
    fn close(&self) {
        self.0.close();
    }

    /// Waits until the controller and all of its bindings have stopped.
    fn done<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let controller = self.0.clone();
        unit_future_into_py(py, async move { controller.done().await })
    }
}

/// Control and progress for one managed session.
#[pyclass(frozen, module = "zmux")]
struct SessionControl(zmux::SessionControl);

/// An observation captured with the controller's member table.
#[pyclass(frozen, module = "zmux")]
struct ControllerPath {
    snapshot: Arc<zmux::ControllerSnapshot>,
    index: usize,
}

impl ControllerPath {
    fn path(&self) -> &zmux::PipeStats {
        &self.snapshot.paths[self.index]
    }
}

/// The original observation a replacement relies on.
#[pyclass(frozen, module = "zmux")]
struct QualityEvidence(zmux::QualityInput);

#[pymethods]
impl QualityEvidence {
    /// Original observation time in monotonic seconds.
    #[getter]
    fn sampled_at(&self, py: Python<'_>) -> PyResult<f64> {
        monotonic(py, self.0.sampled_at())
    }

    /// Exclusive expiration in monotonic seconds, if the measurement expires.
    #[getter]
    fn valid_until(&self, py: Python<'_>) -> PyResult<Option<f64>> {
        at(py, self.0.valid_until())
    }
}

#[pymethods]
impl ControllerPath {
    /// The member that owns this attachment, if any.
    #[getter]
    fn member(&self) -> Option<u64> {
        self.snapshot
            .members
            .iter()
            .find(|member| member.pipes.contains(&self.path().pipe))
            .map(|member| member.id.0)
    }

    /// The captured statistics and directional health.
    #[getter]
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        crate::stats_dict(py, self.path())
    }

    /// Retains the evidence and its original validity for use in a replacement.
    #[pyo3(signature = (measurement="health", *, direction="Outbound"))]
    fn evidence(&self, measurement: &str, direction: &str) -> PyResult<QualityEvidence> {
        use zmux::QualityMeasurement as Q;
        let missing = || PyValueError::new_err("the path has no evidence for this measurement");
        let direction = match direction {
            "Outbound" => zmux::PipeHalf::Outbound,
            "Inbound" => zmux::PipeHalf::Inbound,
            _ => return Err(PyValueError::new_err("unknown pipe half")),
        };
        let path = self.path();
        let measurement = match measurement {
            "health" => Q::Health,
            "current_rtt" => Q::CurrentRtt,
            "baseline_rtt" => Q::BaselineRtt,
            "delivery" => Q::Delivery,
            "loss" => {
                let sample = path.carrier_loss.as_ref().ok_or_else(missing)?;
                Q::Loss(sample.connection.clone(), sample.generation)
            }
            _ => return Err(PyValueError::new_err("unknown quality measurement")),
        };
        self.snapshot
            .quality_input(path.pipe, direction, measurement)
            .map(QualityEvidence)
            .ok_or_else(missing)
    }
}

fn controller_snapshot(py: Python<'_>, s: zmux::ControllerSnapshot) -> PyResult<Bound<'_, PyAny>> {
    let s = Arc::new(s);
    let paths = PyTuple::new(
        py,
        (0..s.paths.len()).map(|index| ControllerPath {
            snapshot: Arc::clone(&s),
            index,
        }),
    )?;
    let usage = PyDict::new(py);
    usage.set_item("host_calls_in_flight", s.host_calls_in_flight)?;
    usage.set_item("cleanup_in_flight", s.cleanup_in_flight)?;
    usage.set_item("domain_openers", s.domain_openers)?;
    usage.set_item("domain_cleanup", s.domain_cleanup)?;
    types(py)?.getattr("ControllerSnapshot")?.call(
        (
            s.generation,
            s.predecessor,
            s.revision,
            capacity_obj(py, s.capacity)?,
            members_obj(py, &s.members)?,
            paths,
            tuple(py, &s.deficits, |q| {
                types(py)?
                    .getattr("QuotaDeficit")?
                    .call1((&q.group, &q.quota, q.missing))
            })?,
            PyTuple::new(py, s.attempts.iter().map(|id| id.0))?,
            s.last_attempt
                .as_ref()
                .map(|r| attempt_result(py, r))
                .transpose()?,
            s.blocked.map(|reason| kind_of(&reason)),
            at(py, s.next_retry)?,
        ),
        Some(&usage),
    )
}

#[pymethods]
impl SessionControl {
    /// Installs a strictly newer target, or the unchanged current revision.
    fn set_target(&self, target: &Bound<'_, PyAny>) -> PyResult<()> {
        self.0
            .set_target(target_of(target)?)
            .map_err(controller_error)
    }

    /// Reads controller progress and the associated capacity observation.
    fn snapshot<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        controller_snapshot(py, self.0.snapshot())
    }

    /// Releases this binding and preserves confirmed coverage.
    fn release(&self) -> PyResult<()> {
        self.0.release().map_err(controller_error)
    }

    /// Waits for the controller binding to stop, independently of other waits.
    fn done<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let control = self.0.clone();
        unit_future_into_py(py, async move { control.done().await })
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CapacityChange>()?;
    m.add_class::<ControllerPath>()?;
    m.add_class::<QualityEvidence>()?;
    m.add_class::<Attempt>()?;
    m.add_class::<SessionController>()?;
    m.add_class::<SessionControl>()
}
