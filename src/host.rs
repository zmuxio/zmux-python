//! Immutable host observations and record accounting.

use std::time::Instant;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyTuple;

use crate::rt::{deferred, future_into_py};
use crate::{dur, kind_of, monotonic, seconds, types};

pub(crate) fn at(py: Python<'_>, time: Option<Instant>) -> PyResult<Option<f64>> {
    time.map(|t| monotonic(py, t)).transpose()
}

pub(crate) fn instant(py: Python<'_>, name: &str, value: f64) -> PyResult<Instant> {
    let now = Instant::now();
    let anchor = monotonic(py, now)?;
    let delta = seconds(name, (value - anchor).abs())?;
    let result = if value >= anchor {
        now.checked_add(delta)
    } else {
        now.checked_sub(delta)
    };
    result.ok_or_else(|| {
        PyValueError::new_err(format!("{name} is outside the monotonic clock range"))
    })
}

pub(crate) fn pipe_ids(pipes: &[zmux::PipeId]) -> impl ExactSizeIterator<Item = u64> + '_ {
    pipes.iter().map(|p| p.get())
}

fn source_obj<'py>(
    py: Python<'py>,
    source: &zmux::CarrierHalfSource,
) -> PyResult<Bound<'py, PyAny>> {
    types(py)?.getattr("CarrierHalfSource")?.call1((
        source.connection.as_ref().map(zmux::CarrierConnId::get),
        source
            .kind
            .map(|k| crate::typed(py, "CarrierKind", k.name().to_owned())),
        source.route.as_deref(),
    ))
}

fn source_of(value: &Bound<'_, PyAny>) -> PyResult<zmux::CarrierHalfSource> {
    let mut source = zmux::CarrierHalfSource::default();
    source.kind = value
        .getattr("kind")?
        .extract::<Option<String>>()?
        .as_deref()
        .map(crate::choice::kind)
        .transpose()?;
    source.route = value
        .getattr("route")?
        .extract::<Option<String>>()?
        .map(Into::into);
    let connection = value.getattr("connection")?;
    if !connection.is_none() {
        return Err(PyValueError::new_err(
            "only the carrier adapter can provide a connection identity",
        ));
    }
    Ok(source)
}

pub(crate) fn sources_of(
    send: Option<&Bound<'_, PyAny>>,
    receive: Option<&Bound<'_, PyAny>>,
) -> PyResult<zmux::CarrierHalfSources> {
    let mut sources = zmux::CarrierHalfSources::default();
    if let Some(send) = send {
        sources.send = source_of(send)?;
    }
    if let Some(receive) = receive {
        sources.receive = source_of(receive)?;
    }
    Ok(sources)
}

pub(crate) fn join_authorization(
    py: Python<'_>,
    info: zmux::JoinAuthorization,
) -> PyResult<Bound<'_, PyAny>> {
    let batch = info.first_batch;
    let summary = types(py)?.getattr("JoinFirstBatch")?.call1((
        batch.encoded_bytes,
        batch.stream_frames,
        batch.stream_bytes,
        batch.malformed,
    ))?;
    types(py)?.getattr("JoinAuthorization")?.call1((
        info.session.get(),
        info.auth_generation,
        info.join_epoch,
        info.pipe_id.get(),
        crate::direction_obj(py, info.direction),
        crate::seal::record_mode_obj(py, info.record_mode)?,
        info.carrier_kind
            .map(|k| crate::typed(py, "CarrierKind", k.name().to_owned())),
        source_obj(py, &info.sources.send)?,
        source_obj(py, &info.sources.receive)?,
        crate::admission::admitted_obj(py, info.principal.as_ref()),
        crate::admission::admitted_obj(py, info.admitted.as_ref()),
        summary,
    ))
}

fn direction_health(py: Python<'_>, h: zmux::DirectionHealth) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("DirectionHealth")?.call1((
        kind_of(&h.state),
        kind_of(&h.reason),
        at(py, h.since)?,
        h.can_carry,
        h.proof_kind.map(|proof| kind_of(&proof)),
        h.settled,
        h.evidence.map(|e| direction_evidence(py, e)).transpose()?,
    ))
}

fn direction_evidence(
    py: Python<'_>,
    evidence: zmux::DirectionEvidence,
) -> PyResult<Bound<'_, PyAny>> {
    types(py)?
        .getattr("DirectionEvidence")?
        .call1((evidence.generation, monotonic(py, evidence.since)?))
}

pub(crate) fn health(py: Python<'_>, h: zmux::PipeHealth) -> PyResult<Bound<'_, PyAny>> {
    types(py)?.getattr("PipeHealth")?.call1((
        h.seq,
        direction_health(py, h.send)?,
        direction_health(py, h.receive)?,
        h.peer_attached,
        at(py, h.joined_at)?,
        at(py, h.attached_at)?,
        h.send_evidence
            .map(|e| direction_evidence(py, e))
            .transpose()?,
        h.receive_evidence
            .map(|e| direction_evidence(py, e))
            .transpose()?,
        h.eligible_for_new_data,
        h.since_join.as_secs_f64(),
        h.failure.map(|failure| failure.to_string()),
        h.settled(),
    ))
}

pub(crate) fn health_change<'py>(
    py: Python<'py>,
    c: &zmux::PipeHealthChange,
) -> PyResult<Bound<'py, PyAny>> {
    let physical = c
        .physical_failure
        .as_ref()
        .map(|event| {
            types(py)?.getattr("CarrierFailure")?.call1((
                event.report.connection.get(),
                event.report.round.get(),
                kind_of(&event.report.kind),
                dur(event.report.retry_after),
                monotonic(py, event.at)?,
                at(py, event.retry_at)?,
            ))
        })
        .transpose()?;
    types(py)?.getattr("PipeHealthChange")?.call1((
        c.seq,
        c.pipe.get(),
        crate::typed(py, "PipeHalf", kind_of(&c.half)),
        direction_health(py, c.before)?,
        direction_health(py, c.after)?,
        kind_of(&c.reason),
        monotonic(py, c.at)?,
        c.since_join.as_secs_f64(),
        c.failure.map(|failure| failure.to_string()),
        physical,
    ))
}

pub(crate) fn carrier_loss<'py>(
    py: Python<'py>,
    loss: &zmux::CarrierLoss,
) -> PyResult<Bound<'py, PyAny>> {
    types(py)?.getattr("CarrierLoss")?.call1((
        loss.connection.get(),
        loss.generation,
        crate::typed(py, "CarrierSource", loss.source.name().to_owned()),
        kind_of(&loss.unit),
        monotonic(py, loss.since)?,
        monotonic(py, loss.at)?,
        loss.sent,
        loss.lost,
    ))
}

fn half_totals<'py>(py: Python<'py>, totals: &[zmux::HalfTotals]) -> PyResult<Bound<'py, PyTuple>> {
    PyTuple::new(
        py,
        totals
            .iter()
            .map(|t| {
                types(py)?.getattr("HalfTotals")?.call1((
                    source_obj(py, &t.source)?,
                    t.bytes,
                    t.records,
                    t.active_complete_record_bytes,
                    t.retired_complete_record_bytes,
                    t.partial_bytes,
                    t.imprecise,
                    t.source_overflow,
                ))
            })
            .collect::<PyResult<Vec<_>>>()?,
    )
}

pub(crate) fn accounting<'py>(
    py: Python<'py>,
    totals: &zmux::PipeAccounting,
) -> PyResult<Bound<'py, PyAny>> {
    types(py)?.getattr("PipeAccounting")?.call1((
        totals.pipe.get(),
        half_totals(py, &totals.send)?,
        half_totals(py, &totals.receive)?,
    ))
}

/// An independently awaitable observation of the final record accounting.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct AccountingTicket(pub(crate) zmux::AccountingTicket);

#[pymethods]
impl AccountingTicket {
    fn __await__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.wait(py)?.call_method0("__await__")
    }

    /// Waits for final totals without consuming them. Cancelling a wait leaves the ticket usable.
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let ticket = self.0.clone();
        future_into_py(py, async move {
            let totals = ticket.wait().await;
            Ok(deferred(move |py| Ok(accounting(py, &totals)?.unbind())))
        })
    }
}

/// An application-owned collection of accounting tickets published at attachment handoff.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct AccountingTickets(pub(crate) zmux::AccountingTickets);

#[pymethods]
impl AccountingTickets {
    /// Creates an empty collection to register with a session or listener configuration.
    #[new]
    fn new() -> Self {
        Self(zmux::AccountingTickets::default())
    }

    /// Takes one published ticket by session and pipe ID, including after retirement.
    #[pyo3(signature = (session, *, pipe))]
    fn take(
        &self,
        #[pyo3(from_py_with = crate::ranged)] session: u64,
        #[pyo3(from_py_with = crate::ranged)] pipe: u64,
    ) -> Option<AccountingTicket> {
        self.0
            .take(zmux::SessionId::from_raw(session)?, zmux::PipeId::new(pipe))
            .map(AccountingTicket)
    }

    /// Takes every published ticket, including retired attachments, in session and pipe order.
    fn drain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(
            py,
            self.0.drain().into_iter().map(|(session, pipe, ticket)| {
                (session.get(), pipe.get(), AccountingTicket(ticket))
            }),
        )
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AccountingTicket>()?;
    m.add_class::<AccountingTickets>()?;
    m.add_class::<ClockDomain>()?;
    #[cfg(feature = "test-hooks")]
    m.add("_TestClock", m.py().get_type::<test_clock::TestClock>())?;
    #[cfg(feature = "test-hooks")]
    m.add_class::<TestRevision>()?;
    #[cfg(feature = "test-hooks")]
    m.add_function(wrap_pyfunction!(with_backoff_jitter, m)?)?;
    Ok(())
}

/// Runs a synchronous test observation with a fixed jitter sample.
#[cfg(feature = "test-hooks")]
#[pyfunction(name = "_with_backoff_jitter")]
#[pyo3(signature = (sample, *, observe))]
fn with_backoff_jitter(sample: f64, observe: Bound<'_, PyAny>) -> PyResult<(Py<PyAny>, u64)> {
    let (result, draws) = zmux::test_hooks::with_backoff_jitter(sample, || observe.call0());
    Ok((result?.unbind(), draws))
}

#[cfg(feature = "test-hooks")]
#[pyclass(frozen, name = "_TestRevision", module = "zmux")]
pub(crate) struct TestRevision(
    std::sync::Arc<tokio::sync::Mutex<tokio::sync::watch::Receiver<()>>>,
);

#[cfg(feature = "test-hooks")]
impl TestRevision {
    pub(crate) fn new(receiver: tokio::sync::watch::Receiver<()>) -> Self {
        Self(std::sync::Arc::new(tokio::sync::Mutex::new(receiver)))
    }
}

#[cfg(feature = "test-hooks")]
#[pymethods]
impl TestRevision {
    /// Waits for a commit after the latest revision seen by this observer.
    fn changed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let receiver = self.0.clone();
        crate::future_into_py(py, async move {
            receiver
                .lock()
                .await
                .changed()
                .await
                .map_err(|error| crate::io_err(std::io::Error::other(error)))
        })
    }
}

/// A shared monotonic clock identity for sessions, controllers and caches.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct ClockDomain(pub(crate) zmux::ClockDomain);

#[pymethods]
impl ClockDomain {
    /// Creates a distinct domain using the native monotonic clock.
    #[new]
    fn new() -> Self {
        Self(zmux::ClockDomain::new())
    }

    /// Returns current time in seconds on this domain's monotonic clock.
    fn now(&self, py: Python<'_>) -> PyResult<f64> {
        monotonic(py, self.0.now())
    }
}

#[cfg(feature = "test-hooks")]
mod test_clock {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Instant;

    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use tokio::sync::watch;

    #[derive(Clone)]
    struct Clock {
        time: watch::Sender<Instant>,
        registrations: watch::Sender<HashMap<Instant, usize>>,
    }

    impl zmux::MonotonicClock for Clock {
        fn now(&self) -> Instant {
            *self.time.borrow()
        }

        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let mut rx = self.time.subscribe();
            Box::pin(async move {
                let _ = rx.wait_for(|now| *now >= deadline).await;
            })
        }

        fn timer_registered(&self, deadline: Instant) {
            self.registrations.send_modify(|counts| {
                *counts.entry(deadline).or_default() += 1;
            });
        }
    }

    #[pyclass(frozen)]
    pub(super) struct TestClock(Clock, zmux::ClockDomain);

    #[pymethods]
    impl TestClock {
        #[new]
        fn new() -> Self {
            let clock = Clock {
                time: watch::Sender::new(Instant::now()),
                registrations: watch::Sender::new(HashMap::new()),
            };
            Self(clock.clone(), zmux::ClockDomain::with_source(clock))
        }

        #[getter]
        /// The domain that uses this clock.
        fn domain(&self) -> super::ClockDomain {
            super::ClockDomain(self.1.clone())
        }

        /// Advances this clock by the given number of seconds.
        fn advance(&self, seconds: f64) -> PyResult<()> {
            let delay = crate::seconds("seconds", seconds)?;
            let mut result = Ok(());
            self.0.time.send_if_modified(|now| {
                if let Some(next) = now.checked_add(delay) {
                    *now = next;
                    true
                } else {
                    result = Err(PyValueError::new_err("clock advance overflows"));
                    false
                }
            });
            result
        }

        /// Waits until the given number of timers at now + delay have registered their wakeups.
        #[pyo3(signature = (delay, *, count=1))]
        fn wait_for_timer<'py>(
            &self,
            py: Python<'py>,
            delay: f64,
            count: usize,
        ) -> PyResult<Bound<'py, PyAny>> {
            let delay = crate::seconds("delay", delay)?;
            let deadline = self
                .1
                .now()
                .checked_add(delay)
                .ok_or_else(|| PyValueError::new_err("timer deadline overflows"))?;
            let mut registrations = self.0.registrations.subscribe();
            crate::rt::future_into_py(py, async move {
                let _ = registrations
                    .wait_for(|counts| counts.get(&deadline).copied().unwrap_or_default() >= count)
                    .await;
                Ok(())
            })
        }
    }
}
