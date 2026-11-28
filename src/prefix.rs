//! Ticket credential and authority bindings. Presentation and redemption run in zmux.

use std::io;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zmux::CarrierCredential;

use crate::admission::CarrierInfo;
use crate::rt::LoopRef;
use crate::{ranged, value_err};

#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct PrefixGeneration(zmux::PrefixGeneration);

#[pymethods]
impl PrefixGeneration {
    /// An outer key and its inclusive issue-slot interval.
    #[new]
    #[pyo3(signature = (key, *, first_slot, last_slot))]
    fn new(key: [u8; 32], first_slot: u64, last_slot: u64) -> PyResult<Self> {
        if first_slot > last_slot {
            return Err(PyValueError::new_err(
                "first_slot must be at most last_slot",
            ));
        }
        Ok(Self(zmux::PrefixGeneration::new(
            key,
            first_slot..=last_slot,
        )))
    }
}

#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct PrefixSchedule(Arc<zmux::PrefixSchedule>);

fn generations(value: &Bound<'_, PyAny>) -> PyResult<Vec<zmux::PrefixGeneration>> {
    value
        .try_iter()?
        .map(|g| Ok(g?.cast::<PrefixGeneration>()?.get().0.clone()))
        .collect()
}

#[pymethods]
impl PrefixSchedule {
    /// A versioned snapshot of the outer keys.
    #[new]
    #[pyo3(signature = (generations, *, version=1))]
    fn new(generations: &Bound<'_, PyAny>, version: u64) -> PyResult<Self> {
        zmux::PrefixSchedule::new(version, self::generations(generations)?)
            .map(|s| Self(Arc::new(s)))
            .map_err(value_err)
    }

    /// The authority's revision of the schedule.
    #[getter]
    fn version(&self) -> u64 {
        self.0.version()
    }
}

#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct PrefixTicket(zmux::PrefixTicket);

#[pymethods]
impl PrefixTicket {
    /// A ticket ID, dedicated key and inclusive lifetime in UTC slots.
    #[new]
    #[pyo3(signature = (id, *, key, first_slot, last_slot, version=1, single_use=true))]
    fn new(
        id: [u8; 16],
        key: [u8; 32],
        first_slot: u64,
        last_slot: u64,
        version: u64,
        single_use: bool,
    ) -> PyResult<Self> {
        if first_slot > last_slot {
            return Err(PyValueError::new_err(
                "first_slot must be at most last_slot",
            ));
        }
        Ok(Self(zmux::PrefixTicket::new(
            id,
            key,
            version,
            first_slot..=last_slot,
            single_use,
        )))
    }
}

#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct PrefixWindow(zmux::PrefixWindow);

#[pymethods]
impl PrefixWindow {
    /// Slot length and the number of neighboring slots a verifier accepts.
    #[new]
    #[pyo3(signature = (slot_seconds, *, skew=0, skew_limit=None))]
    fn new(slot_seconds: u64, skew: u32, skew_limit: Option<u32>) -> PyResult<Self> {
        zmux::PrefixWindow::new(slot_seconds, skew, skew_limit.unwrap_or(skew))
            .map(Self)
            .map_err(value_err)
    }

    /// Whole seconds per slot.
    #[getter]
    fn slot_seconds(&self) -> u64 {
        self.0.slot_seconds()
    }

    /// Allowed clock difference in slots.
    #[getter]
    fn skew(&self) -> u32 {
        self.0.skew()
    }
}

#[pyclass(frozen, module = "zmux")]
struct MemoryPrefixStore(Arc<zmux::MemoryPrefixStore>);

#[pymethods]
impl MemoryPrefixStore {
    /// An in-process ticket and replay authority.
    #[new]
    #[pyo3(signature = (generations, *, window, capacity=0))]
    fn new(
        generations: &Bound<'_, PyAny>,
        window: &PrefixWindow,
        #[pyo3(from_py_with = ranged)] capacity: usize,
    ) -> PyResult<Self> {
        zmux::MemoryPrefixStore::new(window.0, self::generations(generations)?, capacity)
            .map(|s| Self(Arc::new(s)))
            .map_err(value_err)
    }

    /// Installs a new ticket.
    fn add_ticket(&self, ticket: &PrefixTicket) -> PyResult<()> {
        self.0.add_ticket(ticket.0.clone()).map_err(value_err)
    }

    /// Revokes a ticket ID and retains its tombstone.
    fn revoke_ticket(&self, id: [u8; 16]) {
        self.0.revoke_ticket(id);
    }

    /// Publishes new outer generations and invalidates the previous revision.
    fn set_generations(&self, generations: &Bound<'_, PyAny>) -> PyResult<()> {
        self.0
            .set_generations(self::generations(generations)?)
            .map_err(value_err)
    }

    /// Retires expired claims and tickets at the given Unix time in seconds.
    fn expire(&self, unix_seconds: u64) {
        self.0.expire(unix_seconds);
    }
}

fn binding(value: &str) -> PyResult<zmux::PrefixBinding> {
    match value {
        "bound" => Ok(zmux::PrefixBinding::Bound),
        "encrypted" => Ok(zmux::PrefixBinding::Encrypted),
        "allow_cleartext" => Ok(zmux::PrefixBinding::AllowCleartext),
        _ => Err(PyValueError::new_err("unknown ticket binding policy")),
    }
}

/// A client's ticket presenter.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PrefixAuth {
    pub(crate) inner: zmux::PrefixAuth,
    binding: String,
}

#[pymethods]
impl PrefixAuth {
    /// Presents a fresh ticket for a carrier.
    #[new]
    #[pyo3(signature = (ticket, *, schedule, slot_seconds, binding="bound", header=None))]
    fn new(
        ticket: &PrefixTicket,
        schedule: &PrefixSchedule,
        slot_seconds: u64,
        binding: &str,
        header: Option<String>,
    ) -> PyResult<Self> {
        let mut inner = zmux::PrefixAuth::new(
            ticket.0.clone(),
            schedule.0.clone(),
            slot_seconds,
            self::binding(binding)?,
        )
        .map_err(value_err)?;
        if let Some(header) = header {
            inner = inner.with_header(header).map_err(value_err)?;
        }
        Ok(Self {
            inner,
            binding: binding.to_owned(),
        })
    }

    /// The carrier binding policy.
    #[getter]
    fn binding<'py>(&self, py: Python<'py>) -> Bound<'py, PyAny> {
        crate::typed(py, "PrefixBinding", self.binding.clone())
    }

    /// The request header name used on head-admitted carriers.
    #[getter]
    fn header_name(&self) -> &str {
        self.inner
            .prefix_ticket_header()
            .expect("ticket presenters have a header")
    }

    /// Produces the 64-byte binary presentation for this carrier.
    fn prefix<'py>(&self, py: Python<'py>, info: &CarrierInfo) -> PyResult<Bound<'py, PyBytes>> {
        let token = self.inner.token(&info.0).map_err(crate::io_err)?;
        Ok(PyBytes::new(py, &token))
    }

    /// Produces the field name and canonical base64url presentation.
    fn header(&self, info: &CarrierInfo) -> PyResult<(String, String)> {
        self.inner.header(&info.0).map_err(crate::io_err)
    }

    /// Produces the unbound presentation for a fixed fixture time and nonce.
    #[cfg(feature = "test-hooks")]
    #[pyo3(name = "_fixture_token", signature = (unix_seconds, *, nonce))]
    fn fixture_token<'py>(
        &self,
        py: Python<'py>,
        unix_seconds: u64,
        nonce: [u8; 16],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let token = self
            .inner
            .fixture_token(unix_seconds, nonce)
            .ok_or_else(|| PyValueError::new_err("could not present fixture ticket"))?;
        Ok(PyBytes::new(py, &token))
    }
}

#[cfg(feature = "test-hooks")]
pub(crate) fn fixture_admission(
    store: &Bound<'_, PyAny>,
    unix_seconds: u64,
) -> PyResult<zmux::Admission> {
    let store = store.cast::<MemoryPrefixStore>()?.get().0.clone();
    let verifier = zmux::PrefixAuthVerifier::new(store, zmux::PrefixBinding::AllowCleartext)
        .map_err(value_err)?
        .with_clock(move || Some(unix_seconds));
    Ok(
        zmux::Admission::prefix_auth(Arc::new(verifier), zmux::PrefixRejection::Fallback)
            .with_first_message_ticket(),
    )
}

/// A deadline and cancellation indicator for an authority operation.
#[pyclass(frozen, module = "zmux")]
struct PrefixDeadline(zmux::PrefixDeadline);

#[pymethods]
impl PrefixDeadline {
    /// Deadline on the monotonic clock, if set.
    #[getter]
    fn deadline(&self, py: Python<'_>) -> PyResult<Option<f64>> {
        crate::host::at(py, self.0.deadline())
    }

    /// Whether the operation was cancelled or reached its deadline.
    #[getter]
    fn ended(&self) -> bool {
        self.0.ended()
    }
}

fn claim_obj(py: Python<'_>, c: zmux::PrefixClaim) -> PyResult<Bound<'_, PyAny>> {
    crate::types(py)?.getattr("PrefixClaim")?.call1((
        PyBytes::new(py, &c.id),
        PyBytes::new(py, &c.nonce),
        PyBytes::new(py, &c.commit_id),
        c.version,
        c.schedule,
        c.generation,
        c.issue_slot,
        c.checked_slot,
        c.local_slot,
    ))
}

struct PythonStore {
    store: Arc<Py<PyAny>>,
    lp: LoopRef,
    window: zmux::PrefixWindow,
    empty: Arc<zmux::PrefixSchedule>,
}

impl PythonStore {
    fn call<R: Send + 'static>(
        &self,
        method: &'static str,
        deadline: zmux::PrefixDeadline,
        args: impl for<'py> FnOnce(
            &Bound<'py, PyAny>,
            Bound<'py, PrefixDeadline>,
        ) -> PyResult<Bound<'py, PyAny>>
        + Send
        + 'static,
        out: impl for<'py> FnOnce(&Bound<'py, PyAny>) -> PyResult<R> + Send + 'static,
    ) -> zmux::PrefixStoreFuture<'_, R> {
        let store = self.store.clone();
        let lp = self.lp.clone();
        Box::pin(async move {
            lp.call(
                move |py| {
                    let deadline = Bound::new(py, PrefixDeadline(deadline))?;
                    if deadline.get().ended() {
                        return Err(pyo3::exceptions::PyTimeoutError::new_err(method));
                    }
                    args(store.bind(py), deadline)
                },
                out,
            )
            .await
            .map_err(io::Error::other)
        })
    }
}

impl zmux::PrefixStore for PythonStore {
    fn window(&self) -> zmux::PrefixWindow {
        self.window
    }

    fn local_schedule(&self) -> (Arc<zmux::PrefixSchedule>, u64) {
        let unavailable = || (self.empty.clone(), u64::MAX);
        crate::rt::hook_or(Ok(unavailable()), |py| {
            let value = self.store.bind(py).call_method0("local_schedule")?;
            let (schedule, floor): (Bound<'_, PrefixSchedule>, u64) = value.extract()?;
            Ok((schedule.get().0.clone(), floor))
        })
        .unwrap_or_else(|err| {
            self.lp.report_callback_error(self.store.clone(), err);
            unavailable()
        })
    }

    fn floor(&self, at: zmux::PrefixDeadline) -> zmux::PrefixStoreFuture<'_, u64> {
        self.call(
            "floor",
            at,
            |store, at| store.call_method1("floor", (at,)),
            |v| v.extract(),
        )
    }

    fn lookup(
        &self,
        at: zmux::PrefixDeadline,
        id: [u8; 16],
    ) -> zmux::PrefixStoreFuture<'_, Option<zmux::PrefixTicket>> {
        self.call(
            "lookup",
            at,
            move |store, at| store.call_method1("lookup", (PyBytes::new(store.py(), &id), at)),
            |v| {
                crate::optional(v)
                    .map(|value| Ok(value.cast::<PrefixTicket>()?.get().0.clone()))
                    .transpose()
            },
        )
    }

    fn claim(
        &self,
        at: zmux::PrefixDeadline,
        claim: zmux::PrefixClaim,
    ) -> zmux::PrefixStoreFuture<'_, bool> {
        self.call(
            "claim",
            at,
            move |store, at| store.call_method1("claim", (claim_obj(store.py(), claim)?, at)),
            |v| v.extract(),
        )
    }

    fn resolve(
        &self,
        at: zmux::PrefixDeadline,
        claim: zmux::PrefixClaim,
    ) -> zmux::PrefixStoreFuture<'_, bool> {
        self.call(
            "resolve",
            at,
            move |store, at| store.call_method1("resolve", (claim_obj(store.py(), claim)?, at)),
            |v| v.extract(),
        )
    }
}

pub(crate) fn admission(
    store: Bound<'_, PyAny>,
    bind: &str,
    header: Option<String>,
    reject: &str,
    max_skew: Option<u32>,
) -> PyResult<(zmux::Admission, Option<LoopRef>)> {
    let (store, lp) = if let Ok(memory) = store.cast::<MemoryPrefixStore>() {
        (memory.get().0.clone() as Arc<dyn zmux::PrefixStore>, None)
    } else {
        let window = store
            .getattr("window")?
            .cast_into::<PrefixWindow>()?
            .get()
            .0;
        let lp = LoopRef::lazy(store.py());
        let store = PythonStore {
            store: Arc::new(store.unbind()),
            lp: lp.clone(),
            window,
            empty: Arc::new(zmux::PrefixSchedule::new(0, vec![]).map_err(value_err)?),
        };
        (Arc::new(store) as Arc<dyn zmux::PrefixStore>, Some(lp))
    };
    let binding = binding(bind)?;
    let mut verifier = match max_skew {
        Some(skew) => zmux::PrefixAuthVerifier::with_max_skew(store, binding, skew),
        None => zmux::PrefixAuthVerifier::new(store, binding),
    }
    .map_err(value_err)?;
    if let Some(header) = header {
        verifier = verifier.with_header(header).map_err(value_err)?;
    }
    let reject = match reject {
        "close" => zmux::PrefixRejection::Close,
        "stall" => zmux::PrefixRejection::Stall,
        "fallback" => zmux::PrefixRejection::Fallback,
        _ => return Err(PyValueError::new_err("unknown ticket rejection policy")),
    };
    Ok((zmux::Admission::prefix_auth(Arc::new(verifier), reject), lp))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PrefixAuth>()?;
    m.add_class::<PrefixGeneration>()?;
    m.add_class::<PrefixSchedule>()?;
    m.add_class::<PrefixTicket>()?;
    m.add_class::<PrefixWindow>()?;
    m.add_class::<MemoryPrefixStore>()?;
    m.add_class::<PrefixDeadline>()?;
    m.add("PREFIX_TOKEN_LEN", zmux::PREFIX_TOKEN_LEN)?;
    Ok(())
}
