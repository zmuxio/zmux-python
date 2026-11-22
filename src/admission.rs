//! Carrier admission and client credentials: `Admission`, given to a
//! `Listener`, decides at every entry, from a carrier's first bytes or
//! request header, whether the listener takes it (a Python decider,
//! synchronous or `async`, or prefix authentication); `PrefixAuth`, or any object with `prefix` and `header`
//! methods, as a client's credential for `dial_*`.

use std::sync::Arc;
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

use crate::ranged;
use crate::rt::LoopRef;
use crate::seconds;

/// The metadata of a carrier, as Python sees it: an owned copy, usable
/// for as long as Python keeps it.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct CarrierInfo(pub(crate) zmux::CarrierInfo);

fn addr(a: Option<std::net::SocketAddr>) -> Option<(String, u16)> {
    a.map(|r| (r.ip().to_string(), r.port()))
}

#[pymethods]
impl CarrierInfo {
    /// The carrier's source, `(host, port)`: the client a trusted
    /// intermediary reports (port 0 when it reported none), or the peer.
    #[getter]
    fn source(&self) -> Option<(String, u16)> {
        addr(self.0.source)
    }
    /// The directly connected peer, `(host, port)`.
    #[getter]
    fn peer(&self) -> Option<(String, u16)> {
        addr(self.0.peer)
    }
    #[getter]
    fn alpn<'p>(&self, py: Python<'p>) -> Option<Bound<'p, PyBytes>> {
        self.0.alpn.as_deref().map(|a| PyBytes::new(py, a))
    }
    #[getter]
    fn server_name(&self) -> Option<&str> {
        self.0.server_name.as_deref()
    }
    #[getter]
    fn headers<'p>(&self, py: Python<'p>) -> PyResult<Option<Vec<Bound<'p, PyTuple>>>> {
        let mut h: Vec<(String, Vec<u8>)> = Vec::new();
        self.0
            .for_each_header(|n, v| h.push((n.to_owned(), v.to_vec())));
        if self.0.request.is_none() && h.is_empty() {
            return Ok(None);
        }
        h.into_iter()
            .map(|(n, v)| (n, PyBytes::new(py, &v)).into_pyobject(py))
            .collect::<PyResult<_>>()
            .map(Some)
    }
    /// What of the carrier the decision is taken on: `AdmissionStage.HEAD`
    /// (an HTTP request head, no prefix) or `AdmissionStage.CARRIER`.
    #[getter]
    fn stage<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        let name = match self.0.stage {
            zmux::AdmissionStage::Head => "head",
            _ => "carrier",
        };
        crate::typed(py, "AdmissionStage", name.to_owned())
    }
    /// The carrier's framing at `AdmissionStage.CARRIER` (`Framing.RECORDS`:
    /// the prefix is its first message).
    #[getter]
    fn framing<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        crate::typed(py, "Framing", framing_name(self.0.framing).to_owned())
    }
    /// The carrier of an HTTP upgrade (WebSocket, WebTransport), on its head
    /// and on the decision a `DEFER` takes on the carrier.
    #[getter]
    fn upgrade(&self) -> bool {
        self.0.upgrade
    }
    /// `length` bytes of the exporter of the carrier's handshake for
    /// `label` and `context`, as it answers without waiting; `None`
    /// without one, or for a value it does not hold.
    #[pyo3(signature = (label, context=b"".to_vec(), length=32))]
    fn export<'p>(
        &self,
        py: Python<'p>,
        label: &str,
        context: Vec<u8>,
        #[pyo3(from_py_with = ranged)] length: usize,
    ) -> Option<Bound<'p, PyBytes>> {
        let value = self.0.export(label, &context, length)?;
        Some(PyBytes::new(py, &value))
    }
    fn __repr__(&self) -> String {
        let stage = if self.0.is_head() { "head" } else { "carrier" };
        format!(
            "CarrierInfo(source={:?}, peer={:?}, server_name={:?}, stage={stage}, framing={}, upgrade={})",
            addr(self.0.source),
            addr(self.0.peer),
            self.0.server_name.as_deref(),
            framing_name(self.0.framing),
            self.0.upgrade
        )
    }
}

pub(crate) fn framing_name(f: zmux::adapter::Framing) -> &'static str {
    match f {
        zmux::adapter::Framing::Records => "records",
        zmux::adapter::Framing::ByteStream => "byte_stream",
    }
}

/// An admission decision for `serve_*`.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct AdmissionVerdict(V);

/// A verdict as Python holds it: an accept's value is a Python object.
enum V {
    Accept {
        skip: usize,
        value: Option<Arc<Py<PyAny>>>,
    },
    Fallback {
        value: Option<Arc<Py<PyAny>>>,
    },
    Takeover {
        value: Option<Arc<Py<PyAny>>>,
    },
    Stall,
    Close,
    More {
        need: usize,
    },
    Defer,
}

/// The Python object of an admission's value (`AdmittedValue`): the one a
/// decider gave `AdmissionVerdict.accept`, `None` without one.
pub(crate) fn admitted_obj(py: Python<'_>, v: Option<&zmux::AdmittedValue>) -> Option<Py<PyAny>> {
    v.and_then(|v| (**v).downcast_ref::<Py<PyAny>>())
        .map(|o| o.clone_ref(py))
}

impl AdmissionVerdict {
    fn native(&self) -> zmux::AdmissionVerdict {
        match &self.0 {
            V::Accept { skip, value } => {
                let v = zmux::AdmissionVerdict::accept(*skip);
                match value {
                    Some(o) => v.with_value(o.clone() as zmux::AdmittedValue),
                    None => v,
                }
            }
            V::Fallback { value } => {
                let v = zmux::AdmissionVerdict::fallback();
                match value {
                    Some(o) => v.with_value(o.clone() as zmux::AdmittedValue),
                    None => v,
                }
            }
            V::Takeover { value } => {
                let verdict = zmux::AdmissionVerdict::takeover();
                match value {
                    Some(o) => verdict.with_value(o.clone() as zmux::AdmittedValue),
                    None => verdict,
                }
            }
            V::Stall => zmux::AdmissionVerdict::Stall,
            V::Close => zmux::AdmissionVerdict::Close,
            V::More { need } => zmux::AdmissionVerdict::More { need: *need },
            V::Defer => zmux::AdmissionVerdict::Defer,
        }
    }
}

#[pymethods]
impl AdmissionVerdict {
    /// Takes the carrier with the first `skip` prefix bytes removed;
    /// `value`, any object, is the carrier's admitted value
    /// (`Session.admitted`, `Pipe.admitted`, `PipeHint.admitted`).
    #[staticmethod]
    #[pyo3(signature = (skip=0, value=None))]
    fn accept(#[pyo3(from_py_with = ranged)] skip: usize, value: Option<Py<PyAny>>) -> Self {
        AdmissionVerdict(V::Accept {
            skip,
            value: value.map(Arc::new),
        })
    }
    /// Hands the carrier to the listener's fallback, what was read
    /// replayed; `value`, any object, is the host's routing of it
    /// (`Takeover.value`).
    #[staticmethod]
    #[pyo3(signature = (value=None))]
    fn fallback(value: Option<Py<PyAny>>) -> Self {
        AdmissionVerdict(V::Fallback {
            value: value.map(Arc::new),
        })
    }
    #[classattr]
    #[allow(non_snake_case)]
    fn STALL() -> AdmissionVerdict {
        AdmissionVerdict(V::Stall)
    }
    #[classattr]
    #[allow(non_snake_case)]
    fn CLOSE() -> AdmissionVerdict {
        AdmissionVerdict(V::Close)
    }
    /// On the head of an HTTP upgrade (`CarrierInfo.upgrade`): completes the
    /// upgrade and decides again on the carrier's first message or bytes.
    #[classattr]
    #[allow(non_snake_case)]
    fn DEFER() -> AdmissionVerdict {
        AdmissionVerdict(V::Defer)
    }
    /// Hands the accepted carrier to the byte-stream target, or stalls without one.
    #[staticmethod]
    #[pyo3(signature = (value=None))]
    fn takeover(value: Option<Py<PyAny>>) -> Self {
        Self(V::Takeover {
            value: value.map(Arc::new),
        })
    }

    /// Waits for a longer prefix before deciding again.

    #[staticmethod]
    fn more(#[pyo3(from_py_with = ranged)] need: usize) -> Self {
        AdmissionVerdict(V::More { need })
    }
    /// A `Decision` of this verdict with the carrier's label `variant`.
    fn labelled(slf: Py<Self>, variant: String) -> Decision {
        Decision {
            verdict: slf,
            variant: Some(variant),
        }
    }
    /// The total prefix a `more` asks for; `None` for another verdict.
    #[getter]
    fn need(&self) -> Option<usize> {
        match self.0 {
            V::More { need } => Some(need),
            _ => None,
        }
    }
    /// The prefix bytes an accept removes; `None` for another verdict.
    #[getter]
    fn skip(&self) -> Option<usize> {
        match self.0 {
            V::Accept { skip, .. } => Some(skip),
            _ => None,
        }
    }
    /// An accept's or a fallback's value.
    #[getter]
    fn value(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        match &self.0 {
            V::Accept { value, .. } | V::Fallback { value } | V::Takeover { value } => {
                value.as_ref().map(|o| o.clone_ref(py))
            }
            _ => None,
        }
    }
    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<AdmissionVerdict>() else {
            return Ok(false);
        };
        Ok(match (&self.0, &o.get().0) {
            (V::Accept { skip: a, value: x }, V::Accept { skip: b, value: y }) => {
                a == b && same(py, x.as_deref(), y.as_deref())?
            }
            (V::Fallback { value: x }, V::Fallback { value: y })
            | (V::Takeover { value: x }, V::Takeover { value: y }) => {
                same(py, x.as_deref(), y.as_deref())?
            }
            (V::Stall, V::Stall) | (V::Close, V::Close) | (V::Defer, V::Defer) => true,
            (V::More { need: a }, V::More { need: b }) => a == b,
            _ => false,
        })
    }
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(match &self.0 {
            V::Accept { skip, value: None } => format!("AdmissionVerdict.accept({skip})"),
            V::Accept {
                skip,
                value: Some(v),
            } => format!(
                "AdmissionVerdict.accept({skip}, value={})",
                v.bind(py).repr()?
            ),
            V::Fallback { value: None } => "AdmissionVerdict.fallback()".into(),
            V::Fallback { value: Some(v) } => {
                format!("AdmissionVerdict.fallback(value={})", v.bind(py).repr()?)
            }
            V::Takeover { value: None } => "AdmissionVerdict.takeover()".into(),
            V::Takeover { value: Some(v) } => {
                format!("AdmissionVerdict.takeover(value={})", v.bind(py).repr()?)
            }
            V::Stall => "AdmissionVerdict.STALL".into(),
            V::Close => "AdmissionVerdict.CLOSE".into(),
            V::More { need } => format!("AdmissionVerdict.more({need})"),
            V::Defer => "AdmissionVerdict.DEFER".into(),
        })
    }
}

/// Whether two optional values are equal.
fn same(py: Python<'_>, x: Option<&Py<PyAny>>, y: Option<&Py<PyAny>>) -> PyResult<bool> {
    match (x, y) {
        (None, None) => Ok(true),
        (Some(x), Some(y)) => x.bind(py).eq(y.bind(py)),
        _ => Ok(false),
    }
}

/// A decision on a carrier: its verdict and the host's label of the kind of
/// carrier.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Decision {
    verdict: Py<AdmissionVerdict>,
    variant: Option<String>,
}

#[pymethods]
impl Decision {
    /// `verdict`, labelled `variant`: the label counts the verdict in
    /// `Listener.variant_stats().variants` and, on an accept, becomes the carrier's
    /// variant. One of a few constants of the host, never derived from the
    /// peer's bytes.
    #[new]
    #[pyo3(signature = (verdict, *, variant=None))]
    fn new(verdict: Py<AdmissionVerdict>, variant: Option<String>) -> Self {
        Self { verdict, variant }
    }
    #[getter]
    fn verdict(&self, py: Python<'_>) -> Py<AdmissionVerdict> {
        self.verdict.clone_ref(py)
    }
    #[getter]
    fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }
    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Decision>() else {
            return Ok(false);
        };
        let o = o.get();
        Ok(self.variant == o.variant && self.verdict.bind(py).eq(o.verdict.bind(py))?)
    }
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Decision({}, variant={:?})",
            self.verdict.bind(py).repr()?,
            self.variant
        ))
    }
}

/// The native decision of what a decider returned.
fn decision(v: &Bound<'_, PyAny>) -> PyResult<zmux::AdmissionDecision> {
    if let Ok(d) = v.cast::<Decision>() {
        let d = d.get();
        let verdict = d.verdict.get().native();
        return Ok(match &d.variant {
            Some(l) => verdict.labelled(l.as_str()),
            None => verdict.into(),
        });
    }
    Ok(v.cast::<AdmissionVerdict>()?.get().native().into())
}

/// A server's admission of new carriers, given to a `Listener`.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Admission {
    pub(crate) inner: zmux::Admission,
    /// The decider written in Python, whose coroutines run on an event loop.
    decider: Option<PyDecide>,
}

impl Admission {
    fn with_times(
        mut a: zmux::Admission,
        decider: Option<PyDecide>,
        peek_timeout: Option<Bound<'_, PyAny>>,
        stall: Option<Bound<'_, PyAny>>,
        fallback_on_peek_timeout: bool,
    ) -> PyResult<Self> {
        a = a.with_fallback_on_peek_timeout(fallback_on_peek_timeout);
        if let Some(t) = peek_timeout.filter(|t| !crate::is_setting(t, "AUTO").unwrap_or(false)) {
            let t = seconds("peek_timeout", t.extract()?)?;
            if t.is_zero() {
                return Err(PyValueError::new_err("peek_timeout is positive"));
            }
            a = a.with_peek_timeout(t);
        }
        if let Some(st) = stall.filter(|t| !crate::is_setting(t, "AUTO").unwrap_or(false)) {
            let (min, max): (f64, f64) = st.extract()?;
            let (min, max) = (seconds("stall", min)?, seconds("stall", max)?);
            if max.is_zero() || min > max {
                return Err(PyValueError::new_err(
                    "stall is (min, max) with 0 <= min <= max and max positive",
                ));
            }
            a = a.with_stall_interval(min, max);
        }
        Ok(Admission { inner: a, decider })
    }

    /// The admission for a listener, and the loop of its Python decider,
    /// which the listener binds at its first use unless it is bound.
    pub(crate) fn for_listener(&self) -> (zmux::Admission, Option<LoopRef>) {
        (
            self.inner.clone(),
            self.decider.as_ref().map(|d| d.lp.clone()),
        )
    }
}

/// A decision written in Python: `decide(info, prefix)` returning a
/// `AdmissionVerdict` or `Decision`, or a coroutine resolving to one.
#[derive(Clone)]
struct PyDecide {
    decide: Arc<Py<PyAny>>,
    lp: LoopRef,
}

/// The decision of a decider's result; an exception or another value is
/// reported as unraisable and closes.
fn settle(
    py: Python<'_>,
    decide: &Py<PyAny>,
    r: PyResult<Bound<'_, PyAny>>,
) -> zmux::AdmissionDecision {
    r.and_then(|v| decision(&v)).unwrap_or_else(|e| {
        e.write_unraisable(py, Some(decide.bind(py)));
        zmux::AdmissionVerdict::Close.into()
    })
}

impl zmux::Decide for PyDecide {
    /// Asks the decider on its loop; the listener drops the answer's
    /// future when it gives the decision up, which cancels the call.
    fn decide(
        &self,
        info: zmux::CarrierInfo,
        prefix: &[u8],
    ) -> zmux::Decision<zmux::AdmissionDecision> {
        self.answer(info, prefix, None)
    }

    fn decide_with_worker(
        &self,
        info: zmux::CarrierInfo,
        prefix: &[u8],
        worker: &mut dyn FnMut() -> Box<dyn Send + Sync>,
    ) -> zmux::Decision<zmux::AdmissionDecision> {
        self.answer(info, prefix, Some(worker()))
    }
}

impl PyDecide {
    fn answer(
        &self,
        info: zmux::CarrierInfo,
        prefix: &[u8],
        worker: Option<Box<dyn Send + Sync>>,
    ) -> zmux::Decision<zmux::AdmissionDecision> {
        let lp = &self.lp;
        let prefix = prefix.to_vec();
        let (decide, settling) = (self.decide.clone(), self.decide.clone());
        zmux::Decision::later(lp.settled(
            move |py| {
                let view = Py::new(py, CarrierInfo(info))?;
                decide.bind(py).call1((view, PyBytes::new(py, &prefix)))
            },
            move |py, r| {
                let _worker = worker;
                settle(py, &settling, r)
            },
            || zmux::AdmissionVerdict::Close.into(),
        ))
    }
}

#[pymethods]
impl Admission {
    /// `decide(info, prefix)` returns an `AdmissionVerdict` or `Decision`, or is
    /// `async` and resolves to one within what remains of the peek timeout; cancelled
    /// (`CancelledError`) when that ends or the listener closes. It runs on
    /// the event loop running when the admission is made, else on that of
    /// the `Listener`'s creation.
    #[new]
    #[pyo3(signature = (decide, *, peek=0, max_peek=0, max_message=0, peek_timeout=None,
        stall=None, fallback_on_peek_timeout=false))]
    fn new(
        py: Python<'_>,
        decide: Py<PyAny>,
        #[pyo3(from_py_with = ranged)] peek: usize,
        #[pyo3(from_py_with = ranged)] max_peek: usize,
        #[pyo3(from_py_with = ranged)] max_message: usize,
        peek_timeout: Option<Bound<'_, PyAny>>,
        stall: Option<Bound<'_, PyAny>>,
        fallback_on_peek_timeout: bool,
    ) -> PyResult<Self> {
        if max_message > zmux::MAX_ADMISSION_MESSAGE {
            return Err(PyValueError::new_err(format!(
                "max_message is at most {}",
                zmux::MAX_ADMISSION_MESSAGE
            )));
        }
        let d = PyDecide {
            decide: Arc::new(decide),
            lp: LoopRef::lazy(py),
        };
        let a = zmux::Admission::with_decider(peek, d.clone())
            .with_max_peek(max_peek)
            .with_max_message(max_message);
        Self::with_times(a, Some(d), peek_timeout, stall, fallback_on_peek_timeout)
    }

    #[staticmethod]
    #[pyo3(signature = (auth, *, skew, max_nonces=65536, peek_timeout=None, stall=None,
        fallback_on_peek_timeout=false))]
    fn prefix_auth(
        auth: PyRef<'_, PrefixAuth>,
        #[pyo3(from_py_with = ranged)] skew: u32,
        #[pyo3(from_py_with = ranged)] max_nonces: usize,
        peek_timeout: Option<Bound<'_, PyAny>>,
        stall: Option<Bound<'_, PyAny>>,
        fallback_on_peek_timeout: bool,
    ) -> PyResult<Self> {
        let verifier = zmux::PrefixAuthVerifier::new(auth.0.clone(), skew, max_nonces)
            .map_err(crate::value_err)?;
        let a = zmux::Admission::prefix_auth(Arc::new(verifier));
        Self::with_times(a, None, peek_timeout, stall, fallback_on_peek_timeout)
    }

    #[getter]
    fn peek(&self) -> usize {
        self.inner.peek()
    }
    /// The largest prefix of a byte stream `AdmissionVerdict.more` may ask
    /// for, at least `peek`.
    #[getter]
    fn max_peek(&self) -> usize {
        self.inner.max_peek()
    }
    /// The largest first message of a message-framed carrier decided on (a
    /// longer one is closed, counted in `too_large`).
    #[getter]
    fn max_message(&self) -> usize {
        self.inner.max_message()
    }
    /// Whether a carrier whose prefix does not arrive within the peek
    /// timeout goes to the fallback (with the bytes read replayed) instead
    /// of being closed.
    #[getter]
    fn fallback_on_peek_timeout(&self) -> bool {
        self.inner.fallback_on_peek_timeout()
    }
    #[getter]
    fn peek_timeout(&self) -> f64 {
        self.inner.peek_timeout().as_secs_f64()
    }
    #[getter]
    fn stall(&self) -> (f64, f64) {
        let (min, max) = self.inner.stall_interval();
        (min.as_secs_f64(), max.as_secs_f64())
    }
}

/// Prefix authentication parameters both ends share; a client's
/// credential.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PrefixAuth(zmux::PrefixAuth);

#[pymethods]
impl PrefixAuth {
    #[new]
    #[pyo3(signature = (psk, *, slot, bind_tls=false, header=None))]
    fn new(
        psk: Vec<u8>,
        #[pyo3(from_py_with = ranged)] slot: u64,
        bind_tls: bool,
        header: Option<String>,
    ) -> PyResult<Self> {
        let auth =
            zmux::PrefixAuth::new(&psk, Duration::from_secs(slot), bind_tls).map_err(|_| {
                PyValueError::new_err("prefix authentication needs a non-empty psk and slot > 0")
            })?;
        Ok(PrefixAuth(match header {
            Some(h) => auth.with_header(h),
            None => auth,
        }))
    }
    #[getter]
    fn bind_tls(&self) -> bool {
        self.0.binds_tls()
    }
    #[getter]
    fn header(&self) -> &str {
        self.0.header_name()
    }
    fn __repr__(&self) -> String {
        let b = if self.0.binds_tls() { "True" } else { "False" };
        format!(
            "PrefixAuth(bind_tls={b}, header={:?})",
            self.0.header_name()
        )
    }
}

impl PrefixAuth {
    pub(crate) fn binds_tls(&self) -> bool {
        self.0.binds_tls()
    }
}

/// A credential implemented in Python: its `prefix(info)` and
/// `header(info)` methods, called with the GIL.
struct PyCarrierCredential(Py<PyAny>);

impl std::fmt::Debug for PyCarrierCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PyCarrierCredential(..)")
    }
}

impl PyCarrierCredential {
    /// `method(info)`, its result taken by `extract`. The Rust trait is
    /// synchronous and asked on the dialing task, so this enters Python
    /// from that thread, through the exit gate.
    fn call<T>(
        &self,
        method: &str,
        info: &zmux::CarrierInfo,
        extract: impl FnOnce(&Bound<'_, PyAny>) -> PyResult<T>,
    ) -> std::io::Result<T> {
        crate::rt::hook_or(Err(crate::rt::exiting()), |py| {
            let view = Py::new(py, CarrierInfo(info.clone()))?;
            let v = self.0.call_method1(py, method, (view,))?;
            extract(v.bind(py))
        })
        .map_err(std::io::Error::other)
    }
}

impl zmux::CarrierCredential for PyCarrierCredential {
    fn prefix(&self, info: &zmux::CarrierInfo) -> std::io::Result<Vec<u8>> {
        self.call("prefix", info, |v| v.extract::<Vec<u8>>())
    }
    fn header(&self, info: &zmux::CarrierInfo) -> std::io::Result<(String, String)> {
        self.call("header", info, |v| v.extract::<(String, String)>())
    }
}

/// The carrier credential of a `carrier_credential=` argument: a `PrefixAuth`, or an
/// object with `prefix` and `header` methods.
pub(crate) fn carrier_credential(
    obj: Option<Bound<'_, PyAny>>,
) -> PyResult<Option<Arc<dyn zmux::CarrierCredential>>> {
    let Some(obj) = obj else {
        return Ok(None);
    };
    if let Ok(p) = obj.cast::<PrefixAuth>() {
        return Ok(Some(Arc::new(p.get().0.clone())));
    }
    if obj.hasattr("prefix")? && obj.hasattr("header")? {
        return Ok(Some(Arc::new(PyCarrierCredential(obj.unbind()))));
    }
    Err(PyValueError::new_err(
        "a carrier credential is a PrefixAuth or has prefix(info) and header(info) methods",
    ))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CarrierInfo>()?;
    m.add_class::<AdmissionVerdict>()?;
    m.add_class::<Decision>()?;
    m.add_class::<Admission>()?;
    m.add_class::<PrefixAuth>()?;
    Ok(())
}
