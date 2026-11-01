//! Carrier admission and client credentials: `Admission`, given to a
//! `Listener`, decides at every entry, from a carrier's first bytes or
//! request header, whether the listener takes it (a Python decider,
//! synchronous or `async`, or prefix authentication); `PrefixAuth`, or any object with `prefix` and `header`
//! methods, as a client's credential for `dial_*`.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Duration;

use pyo3_async_runtimes::TaskLocals;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

use crate::seconds;

/// A request of the Python thread for an exporter value, answered by the
/// thread that holds the carrier's metadata.
enum Ask {
    Export(Vec<u8>, Vec<u8>, usize, mpsc::Sender<Option<Vec<u8>>>),
    Done,
}

/// The metadata of a carrier, as Python sees it during one call of a
/// decider or a credential.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct CarrierInfo {
    source: Option<(String, u16)>,
    peer: Option<(String, u16)>,
    alpn: Option<Vec<u8>>,
    server_name: Option<String>,
    headers: Option<Vec<(String, Vec<u8>)>>,
    head: bool,
    exporter: Option<mpsc::Sender<Ask>>,
}

#[pymethods]
impl CarrierInfo {
    /// The carrier's source, `(host, port)`: the client a trusted
    /// intermediary reports (port 0 when it reported none), or the peer.
    #[getter]
    fn source(&self) -> Option<(String, u16)> {
        self.source.clone()
    }
    /// The directly connected peer, `(host, port)`.
    #[getter]
    fn peer(&self) -> Option<(String, u16)> {
        self.peer.clone()
    }
    #[getter]
    fn alpn<'p>(&self, py: Python<'p>) -> Option<Bound<'p, PyBytes>> {
        self.alpn.as_deref().map(|a| PyBytes::new(py, a))
    }
    #[getter]
    fn server_name(&self) -> Option<String> {
        self.server_name.clone()
    }
    #[getter]
    fn headers<'p>(&self, py: Python<'p>) -> PyResult<Option<Vec<Bound<'p, PyTuple>>>> {
        let Some(h) = &self.headers else {
            return Ok(None);
        };
        h.iter()
            .map(|(n, v)| {
                PyTuple::new(
                    py,
                    [
                        n.into_pyobject(py)?.into_any(),
                        PyBytes::new(py, v).into_any(),
                    ],
                )
            })
            .collect::<PyResult<_>>()
            .map(Some)
    }
    #[getter]
    fn head(&self) -> bool {
        self.head
    }
    /// `length` bytes of the TLS exporter of the carrier's handshake for
    /// `label` and `context`; `None` without one, or once the call that
    /// was given this object has returned.
    #[pyo3(signature = (label, context=b"".to_vec(), length=32))]
    fn export<'p>(
        &self,
        py: Python<'p>,
        label: Vec<u8>,
        context: Vec<u8>,
        length: usize,
    ) -> Option<Bound<'p, PyBytes>> {
        let ask = self.exporter.as_ref()?;
        let value = py.detach(|| {
            let (tx, rx) = mpsc::channel();
            ask.send(Ask::Export(label, context, length, tx)).ok()?;
            rx.recv().ok().flatten()
        })?;
        Some(PyBytes::new(py, &value))
    }
    fn __repr__(&self) -> String {
        format!(
            "CarrierInfo(source={:?}, peer={:?}, server_name={:?}, head={})",
            self.source, self.peer, self.server_name, self.head
        )
    }
}

/// Calls `f` with the Python view of `info`. With an exporter, `f` runs on
/// a scoped thread of its own while this one answers its exporter
/// requests: `info` borrows the carrier and stays here.
fn with_info<R: Send>(
    info: &zmux::CarrierInfo<'_>,
    f: impl FnOnce(CarrierInfo) -> R + Send,
) -> std::io::Result<R> {
    let mut headers = None;
    if info.request.is_some() {
        let mut h = Vec::new();
        info.for_each_header(|n, v| h.push((n.to_owned(), v.to_vec())));
        headers = Some(h);
    }
    let mut view = CarrierInfo {
        source: info.source.map(|r| (r.ip().to_string(), r.port())),
        peer: info.peer.map(|r| (r.ip().to_string(), r.port())),
        alpn: info.alpn.map(<[u8]>::to_vec),
        server_name: info.server_name.map(str::to_owned),
        headers,
        head: info.head,
        exporter: None,
    };
    if !info.has_exporter() {
        return Ok(f(view));
    }
    let (tx, rx) = mpsc::channel();
    view.exporter = Some(tx.clone());
    std::thread::scope(|s| {
        let call = std::thread::Builder::new().spawn_scoped(s, move || {
            crate::rt::mark_runtime_thread();
            let r = f(view);
            let _ = tx.send(Ask::Done);
            r
        })?;
        // Ends with Done; the view's sender may outlive the call.
        while let Ok(Ask::Export(label, context, len, reply)) = rx.recv() {
            let _ = reply.send(info.export(&label, &context, len));
        }
        call.join()
            .map_err(|_| std::io::Error::other("the call panicked"))
    })
}

/// An admission decision for `serve_*`.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct Verdict(V);

/// A verdict as Python holds it: an accept's value is a Python object.
enum V {
    Accept {
        skip: usize,
        value: Option<Arc<Py<PyAny>>>,
    },
    Fallback,
    Stall,
    Close,
}

/// The Python object of an admission's value (`AdmittedValue`): the one a
/// decider gave `Verdict.accept`, `None` without one.
pub(crate) fn admitted_obj(py: Python<'_>, v: Option<&zmux::AdmittedValue>) -> Option<Py<PyAny>> {
    v.and_then(|v| (**v).downcast_ref::<Py<PyAny>>())
        .map(|o| o.clone_ref(py))
}

impl Verdict {
    fn native(&self) -> zmux::Verdict {
        match &self.0 {
            V::Accept { skip, value } => {
                let v = zmux::Verdict::accept(*skip);
                match value {
                    Some(o) => v.with_value(o.clone() as zmux::AdmittedValue),
                    None => v,
                }
            }
            V::Fallback => zmux::Verdict::Fallback,
            V::Stall => zmux::Verdict::Stall,
            V::Close => zmux::Verdict::Close,
        }
    }
}

#[pymethods]
impl Verdict {
    /// Takes the carrier with the first `skip` prefix bytes removed;
    /// `value`, any object, is the carrier's admitted value
    /// (`Session.admitted`, `Pipe.admitted`, `PipeHint.admitted`).
    #[staticmethod]
    #[pyo3(signature = (skip=0, value=None))]
    fn accept(skip: usize, value: Option<Py<PyAny>>) -> Self {
        Verdict(V::Accept {
            skip,
            value: value.map(Arc::new),
        })
    }
    #[classattr]
    #[allow(non_snake_case)]
    fn FALLBACK() -> Verdict {
        Verdict(V::Fallback)
    }
    #[classattr]
    #[allow(non_snake_case)]
    fn STALL() -> Verdict {
        Verdict(V::Stall)
    }
    #[classattr]
    #[allow(non_snake_case)]
    fn CLOSE() -> Verdict {
        Verdict(V::Close)
    }
    /// The prefix bytes an accept removes; `None` for another verdict.
    #[getter]
    fn skip(&self) -> Option<usize> {
        match self.0 {
            V::Accept { skip, .. } => Some(skip),
            _ => None,
        }
    }
    /// An accept's value.
    #[getter]
    fn value(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        match &self.0 {
            V::Accept { value, .. } => value.as_ref().map(|o| o.clone_ref(py)),
            _ => None,
        }
    }
    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Verdict>() else {
            return Ok(false);
        };
        Ok(match (&self.0, &o.get().0) {
            (V::Accept { skip: a, value: x }, V::Accept { skip: b, value: y }) => {
                a == b
                    && match (x, y) {
                        (None, None) => true,
                        (Some(x), Some(y)) => x.bind(py).eq(y.bind(py))?,
                        _ => false,
                    }
            }
            (V::Fallback, V::Fallback) | (V::Stall, V::Stall) | (V::Close, V::Close) => true,
            _ => false,
        })
    }
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(match &self.0 {
            V::Accept { skip, value: None } => format!("Verdict.accept({skip})"),
            V::Accept {
                skip,
                value: Some(v),
            } => format!("Verdict.accept({skip}, value={})", v.bind(py).repr()?),
            V::Fallback => "Verdict.FALLBACK".into(),
            V::Stall => "Verdict.STALL".into(),
            V::Close => "Verdict.CLOSE".into(),
        })
    }
}

/// A server's admission of new carriers, given to a `Listener`.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct Admission {
    pub(crate) inner: zmux::Admission,
    /// The decider written in Python, whose coroutines run on an event loop.
    decider: Option<PyDecide>,
}

impl Admission {
    fn with_times(
        mut a: zmux::Admission,
        decider: Option<PyDecide>,
        peek_timeout: Option<f64>,
        stall: Option<(f64, f64)>,
    ) -> PyResult<Self> {
        if let Some(t) = peek_timeout {
            a = a.with_peek_timeout(seconds("peek_timeout", t)?);
        }
        if let Some((min, max)) = stall {
            a = a.with_stall_interval(seconds("stall", min)?, seconds("stall", max)?);
        }
        Ok(Admission { inner: a, decider })
    }

    /// The admission for a listener made now: an `async` decider's
    /// coroutines run on the event loop running now, unless one was taken
    /// already.
    pub(crate) fn for_listener(&self, py: Python<'_>) -> zmux::Admission {
        if let Some(d) = &self.decider
            && let Ok(l) = pyo3_async_runtimes::tokio::get_current_locals(py)
        {
            let _ = d.locals.set(l);
        }
        self.inner.clone()
    }
}

type Started = Pin<Box<dyn Future<Output = PyResult<Py<PyAny>>> + Send>>;

/// A decision written in Python: `decide(info, prefix)` returning a
/// `Verdict`, or a coroutine resolving to one.
#[derive(Clone)]
struct PyDecide {
    decide: Arc<Py<PyAny>>,
    locals: Arc<OnceLock<TaskLocals>>,
}

impl PyDecide {
    /// Calls the decider with the view of `info`: its verdict, or the
    /// future of its coroutine.
    fn start(&self, info: &zmux::CarrierInfo<'_>, prefix: &[u8]) -> Result<Py<PyAny>, Started> {
        let called = with_info(info, |view| {
            crate::rt::attach(|py| {
                let r = Py::new(py, view)
                    .and_then(|v| self.decide.call1(py, (v, PyBytes::new(py, prefix))));
                match r {
                    Ok(v) if v.bind(py).hasattr("__await__").unwrap_or(false) => {
                        let Some(locals) = self.locals.get() else {
                            return Err(Box::pin(std::future::ready(Err(PyValueError::new_err(
                                "an async decide needs its Listener made inside a running event loop",
                            )))) as Started);
                        };
                        match crate::rt::into_future(locals, v.into_bound(py)) {
                            Ok(f) => Err(Box::pin(f) as Started),
                            Err(e) => Err(Box::pin(std::future::ready(Err(e))) as Started),
                        }
                    }
                    Ok(v) => Ok(v),
                    Err(e) => Err(Box::pin(std::future::ready(Err(e))) as Started),
                }
            })
        });
        called.unwrap_or_else(|e| {
            Err(Box::pin(std::future::ready(Err(PyValueError::new_err(
                e.to_string(),
            )))) as Started)
        })
    }

    /// The verdict of a decider's result; an exception or another value is
    /// reported as unraisable and closes.
    fn verdict(&self, r: PyResult<Py<PyAny>>) -> zmux::Verdict {
        crate::rt::attach(|py| {
            let v = r.and_then(|v| Ok(v.bind(py).cast::<Verdict>()?.get().native()));
            v.unwrap_or_else(|e| {
                e.write_unraisable(py, Some(self.decide.bind(py)));
                zmux::Verdict::Close
            })
        })
    }
}

impl zmux::Decide for PyDecide {
    fn decide<'a>(
        &'a self,
        info: &'a zmux::CarrierInfo<'a>,
        prefix: &'a [u8],
    ) -> zmux::DecideFuture<'a> {
        let started = self.start(info, prefix);
        Box::pin(async move {
            match started {
                Ok(v) => self.verdict(Ok(v)),
                // Dropped when the listener gives the decision up: the
                // coroutine's task is cancelled with it.
                Err(f) => {
                    let r = f.await;
                    self.verdict(r)
                }
            }
        })
    }
}

#[pymethods]
impl Admission {
    /// `decide(info, prefix)` returns a `Verdict`, or is `async` and
    /// resolves to one within what remains of the peek timeout; cancelled
    /// (`CancelledError`) when that ends or the listener closes. An `async`
    /// decide runs on the event loop of the `Listener`'s creation; `info`'s
    /// exporter answers only before its first `await`.
    #[new]
    #[pyo3(signature = (decide, *, peek=0, peek_timeout=None, stall=None))]
    fn new(
        py: Python<'_>,
        decide: Py<PyAny>,
        peek: usize,
        peek_timeout: Option<f64>,
        stall: Option<(f64, f64)>,
    ) -> PyResult<Self> {
        let d = PyDecide {
            decide: Arc::new(decide),
            locals: Arc::new(OnceLock::new()),
        };
        if let Ok(l) = pyo3_async_runtimes::tokio::get_current_locals(py) {
            let _ = d.locals.set(l);
        }
        let a = zmux::Admission::with_decider(peek, d.clone());
        Self::with_times(a, Some(d), peek_timeout, stall)
    }

    #[staticmethod]
    #[pyo3(signature = (auth, *, skew, max_nonces=65536, peek_timeout=None, stall=None))]
    fn prefix_auth(
        auth: PyRef<'_, PrefixAuth>,
        skew: u32,
        max_nonces: usize,
        peek_timeout: Option<f64>,
        stall: Option<(f64, f64)>,
    ) -> PyResult<Self> {
        let verifier = zmux::PrefixAuthVerifier::new(auth.0.clone(), skew, max_nonces);
        let a = zmux::Admission::prefix_auth(Arc::new(verifier));
        Self::with_times(a, None, peek_timeout, stall)
    }

    #[getter]
    fn peek(&self) -> usize {
        self.inner.peek()
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
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct PrefixAuth(zmux::PrefixAuth);

#[pymethods]
impl PrefixAuth {
    #[new]
    #[pyo3(signature = (psk, *, slot, bind_tls=false, header=None))]
    fn new(psk: Vec<u8>, slot: u64, bind_tls: bool, header: Option<String>) -> PyResult<Self> {
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
struct PyCredential(Py<PyAny>);

impl std::fmt::Debug for PyCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PyCredential(..)")
    }
}

impl PyCredential {
    /// `method(info)`, its result taken by `extract`.
    fn call<T: Send>(
        &self,
        method: &str,
        info: &zmux::CarrierInfo<'_>,
        extract: impl FnOnce(&Bound<'_, PyAny>) -> PyResult<T> + Send,
    ) -> std::io::Result<T> {
        with_info(info, |view| {
            crate::rt::attach(|py| {
                let v = self.0.call_method1(py, method, (Py::new(py, view)?,))?;
                extract(v.bind(py))
            })
            .map_err(|e| std::io::Error::other(e.to_string()))
        })?
    }
}

impl zmux::Credential for PyCredential {
    fn prefix(&self, info: &zmux::CarrierInfo<'_>) -> std::io::Result<Vec<u8>> {
        self.call("prefix", info, |v| v.extract::<Vec<u8>>())
    }
    fn header(&self, info: &zmux::CarrierInfo<'_>) -> std::io::Result<(String, String)> {
        self.call("header", info, |v| v.extract::<(String, String)>())
    }
}

/// The credential of a `credential=` argument: a `PrefixAuth`, or an
/// object with `prefix` and `header` methods.
pub(crate) fn credential(
    obj: Option<Bound<'_, PyAny>>,
) -> PyResult<Option<Arc<dyn zmux::Credential>>> {
    let Some(obj) = obj else {
        return Ok(None);
    };
    if let Ok(p) = obj.cast::<PrefixAuth>() {
        return Ok(Some(Arc::new(p.get().0.clone())));
    }
    if obj.hasattr("prefix")? && obj.hasattr("header")? {
        return Ok(Some(Arc::new(PyCredential(obj.unbind()))));
    }
    Err(PyValueError::new_err(
        "a credential is a PrefixAuth or has prefix(info) and header(info) methods",
    ))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CarrierInfo>()?;
    m.add_class::<Verdict>()?;
    m.add_class::<Admission>()?;
    m.add_class::<PrefixAuth>()?;
    Ok(())
}
