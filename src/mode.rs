//! Carrier modes (API.md Section 4.8): `Candidate`, `Mode`, `CarrierCache`
//! and `dial_mode`, over the Rust crate's.

use std::sync::Arc;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::rt::future_into_py;
use crate::{
    ExchangeOptions, H3Dial, QuicDial, Session, TlsConfig, WebTransportDial, ZmuxError, admission,
    http_client_options, seconds,
};

create_exception!(
    _zmux,
    ModeError,
    ZmuxError,
    "No candidate of a carrier mode was usable; `args[1]` lists every try."
);

/// One try of a candidate as the Python `CandidateResult`.
pub(crate) fn result_obj(
    r: &zmux::CandidateResult,
) -> impl FnOnce(Python<'_>) -> PyResult<Py<PyAny>> + '_ {
    move |py| {
        let d = PyDict::new(py);
        d.set_item("carrier", r.kind.name())?;
        d.set_item("outcome", r.outcome.name())?;
        d.set_item("joined", r.joined)?;
        d.set_item("error", r.error.clone())?;
        Ok(crate::types(py)?
            .getattr("_candidate_result")?
            .call1((d,))?
            .unbind())
    }
}

async fn tcp(addr: String) -> std::io::Result<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

fn connect(
    addr: &str,
) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<tokio::net::TcpStream>> + Send>>
+ Send
+ Sync
+ 'static {
    let addr = addr.to_owned();
    move || Box::pin(tcp(addr.clone()))
}

/// One carrier kind a mode may use.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct Candidate(zmux::Candidate);

#[pymethods]
impl Candidate {
    /// A bidirectional streaming `POST` over HTTP/1.1 to `addr`.
    #[staticmethod]
    #[pyo3(signature = (addr, *, path="/zmux".to_owned(), credential=None))]
    fn streaming(
        addr: String,
        path: String,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let opts = http_client_options(path, credential)?;
        Ok(Self(zmux_http::streaming_candidate(
            connect(&addr),
            &addr,
            &opts,
        )))
    }

    /// A split bootstrap (an uplink `POST` and a downlink `GET`) over
    /// HTTP/1.1 to `addr`; as a further pipe it joins as a downlink and an
    /// uplink.
    #[staticmethod]
    #[pyo3(signature = (addr, *, path="/zmux".to_owned(), credential=None))]
    fn split(addr: String, path: String, credential: Option<Bound<'_, PyAny>>) -> PyResult<Self> {
        let opts = http_client_options(path, credential)?;
        Ok(Self(zmux_http::split_candidate(
            connect(&addr),
            &addr,
            &opts,
        )))
    }

    /// The exchange carrier to `addr`; it authenticates with the options'
    /// PSK.
    #[staticmethod]
    #[pyo3(signature = (addr, *, options=None))]
    fn exchange(addr: String, options: Option<PyRef<'_, ExchangeOptions>>) -> Self {
        let o = options.map(|o| o.0.clone()).unwrap_or_default();
        Self(zmux_http::exchange_candidate(connect(&addr), &addr, &o))
    }

    /// A WebSocket to `url` (`ws://`, or `wss://` with `tls`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, credential=None))]
    fn websocket(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut opts = zmux_websocket::Options::default();
        if let Some(c) = admission::credential(credential)? {
            opts = opts.with_credential(c);
        }
        if url.starts_with("wss://") {
            let c = match tls {
                Some(t) => t.client_alpn(crate::http1)?,
                None => TlsConfig::web().client_alpn(crate::http1)?,
            };
            let connector = tokio_rustls::TlsConnector::from(Arc::new(c));
            return Ok(Self(zmux_websocket::candidate_tls(&url, connector, &opts)));
        }
        let uri: http::Uri = url
            .parse()
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        let host = uri
            .host()
            .ok_or_else(|| PyValueError::new_err("URL without a host"))?;
        let addr = format!("{host}:{}", uri.port_u16().unwrap_or(80));
        Ok(Self(zmux_websocket::candidate(connect(&addr), &url, &opts)))
    }

    /// A QUIC connection to `addr`, where the client reaches the server
    /// directly (as `dial_quic`).
    #[staticmethod]
    #[pyo3(signature = (addr, *, tls=None, server_name=None, lanes=4, credential=None))]
    fn quic(
        addr: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        lanes: u32,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = QuicDial::new(addr, tls, server_name, lanes, credential)?;
        Ok(Self(zmux::Candidate::new(
            zmux::CarrierKind::Quic,
            move || {
                let d = d.clone();
                async move { d.open().await }
            },
        )))
    }

    /// An HTTP/3 request to `url` (`https://`), sent to `addr` when given
    /// (as `dial_h3`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, addr=None, lanes=4, credential=None))]
    fn http3(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        addr: Option<String>,
        lanes: u32,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = H3Dial::new(url, tls, addr, lanes, credential)?;
        Ok(Self(zmux::Candidate::new(
            zmux::CarrierKind::Http3,
            move || {
                let d = d.clone();
                async move { d.open().await }
            },
        )))
    }

    /// A WebTransport session to `url` (`https://`, as
    /// `dial_webtransport`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, lanes=4, credential=None))]
    fn webtransport(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        lanes: u32,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = WebTransportDial::new(url, tls, lanes, credential)?;
        Ok(Self(zmux::Candidate::new(
            zmux::CarrierKind::WebTransport,
            move || {
                let d = d.clone();
                async move { d.open().await }
            },
        )))
    }

    /// The candidate's kind.
    #[getter]
    fn kind(&self) -> &'static str {
        self.0.kind().name()
    }

    fn __repr__(&self) -> String {
        format!("Candidate({})", self.0.kind())
    }
}

/// How `dial_mode` chooses the carrier.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct Mode(pub(crate) zmux::Mode);

#[pymethods]
impl Mode {
    /// `candidate` only: a failure is reported, never replaced.
    #[staticmethod]
    fn explicit(candidate: PyRef<'_, Candidate>) -> Self {
        Self(zmux::Mode::explicit(candidate.0.clone()))
    }

    /// A choice among `candidates`, most preferred first.
    #[staticmethod]
    fn auto(candidates: Vec<PyRef<'_, Candidate>>) -> PyResult<Self> {
        if candidates.is_empty() {
            return Err(PyValueError::new_err("auto mode without a candidate"));
        }
        Ok(Self(zmux::Mode::auto(
            candidates.iter().map(|c| c.0.clone()),
        )))
    }

    #[getter]
    fn is_auto(&self) -> bool {
        self.0.is_auto()
    }

    fn __repr__(&self) -> String {
        let kinds: Vec<_> = self
            .0
            .candidates()
            .iter()
            .map(|c| c.kind().name())
            .collect();
        format!(
            "Mode.{}({})",
            if self.0.is_auto() { "auto" } else { "explicit" },
            kinds.join(", ")
        )
    }
}

/// Which carrier kinds worked per server and local network, shared across
/// dials.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct CarrierCache(pub(crate) zmux::CarrierCache);

#[pymethods]
impl CarrierCache {
    #[new]
    #[pyo3(signature = (*, success_ttl=21600.0, backoff_min=60.0, backoff_max=21600.0))]
    fn new(success_ttl: f64, backoff_min: f64, backoff_max: f64) -> PyResult<Self> {
        Ok(Self(zmux::CarrierCache::new(
            seconds("success_ttl", success_ttl)?,
            seconds("backoff_min", backoff_min)?,
            seconds("backoff_max", backoff_max)?,
        )))
    }

    /// Whether `carrier` is held as usable under `key`.
    fn is_usable(&self, key: &str, carrier: &str) -> PyResult<bool> {
        Ok(self.0.is_usable(key, kind(carrier)?))
    }

    /// Whether `carrier` is backing off under `key`.
    fn is_failed(&self, key: &str, carrier: &str) -> PyResult<bool> {
        Ok(self.0.failed_until(key, kind(carrier)?).is_some())
    }

    /// What the cache knows, as JSON text (versioned; times in RFC 3339
    /// UTC), for `restore` later, such as in the next run of the process.
    /// Expired entries are left out.
    fn snapshot(&self) -> String {
        self.0.snapshot().to_json()
    }

    /// Merges a `snapshot` into the cache: of two entries for one key and
    /// kind, the newer is kept; a backoff outside this cache's bounds is
    /// brought within them; expired entries, unknown fields and kinds are
    /// dropped. Malformed text raises `ValueError` and changes nothing.
    fn restore(&self, snapshot: &str) -> PyResult<()> {
        let s = zmux::CacheSnapshot::from_json(snapshot)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.0.restore(&s);
        Ok(())
    }
}

fn kind(name: &str) -> PyResult<zmux::CarrierKind> {
    zmux::CarrierKind::from_name(name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown carrier kind {name:?}")))
}

/// A duration of `name` in seconds: non-negative and finite.
fn dur(name: &str, v: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(v)
        .map_err(|_| PyValueError::new_err(format!("{name} is a non-negative number of seconds")))
}

/// The policy of an auto mode (`dial_mode`, `PipePool.mode`); durations in
/// seconds.
#[allow(clippy::too_many_arguments)]
pub(crate) fn policy(
    cache: Option<PyRef<'_, CarrierCache>>,
    key: String,
    timer_factor: f64,
    timer_min: f64,
    timer_max: f64,
    settle: f64,
    drop_window: f64,
    no_join: bool,
) -> PyResult<zmux::ModePolicy> {
    let mut p = zmux::ModePolicy::default();
    match cache {
        Some(c) => p = p.with_cache(c.0.clone(), key),
        None => p.key = key,
    }
    if !(timer_factor.is_finite() && timer_factor >= 0.0) {
        return Err(PyValueError::new_err(
            "timer_factor is a non-negative finite number",
        ));
    }
    p.timer_factor = timer_factor;
    p.timer_min = dur("timer_min", timer_min)?;
    p.timer_max = dur("timer_max", timer_max)?;
    p.settle = dur("settle", settle)?;
    p.drop_window = dur("drop_window", drop_window)?;
    p.no_join = no_join;
    Ok(p)
}

/// Dials a client session over the carrier `mode` selects; see the
/// Rust crate's `dial_mode`. Durations in seconds.
#[pyfunction]
#[pyo3(signature = (mode, config=None, *, cache=None, key="".to_owned(), timer_factor=3.0,
    timer_min=1.0, timer_max=3.0, settle=1.0, drop_window=30.0, no_join=false))]
#[allow(clippy::too_many_arguments)]
fn dial_mode<'p>(
    py: Python<'p>,
    mode: PyRef<'_, Mode>,
    config: Option<Bound<'p, PyAny>>,
    cache: Option<PyRef<'_, CarrierCache>>,
    key: String,
    timer_factor: f64,
    timer_min: f64,
    timer_max: f64,
    settle: f64,
    drop_window: f64,
    no_join: bool,
) -> PyResult<Bound<'p, PyAny>> {
    let config = crate::cfg(config)?;
    let policy = policy(
        cache,
        key,
        timer_factor,
        timer_min,
        timer_max,
        settle,
        drop_window,
        no_join,
    )?;
    let mode = mode.0.clone();
    future_into_py(py, async move {
        match zmux::dial_mode(&mode, config, &policy).await {
            Ok(s) => Ok(Session::new(s)),
            Err(e) => crate::rt::attach(|py| {
                let results = e
                    .results
                    .iter()
                    .map(|r| result_obj(r)(py))
                    .collect::<PyResult<Vec<_>>>()?;
                Err(ModeError::new_err((e.to_string(), results)))
            }),
        }
    })
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Candidate>()?;
    m.add_class::<Mode>()?;
    m.add_class::<CarrierCache>()?;
    m.add_function(wrap_pyfunction!(dial_mode, m)?)?;
    m.add("ModeError", m.py().get_type::<ModeError>())?;
    Ok(())
}
