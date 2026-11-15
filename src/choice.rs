//! Carrier choice: `Candidate`, `CarrierChoice`, `CarrierChoicePolicy`,
//! `CarrierCache` and `connect_choice`, over the Rust crate's.

use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::rt::future_into_py;
use crate::{
    ExchangeOptions, H3Dial, QuicDial, Session, TlsConfig, WebTransportDial, admission, hostport,
    http_client_options, seconds,
};

/// One try of a candidate as the Python `CandidateResult`.
pub(crate) fn result_obj(
    r: &zmux::CandidateResult,
) -> impl FnOnce(Python<'_>) -> PyResult<Py<PyAny>> + '_ {
    move |py| {
        let d = PyDict::new(py);
        d.set_item("carrier", r.kind.name())?;
        d.set_item("variant", r.variant.as_deref())?;
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

/// One carrier kind a carrier choice may use; each constructor is named
/// after the `dial_*` function that opens the same carrier.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Candidate(zmux::Candidate);

#[pymethods]
impl Candidate {
    /// A bidirectional streaming `POST` over HTTP/1.1 to `addr` (kind
    /// `streaming`, as `dial_streaming`).
    #[staticmethod]
    #[pyo3(signature = (host, port, *, path="/zmux".to_owned(), carrier_credential=None, pair_field=None))]
    fn streaming(
        host: String,
        port: u16,
        path: String,
        carrier_credential: Option<Bound<'_, PyAny>>,
        pair_field: Option<String>,
    ) -> PyResult<Self> {
        let addr = hostport(&host, port);
        let opts = http_client_options(path, carrier_credential, pair_field)?;
        Ok(Self(zmux_http::candidate(connect(&addr), &addr, &opts)))
    }

    /// A split bootstrap (an uplink `POST` and a downlink `GET`) over
    /// HTTP/1.1 to `addr` (kind `split`, as `dial_split`); as a
    /// further pipe it joins as a downlink and an uplink.
    #[staticmethod]
    #[pyo3(signature = (host, port, *, path="/zmux".to_owned(), carrier_credential=None, pair_field=None))]
    fn split(
        host: String,
        port: u16,
        path: String,
        carrier_credential: Option<Bound<'_, PyAny>>,
        pair_field: Option<String>,
    ) -> PyResult<Self> {
        let addr = hostport(&host, port);
        let opts = http_client_options(path, carrier_credential, pair_field)?;
        Ok(Self(zmux_http::candidate_split(
            connect(&addr),
            &addr,
            &opts,
        )))
    }

    /// The exchange carrier to `addr` (kind `exchange`, as
    /// `dial_exchange`); it authenticates with the options' PSK.
    #[staticmethod]
    #[pyo3(signature = (host, port, *, options=None))]
    fn exchange(host: String, port: u16, options: Option<PyRef<'_, ExchangeOptions>>) -> Self {
        let o = options.map(|o| o.0.clone()).unwrap_or_default();
        let addr = hostport(&host, port);
        Self(zmux_http::candidate_exchange(connect(&addr), &addr, &o))
    }

    /// A WebSocket to `url` (`ws://`, or `wss://` with `tls`; kind
    /// `websocket`, as `dial_websocket`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, carrier_credential=None, no_subprotocol=false))]
    fn websocket(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        carrier_credential: Option<Bound<'_, PyAny>>,
        no_subprotocol: bool,
    ) -> PyResult<Self> {
        let mut opts = zmux_websocket::Options::default().with_no_subprotocol(no_subprotocol);
        if let Some(c) = admission::carrier_credential(carrier_credential)? {
            opts = opts.with_carrier_credential(c);
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
    /// directly (kind `quic`, as `dial_quic`).
    #[staticmethod]
    #[pyo3(signature = (host, port, *, tls=None, server_name=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
    fn quic(
        host: String,
        port: u16,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let addr = hostport(&host, port);
        let d = QuicDial::new(addr, tls, server_name, lanes, carrier_credential)?;
        Ok(Self(zmux::Candidate::new(
            zmux::CarrierKind::Quic,
            move || {
                let d = d.clone();
                async move { d.open().await }
            },
        )))
    }

    /// An HTTP/3 request to `url` (`https://`), sent to `addr` when given
    /// (kind `http3`, as `dial_http3`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, addr=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
    fn http3(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        addr: Option<(String, u16)>,
        lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = H3Dial::new(url, tls, addr, lanes, carrier_credential)?;
        Ok(Self(zmux::Candidate::new(
            zmux::CarrierKind::Http3,
            move || {
                let d = d.clone();
                async move { d.open().await }
            },
        )))
    }

    /// A WebTransport session to `url` (`https://`; kind `webtransport`,
    /// as `dial_webtransport`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
    fn webtransport(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = WebTransportDial::new(url, tls, lanes, carrier_credential)?;
        Ok(Self(zmux::Candidate::new(
            zmux::CarrierKind::WebTransport,
            move || {
                let d = d.clone();
                async move { d.open().await }
            },
        )))
    }

    /// The candidate's `CarrierKind`.
    #[getter]
    fn kind<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        crate::typed(py, "CarrierKind", self.0.kind().name().to_owned())
    }

    /// A copy of this candidate with its carriers labelled `variant`: a kind with
    /// different variants makes different candidates, each with its own
    /// place in the cache.
    fn with_variant(&self, variant: &str) -> Self {
        Self(self.0.clone().with_variant(variant))
    }

    /// The candidate's variant, or `None`.
    #[getter]
    fn variant(&self) -> Option<&str> {
        self.0.variant().map(|v| &**v)
    }

    fn __repr__(&self) -> String {
        match self.0.variant() {
            Some(v) => format!("Candidate({}, variant={v:?})", self.0.kind()),
            None => format!("Candidate({})", self.0.kind()),
        }
    }
}

/// How a client chooses the carrier: `explicit(candidate)` or
/// `auto(candidates)`.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct CarrierChoice(pub(crate) zmux::CarrierChoice);

#[pymethods]
impl CarrierChoice {
    /// `candidate` only: a failure is reported, never replaced.
    #[staticmethod]
    fn explicit(candidate: PyRef<'_, Candidate>) -> Self {
        Self(zmux::CarrierChoice::explicit(candidate.0.clone()))
    }

    /// A choice among `candidates`, most preferred first.
    #[staticmethod]
    fn auto(candidates: Vec<PyRef<'_, Candidate>>) -> PyResult<Self> {
        if candidates.is_empty() {
            return Err(PyValueError::new_err("an auto choice without a candidate"));
        }
        Ok(Self(zmux::CarrierChoice::auto(
            candidates.iter().map(|c| c.0.clone()),
        )))
    }

    /// Whether the choice is automatic.
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
            "CarrierChoice.{}({})",
            if self.0.is_auto() { "auto" } else { "explicit" },
            kinds.join(", ")
        )
    }
}

/// How an automatic carrier choice orders, times and remembers its
/// candidates. Durations in seconds.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct CarrierChoicePolicy(pub(crate) zmux::CarrierChoicePolicy);

#[pymethods]
impl CarrierChoicePolicy {
    /// `cache` remembers outcomes across dials under `key` (`None`: a cache
    /// private to the session). A candidate's timer is the round trip of
    /// opening its carrier times `timer_factor`, within `timer_min` and
    /// `timer_max`. A joined pipe of a preferred kind stays `settle` before
    /// the pipes it replaces retire; a kind whose pipes fail within
    /// `drop_window` of being chosen counts as failed. `no_join` tries the
    /// candidates one after another instead of establishing on the most
    /// robust and joining the preferred ones (it does not apply to a pool).
    #[new]
    #[pyo3(signature = (*, cache=None, key=String::new(), timer_factor=3.0, timer_min=1.0,
        timer_max=3.0, settle=1.0, drop_window=30.0, no_join=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        cache: Option<PyRef<'_, CarrierCache>>,
        key: String,
        timer_factor: f64,
        timer_min: f64,
        timer_max: f64,
        settle: f64,
        drop_window: f64,
        no_join: bool,
    ) -> PyResult<Self> {
        let mut p = zmux::CarrierChoicePolicy::default();
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
        p.timer_min = seconds("timer_min", timer_min)?;
        p.timer_max = seconds("timer_max", timer_max)?;
        p.settle = seconds("settle", settle)?;
        p.drop_window = seconds("drop_window", drop_window)?;
        p.no_join = no_join;
        Ok(Self(p))
    }

    #[getter]
    fn key(&self) -> &str {
        &self.0.key
    }
    #[getter]
    fn timer_factor(&self) -> f64 {
        self.0.timer_factor
    }
    #[getter]
    fn timer_min(&self) -> f64 {
        self.0.timer_min.as_secs_f64()
    }
    #[getter]
    fn timer_max(&self) -> f64 {
        self.0.timer_max.as_secs_f64()
    }
    #[getter]
    fn settle(&self) -> f64 {
        self.0.settle.as_secs_f64()
    }
    #[getter]
    fn drop_window(&self) -> f64 {
        self.0.drop_window.as_secs_f64()
    }
    #[getter]
    fn no_join(&self) -> bool {
        self.0.no_join
    }
}

/// Which carrier kinds worked per server and local network, shared across
/// dials.
#[pyclass(frozen, module = "zmux")]
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

    /// Whether the carrier kind `kind` with `variant` is held as usable
    /// under `key`.
    #[pyo3(signature = (key, kind, *, variant=None))]
    fn is_usable(&self, key: &str, kind: &str, variant: Option<&str>) -> PyResult<bool> {
        Ok(self.0.is_usable(key, self::kind(kind)?, variant))
    }

    /// Whether the carrier kind `kind` with `variant` is backing off under
    /// `key`.
    #[pyo3(signature = (key, kind, *, variant=None))]
    fn is_failed(&self, key: &str, kind: &str, variant: Option<&str>) -> PyResult<bool> {
        Ok(self
            .0
            .failed_until(key, self::kind(kind)?, variant)
            .is_some())
    }

    /// Records an outcome learnt after a dial (a `CacheOutcome` or its
    /// name), under `key`, the carrier kind `kind` and the candidate's
    /// `variant`.
    #[pyo3(signature = (key, kind, outcome, *, variant=None))]
    fn report(&self, key: &str, kind: &str, outcome: &str, variant: Option<&str>) -> PyResult<()> {
        let outcome = match outcome {
            "usable" => zmux::CacheOutcome::Usable,
            "failed" => zmux::CacheOutcome::Failed,
            "rejected" => zmux::CacheOutcome::Rejected,
            o => return Err(PyValueError::new_err(format!("unknown outcome {o:?}"))),
        };
        self.0.report(key, self::kind(kind)?, variant, outcome);
        Ok(())
    }

    /// What the cache knows, as JSON text (versioned; times in RFC 3339
    /// UTC), for `restore` later, such as in the next run of the process.
    /// Expired entries are left out.
    fn snapshot(&self) -> String {
        self.0.snapshot().to_json()
    }

    /// Merges a `snapshot` into the cache: of two entries for one key, kind
    /// and variant, the newer is kept; a backoff outside this cache's bounds is
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

/// Establishes a client session over the carrier `choice` selects:
/// explicit, its one candidate; auto, the most robust candidate first, then
/// the preferred ones joined (see `CarrierChoicePolicy`). No usable
/// candidate raises `CarrierChoiceError`, an invalid choice or policy
/// `ValueError`.
#[pyfunction]
#[pyo3(signature = (choice, *, config=None, choice_policy=None))]
fn connect_choice<'p>(
    py: Python<'p>,
    choice: PyRef<'_, CarrierChoice>,
    config: Option<Bound<'p, PyAny>>,
    choice_policy: Option<PyRef<'_, CarrierChoicePolicy>>,
) -> PyResult<Bound<'p, PyAny>> {
    let config = crate::cfg(config)?;
    let policy = choice_policy.map(|p| p.0.clone()).unwrap_or_default();
    let choice = choice.0.clone();
    future_into_py(py, async move {
        match zmux::dial_choice(&choice, config, &policy).await {
            Ok(s) => Ok(Session::new(s)),
            Err(e) if e.invalid.is_some() => Err(PyValueError::new_err(e.to_string())),
            Err(e) => crate::rt::attach(|py| {
                let results = e
                    .results
                    .iter()
                    .map(|r| result_obj(r)(py))
                    .collect::<PyResult<Vec<_>>>()?;
                let t = crate::err_type(py, "CarrierChoiceError");
                Err(PyErr::from_type(t, (e.to_string(), results)))
            }),
        }
    })
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Candidate>()?;
    m.add_class::<CarrierChoice>()?;
    m.add_class::<CarrierChoicePolicy>()?;
    m.add_class::<CarrierCache>()?;
    m.add_function(wrap_pyfunction!(connect_choice, m)?)?;
    Ok(())
}
