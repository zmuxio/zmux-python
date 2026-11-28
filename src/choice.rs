//! Carrier candidates and shared scoring history.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use std::time::{Duration, SystemTime};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::Host;
use crate::ranged;

use crate::{
    ExchangeOptions, H3Dial, QuicDial, TlsConfig, WebSocketDial, WebTransportDial, hostport,
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

pub(crate) fn connect(
    addr: &str,
) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<tokio::net::TcpStream>> + Send>>
+ Send
+ Sync
+ 'static {
    let addr = addr.to_owned();
    move || Box::pin(crate::tcp_nodelay(addr.clone()))
}

/// One carrier kind a carrier choice may use; each constructor is named
/// after the `dial_*` function that opens the same carrier.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Candidate(pub(crate) zmux::Candidate);

impl Candidate {
    fn from_dial<D, F>(
        kind: zmux::CarrierKind,
        dial: D,
        open: impl Fn(D) -> F + Send + Sync + 'static,
    ) -> Self
    where
        D: Clone + Send + Sync + 'static,
        F: Future<Output = std::io::Result<zmux::PipeIo>> + Send + 'static,
    {
        Self(zmux::Candidate::new(kind, move || open(dial.clone())))
    }
}

#[pymethods]
impl Candidate {
    /// A bidirectional streaming `POST` over HTTP/1.1 to `addr` (kind
    /// `streaming`, as `dial_streaming`).
    #[staticmethod]
    #[pyo3(signature = (host, port, *, path=None, carrier_credential=None, pair_field=None))]
    fn streaming(
        host: Host,
        #[pyo3(from_py_with = ranged)] port: u16,
        path: Option<&str>,
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
    #[pyo3(signature = (host, port, *, path=None, carrier_credential=None, pair_field=None))]
    fn split(
        host: Host,
        #[pyo3(from_py_with = ranged)] port: u16,
        path: Option<&str>,
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
    fn exchange(
        host: Host,
        #[pyo3(from_py_with = ranged)] port: u16,
        options: Option<PyRef<'_, ExchangeOptions>>,
    ) -> Self {
        let o = options.map_or_else(Default::default, |o| o.0.clone());
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
        Ok(Self(
            WebSocketDial::new(&url, tls, carrier_credential, no_subprotocol)?.candidate(&url),
        ))
    }

    /// A QUIC connection to `addr`, where the client reaches the server
    /// directly (kind `quic`, as `dial_quic`).
    #[staticmethod]
    #[pyo3(signature = (host, port, *, tls=None, server_name=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
    fn quic(
        host: Host,
        #[pyo3(from_py_with = ranged)] port: u16,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        #[pyo3(from_py_with = ranged)] lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let addr = hostport(&host, port);
        let d = QuicDial::new(
            addr,
            tls,
            server_name,
            lanes,
            carrier_credential,
            zmux::adapter::DIAL_TIMEOUT,
        )?;
        Ok(Self::from_dial(
            zmux::CarrierKind::Quic,
            d,
            |d| async move { d.open().await },
        ))
    }

    /// An HTTP/3 request to `url` (`https://`), sent to `addr` when given
    /// (kind `http3`, as `dial_http3`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, addr=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
    fn http3(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        addr: Option<(Host, u16)>,
        #[pyo3(from_py_with = ranged)] lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = H3Dial::new(
            url,
            tls,
            addr,
            lanes,
            carrier_credential,
            zmux::adapter::DIAL_TIMEOUT,
        )?;
        Ok(Self::from_dial(
            zmux::CarrierKind::Http3,
            d,
            |d| async move { d.open().await },
        ))
    }

    /// A WebTransport session to `url` (`https://`; kind `webtransport`,
    /// as `dial_webtransport`).
    #[staticmethod]
    #[pyo3(signature = (url, *, tls=None, lanes=zmux_quinn::LaneWindows::default().lanes, carrier_credential=None))]
    fn webtransport(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        #[pyo3(from_py_with = ranged)] lanes: u32,
        carrier_credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let d = WebTransportDial::new(
            url,
            tls,
            lanes,
            carrier_credential,
            zmux::adapter::DIAL_TIMEOUT,
        )?;
        Ok(Self::from_dial(
            zmux::CarrierKind::WebTransport,
            d,
            |d| async move { d.open().await },
        ))
    }

    /// Registers a host opener and its exact Join carrier layout.
    #[staticmethod]
    #[pyo3(signature = (kind, *, layout, open))]
    fn custom(
        py: Python<'_>,
        kind: &str,
        layout: &Bound<'_, PyAny>,
        open: Py<PyAny>,
    ) -> PyResult<Self> {
        let kind = self::kind(kind)?;
        let layout = crate::control::layout(layout)?;
        let lp = crate::rt::LoopRef::running(py, "Candidate.custom")?;
        let opener = crate::control::opener(open, lp);
        let candidate = zmux::Candidate::new(kind, || async {
            Err(std::io::Error::other(
                "candidate requires an opener request",
            ))
        });
        Ok(Self(candidate.with_opener(layout, opener)))
    }

    /// Registers this candidate's identity and the host's cache key.
    #[pyo3(signature = (id, *, cache_key))]
    fn with_identity(&self, id: String, cache_key: &str) -> Self {
        Self(self.0.clone().with_identity(id.as_str(), cache_key))
    }

    /// Makes this candidate available for Join only.
    fn join_only(&self) -> Self {
        Self(self.0.clone().join_only())
    }

    /// Sets this candidate's tier and standby preference.
    #[pyo3(signature = (tier, *, standby=false))]
    fn with_preference(&self, tier: u64, standby: bool) -> Self {
        Self(self.0.clone().with_tier(tier).with_standby(standby))
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

/// Authority to report sequenced observations for one cache key.
#[pyclass(frozen, module = "zmux")]
struct CarrierReportSource(zmux::CarrierReportSource);

/// An application-controlled UTC clock for anchoring carrier snapshots.
#[pyclass(frozen, module = "zmux")]
struct WallClock(Arc<AtomicI64>);

#[pymethods]
impl WallClock {
    /// Starts at the supplied signed Unix timestamp in nanoseconds.
    #[new]
    fn new(timestamp_ns: i64) -> Self {
        Self(Arc::new(AtomicI64::new(timestamp_ns)))
    }

    /// Replaces the stored timestamp. The clock may move backward.
    fn set(&self, timestamp_ns: i64) {
        self.0.store(timestamp_ns, Ordering::Relaxed);
    }

    /// Returns the stored Unix timestamp in nanoseconds.
    #[getter]
    fn timestamp_ns(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

fn wall_time(nanos: i64) -> SystemTime {
    let duration = Duration::from_nanos(nanos.unsigned_abs());
    if nanos < 0 {
        SystemTime::UNIX_EPOCH - duration
    } else {
        SystemTime::UNIX_EPOCH + duration
    }
}

/// Shared scoring history and retry admission for carrier candidates.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct CarrierCache(pub(crate) zmux::CarrierCache);

fn cache_error(error: zmux::CarrierCacheError) -> PyErr {
    use zmux::CarrierCacheError as E;
    let name = match error {
        E::Version => "CarrierCacheVersionError",
        E::Format => "CarrierCacheFormatError",
        _ => "CarrierCacheValueError",
    };
    crate::new_err(name, error.to_string())
}

#[pymethods]
impl CarrierCache {
    /// Creates an empty cache with optional scoring and retry settings.
    #[new]
    #[pyo3(signature = (*, half_life=None, drop_window=None, performance_window=None,
        health_reset=None, backoff=None, retry_profile=None, kind_priors=None,
        import_limit=None, max_age=None, min_weight=0.0, clock_domain=None, wall_clock=None))]
    fn new(
        half_life: Option<f64>,
        drop_window: Option<f64>,
        performance_window: Option<f64>,
        health_reset: Option<f64>,
        backoff: Option<Bound<'_, PyAny>>,
        retry_profile: Option<&str>,
        kind_priors: Option<Bound<'_, PyDict>>,
        #[pyo3(from_py_with = crate::ranged_opt)] import_limit: Option<usize>,
        max_age: Option<f64>,
        min_weight: f64,
        clock_domain: Option<&crate::host::ClockDomain>,
        wall_clock: Option<&WallClock>,
    ) -> PyResult<Self> {
        let mut config = zmux::CarrierCacheConfig::default();
        if let Some(clock) = wall_clock {
            let timestamp = clock.0.clone();
            config = config.with_wall_clock(move || wall_time(timestamp.load(Ordering::Relaxed)));
        }
        if let Some(domain) = clock_domain {
            config.clock_domain = domain.0.clone();
        }
        for (name, input, target) in [
            ("half_life", half_life, &mut config.half_life),
            ("drop_window", drop_window, &mut config.drop_window),
            (
                "performance_window",
                performance_window,
                &mut config.performance_window,
            ),
            ("health_reset", health_reset, &mut config.health_reset),
        ] {
            if let Some(input) = input {
                *target = seconds(name, input)?;
            }
        }
        if let Some(backoff) = &backoff {
            config.backoff = crate::backoff_of(backoff)?;
        }
        match retry_profile {
            None => {}
            Some("short_drop_resilient") if backoff.is_none() => {
                config = config.with_short_drop_resilience();
            }
            Some("short_drop_resilient") => {
                return Err(PyValueError::new_err(
                    "backoff and retry_profile are mutually exclusive",
                ));
            }
            Some(_) => return Err(PyValueError::new_err("unknown cache retry profile")),
        }
        if let Some(priors) = kind_priors {
            for (key, prior) in priors.iter() {
                config
                    .kind_priors
                    .insert(kind(key.extract::<&str>()?)?, prior.extract()?);
            }
        }
        config.import_limit = import_limit;
        config.max_age = max_age.map(|v| seconds("max_age", v)).transpose()?;
        config.min_weight = min_weight;
        Ok(Self(
            zmux::CarrierCache::new(config).map_err(crate::config_err)?,
        ))
    }

    /// Reads retry pacing and suppression counters for a candidate.
    #[pyo3(signature = (key, *, kind, variant=""))]
    fn retry_metrics<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        kind: &str,
        variant: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let m = self.0.retry_metrics(key, self::kind(kind)?, variant);
        let suppressions = pyo3::types::PyDict::new(py);
        for (reason, count) in m.suppressions {
            suppressions.set_item(crate::helpers::snake(&crate::kind_of(&reason)), count)?;
        }
        crate::types(py)?.getattr("RetryMetrics")?.call1((
            m.attempted_starts,
            m.recovery_nominal.as_secs_f64(),
            m.recovery_sampled.as_secs_f64(),
            crate::host::at(py, m.recovery_retry_at)?,
            m.faults,
            suppressions,
            crate::dur(m.elapsed),
            m.remaining.as_secs_f64(),
        ))
    }

    /// Reads the decayed score, observations and current cooldown.
    #[pyo3(signature = (key, *, kind, variant=""))]
    fn score<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        kind: &str,
        variant: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let score = self.0.score(key, self::kind(kind)?, variant);
        let types = crate::types(py)?;
        let cooldown = score
            .cooldown
            .map(|value| {
                types.getattr("Cooldown")?.call1((
                    value.reason.map(|v| crate::kind_of(&v)),
                    crate::host::at(py, value.started_at)?,
                    value.nominal_wait.as_secs_f64(),
                    crate::dur(value.sampled_wait),
                    crate::monotonic(py, value.retry_at)?,
                    value.remaining.as_secs_f64(),
                ))
            })
            .transpose()?;
        types.getattr("CarrierScore")?.call1((
            score.score,
            score.attempts,
            score.weight,
            score.success_weight,
            score.window_survived,
            score.short_drops,
            score.post_window_faults,
            crate::dur(score.age),
            cooldown,
            score.post_window_seconds,
            measurement(py, score.rtt)?,
            measurement(py, score.rate)?,
        ))
    }

    /// Registers an independent sequence space for observations of one carrier key.
    #[pyo3(signature = (key, *, kind, variant=""))]
    fn register_report_source(
        &self,
        key: &str,
        kind: &str,
        variant: &str,
    ) -> PyResult<CarrierReportSource> {
        Ok(CarrierReportSource(self.0.register_report_source(
            key,
            self::kind(kind)?,
            variant,
        )))
    }

    /// Applies a typed observation once. Returns whether the observation was new.
    #[pyo3(signature = (source, *, sequence, outcome, observation=None))]
    fn report(
        &self,
        source: &CarrierReportSource,
        #[pyo3(from_py_with = ranged)] sequence: u64,
        outcome: &str,
        observation: Option<Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        use zmux::CacheOutcome as O;
        let outcome = match outcome {
            "usable" => O::Usable,
            "failed" => O::Failed,
            "rejected" => O::Rejected,
            "survived" => O::Survived,
            "short_drop" => O::ShortDrop,
            "late_drop" => O::LateDrop,
            "lifetime" => O::Lifetime,
            "performance" => O::Performance,
            "recovered" => O::Recovered,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "unknown cache outcome {outcome:?}"
                )));
            }
        };
        let mut sample = zmux::CarrierObservation::default();
        if let Some(value) = observation {
            sample.at = value
                .getattr("at")?
                .extract::<Option<f64>>()?
                .map(|v| crate::host::instant(value.py(), "at", v))
                .transpose()?;
            sample.duration = crate::field_secs("duration", &value.getattr("duration")?)?;
            sample.rtt = crate::field_secs("rtt", &value.getattr("rtt")?)?;
            sample.rate = crate::field_count("rate", &value.getattr("rate")?)?;
            sample.valid_for = crate::field_secs("valid_for", &value.getattr("valid_for")?)?;
        }
        self.0
            .report_from(&source.0, sequence, outcome, sample)
            .map_err(cache_error)
    }

    /// Exports the versioned cache snapshot as UTF-8 JSON bytes.
    fn export(&self, py: Python<'_>) -> PyResult<crate::rt::Bin> {
        py.detach(|| self.0.export())
            .map(crate::rt::Bin::from)
            .map_err(cache_error)
    }

    /// Validates and atomically merges a snapshot in the shared v2 format.
    fn import_snapshot(
        &self,
        py: Python<'_>,
        snapshot: &Bound<'_, pyo3::types::PyBytes>,
    ) -> PyResult<()> {
        let snapshot = snapshot.as_bytes();
        py.detach(|| self.0.import(snapshot)).map_err(cache_error)
    }
}

fn measurement(
    py: Python<'_>,
    value: Option<zmux::CarrierMeasurement>,
) -> PyResult<Option<Bound<'_, PyAny>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let source = match value.source {
        Some(zmux::CarrierMeasurementSource::Protocol) => Some("protocol"),
        Some(zmux::CarrierMeasurementSource::HostReport) => Some("host_report"),
        _ => None,
    };
    let types = crate::types(py)?;
    let source = source
        .map(|source| types.getattr("CarrierMeasurementSource")?.call1((source,)))
        .transpose()?;
    types
        .getattr("CarrierMeasurement")?
        .call1((
            value.value,
            value.age.as_secs_f64(),
            value.valid_for.as_secs_f64(),
            source,
        ))
        .map(Some)
}

pub(crate) fn kind(name: &str) -> PyResult<zmux::CarrierKind> {
    zmux::CarrierKind::from_name(name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown carrier kind {name:?}")))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Candidate>()?;
    m.add_class::<CarrierCache>()?;
    m.add_class::<CarrierReportSource>()?;
    m.add_class::<WallClock>()?;
    Ok(())
}
