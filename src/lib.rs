//! PyO3 bindings over the zmux Rust crates. Every I/O operation runs on the
//! tokio runtime owned by `pyo3-async-runtimes`; Python awaits futures that
//! resolve on its asyncio loop. No protocol logic lives here.

use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use pyo3::exceptions::{
    PyException, PyRuntimeError, PyStopAsyncIteration, PyTypeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use pyo3::{IntoPyObjectExt, create_exception};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};

mod admission;
mod helpers;
mod layer;
mod mode;
mod pool;
mod rt;
mod shaping;
use admission::Admission;
use rt::{future_into_py, get_runtime};

create_exception!(_zmux, ZmuxError, PyException, "Base of every zmux error.");
create_exception!(
    _zmux,
    ConnectError,
    ZmuxError,
    "Establishing a session failed."
);
create_exception!(_zmux, SessionClosed, ZmuxError, "The session ended.");
create_exception!(
    _zmux,
    EarlyDataRejected,
    ZmuxError,
    "The peer processed none of the early data; retry on a new session without it."
);
create_exception!(_zmux, StreamError, ZmuxError, "A stream operation failed.");
create_exception!(
    _zmux,
    StreamReset,
    StreamError,
    "The peer reset the stream."
);
create_exception!(
    _zmux,
    StreamStopped,
    StreamError,
    "The peer stopped reading the stream."
);
create_exception!(
    _zmux,
    IncompleteRead,
    StreamError,
    "The stream finished before the requested bytes arrived."
);
create_exception!(
    _zmux,
    LimitExceeded,
    StreamError,
    "The stream is longer than the read limit."
);
create_exception!(_zmux, ListenerClosed, ZmuxError, "The listener was closed.");
create_exception!(_zmux, OpenError, ZmuxError, "Opening a stream failed.");
create_exception!(
    _zmux,
    DatagramError,
    ZmuxError,
    "Sending a datagram failed."
);
create_exception!(_zmux, PipeError, ZmuxError, "A pipe operation failed.");
create_exception!(
    _zmux,
    PreambleTooLargeError,
    PyValueError,
    "A stream's preamble is larger than the limit known: the peer's Maximum Preamble Size (before its parameters the remembered one or 1024 bytes), at most 4096."
);

// ---- errors ---------------------------------------------------------------------------

fn kind_of(e: &impl Debug) -> String {
    let s = format!("{e:?}");
    s.split(['(', ' ', '{']).next().unwrap_or("").to_owned()
}

/// Builds an exception of `T` with the attributes `kind`, `retryable` and `code`.
fn raise<T: pyo3::PyTypeInfo>(
    e: &(impl Debug + Display),
    retryable: bool,
    code: Option<u64>,
) -> PyErr {
    rt::attach(|py| {
        let err = PyErr::new::<T, _>(e.to_string());
        let v = err.value(py);
        let _ = v.setattr("kind", typed(py, "ErrorKind", kind_of(e)));
        let _ = v.setattr("retryable", retryable);
        let _ = v.setattr("code", code);
        err
    })
}

/// A `zmux._types` enum member for `v`, or `v` itself when unknown.
fn typed<'p>(py: Python<'p>, enum_name: &str, v: String) -> Bound<'p, PyAny> {
    types(py)
        .and_then(|t| t.getattr(enum_name)?.call_method1("_of", (&v,)))
        .unwrap_or_else(|_| v.into_pyobject(py).unwrap().into_any())
}

fn types(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    py.import("zmux._types")
}

fn session_err(e: zmux::SessionError) -> PyErr {
    use zmux::SessionError as E;
    let (code, reason, remote) = match &e {
        E::ApplicationClosed {
            code,
            reason,
            remote,
        } => (Some(code.into_inner()), Some(reason.clone()), Some(*remote)),
        E::TransportClosed {
            code,
            reason,
            remote,
            ..
        } => (Some(code.0), Some(reason.clone()), Some(*remote)),
        E::IdleTimeout { remote } => (None, None, Some(*remote)),
        _ => (None, None, None),
    };
    let err = if e.is_early_data_rejected() {
        raise::<EarlyDataRejected>(&e, e.is_retryable(), code)
    } else {
        raise::<SessionClosed>(&e, e.is_retryable(), code)
    };
    rt::attach(|py| {
        let v = err.value(py);
        let _ = v.setattr("reason", reason.map(|r| PyBytes::new(py, &r)));
        let _ = v.setattr("remote", remote);
    });
    err
}

fn stream_err(e: zmux::StreamError) -> PyErr {
    match &e {
        zmux::StreamError::Reset { code, .. } => {
            raise::<StreamReset>(&e, e.is_retryable(), Some(code.into_inner()))
        }
        zmux::StreamError::Stopped(code) => {
            raise::<StreamStopped>(&e, e.is_retryable(), Some(code.into_inner()))
        }
        zmux::StreamError::SessionLost(s) => session_err(s.clone()),
        zmux::StreamError::PreambleTooLarge => PreambleTooLargeError::new_err(e.to_string()),
        _ => raise::<StreamError>(&e, e.is_retryable(), None),
    }
}

fn open_err(e: zmux::OpenError) -> PyErr {
    match e {
        zmux::OpenError::SessionLost(s) => session_err(s),
        zmux::OpenError::PreambleTooLarge => PreambleTooLargeError::new_err(e.to_string()),
        e => raise::<OpenError>(&e, e.is_retryable(), None),
    }
}

fn datagram_err(e: zmux::DatagramError) -> PyErr {
    match e {
        zmux::DatagramError::SessionLost(s) => session_err(s),
        e => raise::<DatagramError>(&e, e.is_retryable(), None),
    }
}

fn pipe_err(e: zmux::PipeError) -> PyErr {
    match e {
        zmux::PipeError::SessionLost(s) => session_err(s),
        // The language's existing argument error (API.md Section 6).
        zmux::PipeError::InvalidOptions => PyValueError::new_err(e.to_string()),
        e => raise::<PipeError>(&e, e.is_retryable(), None),
    }
}

fn connect_err(e: zmux::ConnectError) -> PyErr {
    match e {
        zmux::ConnectError::Closed(s) => session_err(s),
        e => raise::<ConnectError>(&e, e.is_retryable(), None),
    }
}

fn io_err(e: std::io::Error) -> PyErr {
    let err = raise::<ConnectError>(&e, false, None);
    rt::attach(|py| {
        let _ = err
            .value(py)
            .setattr("kind", typed(py, "ErrorKind", "Io".into()));
    });
    err
}

fn pyb(b: &[u8]) -> Py<PyBytes> {
    rt::attach(|py| PyBytes::new(py, b).unbind())
}

fn busy() -> PyErr {
    PyRuntimeError::new_err("another operation on this stream is in progress")
}

// ---- configuration --------------------------------------------------------------------

/// Session configuration from the fields of `zmux.Config`: a field left
/// out, or `None`, keeps the Rust default; an unknown field raises
/// `TypeError`.
#[pyclass(frozen, module = "zmux._zmux")]
#[derive(Clone)]
struct Config(Arc<zmux::Config>);

/// A non-negative duration of the field `name` in seconds.
fn field_secs(name: &str, v: &Bound<'_, PyAny>) -> PyResult<Duration> {
    seconds(name, v.extract()?)
}

/// A timer or period in seconds; `None` is no timeout or off.
fn field_opt_secs(name: &str, v: &Bound<'_, PyAny>) -> PyResult<Option<Duration>> {
    if v.is_none() {
        return Ok(None);
    }
    field_secs(name, v).map(Some)
}

/// A memory budget in bytes; `math.inf` is unlimited.
fn field_budget(name: &str, v: &Bound<'_, PyAny>) -> PyResult<zmux::Budget> {
    if v.is_instance_of::<pyo3::types::PyFloat>() {
        if v.extract::<f64>()? == f64::INFINITY {
            return Ok(zmux::Budget::Unlimited);
        }
        return Err(PyValueError::new_err(format!(
            "{name} is a non-negative integer or math.inf"
        )));
    }
    natural(name, v).map(zmux::Budget::Bytes)
}

/// A cap: `None` is auto (the caller skips it), a value fixes it.
fn field_cap(v: &Bound<'_, PyAny>) -> PyResult<zmux::Cap> {
    Ok(zmux::Cap::Fixed(v.extract()?))
}

/// The scheduling policy of a name.
fn policy(name: &str) -> PyResult<zmux::Policy> {
    Ok(match name {
        "affinity" => zmux::Policy::Affinity,
        "session-affinity" => zmux::Policy::SessionAffinity,
        "spread-eta" => zmux::Policy::SpreadEta,
        "spread-round-robin" => zmux::Policy::SpreadRoundRobin,
        "spread-rate-weighted" => zmux::Policy::SpreadRateWeighted,
        _ => {
            return Err(PyValueError::new_err(format!("unknown scheduler {name:?}")));
        }
    })
}

/// The join credentials of a `zmux.PipeAuth`.
fn pipe_auth(v: &Bound<'_, PyAny>) -> PyResult<zmux::PipeAuth> {
    let tls: bool = v.getattr("_tls")?.extract()?;
    let insecure: bool = v.getattr("_insecure")?.extract()?;
    let psk: Option<Vec<u8>> = v.getattr("_psk")?.extract()?;
    let base = match (tls, insecure) {
        (true, _) => zmux::PipeAuth::tls(),
        (false, true) => zmux::PipeAuth::insecure(),
        (false, false) => zmux::PipeAuth::none(),
    };
    Ok(match psk {
        Some(k) => base.with_psk(k),
        None => base,
    })
}

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (**fields))]
    fn new(fields: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut c = zmux::Config::default();
        let mut early = zmux::EarlyData::default();
        for (k, v) in fields.into_iter().flatten() {
            let k: String = k.extract()?;
            // None is no timeout or off for the timers and periods, unset
            // (the default) for every other field.
            match k.as_str() {
                "handshake_timeout" => c.handshake_timeout = field_opt_secs(&k, &v)?,
                "max_idle_timeout" => c.max_idle_timeout = field_opt_secs(&k, &v)?,
                "keep_alive_period" => c.keep_alive_period = field_opt_secs(&k, &v)?,
                "standby_probe" => c.standby_probe = field_opt_secs(&k, &v)?,
                "probe_interval" => c.probe_interval = field_opt_secs(&k, &v)?,
                _ => {}
            }
            if v.is_none() {
                continue;
            }
            let v = &v;
            match k.as_str() {
                "handshake_timeout" | "max_idle_timeout" | "keep_alive_period"
                | "standby_probe" | "probe_interval" => {}
                "initial_stream_receive_window" => c.initial_stream_receive_window = v.extract()?,
                "max_stream_receive_window" => c.max_stream_receive_window = field_cap(v)?,
                "latency_budget" => c.latency_budget = field_secs(&k, v)?,
                "initial_connection_receive_window" => {
                    c.initial_connection_receive_window = v.extract()?;
                }
                "max_connection_receive_window" => {
                    c.max_connection_receive_window = field_cap(v)?;
                }
                "memory_budget" => c.memory_budget = Some(field_budget(&k, v)?),
                "max_incoming_streams" => c.max_incoming_streams = v.extract()?,
                "max_incoming_uni_streams" => c.max_incoming_uni_streams = Some(v.extract()?),
                "enable_datagrams" => c.enable_datagrams = v.extract()?,
                "datagram_send_queue" => c.datagram_send_queue = v.extract()?,
                "datagram_receive_queue" => c.datagram_receive_queue = v.extract()?,
                "datagram_stream_queue" => c.datagram_stream_queue = v.extract()?,
                "datagram_receive_bytes" => c.datagram_receive_bytes = v.extract()?,
                "send_buffer" => c.send_buffer = v.extract()?,
                "send_buffer_max" => c.send_buffer_max = field_cap(v)?,
                "max_pipes" => c.max_pipes = v.extract()?,
                "pipe_headroom" => c.pipe_headroom = v.extract()?,
                "replay_window" => c.replay_window = Some(v.extract()?),
                "max_lanes" => {
                    c.max_lanes = std::num::NonZeroU64::new(v.extract()?)
                        .ok_or_else(|| PyValueError::new_err("max_lanes is at least 1"))?;
                }
                "resume_timeout" => {
                    let d = field_secs(&k, v)?;
                    c.resume_timeout = (!d.is_zero()).then_some(d);
                }
                "scheduler" => c.scheduler = policy(&v.extract::<String>()?)?,
                "spread_chunk" => c.spread_chunk = v.extract()?,
                "suspect_floor" => c.suspect_floor = field_secs(&k, v)?,
                "dead_timeout" => c.dead_timeout = Some(field_secs(&k, v)?),
                "probation" => c.probation = Some(field_secs(&k, v)?),
                "overflow_delay" => c.overflow_delay = field_secs(&k, v)?,
                "probe_jitter" => c.probe_jitter = v.extract()?,
                "redundancy" => {
                    c.redundancy = match v.extract::<String>()?.as_str() {
                        "urgent" => zmux::Redundancy::Urgent,
                        "off" => zmux::Redundancy::Off,
                        r => {
                            return Err(PyValueError::new_err(format!(
                                "redundancy is \"urgent\" or \"off\", not {r:?}"
                            )));
                        }
                    };
                }
                "pipe_auth" => c.pipe_auth = pipe_auth(v)?,
                "early_data" => early.zmux_peer = v.extract()?,
                "carrier_early_data" => early.carrier_early_data = v.extract()?,
                "protocols" => c.protocols = Some(v.extract()?),
                "shaping_limits" => c.shaping_limits = shaping::session_limits(v)?,
                "shaping" => {
                    let f = shaping::by_kind(v, &zmux_shaping::Options::default())?;
                    c.shaper = Some(Arc::new(f));
                }
                _ => return Err(PyTypeError::new_err(format!("unknown Config field {k:?}"))),
            }
        }
        c.early_data = early;
        Ok(Config(Arc::new(c)))
    }
}

/// The native configuration of a `zmux.Config` (or of this class itself).
fn cfg(c: Option<Bound<'_, PyAny>>) -> PyResult<Arc<zmux::Config>> {
    let Some(c) = c else {
        return Ok(Arc::default());
    };
    let n = if c.is_instance_of::<Config>() {
        c
    } else {
        c.getattr("_native")?
    };
    Ok(n.extract::<PyRef<'_, Config>>()?.0.clone())
}

/// TLS settings for the TLS and QUIC carriers (rustls). PEM `str` arguments are
/// file paths, `bytes` arguments are PEM contents.
#[pyclass(frozen, module = "zmux._zmux")]
#[derive(Clone)]
struct TlsConfig {
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    ca: Option<Vec<u8>>,
    verify: bool,
    alpn: Vec<Vec<u8>>,
}

#[derive(FromPyObject)]
enum Pem {
    Path(std::path::PathBuf),
    Data(Vec<u8>),
}

impl Pem {
    fn load(self) -> PyResult<Vec<u8>> {
        match self {
            Pem::Path(p) => std::fs::read(&p)
                .map_err(|e| PyValueError::new_err(format!("{}: {e}", p.display()))),
            Pem::Data(d) => Ok(d),
        }
    }
}

/// zmux's ALPN identifiers.
fn zmux_alpn() -> Vec<Vec<u8>> {
    zmux::alpn_protocols(&[])
}

/// HTTP/1.1's ALPN identifier.
fn http1() -> Vec<Vec<u8>> {
    vec![HTTP1.to_vec()]
}

fn pem_err(e: impl Display) -> PyErr {
    PyValueError::new_err(format!("invalid PEM: {e}"))
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

type Chain = (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
);

impl TlsConfig {
    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn chain(&self) -> PyResult<Option<Chain>> {
        use rustls::pki_types::pem::PemObject;
        let (Some(cert), Some(key)) = (&self.cert, &self.key) else {
            return Ok(None);
        };
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(pem_err)?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key).map_err(pem_err)?;
        Ok(Some((certs, key)))
    }

    fn client(&self) -> PyResult<rustls::ClientConfig> {
        use rustls::pki_types::pem::PemObject;
        let builder = rustls::ClientConfig::builder_with_provider(Self::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let builder = if !self.verify {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(Self::provider())))
        } else {
            let mut roots = rustls::RootCertStore::empty();
            match &self.ca {
                Some(ca) => {
                    for c in rustls::pki_types::CertificateDer::pem_slice_iter(ca) {
                        roots
                            .add(c.map_err(pem_err)?)
                            .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            builder.with_root_certificates(roots)
        };
        let mut c = match self.chain()? {
            Some((certs, key)) => builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
            None => builder.with_no_client_auth(),
        };
        c.alpn_protocols = self.alpn.clone();
        Ok(c)
    }

    /// The client configuration with `defaults` when no ALPN is set.
    fn client_alpn(
        &self,
        defaults: impl FnOnce() -> Vec<Vec<u8>>,
    ) -> PyResult<rustls::ClientConfig> {
        let mut c = self.client()?;
        zmux::default_alpn(&mut c.alpn_protocols, defaults);
        Ok(c)
    }

    /// The server configuration with `defaults` when no ALPN is set.
    fn server_alpn(
        &self,
        defaults: impl FnOnce() -> Vec<Vec<u8>>,
    ) -> PyResult<rustls::ServerConfig> {
        let mut c = self.server()?;
        zmux::default_alpn(&mut c.alpn_protocols, defaults);
        Ok(c)
    }

    /// The client configuration of a zmux carrier: zmux's ALPN
    /// identifiers when none is set.
    fn client_zmux(&self) -> PyResult<rustls::ClientConfig> {
        self.client_alpn(zmux_alpn)
    }

    /// The server configuration of a zmux carrier: zmux's ALPN
    /// identifiers when none is set.
    fn server_zmux(&self) -> PyResult<rustls::ServerConfig> {
        self.server_alpn(zmux_alpn)
    }

    /// Verification against the bundled web roots, no client certificate.
    fn web() -> Self {
        TlsConfig {
            cert: None,
            key: None,
            ca: None,
            verify: true,
            alpn: Vec::new(),
        }
    }

    fn server(&self) -> PyResult<rustls::ServerConfig> {
        let (certs, key) = self
            .chain()?
            .ok_or_else(|| PyValueError::new_err("a server needs cert and key"))?;
        let mut c = rustls::ServerConfig::builder_with_provider(Self::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| PyValueError::new_err(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        c.alpn_protocols = self.alpn.clone();
        Ok(c)
    }
}

#[pymethods]
impl TlsConfig {
    #[new]
    #[pyo3(signature = (*, cert=None, key=None, ca=None, verify=true, alpn=None))]
    fn new(
        cert: Option<Pem>,
        key: Option<Pem>,
        ca: Option<Pem>,
        verify: bool,
        alpn: Option<Vec<String>>,
    ) -> PyResult<Self> {
        Ok(TlsConfig {
            cert: cert.map(Pem::load).transpose()?,
            key: key.map(Pem::load).transpose()?,
            ca: ca.map(Pem::load).transpose()?,
            verify,
            alpn: alpn
                .unwrap_or_default()
                .into_iter()
                .map(String::into_bytes)
                .collect(),
        })
    }
}

// ---- pipes ----------------------------------------------------------------------------

/// A carrier's unsent count that the application keeps up to date
/// (`set`), typically at each write to the carrier; the session reads it
/// from its driver without the interpreter lock (`PipeIo.with_unsent`).
#[pyclass(frozen, module = "zmux._zmux")]
struct UnsentCount(Arc<std::sync::atomic::AtomicU64>);

impl UnsentCount {
    /// `None` is stored as `u64::MAX`.
    fn decode(c: &std::sync::atomic::AtomicU64) -> Option<u64> {
        match c.load(std::sync::atomic::Ordering::Relaxed) {
            u64::MAX => None,
            n => Some(n),
        }
    }
}

#[pymethods]
impl UnsentCount {
    /// A count of `n` bytes, `None` (the default) when the carrier cannot
    /// tell.
    #[new]
    #[pyo3(signature = (n=None))]
    fn new(n: Option<u64>) -> Self {
        Self(Arc::new(std::sync::atomic::AtomicU64::new(
            n.map_or(u64::MAX, |n| n.min(u64::MAX - 1)),
        )))
    }

    /// Sets the count: the bytes the carrier took and has not yet
    /// transmitted, or `None`.
    #[pyo3(signature = (n))]
    fn set(&self, n: Option<u64>) {
        self.0.store(
            n.map_or(u64::MAX, |n| n.min(u64::MAX - 1)),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// The count as last set.
    #[getter]
    fn value(&self) -> Option<u64> {
        Self::decode(&self.0)
    }
}

/// A carrier connection not yet given to a session; usable once.
#[pyclass(frozen, module = "zmux._zmux")]
struct PipeIo(StdMutex<Option<zmux::PipeIo>>);

impl PipeIo {
    fn wrap(io: zmux::PipeIo) -> Self {
        PipeIo(StdMutex::new(Some(io)))
    }
    fn take(&self) -> PyResult<zmux::PipeIo> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("pipe already used"))
    }
}

#[pymethods]
impl PipeIo {
    /// This carrier labelled with carrier kind `kind` (a `CarrierKind` or
    /// its name): what a by-kind shaper picks by, and the kind in pipe
    /// events and statistics. This object is used up.
    fn with_carrier(&self, kind: &Bound<'_, PyAny>) -> PyResult<PipeIo> {
        let k = shaping::carrier_kind(kind)?;
        Ok(PipeIo::wrap(self.take()?.with_carrier(k)))
    }

    /// This carrier with an unsent count: `count` holds the bytes the
    /// carrier took and has not yet transmitted, or `None` when it cannot
    /// tell, as the application last set it. The session's driver reads it
    /// without the interpreter lock. This object is used up.
    fn with_unsent(&self, count: &UnsentCount) -> PyResult<PipeIo> {
        let c = count.0.clone();
        let io = self.take()?.with_unsent(move || UnsentCount::decode(&c));
        Ok(PipeIo::wrap(io))
    }

    /// This carrier with a write overhead: the fixed bytes (0 to 65535)
    /// the layers below zmux add to each write on it, such as a wrapping
    /// layer's record header and tag, which a shaper takes into account.
    /// zmux does not otherwise use it. This object is used up.
    fn with_write_overhead(&self, overhead: i64) -> PyResult<PipeIo> {
        let n = u16::try_from(overhead)
            .map_err(|_| PyValueError::new_err("write_overhead is between 0 and 65535"))?;
        Ok(PipeIo::wrap(self.take()?.with_write_overhead(n)))
    }

    /// The carrier's halves as one byte stream (`CarrierStream`), for a
    /// layer that runs over a stream; bytes a listener already read from it
    /// come first. Every other property of the carrier is dropped (`wrap`
    /// keeps them). This object is used up.
    #[allow(clippy::wrong_self_convention)] // Python's name; the object is used up
    fn into_stream(&self) -> PyResult<layer::CarrierStream> {
        Ok(layer::CarrierStream::new(self.take()?.into_stream()))
    }

    /// Runs a layer over the carrier: `layer(reader, writer)`, given the
    /// carrier as an asyncio stream pair, returns the layer's pair (for
    /// example after `writer.start_tls(...)`), which becomes the carrier's
    /// halves. The carrier keeps its framing, kind and other properties.
    /// Each write on the result is one write on the layer's writer, then a
    /// drain, so that a layer that writes once below for each write on it
    /// (asyncio's TLS does) keeps one carrier write per write. With
    /// `server_side`, `writer.start_tls` takes the server side. This object
    /// is used up; needs a running event loop, on which the layer runs.
    #[pyo3(name = "wrap", signature = (layer, *, server_side=false))]
    fn wrap_layer<'p>(
        &self,
        py: Python<'p>,
        layer: Py<PyAny>,
        server_side: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
        let io = self.take()?;
        future_into_py(py, async move {
            let io = layer::wrap(io, layer, server_side, locals)
                .await
                .map_err(io_err)?;
            Ok(PipeIo::wrap(io))
        })
    }

    /// The carrier kind's name, or `None`.
    #[getter]
    fn carrier(&self) -> PyResult<Option<&'static str>> {
        let g = self.0.lock().unwrap();
        let io = g
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("pipe already used"))?;
        Ok(io.carrier().map(zmux::CarrierKind::name))
    }
}

/// The far end of `pipe_pair()`: bytes written here are what the pipe reads.
#[pyclass(frozen, module = "zmux._zmux")]
struct PipeEnd {
    r: Arc<Mutex<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    w: Arc<Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
}

#[pymethods]
impl PipeEnd {
    /// Up to `n` bytes the session wrote; `b""` once the session side closed.
    #[pyo3(signature = (n=65536))]
    fn read<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let r = self.r.clone();
        future_into_py(py, async move {
            let mut buf = vec![0u8; n];
            let k = r.lock().await.read(&mut buf).await.unwrap_or(0);
            buf.truncate(k);
            Ok(pyb(&buf))
        })
    }
    /// Feeds `data` to the session; `b""` signals end of input.
    fn write<'p>(&self, py: Python<'p>, data: Vec<u8>) -> PyResult<Bound<'p, PyAny>> {
        let w = self.w.clone();
        future_into_py(py, async move {
            let mut w = w.lock().await;
            let r = if data.is_empty() {
                w.shutdown().await
            } else {
                w.write_all(&data).await
            };
            r.map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }
}

/// An in-memory pipe whose other end Python drives (the stream-pair entry).
/// `carrier`: the pipe's carrier kind (`PipeIo.with_carrier`).
#[pyfunction]
#[pyo3(signature = (*, carrier=None))]
fn pipe_pair(carrier: Option<Bound<'_, PyAny>>) -> PyResult<(PipeIo, PipeEnd)> {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (r, w) = tokio::io::split(b);
    let mut io = zmux::PipeIo::new(a);
    if let Some(k) = carrier {
        io = io.with_carrier(shaping::carrier_kind(&k)?);
    }
    Ok((
        PipeIo::wrap(io),
        PipeEnd {
            r: Arc::new(Mutex::new(r)),
            w: Arc::new(Mutex::new(w)),
        },
    ))
}

async fn resolve(addr: &str) -> PyResult<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await
        .map_err(io_err)?
        .next()
        .ok_or_else(|| PyValueError::new_err("no address"))
}

/// [`resolve`] inside a carrier's dial, where errors are I/O errors.
async fn lookup(addr: &str) -> std::io::Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address"))
}

#[pyfunction]
#[pyo3(signature = (addr, *, credential=None))]
fn dial_tcp<'p>(
    py: Python<'p>,
    addr: String,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let credential = admission::credential(credential)?;
    future_into_py(py, async move {
        let mut tcp = tokio::net::TcpStream::connect(addr).await.map_err(io_err)?;
        if let Some(c) = credential {
            let prefix = {
                let mut info = zmux::CarrierInfo::new();
                if let Ok(peer) = tcp.peer_addr() {
                    info = info.with_source(peer).with_peer(peer);
                }
                c.prefix(&info).map_err(io_err)?
            };
            tcp.write_all(&prefix).await.map_err(io_err)?;
        }
        Ok(PipeIo::wrap(zmux::PipeIo::tcp(tcp)))
    })
}

/// The client TLS settings, by default the bundled web roots.
fn client_tls(tls: Option<PyRef<'_, TlsConfig>>) -> TlsConfig {
    tls.map_or_else(TlsConfig::web, |t| t.clone())
}

#[pyfunction]
#[pyo3(signature = (addr, *, tls=None, server_name=None, credential=None))]
fn dial_tls<'p>(
    py: Python<'p>,
    addr: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    server_name: Option<String>,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let c = Arc::new(client_tls(tls).client_zmux()?);
    let server_name = server_name.unwrap_or_else(|| host_of(&addr));
    let credential = admission::credential(credential)?;
    future_into_py(py, async move {
        let io = zmux_rustls::dial(addr, &server_name, c, credential.as_deref()).await;
        Ok(PipeIo::wrap(io.map_err(io_err)?))
    })
}

fn quic_options(lanes: u32) -> zmux_quinn::Options {
    zmux_quinn::Options::default().with_windows(zmux_quinn::LaneWindows::new().with_lanes(lanes))
}

/// How a QUIC carrier to one server is opened: by `dial_quic`, and by
/// every dial of `Candidate.quic`.
#[derive(Clone)]
pub(crate) struct QuicDial {
    addr: String,
    server_name: String,
    qc: quinn::ClientConfig,
    opts: zmux_quinn::Options,
}

impl QuicDial {
    pub(crate) fn new(
        addr: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        lanes: u32,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut opts = quic_options(lanes);
        if let Some(c) = admission::credential(credential)? {
            opts = opts.with_credential(c);
        }
        let server_name = server_name.unwrap_or_else(|| host_of(&addr));
        let qc = zmux_quinn::client_config(client_tls(tls).client_zmux()?, &opts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            addr,
            server_name,
            qc,
            opts,
        })
    }

    /// A pipe on a new connection, from an endpoint of its own.
    pub(crate) async fn open(&self) -> std::io::Result<zmux::PipeIo> {
        let addr = lookup(&self.addr).await?;
        let mut ep = quinn::Endpoint::client(bind_for(&addr))?;
        ep.set_default_client_config(self.qc.clone());
        zmux_quinn::dial(&ep, addr, &self.server_name, &self.opts).await
    }
}

#[pyfunction]
#[pyo3(signature = (addr, *, tls=None, server_name=None, lanes=4, credential=None))]
fn dial_quic<'p>(
    py: Python<'p>,
    addr: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    server_name: Option<String>,
    lanes: u32,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let d = QuicDial::new(addr, tls, server_name, lanes, credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(d.open().await.map_err(io_err)?))
    })
}

fn value_err(e: impl Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

const HTTP1: &[u8] = b"http/1.1";

/// `ws://` or `wss://` (TLS with `tls`, by default the bundled web roots);
/// `headers` are added to the upgrade request, for example the
/// `Zmux-Pipe-Join` header of a `PipeReservation`, and the credential's
/// header field.
#[pyfunction]
#[pyo3(signature = (url, *, tls=None, headers=None, credential=None))]
fn dial_websocket<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    headers: Option<Bound<'p, PyAny>>,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let mut opts = zmux_websocket::Options::default();
    if let Some(c) = admission::credential(credential)? {
        opts = opts.with_credential(c);
    }
    let headers: Option<Vec<(String, String)>> = match headers {
        Some(h) if h.hasattr("items")? => Some(
            py.import("builtins")?
                .getattr("list")?
                .call1((h.call_method0("items")?,))?
                .extract()?,
        ),
        Some(h) => Some(h.extract()?),
        None => None,
    };
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
    let mut req = url.as_str().into_client_request().map_err(value_err)?;
    for (k, v) in headers.unwrap_or_default() {
        req.headers_mut().insert(
            HeaderName::from_bytes(k.as_bytes()).map_err(value_err)?,
            HeaderValue::from_str(&v).map_err(value_err)?,
        );
    }
    let connector = if req.uri().scheme_str() == Some("wss") {
        let c = match tls {
            Some(t) => t.client_alpn(http1)?,
            None => TlsConfig::web().client_alpn(http1)?,
        };
        Some(tokio_rustls::TlsConnector::from(Arc::new(c)))
    } else {
        None
    };
    future_into_py(py, async move {
        let io = match connector {
            Some(c) => zmux_websocket::dial_tls(req, &c, &opts).await,
            None => zmux_websocket::dial(req, &opts).await,
        }
        .map_err(io_err)?;
        Ok(PipeIo::wrap(io))
    })
}

/// An HTTP/2 connection whose exchanges carry pipes: prior knowledge
/// without `tls`, ALPN `h2` with it.
#[pyclass(frozen, module = "zmux._zmux")]
struct Http2Connection(zmux_http::Http2Connection);

#[pymethods]
impl Http2Connection {
    #[staticmethod]
    #[pyo3(signature = (addr, *, path="/zmux".to_owned(), tls=None, server_name=None, credential=None))]
    fn connect<'p>(
        py: Python<'p>,
        addr: String,
        path: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
        credential: Option<Bound<'p, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts = http_client_options(path, credential)?;
        let tls = tls
            .map(|t| t.client_alpn(|| vec![b"h2".to_vec()]))
            .transpose()?
            .map(|c| tokio_rustls::TlsConnector::from(Arc::new(c)));
        future_into_py(py, async move {
            let conn = match tls {
                None => zmux_http::Http2Connection::connect(&addr, opts).await,
                Some(c) => {
                    let host = server_name.unwrap_or_else(|| host_of(&addr));
                    let name = rustls::pki_types::ServerName::try_from(host).map_err(value_err)?;
                    let tcp = tokio::net::TcpStream::connect(&addr)
                        .await
                        .map_err(io_err)?;
                    let _ = tcp.set_nodelay(true);
                    let io = c.connect(name, tcp).await.map_err(io_err)?;
                    zmux_http::Http2Connection::handshake(io, &addr, opts).await
                }
            }
            .map_err(io_err)?;
            Ok(Http2Connection(conn))
        })
    }

    /// A pipe on a new exchange of the connection.
    fn open_pipe<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let c = self.0.clone();
        future_into_py(py, async move {
            Ok(PipeIo::wrap(c.open_pipe().await.map_err(io_err)?))
        })
    }

    /// A carrier of `carrier`'s direction on a new request (see `dial_http`).
    #[pyo3(signature = (carrier="bidirectional", join=None))]
    fn open_carrier<'p>(
        &self,
        py: Python<'p>,
        carrier: &str,
        join: Option<String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let request = dial_request(carrier, join)?;
        let c = self.0.clone();
        future_into_py(py, async move {
            Ok(PipeIo::wrap(
                c.open_carrier(&request).await.map_err(io_err)?,
            ))
        })
    }

    /// A split bootstrap on two new requests of the connection.
    fn open_split<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let c = self.0.clone();
        future_into_py(py, async move {
            Ok(PipeIo::wrap(c.open_split().await.map_err(io_err)?))
        })
    }

    /// Joins a split carrier on two new requests of the connection to
    /// `session` as two further pipes (see `join_http_split`).
    #[pyo3(signature = (session, *, options=None))]
    fn join_split<'p>(
        &self,
        py: Python<'p>,
        session: &Session,
        options: Option<Bound<'p, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let po = pipe_options(options)?;
        let (c, s) = (self.0.clone(), session.0.clone());
        future_into_py(py, async move {
            let pipes = c.join_split(&s, po).await.map_err(io_err)?;
            Ok(pipes.into_iter().map(Pipe).collect::<Vec<_>>())
        })
    }
}

/// The host part of `host:port`, without IPv6 brackets.
fn host_of(addr: &str) -> String {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned()
}

fn bind_for(addr: &SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// The `host:port` of an `https://` URL.
fn authority_of(uri: &http::Uri) -> PyResult<String> {
    let host = uri
        .host()
        .ok_or_else(|| PyValueError::new_err("URL without a host"))?;
    Ok(format!("{host}:{}", uri.port_u16().unwrap_or(443)))
}

/// How an HTTP/3 carrier is opened: a request to `url` (`https://`) on a
/// new connection to `addr` when given, else to the URL's host and port;
/// by `dial_h3`, and by every dial of `Candidate.http3`.
#[derive(Clone)]
pub(crate) struct H3Dial {
    uri: http::Uri,
    addr: String,
    qc: quinn::ClientConfig,
    opts: zmux_h3::Options,
}

impl H3Dial {
    pub(crate) fn new(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        addr: Option<String>,
        lanes: u32,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let uri: http::Uri = url.parse().map_err(value_err)?;
        let addr = match addr {
            Some(a) => a,
            None => authority_of(&uri)?,
        };
        let mut opts =
            zmux_h3::Options::new().with_windows(zmux_h3::LaneWindows::new().with_lanes(lanes));
        if let Some(c) = admission::credential(credential)? {
            opts = opts.with_credential(c);
        }
        let qc = zmux_h3::client_config(client_tls(tls).client()?, &opts).map_err(value_err)?;
        Ok(Self {
            uri,
            addr,
            qc,
            opts,
        })
    }

    /// A pipe on a new connection, from an endpoint of its own.
    pub(crate) async fn open(&self) -> std::io::Result<zmux::PipeIo> {
        let addr = lookup(&self.addr).await?;
        let mut ep = quinn::Endpoint::client(bind_for(&addr))?;
        ep.set_default_client_config(self.qc.clone());
        zmux_h3::dial(&ep, addr, self.uri.clone(), &self.opts).await
    }
}

/// A pipe on a new HTTP/3 connection: a request to `url` (`https://`),
/// to `addr` when given, else to the URL's host and port.
#[pyfunction]
#[pyo3(signature = (url, *, tls=None, addr=None, lanes=4, credential=None))]
fn dial_h3<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    addr: Option<String>,
    lanes: u32,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let d = H3Dial::new(url, tls, addr, lanes, credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(d.open().await.map_err(io_err)?))
    })
}

use zmux_webtransport::web_transport_quinn as wt;

/// How a WebTransport carrier is opened: a session to `url` (`https://`),
/// on a new QUIC connection to the URL's host, whose exporter a bound
/// credential is given; by `dial_webtransport`, and by every dial of
/// `Candidate.webtransport`.
#[derive(Clone)]
pub(crate) struct WebTransportDial {
    url: zmux_webtransport::Url,
    host: String,
    authority: String,
    qc: quinn::ClientConfig,
    opts: zmux_webtransport::Options,
}

impl WebTransportDial {
    pub(crate) fn new(
        url: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        lanes: u32,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let url: zmux_webtransport::Url = url.parse().map_err(value_err)?;
        let host = url
            .host_str()
            .ok_or_else(|| PyValueError::new_err("URL without a host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let authority = format!(
            "{}:{}",
            url.host_str().unwrap_or_default(),
            url.port_or_known_default().unwrap_or(443)
        );
        let mut opts = zmux_webtransport::Options::new()
            .with_windows(zmux_webtransport::LaneWindows::new().with_lanes(lanes));
        if let Some(c) = admission::credential(credential)? {
            opts = opts.with_credential(c);
        }
        let mut c = client_tls(tls).client()?;
        c.alpn_protocols = vec![wt::ALPN.as_bytes().to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(c).map_err(value_err)?;
        let mut qc = quinn::ClientConfig::new(Arc::new(crypto));
        qc.transport_config(Arc::new(opts.transport_config()));
        Ok(Self {
            url,
            host,
            authority,
            qc,
            opts,
        })
    }

    /// A pipe on a new connection, from an endpoint of its own.
    pub(crate) async fn open(&self) -> std::io::Result<zmux::PipeIo> {
        let addr = lookup(&self.authority).await?;
        let ep = quinn::Endpoint::client(bind_for(&addr))?;
        let conn = ep
            .connect_with(self.qc.clone(), addr, &self.host)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .await
            .map_err(std::io::Error::other)?;
        zmux_webtransport::dial_over(conn, self.url.clone(), &self.opts).await
    }
}

/// A pipe on a new WebTransport session to `url` (`https://`), on a QUIC
/// connection to the URL's host, whose exporter a bound credential is
/// given.
#[pyfunction]
#[pyo3(signature = (url, *, tls=None, lanes=4, credential=None))]
fn dial_webtransport<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    lanes: u32,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let d = WebTransportDial::new(url, tls, lanes, credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(d.open().await.map_err(io_err)?))
    })
}

/// A QUIC client endpoint kept across connections, so that TLS sessions
/// resume; with `zero_rtt` it remembers each server's parameters and
/// sends a session's first records as 0-RTT data when the session's
/// `Config(carrier_early_data=True)` allows it.
#[pyclass(frozen, module = "zmux._zmux")]
struct QuicClient {
    ep: quinn::Endpoint,
    opts: zmux_quinn::Options,
    memory: Option<zmux_quinn::ParameterMemory>,
}

#[pymethods]
impl QuicClient {
    #[new]
    #[pyo3(signature = (tls=None, *, lanes=4, zero_rtt=false, memory_capacity=None, bind="0.0.0.0:0".to_owned(), credential=None))]
    fn new(
        tls: Option<PyRef<'_, TlsConfig>>,
        lanes: u32,
        zero_rtt: bool,
        memory_capacity: Option<usize>,
        bind: String,
        credential: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let memory = zero_rtt.then(|| match memory_capacity {
            Some(n) => zmux_quinn::ParameterMemory::with_capacity(n),
            None => zmux_quinn::ParameterMemory::new(),
        });
        let mut opts = quic_options(lanes);
        if let Some(m) = &memory {
            opts = opts.with_zero_rtt(m.clone());
        }
        if let Some(c) = admission::credential(credential)? {
            opts = opts.with_credential(c);
        }
        let qc =
            zmux_quinn::client_config(client_tls(tls).client_zmux()?, &opts).map_err(value_err)?;
        let bind: SocketAddr = bind.parse().map_err(value_err)?;
        let _g = get_runtime().enter();
        let mut ep = quinn::Endpoint::client(bind).map_err(io_err)?;
        ep.set_default_client_config(qc);
        Ok(QuicClient { ep, opts, memory })
    }

    /// A pipe on a new connection.
    #[pyo3(signature = (addr, *, server_name=None))]
    fn dial<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        server_name: Option<String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let server_name = server_name.unwrap_or_else(|| host_of(&addr));
        let (ep, opts) = (self.ep.clone(), self.opts.clone());
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            Ok(PipeIo::wrap(
                zmux_quinn::dial(&ep, addr, &server_name, &opts)
                    .await
                    .map_err(io_err)?,
            ))
        })
    }

    /// A session on a new connection, with what became of its 0-RTT data:
    /// `(Session, ZeroRtt)`.
    #[pyo3(signature = (addr, *, server_name=None, config=None))]
    fn connect<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        server_name: Option<String>,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let (ep, opts, c) = (self.ep.clone(), self.opts.clone(), cfg(config)?);
        let server_name = server_name.unwrap_or_else(|| host_of(&addr));
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let (s, z) = zmux_quinn::connect_with_report(&ep, addr, &server_name, &opts, c)
                .await
                .map_err(connect_err)?;
            rt::attach(|py| Ok(Session(s, Some(Py::new(py, ZeroRtt(z))?))))
        })
    }

    /// Forgets the parameters remembered for `server_name`, for example
    /// after `EarlyDataRejected`.
    fn forget(&self, server_name: &str) {
        if let Some(m) = &self.memory {
            m.forget(server_name);
        }
    }

    /// Forgets every remembered server.
    fn clear(&self) {
        if let Some(m) = &self.memory {
            m.clear();
        }
    }

    /// Whether parameters are remembered for `server_name`.
    fn remembers(&self, server_name: &str) -> bool {
        self.memory
            .as_ref()
            .is_some_and(|m| m.get(server_name).is_some())
    }
}

/// What became of a session's 0-RTT data.
#[pyclass(frozen, module = "zmux._zmux")]
struct ZeroRtt(zmux_quinn::ZeroRtt);

#[pymethods]
impl ZeroRtt {
    #[getter]
    fn sent(&self) -> bool {
        self.0.sent()
    }
    /// `None` while unknown or when none was sent.
    #[getter]
    fn accepted(&self) -> Option<bool> {
        self.0.accepted()
    }
    #[getter]
    fn rewritten(&self) -> bool {
        self.0.rewritten()
    }
}

/// A client's HTTP options: `path`, and the credential whose prefix goes
/// first on each request body. The adapter does not see the TLS layer, so
/// a credential bound to it is refused here.
fn http_client_options(
    path: String,
    credential: Option<Bound<'_, PyAny>>,
) -> PyResult<zmux_http::Options> {
    let mut opts = zmux_http::Options::new().with_path(path);
    if let Some(c) = &credential
        && c.cast::<admission::PrefixAuth>()
            .is_ok_and(|p| p.get().binds_tls())
    {
        return Err(PyValueError::new_err(
            "HTTP carriers take tokens without bind_tls",
        ));
    }
    if let Some(c) = admission::credential(credential)? {
        opts = opts.with_credential(c);
    }
    Ok(opts)
}

/// The direction of an HTTP carrier: `bidirectional` (a `POST` whose
/// bodies carry both directions), `uplink` (a `POST` whose request body is
/// the only direction) or `downlink` (a `GET` whose response body is), with
/// the `Zmux-Pipe-Join` value of a reservation.
fn dial_request(carrier: &str, join: Option<String>) -> PyResult<zmux::DialRequest> {
    let dir = match carrier {
        "bidirectional" => zmux::PipeDirection::Bidi,
        "uplink" => zmux::PipeDirection::Out,
        "downlink" => zmux::PipeDirection::In,
        c => return Err(PyValueError::new_err(format!("unknown HTTP carrier {c:?}"))),
    };
    Ok(zmux::DialRequest::new(dir, join))
}

#[pyfunction]
#[pyo3(signature = (addr, *, path="/zmux".to_owned(), credential=None, carrier="bidirectional", join=None))]
fn dial_http<'p>(
    py: Python<'p>,
    addr: String,
    path: String,
    credential: Option<Bound<'p, PyAny>>,
    carrier: &str,
    join: Option<String>,
) -> PyResult<Bound<'p, PyAny>> {
    let opts = http_client_options(path, credential)?;
    let request = dial_request(carrier, join)?;
    future_into_py(py, async move {
        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(io_err)?;
        let _ = tcp.set_nodelay(true);
        Ok(PipeIo::wrap(
            zmux_http::dial_http1_carrier_over(tcp, &addr, &opts, &request)
                .await
                .map_err(io_err)?,
        ))
    })
}

/// A split bootstrap over two HTTP/1.1 connections: an uplink `POST` and
/// a downlink `GET` paired by a fresh token.
#[pyfunction]
#[pyo3(signature = (addr, *, path="/zmux".to_owned(), credential=None))]
fn dial_http_split<'p>(
    py: Python<'p>,
    addr: String,
    path: String,
    credential: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let opts = http_client_options(path, credential)?;
    future_into_py(py, async move {
        Ok(PipeIo::wrap(
            zmux_http::dial_http1_split(&addr, &opts)
                .await
                .map_err(io_err)?,
        ))
    })
}

/// Joins a split carrier over two HTTP/1.1 connections to `session` as
/// two further pipes with `options`: a downlink `GET` joined out of band
/// and an uplink `POST` joined in band, opened at once; returns
/// `[downlink, uplink]` once both joins are confirmed (a split bootstrap's
/// carrier joins no session). A `PipePool(join=...)` keeps such pairs up.
#[pyfunction]
#[pyo3(signature = (session, addr, *, path="/zmux".to_owned(), credential=None, options=None))]
fn join_http_split<'p>(
    py: Python<'p>,
    session: &Session,
    addr: String,
    path: String,
    credential: Option<Bound<'p, PyAny>>,
    options: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let opts = http_client_options(path, credential)?;
    let po = pipe_options(options)?;
    let s = session.0.clone();
    future_into_py(py, async move {
        let connect = || async {
            let tcp = tokio::net::TcpStream::connect(&addr).await?;
            let _ = tcp.set_nodelay(true);
            Ok::<_, std::io::Error>(tcp)
        };
        let pipes = zmux_http::join_http1_split_with(&s, connect, &addr, &opts, po)
            .await
            .map_err(io_err)?;
        Ok(pipes.into_iter().map(Pipe).collect::<Vec<_>>())
    })
}

/// The HTTP exchange carrier's options, for `dial_exchange` and
/// `Listener.serve_http(exchange=...)`.
#[pyclass(frozen, module = "zmux._zmux")]
struct ExchangeOptions(zmux_http::ExchangeOptions);

#[pymethods]
impl ExchangeOptions {
    #[new]
    #[pyo3(signature = (*, psk=None, unauthenticated=false, encoding="binary", path=None, down_path=None, query=None,
        down_requests=None, up_requests=None, up_piece=None, max_down_piece=None,
        backoff_initial=None, backoff_max=None, request_timeout=None, deadline=None, hold=None,
        coalesce=None, down_piece=None, down_window=None, max_up_piece=None, up_store=None,
        idle_timeout=None, gone_memory=None, max_carriers=None, time_window=None, max_recorded=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        psk: Option<Vec<u8>>,
        unauthenticated: bool,
        encoding: &str,
        path: Option<String>,
        down_path: Option<String>,
        query: Option<String>,
        down_requests: Option<usize>,
        up_requests: Option<usize>,
        up_piece: Option<usize>,
        max_down_piece: Option<usize>,
        backoff_initial: Option<f64>,
        backoff_max: Option<f64>,
        request_timeout: Option<f64>,
        deadline: Option<f64>,
        hold: Option<f64>,
        coalesce: Option<f64>,
        down_piece: Option<usize>,
        down_window: Option<u64>,
        max_up_piece: Option<usize>,
        up_store: Option<usize>,
        idle_timeout: Option<f64>,
        gone_memory: Option<f64>,
        max_carriers: Option<usize>,
        time_window: Option<f64>,
        max_recorded: Option<usize>,
    ) -> PyResult<Self> {
        let mut o = zmux_http::ExchangeOptions::new();
        o.encoding = match encoding {
            "binary" => zmux_http::BodyEncoding::Binary,
            "base64" => zmux_http::BodyEncoding::Base64,
            e => return Err(PyValueError::new_err(format!("unknown encoding {e:?}"))),
        };
        o.unauthenticated = unauthenticated;
        o.down_path = down_path;
        o.max_carriers = max_carriers;
        macro_rules! set {
            ($($f:ident),*) => { $(if let Some(v) = $f { o.$f = v; })* };
        }
        set!(
            psk,
            path,
            query,
            down_requests,
            up_requests,
            down_window,
            up_store,
            max_recorded
        );
        // Unset piece sizes follow the encoding (default_piece_size).
        o.up_piece = up_piece;
        o.max_down_piece = max_down_piece;
        o.down_piece = down_piece;
        o.max_up_piece = max_up_piece;
        macro_rules! set_secs {
            ($($f:ident),*) => { $(if let Some(v) = $f { o.$f = seconds(stringify!($f), v)?; })* };
        }
        set_secs!(
            request_timeout,
            deadline,
            hold,
            coalesce,
            idle_timeout,
            gone_memory,
            time_window
        );
        if let Some(v) = backoff_initial {
            o.backoff.initial = seconds("backoff_initial", v)?;
        }
        if let Some(v) = backoff_max {
            o.backoff.max = seconds("backoff_max", v)?;
        }
        Ok(ExchangeOptions(o))
    }

    #[getter]
    fn encoding(&self) -> &'static str {
        match self.0.encoding {
            zmux_http::BodyEncoding::Base64 => "base64",
            _ => "binary",
        }
    }
    #[getter]
    fn path(&self) -> &str {
        &self.0.path
    }
    #[getter]
    fn down_path(&self) -> Option<&str> {
        self.0.down_path.as_deref()
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// An endpoint of the exchange carrier: plain TCP, or TLS whose ALPN
/// chooses `http/1.1`.
fn exchange_endpoint(
    addr: String,
    tls: Option<&tokio_rustls::TlsConnector>,
    server_name: Option<&str>,
) -> PyResult<zmux_http::ExchangeEndpoint> {
    let Some(tls) = tls.cloned() else {
        return Ok(zmux_http::ExchangeEndpoint::tcp(&addr));
    };
    let host = server_name.map_or_else(|| host_of(&addr), str::to_owned);
    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(value_err)?;
    let port = addr.rsplit_once(':').map_or("443", |(_, p)| p);
    let authority = if port == "443" {
        host
    } else {
        format!("{host}:{port}")
    };
    Ok(zmux_http::ExchangeEndpoint::new(
        move || {
            let (tls, name, addr) = (tls.clone(), name.clone(), addr.clone());
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                let _ = tcp.set_nodelay(true);
                tls.connect(name, tcp).await
            }
        },
        &authority,
    ))
}

/// An exchange carrier: HTTP/1.1 requests to `addr` (and DOWN requests to
/// `down_addr` when given), over TLS with `tls`; with `credential`, its
/// prefix starts the uplink, for a server's admission.
#[pyfunction]
#[pyo3(signature = (addr, *, options=None, down_addr=None, tls=None, server_name=None,
    credential=None))]
fn dial_exchange<'p>(
    py: Python<'p>,
    addr: String,
    options: Option<PyRef<'_, ExchangeOptions>>,
    down_addr: Option<String>,
    tls: Option<PyRef<'_, TlsConfig>>,
    server_name: Option<String>,
    credential: Option<Bound<'_, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let mut opts = options.map(|o| o.0.clone()).unwrap_or_default();
    if let Some(c) = admission::credential(credential)? {
        opts = opts.with_credential(c);
    }
    let tls = tls
        .map(|t| t.client_alpn(http1))
        .transpose()?
        .map(|c| tokio_rustls::TlsConnector::from(Arc::new(c)));
    let up = exchange_endpoint(addr, tls.as_ref(), server_name.as_deref())?;
    let down = match down_addr {
        Some(d) => exchange_endpoint(d, tls.as_ref(), server_name.as_deref())?,
        None => up.clone(),
    };
    future_into_py(py, async move {
        Ok(PipeIo::wrap(
            zmux_http::dial_exchange_split(up, down, &opts).map_err(value_err)?,
        ))
    })
}

// ---- session --------------------------------------------------------------------------

fn preamble(
    info: Option<Vec<u8>>,
    tlvs: Option<Vec<(u64, Vec<u8>)>>,
    pipe_carrier: bool,
) -> Option<zmux::Preamble> {
    if info.is_none() && tlvs.as_ref().is_none_or(Vec::is_empty) && !pipe_carrier {
        return None;
    }
    let mut p = zmux::Preamble::new();
    if pipe_carrier {
        p = p.with_pipe_carrier();
    }
    if let Some(i) = info {
        p = p.with_info(i);
    }
    for (t, v) in tlvs.unwrap_or_default() {
        p = p.with_tlv(t, v);
    }
    Some(p)
}

/// The priorities `open_bi` sets on the parts it opened.
struct Prios(Option<zmux::Priority>, Option<zmux::Priority>);

impl Prios {
    fn new(local: Option<(u8, bool)>, peer: Option<(u8, bool)>) -> PyResult<Self> {
        let p = |v: Option<(u8, bool)>| v.map(|(u, i)| priority(u, i)).transpose();
        Ok(Prios(p(local)?, p(peer)?))
    }
    fn apply(&self, (send, recv): &(zmux::SendStream, zmux::RecvStream)) -> PyResult<()> {
        if let Some(p) = self.0 {
            send.set_priority(p).map_err(stream_err)?;
        }
        if let Some(p) = self.1 {
            recv.set_peer_priority(p).map_err(stream_err)?;
        }
        Ok(())
    }
}

/// A `zmux.QualityBand`.
fn quality_band(b: &Bound<'_, PyAny>) -> PyResult<zmux::QualityBand> {
    Ok(zmux::QualityBand {
        rtt: seconds("rtt", b.getattr("rtt")?.extract()?)?,
        rate_ratio: b.getattr("rate_ratio")?.extract()?,
        min_interval: seconds("min_interval", b.getattr("min_interval")?.extract()?)?,
    })
}

/// A `zmux.CapacityFloor`.
fn capacity_floor(f: &Bound<'_, PyAny>) -> PyResult<zmux::CapacityFloor> {
    Ok(zmux::CapacityFloor {
        rate: f.getattr("rate")?.extract()?,
        rate_ratio: f.getattr("rate_ratio")?.extract()?,
    })
}

fn priority(urgency: u8, incremental: bool) -> PyResult<zmux::Priority> {
    zmux::Priority::new(urgency, incremental)
        .ok_or_else(|| PyValueError::new_err("urgency out of range"))
}

fn varint(v: u64) -> PyResult<zmux::VarInt> {
    zmux::VarInt::from_u64(v).map_err(|_| PyValueError::new_err("code exceeds 2**62-1"))
}

/// A zmux session. Cheap handle; the session runs on the binding's runtime.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct Session(pub(crate) zmux::Session, Option<Py<ZeroRtt>>);

impl Session {
    pub(crate) fn new(s: zmux::Session) -> Self {
        Session(s, None)
    }
}

fn start<'p>(
    py: Python<'p>,
    pipe: &PipeIo,
    config: Option<Bound<'_, PyAny>>,
    how: u8,
) -> PyResult<Bound<'p, PyAny>> {
    let io = pipe.take()?;
    let c = cfg(config)?;
    future_into_py(py, async move {
        let s = match how {
            0 => zmux::Session::connect(io, c).await,
            1 => zmux::Session::accept(io, c).await,
            _ => zmux::Session::peer(io, c).await,
        };
        s.map(Session::new).map_err(connect_err)
    })
}

fn bi(py: Python<'_>, (s, r): (zmux::SendStream, zmux::RecvStream)) -> PyResult<Py<PyTuple>> {
    Ok(PyTuple::new(
        py,
        [
            SendStream::wrap(s).into_py_any(py)?,
            RecvStream::wrap(r).into_py_any(py)?,
        ],
    )?
    .unbind())
}

#[pymethods]
impl Session {
    /// Establishes a session as the dialling side of `pipe`.
    #[staticmethod]
    #[pyo3(signature = (pipe, config=None))]
    fn connect<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 0)
    }
    /// Establishes a single-pipe session as the accepting side of `pipe`.
    #[staticmethod]
    #[pyo3(signature = (pipe, config=None))]
    fn accept<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 1)
    }
    /// Establishes a session over a symmetric carrier; roles are negotiated.
    #[staticmethod]
    #[pyo3(signature = (pipe, config=None))]
    fn peer<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 2)
    }

    /// The value the listener's admission gave the carrier that started
    /// the session (`Verdict.accept(value=...)`; a split bootstrap's
    /// uplink's), for the session's lifetime; `None` without one and on a
    /// client.
    #[getter]
    fn admitted(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        admission::admitted_obj(py, self.0.admitted().as_ref())
    }

    #[pyo3(signature = (*, info=None, tlvs=None, pipe_carrier=false, priority=None, peer_priority=None))]
    fn open_bi<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        pipe_carrier: bool,
        priority: Option<(u8, bool)>,
        peer_priority: Option<(u8, bool)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, pipe_carrier);
        let prios = Prios::new(priority, peer_priority)?;
        future_into_py(py, async move {
            let pair = match p {
                Some(p) => s.open_bi_with(&p).await,
                None => s.open_bi().await,
            }
            .map_err(open_err)?;
            prios.apply(&pair)?;
            rt::attach(|py| bi(py, pair))
        })
    }

    /// Opens a bidirectional stream if stream credit is available now;
    /// `OpenError` otherwise. Never waits.
    #[pyo3(signature = (*, info=None, tlvs=None, pipe_carrier=false, priority=None, peer_priority=None))]
    fn try_open_bi(
        &self,
        py: Python<'_>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        pipe_carrier: bool,
        priority: Option<(u8, bool)>,
        peer_priority: Option<(u8, bool)>,
    ) -> PyResult<Py<PyTuple>> {
        let prios = Prios::new(priority, peer_priority)?;
        let pair = match preamble(info, tlvs, pipe_carrier) {
            Some(p) => self.0.try_open_bi_with(&p),
            None => self.0.try_open_bi(),
        }
        .map_err(open_err)?;
        prios.apply(&pair)?;
        bi(py, pair)
    }

    /// Opens a carrier stream (PIPE_CARRIER) for a nested session, with the
    /// application TLVs `tlvs`.
    #[pyo3(signature = (tlvs=None))]
    fn open_pipe_stream<'p>(
        &self,
        py: Python<'p>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(None, tlvs, false).unwrap_or_default();
        future_into_py(py, async move {
            s.open_pipe_stream(&p)
                .await
                .map(PipeIo::wrap)
                .map_err(open_err)
        })
    }

    /// The default quality band of the session's pipes (`None`: no
    /// reports).
    fn set_quality_band(&self, band: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        self.0
            .set_quality_band(band.map(|b| quality_band(&b)).transpose()?)
            .map_err(pipe_err)
    }

    /// The floor under the session's outbound capacity (`None`: none).
    fn set_capacity_floor(&self, floor: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        self.0
            .set_capacity_floor(floor.map(|f| capacity_floor(&f)).transpose()?)
            .map_err(pipe_err)
    }

    #[pyo3(signature = (*, info=None, tlvs=None, priority=None))]
    fn open_uni<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        priority: Option<(u8, bool)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs, false);
        let prio = priority.map(|(u, i)| self::priority(u, i)).transpose()?;
        future_into_py(py, async move {
            let send = match p {
                Some(p) => s.open_uni_with(&p).await,
                None => s.open_uni().await,
            }
            .map_err(open_err)?;
            if let Some(pr) = prio {
                send.set_priority(pr).map_err(stream_err)?;
            }
            Ok(SendStream::wrap(send))
        })
    }

    fn accept_bi<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let pair = s.accept_bi().await.map_err(session_err)?;
            rt::attach(|py| bi(py, pair))
        })
    }

    fn accept_uni<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            Ok(RecvStream::wrap(s.accept_uni().await.map_err(session_err)?))
        })
    }

    fn send_datagram(&self, data: Vec<u8>) -> PyResult<()> {
        self.0
            .send_datagram(Bytes::from(data))
            .map_err(datagram_err)
    }

    fn read_datagram<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            s.read_datagram()
                .await
                .map(|b| pyb(&b))
                .map_err(session_err)
        })
    }

    #[getter]
    fn max_datagram_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }

    /// Closes at once with an application error code.
    #[pyo3(signature = (code=0, reason=b"".to_vec()))]
    fn close(&self, code: u64, reason: Vec<u8>) -> PyResult<()> {
        self.0.close(varint(code)?, &reason);
        Ok(())
    }

    /// Graceful shutdown: GOAWAY, then close once the streams ended.
    #[pyo3(signature = (code=0, reason=b"".to_vec()))]
    fn shutdown<'p>(
        &self,
        py: Python<'p>,
        code: u64,
        reason: Vec<u8>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let code = varint(code)?;
        future_into_py(py, async move {
            s.shutdown(code, &reason).await.map_err(session_err)
        })
    }

    /// Waits for the end of the session; returns a `CloseInfo`.
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let e = s.closed().await;
            rt::attach(|py| {
                let v = session_err(e).into_value(py).into_bound(py);
                let info = types(py)?.getattr("CloseInfo")?.call1((
                    v.getattr("code")?,
                    v.getattr("reason")?,
                    v.getattr("remote")?,
                    &v,
                ))?;
                Ok(info.unbind())
            })
        })
    }

    fn ping<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            s.ping().await.map(|d| d.as_secs_f64()).map_err(session_err)
        })
    }

    /// The next session event, or `None` once the session ended.
    fn next_event<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            match s.next_event().await {
                Some(e) => rt::attach(|py| event_obj(py, &e).map(Some)),
                None => Ok(None),
            }
        })
    }

    /// Session events as an async iterator.
    fn events(&self) -> EventStream {
        EventStream(self.0.clone())
    }

    /// Received datagrams as an async iterator.
    fn datagrams(&self) -> DatagramStream {
        DatagramStream(self.0.clone())
    }

    /// Shapes every outbound pipe by the definition in `json` or in the
    /// sequence form `sequence`, bounded by `limits` and drawing from a
    /// generator seeded by `seed` (tests); neither: no shaping.
    #[pyo3(signature = (*, json=None, sequence=None, by_kind=None, limits=None, seed=None))]
    fn set_shaper(
        &self,
        json: Option<&str>,
        sequence: Option<&str>,
        by_kind: Option<Bound<'_, PyAny>>,
        limits: Option<Bound<'_, PyAny>>,
        seed: Option<Vec<u8>>,
    ) -> PyResult<()> {
        let o = shaping::options(limits.as_ref(), seed)?;
        let f = match (json, sequence, by_kind) {
            (Some(j), None, None) => zmux_shaping::MachineFactory::from_json(j.as_bytes(), o),
            (None, Some(q), None) => zmux_shaping::MachineFactory::from_sequence(q, o),
            (None, None, Some(m)) => {
                self.0.set_shaper(Some(Arc::new(shaping::by_kind(&m, &o)?)));
                return Ok(());
            }
            (None, None, None) => {
                self.0.set_shaper(None);
                return Ok(());
            }
            _ => {
                return Err(PyValueError::new_err(
                    "at most one of json, sequence and by_kind",
                ));
            }
        };
        let f = f.map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.0.set_shaper(Some(Arc::new(f)));
        Ok(())
    }

    /// The shaping counters of the session.
    fn shaping_stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = self.0.shaping_stats();
        let d = PyDict::new(py);
        d.set_item("padding_bytes", st.padding_bytes)?;
        d.set_item("injected", st.injected)?;
        d.set_item("inject_dropped", st.inject_dropped)?;
        d.set_item("clamped", st.clamped)?;
        d.set_item("pause_total", st.pause_total.as_secs_f64())?;
        d.set_item("faults", st.faults)?;
        Ok(d.into_any())
    }

    /// A statistics snapshot.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = self.0.stats();
        let d = PyDict::new(py);
        macro_rules! put {
            ($($f:ident),*) => { $(d.set_item(stringify!($f), st.$f)?;)* };
        }
        put!(
            bytes_sent,
            bytes_received,
            records_sent,
            records_received,
            bytes_written,
            bytes_read,
            datagram_bytes_sent,
            datagram_bytes_received,
            streams_opened_local,
            streams_opened_remote,
            streams_active,
            stream_credit_waits,
            datagrams_sent,
            datagrams_received,
            datagrams_sent_channel,
            datagrams_received_channel,
            datagrams_dropped_send,
            datagrams_dropped_recv,
            datagrams_dropped_limit,
            no_effect_budget,
            bytes_reinjected,
            bytes_opportunistic,
            penalties,
            reinjections,
            bytes_redundant,
            bytes_duplicate_received,
            send_buffered,
            recv_buffered,
            retained,
            pipes_active,
            pipes_added,
            pipe_failures,
            join_auth_failures,
            join_replays,
            join_refusals,
            suspensions,
            scheduler_answers,
            scheduler_fallbacks
        );
        d.set_item("smoothed_rtt", dur(st.smoothed_rtt))?;
        d.set_item("min_rtt", dur(st.min_rtt))?;
        d.set_item("latest_rtt", dur(st.latest_rtt))?;
        d.set_item("mean_deviation", dur(st.mean_deviation))?;
        d.set_item("suspended_time", st.suspended_time.as_secs_f64())?;
        d.set_item("carrier", st.carrier.map(|k| k.name()))?;
        let tries = st
            .carrier_candidates
            .iter()
            .map(mode::result_obj)
            .map(|r| r(py))
            .collect::<PyResult<Vec<_>>>()?;
        d.set_item("carrier_candidates", tries)?;
        types(py)?.getattr("SessionStats")?.call((), Some(&d))
    }

    /// How the transport's 0-RTT went, for sessions from `QuicClient.connect`.
    #[getter]
    fn zero_rtt(&self, py: Python<'_>) -> Option<Py<ZeroRtt>> {
        self.1.as_ref().map(|z| z.clone_ref(py))
    }

    /// Adds a carrier as a further pipe (multipath); returns at once.
    #[pyo3(signature = (pipe, *, options=None))]
    fn add_pipe(&self, pipe: &PipeIo, options: Option<Bound<'_, PyAny>>) -> PyResult<Pipe> {
        let o = pipe_options(options)?;
        self.0.add_pipe(pipe.take()?, o).map(Pipe).map_err(pipe_err)
    }

    /// Keeps `pool`'s pipes up (dials, redials with backoff, rotation
    /// make before break, its policy's decisions) until the handle is
    /// stopped or collected or the session ends; needs a running event loop.
    fn maintain_pipes(
        &self,
        py: Python<'_>,
        pool: PyRef<'_, pool::PipePool>,
    ) -> PyResult<pool::MaintainHandle> {
        pool::maintain(py, self, &pool)
    }

    /// Reserves a pipe for an out-of-band join: send `header` with the
    /// carrier's request (`Zmux-Pipe-Join`), then `attach` the carrier.
    /// `direction` is "in", "out" or "bidi".
    #[pyo3(signature = (direction="bidi", *, options=None))]
    fn reserve_pipe(
        &self,
        direction: &str,
        options: Option<Bound<'_, PyAny>>,
    ) -> PyResult<PipeReservation> {
        let dir = match direction {
            "in" => zmux::PipeDirection::In,
            "out" => zmux::PipeDirection::Out,
            "bidi" => zmux::PipeDirection::Bidi,
            _ => return Err(PyValueError::new_err("direction is in, out or bidi")),
        };
        let o = pipe_options(options)?;
        let r = self.0.reserve_pipe(dir, o).map_err(pipe_err)?;
        Ok(PipeReservation(StdMutex::new(Some(r))))
    }

    /// Whether a pipe added now would join at once rather than wait.
    #[getter]
    fn join_ready(&self) -> bool {
        self.0.join_ready()
    }

    /// Revalidates every live outbound pipe after a network change.
    fn revalidate_pipes(&self) -> PyResult<()> {
        self.0.revalidate_pipes().map_err(pipe_err)
    }

    fn pipes(&self) -> Vec<Pipe> {
        self.0.pipes().into_iter().map(Pipe).collect()
    }

    fn pipe_stats<'p>(&self, py: Python<'p>) -> PyResult<Vec<Bound<'p, PyAny>>> {
        self.0
            .pipe_stats()
            .iter()
            .map(|s| stats_dict(py, s))
            .collect()
    }

    #[getter]
    fn role<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        typed(py, "Role", format!("{:?}", self.0.role()).to_lowercase())
    }
    #[getter]
    fn rtt(&self) -> Option<f64> {
        self.0.rtt().map(|d| d.as_secs_f64())
    }
    #[getter]
    fn protocol(&self) -> Option<String> {
        self.0.protocol()
    }
    #[getter]
    fn is_plain_qmux_peer(&self) -> bool {
        self.0.is_plain_qmux_peer()
    }
    #[getter]
    fn state<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        typed(py, "SessionState", kind_of(&self.0.state()))
    }
    /// What became of the session's early data.
    #[getter]
    fn early_data<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        typed(py, "EarlyDataState", kind_of(&self.0.early_data()))
    }

    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        _t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        self.0.close(zmux::VarInt::from_u32(0), b"");
        future_into_py(py, async move { Ok(false) })
    }
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    /// Iterates accepted bidirectional streams until the session ends.
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            match s.accept_bi().await {
                Ok(pair) => rt::attach(|py| bi(py, pair)),
                Err(_) => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

/// The state of a direction, by its type's name (`OutboundState` or
/// `InboundState` in Python).
fn direction_state(s: zmux::DirectionState) -> String {
    match s {
        zmux::DirectionState::Outbound(o) => kind_of(&o),
        zmux::DirectionState::Inbound(i) => kind_of(&i),
    }
}

fn dur(d: Option<Duration>) -> Option<f64> {
    d.map(|d| d.as_secs_f64())
}

fn event_obj(py: Python<'_>, e: &zmux::SessionEvent) -> PyResult<Py<PyAny>> {
    use zmux::SessionEvent as E;
    let d = PyDict::new(py);
    let kind = match e {
        E::PipeState {
            pipe,
            state,
            failure,
            carrier,
            ..
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("half", format!("{:?}", state.half()))?;
            d.set_item("state", direction_state(*state))?;
            d.set_item("failure", failure.map(|f| f.to_string()))?;
            d.set_item("carrier", carrier.map(zmux::CarrierKind::name))?;
            "PipeState"
        }
        E::JoinAuthFailed {
            carrier_bound,
            count,
            ..
        } => {
            d.set_item("carrier_bound", carrier_bound)?;
            d.set_item("count", count)?;
            "JoinAuthFailed"
        }
        E::JoinSecurityUnavailable => "JoinSecurityUnavailable",
        E::PipePriorityChanged {
            pipe,
            send_priority,
            standby,
            weight,
            source,
            ..
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("send_priority", send_priority)?;
            d.set_item("standby", standby)?;
            d.set_item("weight", weight)?;
            d.set_item("source", format!("{source:?}"))?;
            "PipePriorityChanged"
        }
        E::PipeQualityChanged {
            pipe,
            smoothed_rtt,
            delivery_rate,
            ..
        } => {
            d.set_item("pipe", pipe.get())?;
            d.set_item("smoothed_rtt", dur(*smoothed_rtt))?;
            d.set_item("delivery_rate", delivery_rate)?;
            "PipeQualityChanged"
        }
        E::TierSaturation {
            priority,
            saturated,
            ..
        } => {
            d.set_item("priority", priority)?;
            d.set_item("saturated", saturated)?;
            "TierSaturation"
        }
        E::CapacityBelow { rate, .. } => {
            d.set_item("rate", rate)?;
            "CapacityBelow"
        }
        E::CapacityRestored { rate, .. } => {
            d.set_item("rate", rate)?;
            "CapacityRestored"
        }
        E::GoAway(g) => {
            d.set_item("max_bidi", g.max_bidi)?;
            d.set_item("max_uni", g.max_uni)?;
            d.set_item("code", g.code)?;
            "GoAway"
        }
        E::Suspended => "Suspended",
        E::Resumed => "Resumed",
        E::PipesRetired {
            retired,
            failed,
            closed,
            dropped,
            last,
            ..
        } => {
            d.set_item("retired", retired)?;
            d.set_item("failed", failed)?;
            d.set_item("closed", closed)?;
            d.set_item("dropped", dropped)?;
            d.set_item("last", last.iter().map(|p| p.get()).collect::<Vec<_>>())?;
            "PipesRetired"
        }
        E::CarrierCandidate {
            kind,
            outcome,
            joined,
            ..
        } => {
            d.set_item("carrier", kind.name())?;
            d.set_item("outcome", outcome.name())?;
            d.set_item("joined", joined)?;
            "CarrierCandidate"
        }
        E::CarrierChosen(kind) => {
            d.set_item("carrier", kind.name())?;
            "CarrierChosen"
        }
        _ => {
            d.set_item("detail", format!("{e:?}"))?;
            "Unknown"
        }
    };
    Ok(types(py)?.getattr("_event")?.call1((kind, d))?.unbind())
}

/// `Session.events()`: session events until the session ended.
#[pyclass(frozen, module = "zmux._zmux")]
struct EventStream(zmux::Session);

#[pymethods]
impl EventStream {
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            match s.next_event().await {
                Some(e) => rt::attach(|py| event_obj(py, &e)),
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

/// `Session.datagrams()`: received datagrams until the session ended.
#[pyclass(frozen, module = "zmux._zmux")]
struct DatagramStream(zmux::Session);

#[pymethods]
impl DatagramStream {
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            match s.read_datagram().await {
                Ok(b) => Ok(pyb(&b)),
                Err(_) => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

/// A duration in seconds from Python: finite and non-negative, else
/// `ValueError`.
pub(crate) fn seconds(name: &str, v: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(v)
        .map_err(|_| PyValueError::new_err(format!("{name} is a non-negative number of seconds")))
}

/// A non-negative integer from Python, else `ValueError`.
fn natural(name: &str, v: &Bound<'_, PyAny>) -> PyResult<u64> {
    let n: i128 = v.extract()?;
    u64::try_from(n).map_err(|_| PyValueError::new_err(format!("{name} is a non-negative integer")))
}

fn opt_attr<'py>(o: &Bound<'py, PyAny>, name: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    let v = o.getattr(name)?;
    Ok((!v.is_none()).then_some(v))
}

/// The native options of a pipe from a `PipeOptions` (`None`: the
/// defaults); invalid values raise `ValueError`.
pub(crate) fn pipe_options(options: Option<Bound<'_, PyAny>>) -> PyResult<zmux::PipeOptions> {
    let mut o = zmux::PipeOptions::new();
    let Some(opts) = options else {
        return Ok(o);
    };
    let int = |n: &str| -> PyResult<Option<u64>> {
        opt_attr(&opts, n)?.map(|v| natural(n, &v)).transpose()
    };
    let dur = |n: &str| -> PyResult<Option<Duration>> {
        opt_attr(&opts, n)?
            .map(|v| seconds(n, v.extract()?))
            .transpose()
    };
    o.send_priority = int("send_priority")?;
    if let Some(v) = int("receive_priority")? {
        o.receive_priority = v;
    }
    o.send_standby = opts.getattr("send_standby")?.extract()?;
    if let Some(v) = opts.getattr("receive_standby")?.extract::<Option<bool>>()? {
        o.receive_standby = v;
    }
    if let Some(v) = int("weight")? {
        o.weight = v;
    }
    o.probation = dur("probation")?;
    o.label = opts
        .getattr("label")?
        .extract::<Option<String>>()?
        .map(Into::into);
    if let Some(v) = int("fate_group")? {
        o.fate_group = v;
    }
    o.suspect_floor = dur("suspect_floor")?;
    o.dead_timeout = dur("dead_timeout")?;
    let idle_probes: Option<bool> = opts.getattr("idle_probes")?.extract()?;
    o.probe_interval = match (idle_probes, dur("probe_interval")?) {
        (Some(false), Some(_)) => {
            return Err(PyValueError::new_err(
                "probe_interval is set only with idle probes on",
            ));
        }
        (Some(false), None) => Some(zmux::Period::Off),
        (_, d) => d.map(zmux::Period::Every),
    };
    o.probe_jitter = opts.getattr("probe_jitter")?.extract()?;
    o.validate().map_err(|_| {
        PyValueError::new_err(
            "suspect_floor is at least 0.05 s, dead_timeout at least 1 s, probe_interval \
             at least 1 s, probe_jitter in [0, 1)",
        )
    })?;
    Ok(o)
}

/// The Python `PipeOptions` of native options.
pub(crate) fn options_obj<'p>(py: Python<'p>, o: &zmux::PipeOptions) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("send_priority", o.send_priority)?;
    d.set_item("receive_priority", o.receive_priority)?;
    d.set_item("send_standby", o.send_standby)?;
    d.set_item("receive_standby", o.receive_standby)?;
    d.set_item("weight", o.weight)?;
    d.set_item("probation", dur(o.probation))?;
    d.set_item("label", o.label.as_deref())?;
    d.set_item("fate_group", o.fate_group)?;
    d.set_item("suspect_floor", dur(o.suspect_floor))?;
    d.set_item("dead_timeout", dur(o.dead_timeout))?;
    d.set_item(
        "probe_interval",
        o.probe_interval
            .and_then(zmux::Period::duration)
            .map(|d| d.as_secs_f64()),
    )?;
    d.set_item(
        "idle_probes",
        o.probe_interval.map(|p| p != zmux::Period::Off),
    )?;
    d.set_item("probe_jitter", o.probe_jitter)?;
    types(py)?.getattr("PipeOptions")?.call((), Some(&d))
}

/// The options a live pipe changes with `Pipe.update`, and those fixed
/// when it is added.
const UPDATABLE: [&str; 6] = [
    "send_priority",
    "receive_priority",
    "send_standby",
    "receive_standby",
    "weight",
    "probation",
];
const FIXED: [&str; 7] = [
    "label",
    "fate_group",
    "suspect_floor",
    "dead_timeout",
    "probe_interval",
    "idle_probes",
    "probe_jitter",
];

/// The native update of `Pipe.update(**fields)`.
fn pipe_update(kw: Option<&Bound<'_, PyDict>>) -> PyResult<zmux::PipeUpdate> {
    let mut u = zmux::PipeUpdate::default();
    let Some(kw) = kw else {
        return Ok(u);
    };
    for (k, v) in kw.iter() {
        let k: String = k.extract()?;
        if FIXED.contains(&k.as_str()) {
            return Err(PyTypeError::new_err(format!(
                "{k} is fixed when the pipe is added"
            )));
        }
        if !UPDATABLE.contains(&k.as_str()) {
            return Err(PyTypeError::new_err(format!("no pipe option {k}")));
        }
        let none = v.is_none();
        if none && !matches!(k.as_str(), "send_priority" | "send_standby") {
            return Err(PyTypeError::new_err(format!("{k} takes a value, not None")));
        }
        match k.as_str() {
            "send_priority" => {
                u.send_priority = Some((!none).then(|| natural(&k, &v)).transpose()?);
            }
            "send_standby" => u.send_standby = Some(v.extract()?),
            "receive_priority" => u.receive_priority = Some(natural(&k, &v)?),
            "receive_standby" => u.receive_standby = Some(v.extract()?),
            "weight" => u.weight = Some(natural(&k, &v)?),
            _ => u.probation = Some(Some(seconds(&k, v.extract()?)?)),
        }
    }
    Ok(u)
}

/// A pipe reserved for an out-of-band join; attach or cancel it once.
#[pyclass(frozen, module = "zmux._zmux")]
struct PipeReservation(StdMutex<Option<zmux::PipeReservation>>);

impl PipeReservation {
    fn take(&self) -> PyResult<zmux::PipeReservation> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("reservation already used"))
    }
    fn with<T>(&self, f: impl FnOnce(&zmux::PipeReservation) -> T) -> PyResult<T> {
        let g = self.0.lock().unwrap();
        g.as_ref()
            .map(f)
            .ok_or_else(|| PyRuntimeError::new_err("reservation already used"))
    }
}

#[pymethods]
impl PipeReservation {
    #[getter]
    fn id(&self) -> PyResult<u64> {
        self.with(|r| r.id().get())
    }
    /// The PIPE_JOIN frame to deliver out of band.
    #[getter]
    fn frame(&self) -> PyResult<Py<PyBytes>> {
        self.with(|r| pyb(r.frame()))
    }
    /// The `Zmux-Pipe-Join` header value.
    #[getter]
    fn header(&self) -> PyResult<String> {
        self.with(|r| r.header())
    }
    fn attach(&self, pipe: &PipeIo) -> PyResult<Pipe> {
        let io = pipe.take()?;
        self.take()?.attach(io).map(Pipe).map_err(pipe_err)
    }
    fn cancel(&self) -> PyResult<()> {
        self.take()?.cancel();
        Ok(())
    }
}

/// A point in time of the Rust clock on Python's `time.monotonic()`
/// clock: the offset from now on both.
fn monotonic(py: Python<'_>, t: std::time::Instant) -> PyResult<f64> {
    let now = std::time::Instant::now();
    let py_now: f64 = py.import("time")?.call_method0("monotonic")?.extract()?;
    Ok(if t >= now {
        py_now + (t - now).as_secs_f64()
    } else {
        py_now - (now - t).as_secs_f64()
    })
}

fn stats_dict<'p>(py: Python<'p>, s: &zmux::PipeStats) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    macro_rules! put {
        ($($f:ident),*) => { $(d.set_item(stringify!($f), s.$f)?;)* };
    }
    put!(
        local,
        fate_group,
        suspect_count,
        failure_count,
        send_priority,
        standby,
        receive_priority,
        receive_standby,
        request_seq,
        weight,
        in_probation,
        revalidating,
        eligible,
        writable,
        saturated,
        delivery_rate,
        queued_bytes,
        bytes_in_flight,
        bytes_sent,
        bytes_received,
        bytes_acked,
        records_sent,
        records_received,
        bytes_reinjected,
        bytes_lost,
        records_lost,
        bytes_retransmitted,
        loss_rate,
        bytes_opportunistic,
        bytes_redundant,
        bytes_duplicate_received,
        pings_sent,
        pings_answered,
        lanes_out,
        lanes_in,
        lanes_refused
    );
    d.set_item("pipe", s.pipe.get())?;
    d.set_item("label", s.label.as_deref())?;
    d.set_item("carrier", s.carrier.map(zmux::CarrierKind::name))?;
    d.set_item("inbound", s.inbound.map(|x| kind_of(&x)))?;
    d.set_item("outbound", s.outbound.map(|x| kind_of(&x)))?;
    d.set_item("attached_for", s.attached_for.as_secs_f64())?;
    d.set_item("failure", s.failure.map(|x| x.to_string()))?;
    d.set_item("send_priority_source", kind_of(&s.send_priority_source))?;
    d.set_item("standby_source", kind_of(&s.standby_source))?;
    d.set_item(
        "peer_request",
        s.peer_request.map(|r| (r.priority, r.standby)),
    )?;
    d.set_item(
        "probation_until",
        s.probation_until.map(|t| monotonic(py, t)).transpose()?,
    )?;
    d.set_item(
        "rtt_source",
        s.rtt_source.map(|r| kind_of(&r).to_lowercase()),
    )?;
    d.set_item("smoothed_rtt", dur(s.smoothed_rtt))?;
    d.set_item("min_rtt", dur(s.min_rtt))?;
    d.set_item("rttvar", dur(s.rttvar))?;
    d.set_item("one_way_delay", dur(s.one_way_delay))?;
    d.set_item("queue_delay", dur(s.queue_delay))?;
    d.set_item("since_last_ack", dur(s.since_last_ack))?;
    d.set_item("since_last_receive", dur(s.since_last_receive))?;
    d.set_item("since_last_traffic", dur(s.since_last_traffic))?;
    let lanes = s
        .lanes
        .iter()
        .map(|l| {
            (
                l.lane.get(),
                l.position_sent,
                l.position_acked,
                l.position_received,
            )
        })
        .collect::<Vec<_>>();
    d.set_item("lanes", lanes)?;
    types(py)?.getattr("_pipe_stats")?.call1((d,))
}

/// One pipe of a session.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct Pipe(pub(crate) zmux::Pipe);

#[pymethods]
impl Pipe {
    #[getter]
    fn id(&self) -> u64 {
        self.0.id().get()
    }
    /// The value the listener's admission gave the carrier that brought
    /// the pipe (`Verdict.accept(value=...)`): its join's carrier, the
    /// session's for pipe 0; `None` without one and once the session
    /// forgot the pipe.
    #[getter]
    fn admitted(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        admission::admitted_obj(py, self.0.admitted().as_ref())
    }
    /// Waits until the join is confirmed.
    fn joined<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = self.0.clone();
        future_into_py(py, async move { p.joined().await.map_err(pipe_err) })
    }
    /// Waits until the pipe ended.
    fn closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = self.0.clone();
        future_into_py(py, async move { p.closed().await.map_err(pipe_err) })
    }
    /// The session the pipe belongs to.
    #[getter]
    fn session(&self) -> Session {
        Session::new(self.0.session())
    }
    /// Changes the settings a live pipe changes, together: a keyword left
    /// out keeps its value; `send_priority=None` and `send_standby=None`
    /// clear the local setting. A field fixed when the pipe is added, an
    /// unknown name or `None` for another field raises `TypeError`; an
    /// invalid value raises `ValueError` and changes nothing.
    #[pyo3(signature = (**fields))]
    fn update(&self, fields: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
        let u = pipe_update(fields)?;
        self.0.update(&u).map_err(pipe_err)
    }
    /// The options in force, with the fields `update` set; `None` once the
    /// pipe's state is released.
    #[getter]
    fn options<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0.options().map(|o| options_obj(py, &o)).transpose()
    }
    /// The outbound direction's state (else the inbound one's).
    #[getter]
    fn state<'p>(&self, py: Python<'p>) -> Option<Bound<'p, PyAny>> {
        let s = self.0.stats()?;
        match (s.outbound, s.inbound) {
            (Some(o), _) => Some(typed(py, "OutboundState", kind_of(&o))),
            (None, Some(i)) => Some(typed(py, "InboundState", kind_of(&i))),
            (None, None) => None,
        }
    }
    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let _ = if t.is_none() {
            self.0.close()
        } else {
            self.0.abort()
        };
        future_into_py(py, async move { Ok(false) })
    }
    fn close(&self) -> PyResult<()> {
        self.0.close().map_err(pipe_err)
    }
    fn abort(&self) -> PyResult<()> {
        self.0.abort().map_err(pipe_err)
    }
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0.stats().map(|s| stats_dict(py, &s)).transpose()
    }
    /// The pipe's own quality band (`None`: the session's default).
    fn set_quality_band(&self, band: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        self.0
            .set_quality_band(band.map(|b| quality_band(&b)).transpose()?)
            .map_err(pipe_err)
    }
}

type PreambleTuple<'p> = (
    Option<Bound<'p, PyBytes>>,
    Vec<(u64, Bound<'p, PyBytes>)>,
    bool,
);

// ---- streams --------------------------------------------------------------------------

/// A stream part a Python handle holds: taken out by the calls that consume
/// it (`reject`, `stream_pipe`, `splice`).
pub(crate) type Part<T> = Arc<Mutex<Option<T>>>;

/// The error of a part another call took.
fn taken() -> PyErr {
    stream_err(zmux::StreamError::ClosedLocally)
}

/// The part, waiting for an operation in progress.
async fn held<T>(p: &Part<T>) -> PyResult<MappedMutexGuard<'_, T>> {
    MutexGuard::try_map(p.lock().await, Option::as_mut).map_err(|_| taken())
}

/// The part now, for the calls that never wait; `RuntimeError` while an
/// operation is in progress.
fn held_now<T>(p: &Part<T>) -> PyResult<MappedMutexGuard<'_, T>> {
    MutexGuard::try_map(p.try_lock().map_err(|_| busy())?, Option::as_mut).map_err(|_| taken())
}

/// Takes the part out of its handle, which fails from then on.
pub(crate) fn take_now<T>(p: &Part<T>) -> PyResult<T> {
    p.try_lock().map_err(|_| busy())?.take().ok_or_else(taken)
}

/// A received buffer lent to Python without a copy (`memoryview(chunk)`).
#[pyclass(frozen, module = "zmux._zmux")]
struct Chunk(Bytes);

#[pymethods]
impl Chunk {
    unsafe fn __getbuffer__(
        slf: Bound<'_, Self>,
        view: *mut pyo3::ffi::Py_buffer,
        flags: std::os::raw::c_int,
    ) -> PyResult<()> {
        if flags & pyo3::ffi::PyBUF_WRITABLE != 0 {
            return Err(pyo3::exceptions::PyBufferError::new_err(
                "the chunk is read-only",
            ));
        }
        let b = &slf.get().0;
        // SAFETY: the view exports the immutable bytes of the chunk, which the
        // exporter object `slf` keeps alive for the view's lifetime.
        unsafe {
            let r = pyo3::ffi::PyBuffer_FillInfo(
                view,
                slf.as_ptr(),
                b.as_ptr().cast_mut().cast(),
                b.len() as pyo3::ffi::Py_ssize_t,
                1,
                flags,
            );
            if r == -1 {
                return Err(PyErr::fetch(slf.py()));
            }
        }
        Ok(())
    }
    unsafe fn __releasebuffer__(&self, _view: *mut pyo3::ffi::Py_buffer) {}
}

/// A Python buffer handed to a sending part without a copy: the caller
/// does not modify it afterwards.
struct Lent(pyo3::buffer::PyBuffer<u8>);

impl AsRef<[u8]> for Lent {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the buffer is C-contiguous (checked when lent) and stays
        // exported while `self` holds it.
        unsafe { std::slice::from_raw_parts(self.0.buf_ptr().cast::<u8>(), self.0.len_bytes()) }
    }
}

fn lend(data: &Bound<'_, PyAny>) -> PyResult<Bytes> {
    let buf = pyo3::buffer::PyBuffer::<u8>::get(data)?;
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err("the buffer is not contiguous"));
    }
    Ok(Bytes::from_owner(Lent(buf)))
}

fn stream_stats<'p>(py: Python<'p>, st: &zmux::StreamStats) -> PyResult<Bound<'p, PyAny>> {
    let d = PyDict::new(py);
    macro_rules! put {
        ($($f:ident),*) => { $(d.set_item(stringify!($f), st.$f)?;)* };
    }
    put!(
        bytes_written,
        bytes_sent,
        bytes_acknowledged,
        bytes_received,
        bytes_read,
        datagrams_sent,
        datagrams_received,
        datagrams_dropped_recv,
        datagram_bytes_sent,
        datagram_bytes_received,
        send_buffered,
        recv_buffered,
        recv_window
    );
    d.set_item("pipe_id", st.pipe_id.map(zmux::PipeId::get))?;
    types(py)?.getattr("StreamStats")?.call((), Some(&d))
}

/// The sending part of a stream.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct SendStream(pub(crate) Part<zmux::SendStream>);

impl SendStream {
    fn wrap(s: zmux::SendStream) -> Self {
        SendStream(Arc::new(Mutex::new(Some(s))))
    }
}

#[pymethods]
impl SendStream {
    /// Writes all of `data`, waiting for flow control.
    fn write<'p>(
        &self,
        py: Python<'p>,
        data: pyo3::pybacked::PyBackedBytes,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        // Zero-copy for `bytes`: the chunk keeps the Python object alive.
        future_into_py(py, async move {
            held(&s)
                .await?
                .write_chunk(Bytes::from_owner(data))
                .await
                .map_err(stream_err)
        })
    }
    /// Writes the buffer without copying it; the caller does not modify it
    /// afterwards.
    fn write_chunk<'p>(
        &self,
        py: Python<'p>,
        buffer: &Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let data = lend(buffer)?;
        future_into_py(py, async move {
            held(&s).await?.write_chunk(data).await.map_err(stream_err)
        })
    }
    /// Ends the stream cleanly (FIN).
    /// Waits for an operation in progress (a cancelled one releases at once).
    fn finish<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(
            py,
            async move { held(&s).await?.finish().map_err(stream_err) },
        )
    }
    /// Abandons the stream with an application error code.
    #[pyo3(signature = (code=0))]
    fn reset<'p>(&self, py: Python<'p>, code: u64) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let code = varint(code)?;
        future_into_py(py, async move {
            held(&s).await?.reset(code).map_err(stream_err)
        })
    }
    /// Marks the bytes written so far as delivered even if the stream is
    /// reset later (RESET_STREAM_AT).
    fn set_reliable_boundary(&self) -> PyResult<()> {
        held_now(&self.0)?
            .set_reliable_boundary()
            .map_err(stream_err)
    }
    fn set_priority(&self, priority: (u8, bool)) -> PyResult<()> {
        held_now(&self.0)?
            .set_priority(self::priority(priority.0, priority.1)?)
            .map_err(stream_err)
    }
    #[getter]
    fn priority<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = held_now(&self.0)?.priority().map_err(stream_err)?;
        types(py)?
            .getattr("Priority")?
            .call1((p.urgency(), p.incremental()))
    }
    /// The bytes the part could transmit now.
    fn send_capacity(&self) -> PyResult<u64> {
        Ok(held_now(&self.0)?.send_capacity())
    }
    /// Waits until the send capacity is at least `min` (or above 0 while
    /// nothing is unsent) and returns it.
    fn wait_send_capacity<'p>(&self, py: Python<'p>, min: u64) -> PyResult<Bound<'p, PyAny>> {
        if min == 0 {
            return Err(PyValueError::new_err("min is at least 1"));
        }
        let s = self.0.clone();
        future_into_py(py, async move {
            held(&s)
                .await?
                .wait_send_capacity(min)
                .await
                .map_err(stream_err)
        })
    }
    /// The bytes written and not yet released that the part may hold.
    fn set_send_buffer(&self, n: u64) -> PyResult<()> {
        held_now(&self.0)?.set_send_buffer(n).map_err(stream_err)
    }
    /// The part's scheduling policy (a name of `Config.scheduler`); `None`
    /// follows the session's.
    #[pyo3(signature = (scheduler))]
    fn set_scheduler(&self, scheduler: Option<&str>) -> PyResult<()> {
        let p = scheduler.map(policy).transpose()?;
        held_now(&self.0)?.set_scheduler(p).map_err(stream_err)
    }
    /// Sends the part's chunks redundantly on a second pipe (multipath):
    /// `True` on, `False` off, `None` following the session's `redundancy`.
    #[pyo3(signature = (on))]
    fn set_redundant(&self, on: Option<bool>) -> PyResult<()> {
        held_now(&self.0)?.set_redundant(on).map_err(stream_err)
    }
    /// Sends a datagram of the stream with the context ID `context`.
    #[pyo3(signature = (payload, context=0))]
    fn send_datagram(&self, payload: Vec<u8>, context: u64) -> PyResult<()> {
        held_now(&self.0)?
            .send_datagram(context, Bytes::from(payload))
            .map_err(datagram_err)
    }
    /// A snapshot of the stream's statistics.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = held_now(&self.0)?.stats();
        stream_stats(py, &st)
    }
    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    /// Finishes on a normal exit (unless already ended), resets with code 0 on an exception.
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let ok = t.is_none();
        let s = self.0.clone();
        future_into_py(py, async move {
            let mut g = s.lock().await;
            let Some(g) = g.as_mut() else {
                return Ok(false);
            };
            if !ok {
                let _ = g.reset(zmux::VarInt::from_u32(0));
                return Ok(false);
            }
            match g.finish() {
                Err(e) if kind_of(&e) == "ClosedLocally" => Ok(false),
                r => r.map(|()| false).map_err(stream_err),
            }
        })
    }
    /// Waits until the peer stops the stream; returns its code or `None` once all data was acknowledged.
    fn stopped<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let fut = {
                let g = held(&s).await?;
                async move { g.stopped().await }
            };
            fut.await
                .map(|c| c.map(|c| c.into_inner()))
                .map_err(stream_err)
        })
    }
    #[getter]
    fn id(&self) -> PyResult<Option<u64>> {
        Ok(held_now(&self.0)?.id().map(|i| i.into_inner()))
    }
}

/// The receiving part of a stream.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct RecvStream(pub(crate) Part<zmux::RecvStream>);

impl RecvStream {
    fn wrap(s: zmux::RecvStream) -> Self {
        RecvStream(Arc::new(Mutex::new(Some(s))))
    }
}

#[pymethods]
impl RecvStream {
    /// Up to `n` bytes; `b""` at the end of the stream.
    #[pyo3(signature = (n=65536))]
    fn read<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            Ok(held(&s)
                .await?
                .read_chunk(n)
                .await
                .map_err(stream_err)?
                .as_deref()
                .map(pyb)
                .unwrap_or_else(|| pyb(b"")))
        })
    }
    /// Up to `max` bytes as a `memoryview` of the received buffer, without
    /// a copy; an empty one at the end of the stream.
    #[pyo3(signature = (max=65536))]
    fn read_chunk<'p>(&self, py: Python<'p>, max: usize) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let b = held(&s)
                .await?
                .read_chunk(max)
                .await
                .map_err(stream_err)?
                .unwrap_or_default();
            rt::attach(|py| {
                let c = Bound::new(py, Chunk(b))?;
                Ok(pyo3::types::PyMemoryView::from(&c)?.into_any().unbind())
            })
        })
    }
    /// Exactly `n` bytes, or `IncompleteRead`.
    fn read_exact<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let mut buf = vec![0u8; n];
            match held(&s).await?.read_exact(&mut buf).await {
                Ok(()) => Ok(pyb(&buf)),
                Err(zmux::ReadExactError::Read(e)) => Err(stream_err(e)),
                Err(e) => Err(raise::<IncompleteRead>(&e, false, None)),
            }
        })
    }
    /// The rest of the stream, at most `limit` bytes.
    #[pyo3(signature = (limit=16 * 1024 * 1024))]
    fn read_to_end<'p>(&self, py: Python<'p>, limit: usize) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            match held(&s).await?.read_to_end(limit).await {
                Ok(v) => Ok(pyb(&v)),
                Err(zmux::ReadToEndError::Read(e)) => Err(stream_err(e)),
                Err(e) => Err(raise::<LimitExceeded>(&e, false, None)),
            }
        })
    }
    /// Asks the peer to stop sending (STOP_SENDING).
    #[pyo3(signature = (code=0))]
    fn stop<'p>(&self, py: Python<'p>, code: u64) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let code = varint(code)?;
        future_into_py(
            py,
            async move { held(&s).await?.stop(code).map_err(stream_err) },
        )
    }
    /// Declines the stream before reading it (ZMUX_REJECTED); the handle
    /// is used up.
    fn reject(&self) -> PyResult<()> {
        take_now(&self.0)?.reject().map_err(stream_err)
    }
    /// The receive window of the stream: `initial` now, auto-tuned up to `max`.
    fn set_receive_window(&self, initial: u64, max: u64) -> PyResult<()> {
        held_now(&self.0)?
            .set_receive_window(initial, max)
            .map_err(stream_err)
    }
    /// Asks the peer to send the stream with `priority`.
    fn set_peer_priority(&self, priority: (u8, bool)) -> PyResult<()> {
        held_now(&self.0)?
            .set_peer_priority(self::priority(priority.0, priority.1)?)
            .map_err(stream_err)
    }
    /// The next datagram of the stream: `(context, payload)`.
    fn read_datagram<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let (c, b) = held(&s).await?.read_datagram().await.map_err(stream_err)?;
            Ok((c, pyb(&b)))
        })
    }
    /// A snapshot of the stream's statistics.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = held_now(&self.0)?.stats();
        stream_stats(py, &st)
    }
    /// The stream's `Preamble`.
    #[getter]
    fn preamble<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = held_now(&self.0)?.preamble();
        let t: PreambleTuple<'p> = (
            p.info().map(|b| PyBytes::new(py, b)),
            p.tlvs().map(|(t, v)| (t, PyBytes::new(py, &v))).collect(),
            p.is_pipe_carrier(),
        );
        types(py)?.getattr("_preamble")?.call1(t)
    }
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    /// Chunks until the end of the stream.
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            match held(&s)
                .await?
                .read_chunk(65536)
                .await
                .map_err(stream_err)?
            {
                Some(b) if !b.is_empty() => Ok(pyb(&b)),
                _ => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    /// Stops the stream with code 0 on an exception; nothing on a normal exit.
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let ok = t.is_none();
        let s = self.0.clone();
        future_into_py(py, async move {
            if !ok && let Some(g) = s.lock().await.as_mut() {
                let _ = g.stop(zmux::VarInt::from_u32(0));
            }
            Ok(false)
        })
    }
    #[getter]
    fn is_replayable(&self) -> PyResult<bool> {
        Ok(held_now(&self.0)?.is_replayable())
    }
    #[getter]
    fn id(&self) -> PyResult<Option<u64>> {
        Ok(held_now(&self.0)?.id().map(|i| i.into_inner()))
    }
}

// ---- listener -------------------------------------------------------------------------

/// Accepts sessions (and multipath joins) from any number of carriers.
#[pyclass(frozen, module = "zmux._zmux")]
struct Listener {
    inner: zmux::Listener,
    tasks: Arc<StdMutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Listener {
    fn serve<'p, F, Fut>(&self, py: Python<'p>, addr: String, run: F) -> PyResult<Bound<'p, PyAny>>
    where
        F: FnOnce(zmux::Listener, tokio::net::TcpListener) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let tcp = tokio::net::TcpListener::bind(addr).await.map_err(io_err)?;
            let local = tcp.local_addr().map_err(io_err)?.to_string();
            tasks(tokio::spawn(run(l, tcp)));
            Ok(local)
        })
    }
    fn spawner(&self) -> impl FnOnce(tokio::task::JoinHandle<()>) + Send + 'static {
        let tasks = self.tasks.clone();
        move |h| tasks.lock().unwrap().push(h)
    }
}

#[pymethods]
impl Listener {
    #[new]
    #[pyo3(signature = (config=None, *, max_pending=None, max_pending_per_source=None,
        max_pending_per_session=None, first_record_timeout=None, handshake_timeout=None,
        max_record_size=None, accept_sessions=None, max_suspended=None, memory_budget=None,
        instance_id=None, on_memory_pressure=None, trusted_proxies=None, forwarded_header=None,
        proxy_protocol=false, admission=None, inbound_transform=None,
        answer_unknown_joins=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        config: Option<Bound<'_, PyAny>>,
        max_pending: Option<usize>,
        max_pending_per_source: Option<usize>,
        max_pending_per_session: Option<usize>,
        first_record_timeout: Option<f64>,
        handshake_timeout: Option<f64>,
        max_record_size: Option<u64>,
        accept_sessions: Option<bool>,
        max_suspended: Option<usize>,
        memory_budget: Option<Bound<'_, PyAny>>,
        instance_id: Option<Vec<u8>>,
        on_memory_pressure: Option<Py<PyAny>>,
        trusted_proxies: Option<Vec<String>>,
        forwarded_header: Option<String>,
        proxy_protocol: bool,
        admission: Option<PyRef<'_, Admission>>,
        inbound_transform: Option<Py<PyAny>>,
        answer_unknown_joins: bool,
    ) -> PyResult<Self> {
        let mut l = zmux::ListenerConfig::default();
        let mut trusted = zmux::TrustedProxies::new().with_proxy_protocol(proxy_protocol);
        for net in trusted_proxies.unwrap_or_default() {
            trusted = trusted.with_net(net.parse().map_err(value_err)?);
        }
        if let Some(h) = forwarded_header {
            trusted = trusted.with_forwarded_header(h);
        }
        l.trusted_proxies = trusted;
        macro_rules! set {
            ($($f:ident),*) => { $(if let Some(v) = $f { l.$f = v; })* };
        }
        set!(
            max_pending,
            max_pending_per_source,
            max_pending_per_session,
            max_record_size,
            accept_sessions,
            max_suspended,
            instance_id
        );
        if let Some(v) = memory_budget {
            l.memory_budget = field_budget("memory_budget", &v)?;
        }
        if let Some(v) = first_record_timeout {
            l.first_record_timeout = seconds("first_record_timeout", v)?;
        }
        if let Some(v) = handshake_timeout {
            l.handshake_timeout = seconds("handshake_timeout", v)?;
        }
        if l.instance_id.len() > zmux::MAX_INSTANCE_ID_LEN {
            return Err(PyValueError::new_err(format!(
                "instance_id is longer than {} bytes",
                zmux::MAX_INSTANCE_ID_LEN
            )));
        }
        if let Some(f) = on_memory_pressure {
            l.on_memory_pressure = Some(zmux::OnMemoryPressure(Arc::new(move |m| {
                rt::attach(|py| {
                    if let Err(e) = f.call1(py, (m.used, m.budget, m.active)) {
                        e.write_unraisable(py, Some(f.bind(py)));
                    }
                });
            })));
        }
        l.admission = admission.map(|a| a.for_listener(py));
        if let Some(f) = inbound_transform {
            let locals = pyo3_async_runtimes::tokio::get_current_locals(py).map_err(|_| {
                PyRuntimeError::new_err(
                    "inbound_transform needs the Listener made inside a running event loop",
                )
            })?;
            l.inbound_transform = Some(layer::transform(f, locals));
        }
        l.answer_unknown_joins = answer_unknown_joins;
        let config = cfg(config)?;
        let _g = get_runtime().enter();
        Ok(Listener {
            inner: zmux::Listener::new(config, l),
            tasks: Arc::default(),
        })
    }

    /// Serves plain TCP on `addr`; returns the bound address. With the
    /// listener's `admission`, a connection reaches it only once admitted.
    fn serve_tcp<'p>(&self, py: Python<'p>, addr: String) -> PyResult<Bound<'p, PyAny>> {
        self.serve(py, addr, |l, tcp| l.serve(tcp))
    }
    #[pyo3(signature = (addr, *, tls))]
    fn serve_tls<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let c = Arc::new(tls.server_zmux()?);
        self.serve(py, addr, move |l, tcp| zmux_rustls::serve(l, tcp, c))
    }
    /// HTTP/1.1 and HTTP/2 (prior knowledge, or ALPN with `tls`).
    /// With `exchange`, requests to its path are the exchange carrier's.
    ///
    /// Every carrier kind shares `path` (one endpoint, each request
    /// classified by its head): bidirectional, uplink and downlink requests
    /// and split bootstraps, the exchange (with `exchange`), and WebSocket
    /// upgrades (with `websocket`). A connection from a trusted
    /// intermediary configured for the PROXY protocol reads its header
    /// first.
    #[pyo3(signature = (addr, *, path="/zmux".to_owned(), tls=None, exchange=None,
        websocket=false))]
    #[allow(clippy::too_many_arguments)]
    fn serve_http<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        path: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        exchange: Option<PyRef<'_, ExchangeOptions>>,
        websocket: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let mut opts = zmux_http::Options::new().with_path(path);
        if let Some(x) = exchange {
            let server =
                zmux_http::ExchangeServer::new(&self.inner, x.0.clone()).map_err(value_err)?;
            opts = opts.with_exchange(server);
        }
        let mut endpoint = zmux_http::Endpoint::new(self.inner.clone(), opts);
        if websocket {
            endpoint = endpoint.with_websocket(zmux_websocket::Options::default());
        }
        let Some(tls) = tls else {
            return self.serve(py, addr, move |_, tcp| endpoint.serve(tcp));
        };
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(
            tls.server_alpn(|| vec![b"h2".to_vec(), HTTP1.to_vec()])?,
        ));
        self.serve(py, addr, move |l, tcp| async move {
            let trusted = Arc::new(l.trusted_proxies().clone());
            endpoint
                .serve_proxied(
                    || tcp.accept(),
                    move |mut conn, peer| {
                        let (acc, trusted) = (acc.clone(), trusted.clone());
                        async move {
                            let source = zmux::proxied_source(&mut conn, peer, &trusted).await?;
                            Ok((acc.accept(conn).await?, source))
                        }
                    },
                )
                .await
        })
    }
    /// `ws://`, or `wss://` with `tls`. With the listener's `admission`, an
    /// upgrade is decided on its request head (no prefix), over TLS with
    /// the connection's exporter.
    #[pyo3(signature = (addr, *, tls=None))]
    fn serve_websocket<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: Option<PyRef<'_, TlsConfig>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let options = zmux_websocket::Options::default();
        let Some(tls) = tls else {
            return self.serve(py, addr, |l, tcp| zmux_websocket::serve(l, tcp, options));
        };
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(tls.server_alpn(http1)?));
        self.serve(py, addr, move |l, tcp| {
            zmux_websocket::serve_tls(l, tcp, acc, options)
        })
    }
    /// HTTP/3 requests to any path carry pipes. With the listener's
    /// `admission`, each request is decided on the first bytes of its body.
    #[pyo3(signature = (addr, *, tls, lanes=4))]
    fn serve_h3<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts =
            zmux_h3::Options::new().with_windows(zmux_h3::LaneWindows::new().with_lanes(lanes));
        let sc = zmux_h3::server_config(tls.server()?, &opts).map_err(value_err)?;
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = ep.local_addr().map_err(io_err)?.to_string();
            tasks(tokio::spawn(zmux_h3::serve(l, ep, opts)));
            Ok(local)
        })
    }
    /// WebTransport sessions carry pipes. With the listener's `admission`, a
    /// session request is decided on its request head (no prefix), with the
    /// QUIC connection's exporter.
    #[pyo3(signature = (addr, *, tls, lanes=4))]
    fn serve_webtransport<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts = zmux_webtransport::Options::new()
            .with_windows(zmux_webtransport::LaneWindows::new().with_lanes(lanes));
        let mut c = tls.server()?;
        c.alpn_protocols = vec![wt::ALPN.as_bytes().to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(c).map_err(value_err)?;
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        sc.transport_config(Arc::new(opts.transport_config()));
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = ep.local_addr().map_err(io_err)?.to_string();
            tasks(tokio::spawn(zmux_webtransport::serve(l, ep, opts)));
            Ok(local)
        })
    }
    /// QUIC; with `zero_rtt`, 0-RTT data is accepted when the listener's
    /// `Config(carrier_early_data=True)` allows it.
    /// With the listener's `admission`, a connection reaches the listener
    /// only once the first bytes of its first stream are admitted; it
    /// excludes `zero_rtt`.
    #[pyo3(signature = (addr, *, tls, lanes=4, zero_rtt=false))]
    fn serve_quic<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
        zero_rtt: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        if zero_rtt && self.inner.admission().is_some() {
            return Err(PyValueError::new_err(
                "zero_rtt and admission are mutually exclusive",
            ));
        }
        let mut opts = quic_options(lanes);
        if zero_rtt {
            opts = opts.with_zero_rtt(zmux_quinn::ParameterMemory::new());
        }
        let sc = zmux_quinn::server_config(tls.server_zmux()?, &opts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = ep.local_addr().map_err(io_err)?.to_string();
            tasks(tokio::spawn(zmux_quinn::serve(l, ep, opts, None)));
            Ok(local)
        })
    }

    /// Hands over a carrier accepted by the application (for example
    /// `pipe_pair()`): `peer` is its directly connected peer and `source`
    /// the client the application resolved (both `(host, port)`; unset, the
    /// source is the peer, and the peer `127.0.0.1:0`). It takes a source
    /// slot and goes through the listener's admission, joins and
    /// resumptions too.
    #[pyo3(signature = (pipe, *, peer=None, source=None))]
    fn handle_pipe<'p>(
        &self,
        py: Python<'p>,
        pipe: &PipeIo,
        peer: Option<(String, u16)>,
        source: Option<(String, u16)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        let addr = |a: Option<(String, u16)>| -> PyResult<Option<std::net::SocketAddr>> {
            a.map(|(h, p)| {
                h.parse::<std::net::IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, p))
                    .map_err(value_err)
            })
            .transpose()
        };
        let peer = addr(peer)?.unwrap_or((std::net::Ipv4Addr::LOCALHOST, 0).into());
        let source = addr(source)?;
        let io = pipe.take()?;
        future_into_py(py, async move {
            let mut hint = zmux::PipeHint::from_peer(peer);
            if let Some(s) = source {
                hint = hint.with_source(s);
            }
            l.handle_pipe(io, hint)
                .await
                .map_err(|e| raise::<ConnectError>(&e, false, None))
        })
    }

    /// The next established session; `ListenerClosed` once closed.
    fn accept<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        future_into_py(py, async move {
            l.accept().await.map(Session::new).ok_or_else(|| {
                rt::attach(|py| {
                    let e = ListenerClosed::new_err("listener closed");
                    let v = e.value(py);
                    let _ = v.setattr("kind", typed(py, "ErrorKind", "ListenerClosed".into()));
                    let _ = v.setattr("retryable", false);
                    let _ = v.setattr("code", py.None());
                    e
                })
            })
        })
    }

    /// Closes gracefully: new sessions are refused at once while the joins
    /// and resumptions of the live sessions are taken; every session is
    /// shut down with `code` and `reason`, and once they all ended the
    /// listener closes. Cancelled (a timeout at a deadline), it closes at
    /// once.
    #[pyo3(signature = (code=0, reason=b"".to_vec()))]
    fn shutdown<'p>(
        &self,
        py: Python<'p>,
        code: u64,
        reason: Vec<u8>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        let code = zmux::VarInt::from_u64(code).map_err(value_err)?;
        let tasks = self.tasks.clone();
        future_into_py(py, async move {
            l.shutdown(code, &reason).await;
            for t in tasks.lock().unwrap().drain(..) {
                t.abort();
            }
            Ok(())
        })
    }

    fn close(&self) {
        self.inner.close();
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }

    /// What happened to the listener's carriers: counts since it was made.
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let st = self.inner.stats();
        let d = PyDict::new(py);
        d.set_item("sessions", st.sessions)?;
        d.set_item("joins", st.joins)?;
        d.set_item("setup_failures", st.setup_failures)?;
        d.set_item("rejected", st.rejected)?;
        d.set_item("refused", st.refused)?;
        d.set_item("timed_out", st.timed_out)?;
        let a = &st.admission;
        let ad = PyDict::new(py);
        ad.set_item("accepted", a.accepted)?;
        ad.set_item("fallback", a.fallback)?;
        ad.set_item("stalled", a.stalled)?;
        ad.set_item("closed", a.closed)?;
        ad.set_item("stall_overflow", a.stall_overflow)?;
        ad.set_item("peek_timed_out", a.peek_timed_out)?;
        ad.set_item("handshake_failed", a.handshake_failed)?;
        d.set_item(
            "admission",
            types(py)?.getattr("AdmissionStats")?.call((), Some(&ad))?,
        )?;
        types(py)?.getattr("ListenerStats")?.call((), Some(&d))
    }

    fn __aenter__<'p>(slf: Bound<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let o = slf.unbind();
        future_into_py(py, async move { Ok(o) })
    }
    fn __aexit__<'p>(
        &self,
        py: Python<'p>,
        _t: Bound<'p, PyAny>,
        _v: Bound<'p, PyAny>,
        _tb: Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        self.close();
        future_into_py(py, async move { Ok(false) })
    }
    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        future_into_py(py, async move {
            l.accept()
                .await
                .map(Session::new)
                .ok_or_else(|| PyStopAsyncIteration::new_err(()))
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.inner.close();
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

#[pymodule(gil_used = false)]
fn _zmux(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    rt::register(m)?;
    m.add_class::<Config>()?;
    m.add_class::<TlsConfig>()?;
    m.add_class::<PipeIo>()?;
    m.add_class::<UnsentCount>()?;
    m.add_class::<PipeEnd>()?;
    m.add_class::<Session>()?;
    m.add_class::<Pipe>()?;
    m.add_class::<SendStream>()?;
    m.add_class::<RecvStream>()?;
    m.add_class::<Chunk>()?;
    helpers::register(m)?;
    m.add_class::<Listener>()?;
    m.add_class::<PipeReservation>()?;
    m.add_class::<Http2Connection>()?;
    m.add_class::<ExchangeOptions>()?;
    admission::register(m)?;
    layer::register(m)?;
    pool::register(m)?;
    m.add_class::<QuicClient>()?;
    m.add_class::<ZeroRtt>()?;
    m.add_class::<EventStream>()?;
    m.add_class::<DatagramStream>()?;
    m.add_function(wrap_pyfunction!(dial_h3, m)?)?;
    m.add_function(wrap_pyfunction!(dial_webtransport, m)?)?;
    m.add_function(wrap_pyfunction!(pipe_pair, m)?)?;
    m.add_function(wrap_pyfunction!(dial_tcp, m)?)?;
    m.add_function(wrap_pyfunction!(dial_tls, m)?)?;
    m.add_function(wrap_pyfunction!(dial_quic, m)?)?;
    m.add_function(wrap_pyfunction!(dial_websocket, m)?)?;
    m.add_function(wrap_pyfunction!(dial_http, m)?)?;
    m.add_function(wrap_pyfunction!(dial_http_split, m)?)?;
    m.add_function(wrap_pyfunction!(join_http_split, m)?)?;
    mode::register(m)?;
    defaults(m)?;
    m.add_function(wrap_pyfunction!(dial_exchange, m)?)?;
    for (n, t) in [
        ("ZmuxError", py.get_type::<ZmuxError>()),
        ("ConnectError", py.get_type::<ConnectError>()),
        ("SessionClosed", py.get_type::<SessionClosed>()),
        ("EarlyDataRejected", py.get_type::<EarlyDataRejected>()),
        ("StreamError", py.get_type::<StreamError>()),
        ("StreamReset", py.get_type::<StreamReset>()),
        ("StreamStopped", py.get_type::<StreamStopped>()),
        ("IncompleteRead", py.get_type::<IncompleteRead>()),
        ("OpenError", py.get_type::<OpenError>()),
        ("LimitExceeded", py.get_type::<LimitExceeded>()),
        ("ListenerClosed", py.get_type::<ListenerClosed>()),
        ("DatagramError", py.get_type::<DatagramError>()),
        ("PipeError", py.get_type::<PipeError>()),
        (
            "PreambleTooLargeError",
            py.get_type::<PreambleTooLargeError>(),
        ),
    ] {
        m.add(n, t)?;
    }
    Ok(())
}

/// The library defaults, durations in seconds.
fn defaults(m: &Bound<'_, PyModule>) -> PyResult<()> {
    use zmux::proto::session as s;
    m.add(
        "DEFAULT_KEEP_ALIVE_PERIOD",
        s::DEFAULT_KEEP_ALIVE_PERIOD.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_IDLE_TIMEOUT",
        s::DEFAULT_IDLE_TIMEOUT.as_secs_f64(),
    )?;
    m.add("DEFAULT_PROBE_JITTER", s::DEFAULT_PROBE_JITTER)?;
    m.add(
        "DEFAULT_STANDBY_PROBE",
        s::DEFAULT_STANDBY_PROBE.as_secs_f64(),
    )?;
    m.add(
        "DEFAULT_MAX_RECORD_SIZE",
        zmux::proto::params::DEFAULT_MAX_RECORD_SIZE,
    )?;
    m.add(
        "DEFAULT_BACKOFF_MAX",
        zmux::helpers::DEFAULT_BACKOFF_MAX.as_secs_f64(),
    )?;
    m.add("MIN_MAX_LEN", zmux::shaping::MIN_MAX_LEN)?;
    m.add("STARTUP_ALLOWANCE", zmux::shaping::STARTUP_ALLOWANCE)?;
    Ok(())
}
