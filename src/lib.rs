//! PyO3 bindings over the zmux Rust crates. Every I/O operation runs on the
//! tokio runtime owned by `pyo3-async-runtimes`; Python awaits futures that
//! resolve on its asyncio loop. No protocol logic lives here.

use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use pyo3::exceptions::{PyException, PyRuntimeError, PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use pyo3::{IntoPyObjectExt, create_exception};
use pyo3_async_runtimes::tokio::{future_into_py, get_runtime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

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
    SessionClosed,
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
create_exception!(_zmux, OpenError, ZmuxError, "Opening a stream failed.");
create_exception!(
    _zmux,
    DatagramError,
    ZmuxError,
    "Sending a datagram failed."
);
create_exception!(_zmux, PipeError, ZmuxError, "A pipe operation failed.");

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
    Python::attach(|py| {
        let err = PyErr::new::<T, _>(e.to_string());
        let v = err.value(py);
        let _ = v.setattr("kind", kind_of(e));
        let _ = v.setattr("retryable", retryable);
        let _ = v.setattr("code", code);
        err
    })
}

fn session_err(e: zmux::SessionError) -> PyErr {
    let code = match &e {
        zmux::SessionError::ApplicationClosed { code, .. } => Some(code.into_inner()),
        _ => None,
    };
    if e.is_early_data_rejected() {
        raise::<EarlyDataRejected>(&e, e.is_retryable(), code)
    } else {
        raise::<SessionClosed>(&e, e.is_retryable(), code)
    }
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
        _ => raise::<StreamError>(&e, e.is_retryable(), None),
    }
}

fn open_err(e: zmux::OpenError) -> PyErr {
    match e {
        zmux::OpenError::SessionLost(s) => session_err(s),
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
    raise::<ConnectError>(&e, false, None)
}

fn pyb(b: &[u8]) -> Py<PyBytes> {
    Python::attach(|py| PyBytes::new(py, b).unbind())
}

fn busy() -> PyErr {
    PyRuntimeError::new_err("another operation on this stream is in progress")
}

// ---- configuration --------------------------------------------------------------------

fn secs(v: f64) -> Duration {
    Duration::from_secs_f64(v)
}

/// Session configuration; every argument left out keeps the Rust default.
#[pyclass(frozen, module = "zmux._zmux")]
#[derive(Clone)]
struct Config(Arc<zmux::Config>);

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (*, handshake_timeout=None, idle_timeout=None, keep_alive=None,
        datagrams=None, max_incoming_streams=None, max_pipes=None, psk=None, tls_auth=false,
        resume_timeout=None, early_data=false, carrier_early_data=false, protocols=None,
        dead_timeout=None, suspect_floor=None, probation=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        handshake_timeout: Option<f64>,
        idle_timeout: Option<f64>,
        keep_alive: Option<f64>,
        datagrams: Option<bool>,
        max_incoming_streams: Option<u64>,
        max_pipes: Option<u32>,
        psk: Option<Vec<u8>>,
        tls_auth: bool,
        resume_timeout: Option<f64>,
        early_data: bool,
        carrier_early_data: bool,
        protocols: Option<Vec<String>>,
        dead_timeout: Option<f64>,
        suspect_floor: Option<f64>,
        probation: Option<f64>,
    ) -> Self {
        let mut c = zmux::Config::default();
        if let Some(v) = handshake_timeout {
            c.handshake_timeout = secs(v);
        }
        if let Some(v) = idle_timeout {
            c.max_idle_timeout = secs(v);
        }
        if keep_alive.is_some() {
            c.keep_alive_period = keep_alive.map(secs);
        }
        if let Some(v) = datagrams {
            c.enable_datagrams = v;
        }
        if let Some(v) = max_incoming_streams {
            c.max_incoming_streams = v;
        }
        let auth = match (psk, tls_auth) {
            (Some(k), true) => Some(zmux::PipeAuth::tls().with_psk(k)),
            (Some(k), false) => Some(zmux::PipeAuth::psk(k)),
            (None, true) => Some(zmux::PipeAuth::tls()),
            (None, false) => None,
        };
        if let Some(a) = auth {
            c.pipe_auth = a;
            c.max_pipes = 8;
        }
        if let Some(v) = max_pipes {
            c.max_pipes = v;
        }
        if resume_timeout.is_some() {
            c.resume_timeout = resume_timeout.map(secs);
        }
        let mut ed = if early_data {
            zmux::EarlyData::for_zmux_peer()
        } else {
            zmux::EarlyData::default()
        };
        ed.carrier_early_data = carrier_early_data;
        c.early_data = ed;
        if protocols.is_some() {
            c.protocols = protocols;
        }
        if dead_timeout.is_some() {
            c.dead_timeout = dead_timeout.map(secs);
        }
        if let Some(v) = suspect_floor {
            c.suspect_floor = secs(v);
        }
        if probation.is_some() {
            c.probation = probation.map(secs);
        }
        Config(Arc::new(c))
    }
}

fn cfg(c: Option<PyRef<'_, Config>>) -> Arc<zmux::Config> {
    c.map(|c| c.0.clone()).unwrap_or_default()
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

    /// The client configuration with `alpn` when none is set.
    fn client_alpn(&self, alpn: &[&[u8]]) -> PyResult<rustls::ClientConfig> {
        let mut c = self.client()?;
        if c.alpn_protocols.is_empty() {
            c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        }
        Ok(c)
    }

    /// The server configuration with `alpn` when none is set.
    fn server_alpn(&self, alpn: &[&[u8]]) -> PyResult<rustls::ServerConfig> {
        let mut c = self.server()?;
        if c.alpn_protocols.is_empty() {
            c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        }
        Ok(c)
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
#[pyfunction]
fn pipe_pair() -> (PipeIo, PipeEnd) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (r, w) = tokio::io::split(b);
    (
        PipeIo::wrap(zmux::PipeIo::new(a)),
        PipeEnd {
            r: Arc::new(Mutex::new(r)),
            w: Arc::new(Mutex::new(w)),
        },
    )
}

async fn resolve(addr: &str) -> PyResult<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await
        .map_err(io_err)?
        .next()
        .ok_or_else(|| PyValueError::new_err("no address"))
}

#[pyfunction]
fn dial_tcp(py: Python<'_>, addr: String) -> PyResult<Bound<'_, PyAny>> {
    future_into_py(py, async move {
        let tcp = tokio::net::TcpStream::connect(addr).await.map_err(io_err)?;
        Ok(PipeIo::wrap(zmux::PipeIo::tcp(tcp)))
    })
}

#[pyfunction]
#[pyo3(signature = (addr, server_name, tls))]
fn dial_tls<'p>(
    py: Python<'p>,
    addr: String,
    server_name: String,
    tls: PyRef<'_, TlsConfig>,
) -> PyResult<Bound<'p, PyAny>> {
    let c = Arc::new(tls.client()?);
    future_into_py(py, async move {
        Ok(PipeIo::wrap(
            zmux_rustls::dial(addr, &server_name, c)
                .await
                .map_err(io_err)?,
        ))
    })
}

fn quic_options(lanes: u32) -> zmux_quinn::Options {
    zmux_quinn::Options::default().with_lanes(lanes)
}

#[pyfunction]
#[pyo3(signature = (addr, server_name, tls, lanes=4))]
fn dial_quic<'p>(
    py: Python<'p>,
    addr: String,
    server_name: String,
    tls: PyRef<'_, TlsConfig>,
    lanes: u32,
) -> PyResult<Bound<'p, PyAny>> {
    let opts = quic_options(lanes);
    let qc = zmux_quinn::client_config(tls.client()?, &opts)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    future_into_py(py, async move {
        let addr = resolve(&addr).await?;
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();
        let mut ep = quinn::Endpoint::client(bind).map_err(io_err)?;
        ep.set_default_client_config(qc);
        Ok(PipeIo::wrap(
            zmux_quinn::dial(&ep, addr, &server_name, &opts)
                .await
                .map_err(io_err)?,
        ))
    })
}

fn value_err(e: impl Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

const HTTP1: &[u8] = b"http/1.1";

/// `ws://` or `wss://` (TLS with `tls`, by default the bundled web roots);
/// `headers` are added to the upgrade request, for example the
/// `Zmux-Pipe-Join` header of a `PipeReservation`.
#[pyfunction]
#[pyo3(signature = (url, tls=None, headers=None))]
fn dial_websocket<'p>(
    py: Python<'p>,
    url: String,
    tls: Option<PyRef<'_, TlsConfig>>,
    headers: Option<Vec<(String, String)>>,
) -> PyResult<Bound<'p, PyAny>> {
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
            Some(t) => t.client_alpn(&[HTTP1])?,
            None => TlsConfig::web().client_alpn(&[HTTP1])?,
        };
        Some(tokio_rustls::TlsConnector::from(Arc::new(c)))
    } else {
        None
    };
    future_into_py(py, async move {
        let opts = zmux_websocket::Options::default();
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
    #[pyo3(signature = (addr, path="/zmux".to_owned(), tls=None, server_name=None))]
    fn connect<'p>(
        py: Python<'p>,
        addr: String,
        path: String,
        tls: Option<PyRef<'_, TlsConfig>>,
        server_name: Option<String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts = zmux_http::Options::new().with_path(path);
        let tls = tls
            .map(|t| t.client_alpn(&[b"h2"]))
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

/// A pipe on a new HTTP/3 connection: a request to `url` (`https://`),
/// to `addr` when given, else to the URL's host and port.
#[pyfunction]
#[pyo3(signature = (url, tls, addr=None, lanes=4))]
fn dial_h3<'p>(
    py: Python<'p>,
    url: String,
    tls: PyRef<'_, TlsConfig>,
    addr: Option<String>,
    lanes: u32,
) -> PyResult<Bound<'p, PyAny>> {
    let uri: http::Uri = url.parse().map_err(value_err)?;
    let addr = match addr {
        Some(a) => a,
        None => authority_of(&uri)?,
    };
    let opts = zmux_h3::Options::new().with_lanes(lanes);
    let qc = zmux_h3::client_config(tls.client()?, &opts).map_err(value_err)?;
    future_into_py(py, async move {
        let addr = resolve(&addr).await?;
        let mut ep = quinn::Endpoint::client(bind_for(&addr)).map_err(io_err)?;
        ep.set_default_client_config(qc);
        Ok(PipeIo::wrap(
            zmux_h3::dial(&ep, addr, uri, &opts).await.map_err(io_err)?,
        ))
    })
}

use zmux_webtransport::web_transport_quinn as wt;

/// A pipe on a new WebTransport session to `url` (`https://`; the
/// WebTransport client resolves its host itself).
#[pyfunction]
#[pyo3(signature = (url, tls, lanes=4))]
fn dial_webtransport<'p>(
    py: Python<'p>,
    url: String,
    tls: PyRef<'_, TlsConfig>,
    lanes: u32,
) -> PyResult<Bound<'p, PyAny>> {
    let url: zmux_webtransport::Url = url.parse().map_err(value_err)?;
    let authority = format!(
        "{}:{}",
        url.host_str()
            .ok_or_else(|| PyValueError::new_err("URL without a host"))?,
        url.port_or_known_default().unwrap_or(443)
    );
    let opts = zmux_webtransport::Options::new().with_lanes(lanes);
    let mut c = tls.client()?;
    c.alpn_protocols = vec![wt::ALPN.as_bytes().to_vec()];
    let crypto = wt::quinn::crypto::rustls::QuicClientConfig::try_from(c).map_err(value_err)?;
    let mut qc = wt::quinn::ClientConfig::new(Arc::new(crypto));
    qc.transport_config(Arc::new(opts.transport_config()));
    future_into_py(py, async move {
        // The local socket's family follows the host's first address.
        let first = resolve(&authority).await?;
        let ep = wt::quinn::Endpoint::client(bind_for(&first)).map_err(io_err)?;
        let client = wt::Client::new(ep, qc);
        Ok(PipeIo::wrap(
            zmux_webtransport::dial(&client, url, &opts)
                .await
                .map_err(io_err)?,
        ))
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
    #[pyo3(signature = (tls, *, lanes=4, zero_rtt=false, memory_capacity=None, bind="0.0.0.0:0".to_owned()))]
    fn new(
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
        zero_rtt: bool,
        memory_capacity: Option<usize>,
        bind: String,
    ) -> PyResult<Self> {
        let memory = zero_rtt.then(|| match memory_capacity {
            Some(n) => zmux_quinn::ParameterMemory::with_capacity(n),
            None => zmux_quinn::ParameterMemory::new(),
        });
        let mut opts = quic_options(lanes);
        if let Some(m) = &memory {
            opts = opts.with_zero_rtt(m.clone());
        }
        let qc = zmux_quinn::client_config(tls.client()?, &opts).map_err(value_err)?;
        let bind: SocketAddr = bind.parse().map_err(value_err)?;
        let _g = get_runtime().enter();
        let mut ep = quinn::Endpoint::client(bind).map_err(io_err)?;
        ep.set_default_client_config(qc);
        Ok(QuicClient { ep, opts, memory })
    }

    /// A pipe on a new connection.
    fn dial<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        server_name: String,
    ) -> PyResult<Bound<'p, PyAny>> {
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
    #[pyo3(signature = (addr, server_name, config=None))]
    fn connect<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        server_name: String,
        config: Option<PyRef<'_, Config>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let (ep, opts, c) = (self.ep.clone(), self.opts.clone(), cfg(config));
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let (s, z) = zmux_quinn::connect_with_report(&ep, addr, &server_name, &opts, c)
                .await
                .map_err(connect_err)?;
            Ok((Session(s), ZeroRtt(z)))
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

#[pyfunction]
#[pyo3(signature = (addr, path="/zmux".to_owned()))]
fn dial_http(py: Python<'_>, addr: String, path: String) -> PyResult<Bound<'_, PyAny>> {
    future_into_py(py, async move {
        let opts = zmux_http::Options::new().with_path(path);
        Ok(PipeIo::wrap(
            zmux_http::dial_http1(&addr, &opts).await.map_err(io_err)?,
        ))
    })
}

// ---- session --------------------------------------------------------------------------

fn preamble(info: Option<Vec<u8>>, tlvs: Option<Vec<(u64, Vec<u8>)>>) -> Option<zmux::Preamble> {
    if info.is_none() && tlvs.as_ref().is_none_or(Vec::is_empty) {
        return None;
    }
    let mut p = zmux::Preamble::new();
    if let Some(i) = info {
        p = p.with_info(i);
    }
    for (t, v) in tlvs.unwrap_or_default() {
        p = p.with_tlv(t, v);
    }
    Some(p)
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
struct Session(zmux::Session);

fn start<'p>(
    py: Python<'p>,
    pipe: &PipeIo,
    config: Option<PyRef<'_, Config>>,
    how: u8,
) -> PyResult<Bound<'p, PyAny>> {
    let io = pipe.take()?;
    let c = cfg(config);
    future_into_py(py, async move {
        let s = match how {
            0 => zmux::Session::connect(io, c).await,
            1 => zmux::Session::accept(io, c).await,
            _ => zmux::Session::peer(io, c).await,
        };
        s.map(Session).map_err(connect_err)
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
        config: Option<PyRef<'_, Config>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 0)
    }
    /// Establishes a single-pipe session as the accepting side of `pipe`.
    #[staticmethod]
    #[pyo3(signature = (pipe, config=None))]
    fn accept<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<PyRef<'_, Config>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 1)
    }
    /// Establishes a session over a symmetric carrier; roles are negotiated.
    #[staticmethod]
    #[pyo3(signature = (pipe, config=None))]
    fn peer<'p>(
        py: Python<'p>,
        pipe: &PipeIo,
        config: Option<PyRef<'_, Config>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        start(py, pipe, config, 2)
    }

    #[pyo3(signature = (*, info=None, tlvs=None, priority=None, peer_priority=None))]
    fn open_bi<'p>(
        &self,
        py: Python<'p>,
        info: Option<Vec<u8>>,
        tlvs: Option<Vec<(u64, Vec<u8>)>>,
        priority: Option<(u8, bool)>,
        peer_priority: Option<(u8, bool)>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let p = preamble(info, tlvs);
        let prio = priority.map(|(u, i)| self::priority(u, i)).transpose()?;
        let peer = peer_priority
            .map(|(u, i)| self::priority(u, i))
            .transpose()?;
        future_into_py(py, async move {
            let pair = match p {
                Some(p) => s.open_bi_with(&p).await,
                None => s.open_bi().await,
            }
            .map_err(open_err)?;
            if let Some(pr) = prio {
                pair.0.set_priority(pr).map_err(stream_err)?;
            }
            if let Some(pr) = peer {
                pair.1.set_peer_priority(pr).map_err(stream_err)?;
            }
            Python::attach(|py| bi(py, pair))
        })
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
        let p = preamble(info, tlvs);
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
            Python::attach(|py| bi(py, pair))
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

    /// Waits for the end of the session; returns why it ended as an exception instance.
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let e = s.closed().await;
            Python::attach(|py| Ok(session_err(e).into_value(py).into_any()))
        })
    }

    fn ping<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            s.ping().await.map(|d| d.as_secs_f64()).map_err(session_err)
        })
    }

    /// The next session event as `(kind, detail)`, or `None` once the session ended.
    fn next_event<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            Ok(s.next_event()
                .await
                .map(|e| (kind_of(&e), format!("{e:?}"))))
        })
    }

    /// Adds a carrier as a further pipe (multipath); returns at once.
    #[pyo3(signature = (pipe, *, priority=None, standby=None, weight=None))]
    fn add_pipe(
        &self,
        pipe: &PipeIo,
        priority: Option<u64>,
        standby: Option<bool>,
        weight: Option<u64>,
    ) -> PyResult<Pipe> {
        let o = pipe_options(priority, standby, weight);
        self.0.add_pipe(pipe.take()?, o).map(Pipe).map_err(pipe_err)
    }

    /// Reserves a pipe for an out-of-band join: send `header` with the
    /// carrier's request (`Zmux-Pipe-Join`), then `attach` the carrier.
    /// `direction` is "in", "out" or "bidi".
    #[pyo3(signature = (direction="bidi", *, priority=None, standby=None, weight=None))]
    fn reserve_pipe(
        &self,
        direction: &str,
        priority: Option<u64>,
        standby: Option<bool>,
        weight: Option<u64>,
    ) -> PyResult<PipeReservation> {
        let dir = match direction {
            "in" => zmux::PipeDirection::In,
            "out" => zmux::PipeDirection::Out,
            "bidi" => zmux::PipeDirection::Bidi,
            _ => return Err(PyValueError::new_err("direction is in, out or bidi")),
        };
        let o = pipe_options(priority, standby, weight);
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

    fn pipe_stats<'p>(&self, py: Python<'p>) -> PyResult<Vec<Bound<'p, PyDict>>> {
        self.0
            .pipe_stats()
            .iter()
            .map(|s| stats_dict(py, s))
            .collect()
    }

    #[getter]
    fn role(&self) -> String {
        format!("{:?}", self.0.role()).to_lowercase()
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
    fn state(&self) -> String {
        kind_of(&self.0.state())
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
                Ok(pair) => Python::attach(|py| bi(py, pair)),
                Err(_) => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

fn pipe_options(
    priority: Option<u64>,
    standby: Option<bool>,
    weight: Option<u64>,
) -> zmux::PipeOptions {
    let mut o = zmux::PipeOptions::new();
    if let Some(p) = priority {
        o = o.with_priority(p);
    }
    if let Some(s) = standby {
        o = o.with_standby(s);
    }
    if let Some(w) = weight {
        o = o.with_weight(w);
    }
    o
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
        self.with(|r| r.id().0)
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

fn stats_dict<'p>(py: Python<'p>, s: &zmux::PipeStats) -> PyResult<Bound<'p, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("pipe", s.pipe.0)?;
    d.set_item("local", s.local)?;
    d.set_item("inbound", s.inbound.map(|x| kind_of(&x)))?;
    d.set_item("outbound", s.outbound.map(|x| kind_of(&x)))?;
    d.set_item("failure", s.failure.map(|x| format!("{x:?}")))?;
    d.set_item("send_priority", s.send_priority)?;
    d.set_item("receive_priority", s.receive_priority)?;
    d.set_item("standby", s.standby)?;
    d.set_item("weight", s.weight)?;
    d.set_item("failure_count", s.failure_count)?;
    d.set_item("detail", format!("{s:?}"))?;
    Ok(d)
}

/// One pipe of a session.
#[pyclass(frozen, module = "zmux._zmux")]
struct Pipe(zmux::Pipe);

#[pymethods]
impl Pipe {
    #[getter]
    fn id(&self) -> u64 {
        self.0.id().0
    }
    /// Waits until the join is confirmed.
    fn joined<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let p = self.0.clone();
        future_into_py(py, async move { p.joined().await.map_err(pipe_err) })
    }
    fn set_priority(&self, priority: u64) -> PyResult<()> {
        self.0.set_priority(priority).map_err(pipe_err)
    }
    fn set_standby(&self, standby: bool) -> PyResult<()> {
        self.0.set_standby(standby).map_err(pipe_err)
    }
    fn set_weight(&self, weight: u64) -> PyResult<()> {
        self.0.set_weight(weight).map_err(pipe_err)
    }
    fn close(&self) -> PyResult<()> {
        self.0.close().map_err(pipe_err)
    }
    fn abort(&self) -> PyResult<()> {
        self.0.abort().map_err(pipe_err)
    }
    fn stats<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyDict>>> {
        self.0.stats().map(|s| stats_dict(py, &s)).transpose()
    }
}

// ---- streams --------------------------------------------------------------------------

/// The sending part of a stream.
#[pyclass(frozen, module = "zmux._zmux")]
struct SendStream(Arc<Mutex<zmux::SendStream>>);

impl SendStream {
    fn wrap(s: zmux::SendStream) -> Self {
        SendStream(Arc::new(Mutex::new(s)))
    }
    fn now(&self) -> PyResult<tokio::sync::MutexGuard<'_, zmux::SendStream>> {
        self.0.try_lock().map_err(|_| busy())
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
            s.lock()
                .await
                .write_chunk(Bytes::from_owner(data))
                .await
                .map_err(stream_err)
        })
    }
    /// Ends the stream cleanly (FIN).
    /// Waits for an operation in progress (a cancelled one releases at once).
    fn finish<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(
            py,
            async move { s.lock().await.finish().map_err(stream_err) },
        )
    }
    /// Abandons the stream with an application error code.
    #[pyo3(signature = (code=0))]
    fn reset<'p>(&self, py: Python<'p>, code: u64) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        let code = varint(code)?;
        future_into_py(
            py,
            async move { s.lock().await.reset(code).map_err(stream_err) },
        )
    }
    fn set_priority(&self, urgency: u8, incremental: bool) -> PyResult<()> {
        self.now()?
            .set_priority(priority(urgency, incremental)?)
            .map_err(stream_err)
    }
    /// Waits until the peer stops the stream; returns its code or `None` once all data was acknowledged.
    fn stopped<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let fut = {
                let g = s.lock().await;
                async move { g.stopped().await }
            };
            fut.await
                .map(|c| c.map(|c| c.into_inner()))
                .map_err(stream_err)
        })
    }
    #[getter]
    fn id(&self) -> PyResult<Option<u64>> {
        Ok(self.now()?.id().map(|i| i.into_inner()))
    }
}

type PreambleTuple<'p> = (Option<Bound<'p, PyBytes>>, Vec<(u64, Bound<'p, PyBytes>)>);

/// The receiving part of a stream.
#[pyclass(frozen, module = "zmux._zmux")]
struct RecvStream(Arc<Mutex<zmux::RecvStream>>);

impl RecvStream {
    fn wrap(s: zmux::RecvStream) -> Self {
        RecvStream(Arc::new(Mutex::new(s)))
    }
    fn now(&self) -> PyResult<tokio::sync::MutexGuard<'_, zmux::RecvStream>> {
        self.0.try_lock().map_err(|_| busy())
    }
}

#[pymethods]
impl RecvStream {
    /// Up to `n` bytes; `b""` at the end of the stream.
    #[pyo3(signature = (n=65536))]
    fn read<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            Ok(s.lock()
                .await
                .read_chunk(n)
                .await
                .map_err(stream_err)?
                .as_deref()
                .map(pyb)
                .unwrap_or_else(|| pyb(b"")))
        })
    }
    /// Exactly `n` bytes, or `IncompleteRead`.
    fn read_exact<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.clone();
        future_into_py(py, async move {
            let mut buf = vec![0u8; n];
            match s.lock().await.read_exact(&mut buf).await {
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
            match s.lock().await.read_to_end(limit).await {
                Ok(v) => Ok(pyb(&v)),
                Err(zmux::ReadToEndError::Read(e)) => Err(stream_err(e)),
                Err(e) => Err(raise::<StreamError>(&e, false, None)),
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
            async move { s.lock().await.stop(code).map_err(stream_err) },
        )
    }
    /// The stream's preamble as `(info, [(type, value), ...])`.
    fn preamble<'p>(&self, py: Python<'p>) -> PyResult<PreambleTuple<'p>> {
        let p = self.now()?.preamble();
        Ok((
            p.info().map(|b| PyBytes::new(py, b)),
            p.tlvs().map(|(t, v)| (t, PyBytes::new(py, &v))).collect(),
        ))
    }
    #[getter]
    fn is_replayable(&self) -> PyResult<bool> {
        Ok(self.now()?.is_replayable())
    }
    #[getter]
    fn id(&self) -> PyResult<Option<u64>> {
        Ok(self.now()?.id().map(|i| i.into_inner()))
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
    #[pyo3(signature = (config=None))]
    fn new(config: Option<PyRef<'_, Config>>) -> Self {
        let _g = get_runtime().enter();
        Listener {
            inner: zmux::Listener::new(cfg(config), zmux::ListenerConfig::default()),
            tasks: Arc::default(),
        }
    }

    /// Serves plain TCP on `addr`; returns the bound address.
    fn serve_tcp<'p>(&self, py: Python<'p>, addr: String) -> PyResult<Bound<'p, PyAny>> {
        self.serve(py, addr, |l, tcp| l.serve(tcp))
    }
    fn serve_tls<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let c = Arc::new(tls.server()?);
        self.serve(py, addr, move |l, tcp| zmux_rustls::serve(l, tcp, c))
    }
    /// HTTP/1.1 and HTTP/2 (prior knowledge, or ALPN with `tls`).
    #[pyo3(signature = (addr, path="/zmux".to_owned(), tls=None))]
    fn serve_http<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        path: String,
        tls: Option<PyRef<'_, TlsConfig>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts = zmux_http::Options::new().with_path(path);
        let Some(tls) = tls else {
            return self.serve(py, addr, move |l, tcp| zmux_http::serve(l, tcp, opts));
        };
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(tls.server_alpn(&[b"h2", HTTP1])?));
        self.serve(py, addr, move |l, tcp| async move {
            zmux_http::serve_with(
                l,
                || tcp.accept(),
                move |conn, _| {
                    let acc = acc.clone();
                    async move { acc.accept(conn).await }
                },
                opts,
            )
            .await
        })
    }
    /// `ws://`, or `wss://` with `tls`.
    #[pyo3(signature = (addr, tls=None))]
    fn serve_websocket<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: Option<PyRef<'_, TlsConfig>>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let Some(tls) = tls else {
            return self.serve(py, addr, |l, tcp| {
                zmux_websocket::serve(l, tcp, zmux_websocket::Options::default())
            });
        };
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(tls.server_alpn(&[HTTP1])?));
        self.serve(py, addr, move |l, tcp| async move {
            l.serve_with(
                || tcp.accept(),
                move |conn, peer| {
                    let acc = acc.clone();
                    async move {
                        let conn = acc.accept(conn).await?;
                        zmux_websocket::accept(conn, Some(peer.ip()), &Default::default()).await
                    }
                },
            )
            .await
        })
    }
    /// HTTP/3 requests to any path carry pipes.
    #[pyo3(signature = (addr, tls, lanes=4))]
    fn serve_h3<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts = zmux_h3::Options::new().with_lanes(lanes);
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
    /// WebTransport sessions carry pipes.
    #[pyo3(signature = (addr, tls, lanes=4))]
    fn serve_webtransport<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
    ) -> PyResult<Bound<'p, PyAny>> {
        let opts = zmux_webtransport::Options::new().with_lanes(lanes);
        let mut c = tls.server()?;
        c.alpn_protocols = vec![wt::ALPN.as_bytes().to_vec()];
        let crypto = wt::quinn::crypto::rustls::QuicServerConfig::try_from(c).map_err(value_err)?;
        let mut sc = wt::quinn::ServerConfig::with_crypto(Arc::new(crypto));
        sc.transport_config(Arc::new(opts.transport_config()));
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = wt::quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = ep.local_addr().map_err(io_err)?.to_string();
            let server = wt::Server::new(ep);
            tasks(tokio::spawn(zmux_webtransport::serve(l, server, opts)));
            Ok(local)
        })
    }
    /// QUIC; with `zero_rtt`, 0-RTT data is accepted when the listener's
    /// `Config(carrier_early_data=True)` allows it.
    #[pyo3(signature = (addr, tls, lanes=4, zero_rtt=false))]
    fn serve_quic<'p>(
        &self,
        py: Python<'p>,
        addr: String,
        tls: PyRef<'_, TlsConfig>,
        lanes: u32,
        zero_rtt: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let mut opts = quic_options(lanes);
        if zero_rtt {
            opts = opts.with_zero_rtt(zmux_quinn::ParameterMemory::new());
        }
        let sc = zmux_quinn::server_config(tls.server()?, &opts)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let l = self.inner.clone();
        let tasks = self.spawner();
        future_into_py(py, async move {
            let addr = resolve(&addr).await?;
            let ep = quinn::Endpoint::server(sc, addr).map_err(io_err)?;
            let local = ep.local_addr().map_err(io_err)?.to_string();
            tasks(tokio::spawn(zmux_quinn::serve(l, ep, opts)));
            Ok(local)
        })
    }

    /// Hands over a carrier accepted by the application (for example `pipe_pair()`).
    fn handle_pipe<'p>(&self, py: Python<'p>, pipe: &PipeIo) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        let io = pipe.take()?;
        future_into_py(py, async move {
            let hint = zmux::PipeHint::from_addr(std::net::Ipv4Addr::LOCALHOST.into());
            l.handle_pipe(io, hint)
                .await
                .map_err(|e| raise::<ConnectError>(&e, false, None))
        })
    }

    /// The next established session, or `None` once closed.
    fn accept<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let l = self.inner.clone();
        future_into_py(py, async move { Ok(l.accept().await.map(Session)) })
    }

    fn close(&self) {
        self.inner.close();
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
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
                .map(Session)
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
    m.add_class::<Config>()?;
    m.add_class::<TlsConfig>()?;
    m.add_class::<PipeIo>()?;
    m.add_class::<PipeEnd>()?;
    m.add_class::<Session>()?;
    m.add_class::<Pipe>()?;
    m.add_class::<SendStream>()?;
    m.add_class::<RecvStream>()?;
    m.add_class::<Listener>()?;
    m.add_class::<PipeReservation>()?;
    m.add_class::<Http2Connection>()?;
    m.add_class::<QuicClient>()?;
    m.add_class::<ZeroRtt>()?;
    m.add_function(wrap_pyfunction!(dial_h3, m)?)?;
    m.add_function(wrap_pyfunction!(dial_webtransport, m)?)?;
    m.add_function(wrap_pyfunction!(pipe_pair, m)?)?;
    m.add_function(wrap_pyfunction!(dial_tcp, m)?)?;
    m.add_function(wrap_pyfunction!(dial_tls, m)?)?;
    m.add_function(wrap_pyfunction!(dial_quic, m)?)?;
    m.add_function(wrap_pyfunction!(dial_websocket, m)?)?;
    m.add_function(wrap_pyfunction!(dial_http, m)?)?;
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
        ("DatagramError", py.get_type::<DatagramError>()),
        ("PipeError", py.get_type::<PipeError>()),
    ] {
        m.add(n, t)?;
    }
    Ok(())
}
