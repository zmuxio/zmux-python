//! The secure carrier: `establish`, `SecureServer`, the trust of `PinVerifier`, and
//! hosts' own verifiers and gates in Python, synchronous or `async`.

use std::net::SocketAddr;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use pyo3_async_runtimes::TaskLocals;
use zmux::RecordMode;
use zmux_seal as seal;
use zmux_seal::{BoxFuture, VerifyError};

use crate::rt::{self, future_into_py};
use crate::{PipeIo, admission, types};

/// A record mode a pipe can be given: sealed, bound or trusted.
pub(crate) fn record_mode_of(v: &Bound<'_, PyAny>) -> PyResult<RecordMode> {
    let s: String = v.str()?.extract()?;
    match s.as_str() {
        "sealed" => Ok(RecordMode::Sealed),
        "bound" => Ok(RecordMode::Bound),
        "trusted" => Ok(RecordMode::Trusted),
        _ => Err(PyValueError::new_err(format!(
            "a record mode is sealed, bound or trusted, not {s:?}"
        ))),
    }
}

pub(crate) fn record_mode_obj(py: Python<'_>, m: RecordMode) -> PyResult<Bound<'_, PyAny>> {
    let name = match m {
        RecordMode::Sealed => "SEALED",
        RecordMode::Bound => "BOUND",
        RecordMode::Trusted => "TRUSTED",
        RecordMode::Unmanaged => "UNMANAGED",
    };
    types(py)?.getattr("RecordMode")?.getattr(name)
}

fn source_obj(s: Option<SocketAddr>) -> Option<(String, u16)> {
    s.map(|a| (a.ip().to_string(), a.port()))
}

/// Calls `f` and waits for its result when it is awaitable.
async fn call(
    f: impl for<'p> FnOnce(Python<'p>) -> PyResult<Bound<'p, PyAny>>,
    locals: &TaskLocals,
) -> PyResult<Py<PyAny>> {
    let pending = rt::attach(|py| -> PyResult<_> {
        let r = f(py)?;
        if r.hasattr("__await__")? {
            Ok(Err(rt::into_future(locals, r)?))
        } else {
            Ok(Ok(r.unbind()))
        }
    })?;
    match pending {
        Ok(v) => Ok(v),
        Err(f) => f.await,
    }
}

/// Calls `method` of `target` with `args` and waits for its result when it is awaitable.
async fn call_method(
    target: &Py<PyAny>,
    method: &str,
    locals: &TaskLocals,
    args: impl for<'p> FnOnce(Python<'p>) -> PyResult<Bound<'p, PyTuple>>,
) -> PyResult<Py<PyAny>> {
    call(|py| target.bind(py).call_method1(method, args(py)?), locals).await
}

/// A host's exception as a verification failure: `VerifyUnavailableError` is temporary, any
/// other a rejection.
fn verify_err(e: PyErr) -> VerifyError {
    rt::attach(|py| {
        if e.matches(py, crate::err_type(py, "VerifyUnavailableError"))
            .unwrap_or(false)
        {
            VerifyError::unavailable(e.to_string())
        } else {
            VerifyError::rejected(e.to_string())
        }
    })
}

/// The error of a failed Establish: `NoReplyError` (its `__cause__` the end or the
/// timeout), `ValueError` for a configuration mistake, or the carrier's error.
fn establish_err(e: std::io::Error) -> PyErr {
    let Some(inner) = e.get_ref() else {
        return crate::io_err(e);
    };
    if let Some(c) = inner.downcast_ref::<seal::ConfigError>() {
        return PyValueError::new_err(c.to_string());
    }
    if let Some(n) = inner.downcast_ref::<seal::NoReply>() {
        return rt::attach(|py| {
            let err = crate::new_err("NoReplyError", n.to_string());
            let cause = pyo3::exceptions::PyOSError::new_err(n.0.to_string());
            err.set_cause(py, Some(cause));
            err
        });
    }
    crate::io_err(e)
}

fn principal_obj<'p>(py: Python<'p>, p: &seal::Principal) -> PyResult<Bound<'p, PyAny>> {
    let (kind, code, value): (&str, u16, &[u8]) = match p {
        seal::Principal::StaticKey(k) => ("static_key", 0, k),
        seal::Principal::Other(c, v) => ("other", *c, v),
        _ => ("other", 0, &[]),
    };
    types(py)?
        .getattr("Principal")?
        .call1((kind, PyBytes::new(py, value), code))
}

fn principal_of(v: &Bound<'_, PyAny>) -> PyResult<seal::Principal> {
    let kind: String = v.getattr("kind")?.extract()?;
    let value: Vec<u8> = v.getattr("value")?.extract()?;
    Ok(match kind.as_str() {
        "static_key" => seal::Principal::StaticKey(value),
        "other" => seal::Principal::Other(v.getattr("code")?.extract()?, value),
        k => {
            return Err(PyValueError::new_err(format!(
                "a principal is static_key or other, not {k:?}"
            )));
        }
    })
}

fn verdict_obj<'p>(py: Python<'p>, v: &seal::VerifyVerdict) -> PyResult<Bound<'p, PyAny>> {
    types(py)?.getattr("VerifyVerdict")?.call1((
        principal_obj(py, &v.principal)?,
        v.proof_key.map(|k| PyBytes::new(py, &k)),
        admission::admitted_obj(py, v.value.as_ref()),
    ))
}

fn verdict_of(v: &Bound<'_, PyAny>) -> PyResult<seal::VerifyVerdict> {
    let value = v.getattr("value")?;
    Ok(seal::VerifyVerdict {
        principal: principal_of(&v.getattr("principal")?)?,
        proof_key: v.getattr("proof_key")?.extract()?,
        value: (!value.is_none()).then(|| Arc::new(value.unbind()) as zmux::AdmittedValue),
    })
}

fn app_data_obj<'p>(py: Python<'p>, d: &[seal::AppData]) -> PyResult<Bound<'p, PyTuple>> {
    let cls = types(py)?.getattr("AppData")?;
    let items = d
        .iter()
        .map(|a| {
            cls.call1((
                a.message,
                PyBytes::new(py, &a.data),
                a.forward_secret,
                a.authenticated,
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    PyTuple::new(py, items)
}

fn credential_obj<'p>(
    py: Python<'p>,
    c: Option<(u64, &[u8])>,
) -> Option<(u64, Bound<'p, PyBytes>)> {
    c.map(|(k, b)| (k, PyBytes::new(py, b)))
}

fn verify_input_obj<'p>(py: Python<'p>, i: &seal::VerifyInput<'_>) -> PyResult<Bound<'p, PyAny>> {
    let role = crate::role_obj(py, i.role)?;
    types(py)?.getattr("VerifyInput")?.call1((
        role,
        i.profile.value(),
        PyBytes::new(py, i.peer_static),
        i.psk_identity.map(|h| PyBytes::new(py, h)),
        credential_obj(py, i.credential),
        PyBytes::new(py, i.local_context),
        app_data_obj(py, i.peer_app_data)?,
    ))
}

fn peer_obj<'p>(py: Python<'p>, p: &seal::Peer) -> PyResult<Bound<'p, PyAny>> {
    types(py)?.getattr("Peer")?.call1((
        PyBytes::new(py, &p.static_key),
        credential_obj(py, p.credential.as_ref().map(|(k, c)| (*k, c.as_slice()))),
        p.verdict.as_ref().map(|v| verdict_obj(py, v)).transpose()?,
        p.profile,
        record_mode_obj(py, p.record_mode)?,
        app_data_obj(py, &p.app_data)?,
        p.pq_confidential,
        p.pq_authenticated,
    ))
}

pub(crate) fn session_crypto_of(
    v: &Bound<'_, PyAny>,
) -> PyResult<zmux::proto::seal::SessionCrypto> {
    Ok(zmux::proto::seal::SessionCrypto {
        suites: v.getattr("suites")?.extract()?,
        groups: v.getattr("groups")?.extract()?,
    })
}

/// `session_crypto`: the initiator's and the responder's `SessionCrypto`, encoded, as the
/// join keys take it. A set breaking the parameter's rules raises `ValueError`.
#[pyfunction(name = "session_crypto")]
fn session_crypto_py<'p>(
    py: Python<'p>,
    initiator: &Bound<'p, PyAny>,
    responder: &Bound<'p, PyAny>,
) -> PyResult<Bound<'p, PyBytes>> {
    let b = zmux::proto::seal::session_crypto(
        &session_crypto_of(initiator)?,
        &session_crypto_of(responder)?,
    )
    .map_err(crate::value_err)?;
    Ok(PyBytes::new(py, &b))
}

fn join_role(role: &Bound<'_, PyAny>) -> PyResult<zmux::proto::seal::JoinRole> {
    use zmux::proto::seal::JoinRole;
    match role.str()?.extract::<String>()?.as_str() {
        "client" => Ok(JoinRole::Initiator),
        "server" => Ok(JoinRole::Responder),
        r => Err(PyValueError::new_err(format!(
            "a join role is Role.CLIENT or Role.SERVER, not {r:?}"
        ))),
    }
}

/// `join_psk[e]_x` of `role` (`Role.CLIENT`, the initiator, or `Role.SERVER`) from an epoch secret and `session_crypto`, to the Suite's
/// hash length. An unknown Suite raises `ValueError`.
#[pyfunction]
#[pyo3(signature = (suite, epoch_secret, *, role, session_crypto))]
fn derive_join_psk<'p>(
    py: Python<'p>,
    suite: u64,
    epoch_secret: &[u8],
    role: &Bound<'p, PyAny>,
    session_crypto: &[u8],
) -> PyResult<Bound<'p, PyBytes>> {
    use zmux::proto::seal as ps;
    let suite = ps::Suite::from_value(suite)
        .ok_or_else(|| PyValueError::new_err(format!("unknown Join Suite {suite}")))?;
    let k = ps::derive_join_psk(suite, epoch_secret, join_role(role)?, session_crypto)
        .map_err(crate::value_err)?;
    Ok(PyBytes::new(py, &k))
}

/// The Expand of `derive_join_psk` for any Suite value and an output length.
#[pyfunction]
#[pyo3(signature = (suite, epoch_secret, *, role, session_crypto, length))]
fn expand_join_psk<'p>(
    py: Python<'p>,
    suite: u64,
    epoch_secret: &[u8],
    role: &Bound<'p, PyAny>,
    session_crypto: &[u8],
    length: usize,
) -> PyResult<Bound<'p, PyBytes>> {
    let k = zmux::proto::seal::expand_join_psk(
        suite,
        epoch_secret,
        join_role(role)?,
        session_crypto,
        length,
    )
    .map_err(crate::value_err)?;
    Ok(PyBytes::new(py, &k))
}

/// The Handle and the pre-shared key of a secret.
#[pyfunction]
#[pyo3(signature = (secret, domain, context=b"".to_vec()))]
fn derive_handle_psk<'p>(
    py: Python<'p>,
    secret: &[u8],
    domain: &[u8],
    context: Vec<u8>,
) -> PyResult<(Bound<'p, PyBytes>, Bound<'p, PyBytes>)> {
    let k = seal::derive_handle_psk(secret, domain, &context).map_err(crate::value_err)?;
    Ok((PyBytes::new(py, &k.handle), PyBytes::new(py, &k.psk)))
}

/// The `KeyId` of a static key, for `PinVerifier`.
#[pyfunction]
fn static_key_id<'p>(py: Python<'p>, key: &[u8]) -> Bound<'p, PyBytes> {
    PyBytes::new(py, &seal::static_key_id(key))
}

/// The X25519 public key of a 32-byte static secret, as `static_key_id` names it.
#[pyfunction]
fn static_public(py: Python<'_>, secret: [u8; 32]) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &seal::static_public(&secret))
}

/// The `KeyId` of a key of `key_alg`: what a pin and a verdict name it by.
#[pyfunction]
fn key_id<'p>(py: Python<'p>, key_alg: u64, key: &[u8]) -> Bound<'p, PyBytes> {
    PyBytes::new(py, &seal::key_id(key_alg, key))
}

/// Trusts the one static key with this 32-byte `KeyId`; a credential is not looked at.
/// With `proof_key`, the peer must also prove the transcript with that key.
#[pyclass(frozen, module = "zmux")]
struct PinVerifier(Arc<dyn seal::Verifier>);

#[pymethods]
impl PinVerifier {
    #[new]
    #[pyo3(signature = (key_id, *, proof_key=None))]
    fn new(key_id: [u8; 32], proof_key: Option<[u8; 32]>) -> Self {
        Self(Arc::new(match proof_key {
            None => seal::PinVerifier::new(key_id),
            Some(p) => seal::PinVerifier::with_proof_key(key_id, p),
        }))
    }
}

/// A signing key of this process for the transcript proof, a `Signer` itself.
#[pyclass(frozen, module = "zmux")]
struct SigningKey(Arc<seal::KeySigner>);

#[pymethods]
impl SigningKey {
    /// A new key of `key_alg`; an algorithm that cannot sign raises `ValueError`.
    #[staticmethod]
    #[pyo3(signature = (key_alg=seal::KEYALG_MLDSA44))]
    fn generate(key_alg: u64) -> PyResult<Self> {
        let k = seal::SigningKey::generate(key_alg).map_err(crate::value_err)?;
        Ok(Self(Arc::new(seal::KeySigner(k))))
    }

    /// The key of `key_alg` from its seed.
    #[staticmethod]
    fn from_seed(key_alg: u64, seed: &[u8]) -> PyResult<Self> {
        let k = seal::SigningKey::from_seed(key_alg, seed).map_err(crate::value_err)?;
        Ok(Self(Arc::new(seal::KeySigner(k))))
    }

    #[getter]
    fn key_alg(&self) -> u64 {
        self.0.0.key_alg()
    }

    #[getter]
    fn public<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
        PyBytes::new(py, self.0.0.public())
    }

    #[getter]
    fn key_id<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
        PyBytes::new(py, &self.0.0.key_id())
    }

    #[getter]
    fn proof_key<'p>(&self, py: Python<'p>) -> (u64, Bound<'p, PyBytes>) {
        (self.key_alg(), self.public(py))
    }

    fn sign<'p>(&self, py: Python<'p>, message: &[u8]) -> PyResult<Bound<'p, PyBytes>> {
        let sig = self.0.0.sign(message).map_err(crate::value_err)?;
        Ok(PyBytes::new(py, &sig))
    }
}

/// A host's signer: `proof_key` is `(key_alg, public key)`, and `sign(message)` returns
/// the signature, synchronously or `async`.
struct PySigner {
    obj: Py<PyAny>,
    locals: TaskLocals,
    key_alg: u64,
    public: Vec<u8>,
}

impl seal::Signer for PySigner {
    fn proof_key(&self) -> (u64, &[u8]) {
        (self.key_alg, &self.public)
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, std::io::Result<Vec<u8>>> {
        Box::pin(async move {
            let r = call_method(&self.obj, "sign", &self.locals, |py| {
                (PyBytes::new(py, message),).into_pyobject(py)
            })
            .await
            .map_err(std::io::Error::other)?;
            rt::attach(|py| r.bind(py).extract::<Vec<u8>>()).map_err(std::io::Error::other)
        })
    }
}

fn signer_of(v: &Bound<'_, PyAny>, locals: &TaskLocals) -> PyResult<Arc<dyn seal::Signer>> {
    if let Ok(k) = v.cast::<SigningKey>() {
        return Ok(k.get().0.clone());
    }
    let (key_alg, public): (u64, Vec<u8>) = v.getattr("proof_key")?.extract()?;
    Ok(Arc::new(PySigner {
        obj: v.clone().unbind(),
        locals: locals.clone(),
        key_alg,
        public,
    }))
}

/// A host's verifier: an object with `verify(input)` returning a `VerifyVerdict`, or
/// raising `VerifyRejectedError` or `VerifyUnavailableError`; any other exception rejects.
struct PyVerifier(Py<PyAny>, TaskLocals);

impl seal::Verifier for PyVerifier {
    fn verify<'a>(
        &'a self,
        input: seal::VerifyInput<'a>,
    ) -> BoxFuture<'a, Result<seal::VerifyVerdict, VerifyError>> {
        Box::pin(async move {
            let r = call_method(&self.0, "verify", &self.1, |py| {
                (verify_input_obj(py, &input)?,).into_pyobject(py)
            })
            .await
            .map_err(verify_err)?;
            rt::attach(|py| verdict_of(r.bind(py))).map_err(verify_err)
        })
    }
}

fn verifier_of(v: &Bound<'_, PyAny>, locals: &TaskLocals) -> Arc<dyn seal::Verifier> {
    if let Ok(a) = v.cast::<PinVerifier>() {
        return a.get().0.clone();
    }
    Arc::new(PyVerifier(v.clone().unbind(), locals.clone()))
}

/// An `app_data=` callable: `(message, peer, verdict)` returning `bytes` or `None`,
/// synchronously or `async`; `peer` is the `VerifyInput` known by then, `None` for
/// message 1, and `verdict` the client's verifier's on the server for message 3, `None`
/// otherwise. An exception fails the handshake.
fn app_data_of(f: &Bound<'_, PyAny>, locals: &TaskLocals) -> seal::AppDataSource {
    let f = Arc::new(f.clone().unbind());
    let locals = locals.clone();
    Arc::new(
        move |r: &seal::AppDataRequest<'_>| -> BoxFuture<'static, Result<Vec<u8>, VerifyError>> {
            let started = rt::attach(|py| -> PyResult<_> {
                let peer = r.peer.map(|i| verify_input_obj(py, i)).transpose()?;
                let verdict = r.verdict.map(|v| verdict_obj(py, v)).transpose()?;
                let out = f.bind(py).call1((r.message, peer, verdict))?;
                if out.hasattr("__await__")? {
                    Ok(Err(rt::into_future(&locals, out)?))
                } else {
                    Ok(Ok(out.unbind()))
                }
            });
            Box::pin(async move {
                let v = match started.map_err(verify_err)? {
                    Ok(v) => v,
                    Err(pending) => pending.await.map_err(verify_err)?,
                };
                rt::attach(|py| {
                    let v = v.bind(py);
                    if v.is_none() {
                        Ok(Vec::new())
                    } else {
                        v.extract::<Vec<u8>>()
                    }
                })
                .map_err(verify_err)
            })
        },
    )
}

/// The client's static secret: `zmux.AUTO` the process's key, else 32 bytes.
fn static_secret(v: &Bound<'_, PyAny>) -> PyResult<seal::StaticSecret> {
    if crate::is_setting(v, "AUTO")? {
        return Ok(seal::StaticSecret::Process);
    }
    Ok(seal::StaticSecret::Given(v.extract()?))
}

/// Runs the client's handshake on `pipe`: the carrier for `Session.connect`, with what it
/// learned of the server. On a failure the carrier is closed; nothing is retried.
#[pyfunction]
#[pyo3(signature = (pipe, *, verifier=None, allow_psk_only=false, handle=b"".to_vec(), psk=b"".to_vec(),
    static_secret=None, allowed_profiles=None, record_mode=None, credential=None,
    local_context=b"".to_vec(), app_data=None, max_app_data=Some(seal::DEFAULT_MAX_APP_DATA),
    require_pq_auth=false, signer=None, shaper=None,
    shaping_limits=None, reply_timeout=Some(10.0)),
    text_signature = "(pipe, *, verifier=None, allow_psk_only=False, handle=b'', psk=b'', \
        static_secret=None, allowed_profiles=None, record_mode=None, credential=None, \
        local_context=b'', app_data=None, max_app_data=256, require_pq_auth=False, \
        signer=None, shaper=None, shaping_limits=None, reply_timeout=10.0)")]
#[allow(clippy::too_many_arguments)]
fn establish<'p>(
    py: Python<'p>,
    pipe: &PipeIo,
    verifier: Option<Bound<'p, PyAny>>,
    allow_psk_only: bool,
    handle: Vec<u8>,
    psk: Vec<u8>,
    static_secret: Option<Bound<'p, PyAny>>,
    allowed_profiles: Option<Vec<u64>>,
    record_mode: Option<Bound<'p, PyAny>>,
    credential: Option<(u64, Vec<u8>)>,
    local_context: Vec<u8>,
    app_data: Option<Bound<'p, PyAny>>,
    max_app_data: Option<usize>,
    require_pq_auth: bool,
    signer: Option<Bound<'p, PyAny>>,
    shaper: Option<Bound<'p, PyAny>>,
    shaping_limits: Option<Bound<'p, PyAny>>,
    reply_timeout: Option<f64>,
) -> PyResult<Bound<'p, PyAny>> {
    let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
    let reply_timeout = reply_timeout
        .map(|s| crate::seconds("reply_timeout", s))
        .transpose()?;
    let cfg = seal::ClientConfig {
        verifier: verifier.map(|a| verifier_of(&a, &locals)),
        allow_psk_only,
        handle,
        psk,
        static_secret: match &static_secret {
            Some(v) => self::static_secret(v)?,
            None => seal::StaticSecret::Process,
        },
        allowed_profiles: allowed_profiles
            .unwrap_or_else(|| seal::ClientConfig::default().allowed_profiles),
        record_mode: match &record_mode {
            Some(m) => record_mode_of(m)?,
            None => RecordMode::Sealed,
        },
        credential,
        local_context,
        app_data: app_data.map(|f| app_data_of(&f, &locals)),
        max_app_data,
        require_pq_auth,
        signer: signer.map(|s| signer_of(&s, &locals)).transpose()?,
        shaper: shaper.as_ref().map(crate::shaping::hook_of),
        shaping_limits: shaping_limits
            .as_ref()
            .map(crate::shaping::limits_of)
            .transpose()?,
        reply_timeout,
    };
    let io = pipe.take()?;
    future_into_py(py, async move {
        let (io, peer) = seal::establish(io, &cfg).await.map_err(establish_err)?;
        rt::attach(|py| -> PyResult<Py<PyAny>> {
            let out = (Py::new(py, PipeIo::wrap(io))?, peer_obj(py, &peer)?);
            Ok(out.into_pyobject(py)?.into_any().unbind())
        })
    })
}

/// A host's gate: `resolve(handle, source)` returning the pre-shared key,
/// `credential(handle, profile, local_context, source)` returning `(type, bytes)` or
/// `None`, and `commit(handle, peer, source)` whose result is the session's `admitted`.
/// Each raises `VerifyRejectedError` or `VerifyUnavailableError` to refuse; any other exception
/// is a rejection.
struct PyGate(Py<PyAny>, TaskLocals);

impl seal::Gate for PyGate {
    fn resolve<'a>(
        &'a self,
        handle: &'a [u8],
        source: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>> {
        Box::pin(async move {
            let r = call_method(&self.0, "resolve", &self.1, |py| {
                (PyBytes::new(py, handle), source_obj(source)).into_pyobject(py)
            })
            .await
            .map_err(verify_err)?;
            rt::attach(|py| r.bind(py).extract::<Vec<u8>>()).map_err(verify_err)
        })
    }

    fn credential<'a>(
        &'a self,
        handle: &'a [u8],
        profile: seal::Profile,
        local_context: &'a [u8],
        source: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Option<seal::Credential>, VerifyError>> {
        Box::pin(async move {
            let r = call_method(&self.0, "credential", &self.1, |py| {
                (
                    PyBytes::new(py, handle),
                    profile.value(),
                    PyBytes::new(py, local_context),
                    source_obj(source),
                )
                    .into_pyobject(py)
            })
            .await
            .map_err(verify_err)?;
            rt::attach(|py| r.bind(py).extract::<Option<seal::Credential>>()).map_err(verify_err)
        })
    }

    fn commit<'a>(
        &'a self,
        admission: seal::Admission<'a>,
        source: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<zmux::AdmittedValue, VerifyError>> {
        Box::pin(async move {
            let r = call_method(&self.0, "commit", &self.1, |py| {
                (
                    PyBytes::new(py, admission.handle),
                    peer_obj(py, admission.peer)?,
                    source_obj(source),
                )
                    .into_pyobject(py)
            })
            .await
            .map_err(verify_err)?;
            Ok(Arc::new(r) as zmux::AdmittedValue)
        })
    }
}

/// The server's side of Establish, for `Listener(secure_server=...)`.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct SecureServer {
    gate: Py<PyAny>,
    static_key: [u8; 32],
    accepted_profiles: Vec<u64>,
    allow_record_mode: Option<Arc<Py<PyAny>>>,
    shaper: Option<zmux::shaping::HandshakeShaper>,
    shaping_limits: Option<zmux::shaping::Limits>,
    client_verifier: Option<Py<PyAny>>,
    local_context: Vec<u8>,
    require_pq_auth: bool,
    signer: Option<Py<PyAny>>,
    app_data: Option<Py<PyAny>>,
    max_app_data: Option<usize>,
}

/// A gate that is never asked: the stand-in of the constructor's validation.
struct NoGate;

impl seal::Gate for NoGate {
    fn resolve<'a>(
        &'a self,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>> {
        Box::pin(async { Err(VerifyError::unavailable("unused")) })
    }
    fn credential<'a>(
        &'a self,
        _: &'a [u8],
        _: seal::Profile,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Option<seal::Credential>, VerifyError>> {
        Box::pin(async { Err(VerifyError::unavailable("unused")) })
    }
    fn commit<'a>(
        &'a self,
        _: seal::Admission<'a>,
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<zmux::AdmittedValue, VerifyError>> {
        Box::pin(async { Err(VerifyError::unavailable("unused")) })
    }
}

#[pymethods]
impl SecureServer {
    /// Checked here: an unknown or reserved Profile or an empty list in
    /// `accepted_profiles` (unset: 1 and 3; list 4 or 5 to accept a Profile without a pre-shared key), a key
    /// of zeros, and `require_pq_auth` without a client verifier or with a pin of a static
    /// key alone raise `ValueError`.
    #[new]
    #[pyo3(signature = (gate, static_key, *, accepted_profiles=None, allow_record_mode=None,
        shaper=None, shaping_limits=None, client_verifier=None, local_context=b"".to_vec(),
        require_pq_auth=false, signer=None, app_data=None,
        max_app_data=Some(seal::DEFAULT_MAX_APP_DATA)))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        gate: Py<PyAny>,
        static_key: [u8; 32],
        accepted_profiles: Option<Vec<u64>>,
        allow_record_mode: Option<Py<PyAny>>,
        shaper: Option<&Bound<'_, PyAny>>,
        shaping_limits: Option<&Bound<'_, PyAny>>,
        client_verifier: Option<Py<PyAny>>,
        local_context: Vec<u8>,
        require_pq_auth: bool,
        signer: Option<Py<PyAny>>,
        app_data: Option<Py<PyAny>>,
        max_app_data: Option<usize>,
    ) -> PyResult<Self> {
        if let Some(s) = &signer
            && !s.bind(py).is_instance_of::<SigningKey>()
        {
            // A host's signer names its key up front.
            let _: (u64, Vec<u8>) = s.bind(py).getattr("proof_key")?.extract()?;
        }
        let this = Self {
            gate,
            static_key,
            accepted_profiles: accepted_profiles
                .unwrap_or_else(|| seal::ServerOptions::default().accepted_profiles),
            allow_record_mode: allow_record_mode.map(Arc::new),
            shaper: shaper.map(crate::shaping::hook_of),
            shaping_limits: shaping_limits.map(crate::shaping::limits_of).transpose()?,
            client_verifier,
            local_context,
            require_pq_auth,
            signer,
            app_data,
            max_app_data,
        };
        // Validated without a running loop: the callables are not asked here.
        let pin_only = this.client_verifier.as_ref().and_then(|v| {
            v.bind(py)
                .cast::<PinVerifier>()
                .ok()
                .map(|p| p.get().0.clone())
        });
        let verifier = match (&this.client_verifier, pin_only) {
            (None, _) => None,
            (Some(_), Some(pin)) => Some(pin),
            (Some(_), None) => Some(Arc::new(Unasked) as Arc<dyn seal::Verifier>),
        };
        this.server(Arc::new(NoGate), None, verifier, None, None)?;
        Ok(this)
    }
}

/// A host's verifier at validation: it is never asked.
struct Unasked;

impl seal::Verifier for Unasked {
    fn verify<'a>(
        &'a self,
        _: seal::VerifyInput<'a>,
    ) -> BoxFuture<'a, Result<seal::VerifyVerdict, VerifyError>> {
        Box::pin(async { Err(VerifyError::unavailable("unused")) })
    }
}

impl SecureServer {
    pub(crate) fn transform(
        &self,
        py: Python<'_>,
        locals: TaskLocals,
    ) -> PyResult<zmux::InboundTransform> {
        let check = self
            .allow_record_mode
            .clone()
            .map(|f| -> Arc<seal::ModeCheck> {
                Arc::new(move |mode, peer| {
                    rt::attach(|py| {
                        let asked = (|| -> PyResult<bool> {
                            f.bind(py)
                                .call1((record_mode_obj(py, mode)?, peer_obj(py, peer)?))?
                                .extract()
                        })();
                        asked.unwrap_or_else(|e| {
                            e.write_unraisable(py, Some(f.bind(py)));
                            false
                        })
                    })
                })
            });
        let verifier = self
            .client_verifier
            .as_ref()
            .map(|v| verifier_of(v.bind(py), &locals));
        let signer = self
            .signer
            .as_ref()
            .map(|s| signer_of(s.bind(py), &locals))
            .transpose()?;
        let app_data = self
            .app_data
            .as_ref()
            .map(|f| app_data_of(f.bind(py), &locals));
        Ok(self
            .server(
                Arc::new(PyGate(self.gate.clone_ref(py), locals)),
                check,
                verifier,
                signer,
                app_data,
            )?
            .transform())
    }

    fn server(
        &self,
        gate: Arc<dyn seal::Gate>,
        check: Option<Arc<seal::ModeCheck>>,
        client_verifier: Option<Arc<dyn seal::Verifier>>,
        signer: Option<Arc<dyn seal::Signer>>,
        app_data: Option<seal::AppDataSource>,
    ) -> PyResult<seal::ServerConfig> {
        let o = seal::ServerOptions {
            accepted_profiles: self.accepted_profiles.clone(),
            allow_record_mode: check,
            shaper: self.shaper.clone(),
            shaping_limits: self.shaping_limits,
            client_verifier,
            local_context: self.local_context.clone(),
            require_pq_auth: self.require_pq_auth,
            signer,
            app_data,
            max_app_data: self.max_app_data,
        };
        seal::ServerConfig::new(gate, self.static_key, o).map_err(crate::value_err)
    }
}

/// The verdict of a Python `on_reject`; one that raises closes the carrier.
pub(crate) fn on_reject(f: Py<PyAny>) -> zmux::proto::listener::OnReject {
    use zmux::proto::listener::RejectAction;
    zmux::proto::listener::OnReject::new(move |info| {
        rt::attach(|py| {
            let asked = (|| -> PyResult<String> {
                let mode = info
                    .record_mode
                    .map(|m| record_mode_obj(py, m))
                    .transpose()?;
                let i = types(py)?.getattr("RejectInfo")?.call1((
                    info.profile,
                    mode,
                    info.reason,
                    source_obj(info.source),
                ))?;
                let r = f.bind(py).call1((i,))?;
                r.str()?.extract()
            })();
            match asked.as_deref() {
                Ok("stall") => RejectAction::Stall,
                Ok(_) => RejectAction::Close,
                Err(e) => {
                    e.clone_ref(py).write_unraisable(py, Some(f.bind(py)));
                    RejectAction::Close
                }
            }
        })
    })
}

/// `Config(record_policy=...)`: called with the carrier's description.
pub(crate) fn record_policy(f: Py<PyAny>) -> zmux::RecordPolicy {
    zmux::RecordPolicy::new(move |c| {
        rt::attach(|py| {
            let asked = (|| -> PyResult<RecordMode> {
                record_mode_of(&f.bind(py).call1((description(py, c)?,))?)
            })();
            asked.unwrap_or_else(|e| {
                e.write_unraisable(py, Some(f.bind(py)));
                RecordMode::Sealed
            })
        })
    })
}

/// `Config(allow_record_mode=...)`: called with the carrier, the mode and the session's
/// host value.
pub(crate) fn allow_record_mode(f: Py<PyAny>) -> zmux::AllowRecordMode {
    zmux::AllowRecordMode::new(move |c, mode, admitted| {
        rt::attach(|py| {
            let asked = (|| -> PyResult<bool> {
                let v = admission::admitted_obj(py, admitted);
                f.bind(py)
                    .call1((description(py, c)?, record_mode_obj(py, mode)?, v))?
                    .extract()
            })();
            asked.unwrap_or_else(|e| {
                e.write_unraisable(py, Some(f.bind(py)));
                false
            })
        })
    })
}

fn description<'p>(py: Python<'p>, c: &zmux::RecordPolicyInput) -> PyResult<Bound<'p, PyAny>> {
    types(py)?.getattr("RecordPolicyInput")?.call1((
        c.has_exporter,
        c.secure,
        c.label.as_deref(),
        c.is_first_pipe,
    ))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PinVerifier>()?;
    m.add_class::<SigningKey>()?;
    m.add("_KEYALG_X25519", seal::KEYALG_X25519)?;
    m.add("_KEYALG_MLDSA44", seal::KEYALG_MLDSA44)?;
    m.add("DEFAULT_MAX_APP_DATA", seal::DEFAULT_MAX_APP_DATA)?;
    m.add_function(wrap_pyfunction!(key_id, m)?)?;
    m.add_function(wrap_pyfunction!(static_public, m)?)?;
    m.add_class::<SecureServer>()?;
    m.add_function(wrap_pyfunction!(static_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(derive_handle_psk, m)?)?;
    m.add_function(wrap_pyfunction!(session_crypto_py, m)?)?;
    m.add_function(wrap_pyfunction!(derive_join_psk, m)?)?;
    m.add_function(wrap_pyfunction!(expand_join_psk, m)?)?;
    m.add_function(wrap_pyfunction!(establish, m)?)?;
    Ok(())
}
