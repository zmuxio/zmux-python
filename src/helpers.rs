//! Stream pipes and the resolution of duplicate sessions.

use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::rt::LoopRef;
use crate::{PipeIo, RecvStream, SendStream, Session, kind_of, types};

/// Locks `m`, recovering the data of a poisoned lock: every guarded value is
/// plain state that stays valid when a holder panics, and a panic must not
/// spread to the Python callers that share the lock.
pub(crate) fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

type Handles<'p> = (Bound<'p, SendStream>, Bound<'p, RecvStream>);
type Halves = (zmux::SendStream, zmux::RecvStream);

fn validate_pair(
    send: &zmux::SendStream,
    recv: &zmux::RecvStream,
    unread: &crate::Unread,
) -> PyResult<()> {
    if !send.same_stream(recv) {
        return Err(PyValueError::new_err("the parts of two different streams"));
    }
    if !lock(unread).is_empty() {
        return Err(PyValueError::new_err(
            "read the stream's buffered bytes before transferring it",
        ));
    }
    Ok(())
}

/// The parts of a bidirectional stream, taken out of their handles.
pub(crate) fn pair(send: &Bound<'_, SendStream>, recv: &Bound<'_, RecvStream>) -> PyResult<Halves> {
    crate::take_parts(&send.get().0, &recv.get().0, |s, r| {
        validate_pair(s, r, &recv.get().1)
    })
}

/// Take both streams as one transaction. A busy or invalid half leaves
/// every handle available.
pub(crate) fn splice_pairs(a: &Handles<'_>, b: &Handles<'_>) -> PyResult<(Halves, Halves)> {
    if a.0.is(&b.0) || a.1.is(&b.1) {
        return Err(PyValueError::new_err(
            "a stream cannot be spliced into itself",
        ));
    }
    let (mut sa, mut ra, mut sb, mut rb) = crate::rt::when_free(|| {
        Ok::<_, tokio::sync::TryLockError>((
            a.0.get().0.try_lock()?,
            a.1.get().0.try_lock()?,
            b.0.get().0.try_lock()?,
            b.1.get().0.try_lock()?,
        ))
    })
    .map_err(|_| crate::busy())?;
    validate_pair(
        sa.as_ref().ok_or_else(crate::taken)?,
        ra.as_ref().ok_or_else(crate::taken)?,
        &a.1.get().1,
    )?;
    validate_pair(
        sb.as_ref().ok_or_else(crate::taken)?,
        rb.as_ref().ok_or_else(crate::taken)?,
        &b.1.get().1,
    )?;
    Ok((
        (sa.take().expect("validated"), ra.take().expect("validated")),
        (sb.take().expect("validated"), rb.take().expect("validated")),
    ))
}

/// A bidirectional stream as a pipe input: one that carries `PIPE_CARRIER`,
/// or any the application knows to be a carrier. The handles are used up.
#[pyfunction]
fn stream_pipe(send: &Bound<'_, SendStream>, recv: &Bound<'_, RecvStream>) -> PyResult<PipeIo> {
    let (s, r) = pair(send, recv)?;
    Ok(PipeIo::wrap(zmux::PipeIo::from_stream(s, r)))
}

/// Resolves two sessions between the same endpoints that raced (both
/// dialed at once): keeps one, drains the other, and optionally starts a
/// rejoin of the loser's route into the survivor. `ValueError` when the
/// rule does not apply (`DuplicateUndecidedError`, a `ValueError`); nothing
/// is changed then.
#[pyfunction]
#[pyo3(signature = (s1, s2, *, local_identity=None, peer_identity=None, rejoin=None))]
fn resolve_duplicate<'p>(
    py: Python<'p>,
    s1: &Bound<'p, Session>,
    s2: &Bound<'p, Session>,
    local_identity: Option<Vec<u8>>,
    peer_identity: Option<Vec<u8>>,
    rejoin: Option<Py<PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let mut opts = zmux::helpers::DuplicateOptions::default();
    opts.local_identity = local_identity;
    opts.peer_identity = peer_identity;
    if let Some(f) = rejoin {
        let lp = LoopRef::running(py, "resolve_duplicate with rejoin")?;
        let f = Arc::new(f);
        opts.rejoin = Some(zmux::Dial::new(move |_req| {
            let f = f.clone();
            let call = lp.call(
                move |py| f.bind(py).call0(),
                |v| v.cast::<PipeIo>()?.get().take(),
            );
            async move { call.await.map_err(crate::py_io) }
        }));
    }
    let r = {
        let _g = crate::rt::runtime()?.enter();
        zmux::helpers::resolve_duplicate(&s1.get().0, &s2.get().0, &opts)
    }
    .map_err(|e| crate::new_err("DuplicateUndecidedError", e.to_string()))?;
    let d = PyDict::new(py);
    // The caller's own objects (with their returned-result queues and
    // 0-RTT state), not new wrappers.
    let (first, second) = if r.survivor.stable_id() == s1.get().0.stable_id() {
        (s1, s2)
    } else {
        (s2, s1)
    };
    d.set_item("survivor", first)?;
    d.set_item("loser", second)?;
    d.set_item("rule", snake(&kind_of(&r.rule)))?;
    d.set_item("rejoin_started", r.rejoin_started)?;
    types(py)?.getattr("Resolved")?.call((), Some(&d))
}

/// `SessionNonce` as `session_nonce`.
pub(crate) fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(stream_pipe, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_duplicate, m)?)?;
    Ok(())
}
