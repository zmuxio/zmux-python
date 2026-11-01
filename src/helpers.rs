//! The stream helpers of the crate: carrier streams, splicing with Python
//! limiters, and the resolution of duplicate sessions.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3_async_runtimes::TaskLocals;
use pyo3_async_runtimes::tokio::get_current_locals;

use crate::rt::{future_into_py, get_runtime};
use crate::{PipeIo, RecvStream, SendStream, Session, kind_of, types};

type Pending = Pin<Box<dyn Future<Output = PyResult<Py<PyAny>>> + Send>>;

/// A Python `zmux.Limiter` as the Rust limiter of a splice direction: its
/// coroutine `ready` runs on the caller's event loop; an exception allows
/// nothing, as a panicking Rust limiter does.
struct PyLimiter {
    obj: Py<PyAny>,
    locals: TaskLocals,
    pending: StdMutex<Option<Pending>>,
}

impl PyLimiter {
    fn shared(obj: Py<PyAny>, locals: TaskLocals) -> Arc<dyn zmux::Limiter> {
        Arc::new(PyLimiter {
            obj,
            locals,
            pending: StdMutex::new(None),
        })
    }
}

/// The count a limiter call returned; 0 after an exception, which is
/// reported as unraisable.
fn allowance(py: Python<'_>, r: PyResult<Py<PyAny>>) -> usize {
    match r.and_then(|v| v.bind(py).extract::<usize>()) {
        Ok(n) => n,
        Err(e) => {
            e.write_unraisable(py, None);
            0
        }
    }
}

impl zmux::Limiter for PyLimiter {
    fn poll_ready(&self, cx: &mut Context<'_>, min: usize, max: usize) -> Poll<usize> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_none() {
            let started = crate::rt::attach(|py| {
                let coro = self.obj.bind(py).call_method1("ready", (min, max))?;
                crate::rt::into_future(&self.locals, coro)
            });
            match started {
                Ok(f) => *pending = Some(Box::pin(f)),
                Err(e) => return Poll::Ready(crate::rt::attach(|py| allowance(py, Err(e)))),
            }
        }
        let f = pending.as_mut().expect("started");
        match f.as_mut().poll(cx) {
            Poll::Ready(r) => {
                *pending = None;
                Poll::Ready(crate::rt::attach(|py| allowance(py, r)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn try_ready(&self, max: usize) -> usize {
        crate::rt::attach(|py| {
            let r = self.obj.call_method1(py, "try_ready", (max,));
            allowance(py, r)
        })
    }

    fn charge(&self, n: usize) {
        crate::rt::attach(|py| {
            if let Err(e) = self.obj.call_method1(py, "charge", (n,)) {
                e.write_unraisable(py, None);
            }
        });
    }
}

/// The parts of a bidirectional stream, taken out of their handles.
fn pair(
    send: &Bound<'_, SendStream>,
    recv: &Bound<'_, RecvStream>,
) -> PyResult<(zmux::SendStream, zmux::RecvStream)> {
    let (s, r) = (&send.get().0, &recv.get().0);
    // Both locks first, so that a failure takes neither part.
    let mut sg = s.try_lock().map_err(|_| crate::busy())?;
    let mut rg = r.try_lock().map_err(|_| crate::busy())?;
    match (sg.as_ref(), rg.as_ref()) {
        (Some(a), Some(b)) => {
            if let (Some(x), Some(y)) = (a.id(), b.id())
                && x != y
            {
                return Err(PyValueError::new_err("the parts of two different streams"));
            }
        }
        _ => return Err(crate::stream_err(zmux::StreamError::ClosedLocally)),
    }
    Ok((sg.take().expect("checked"), rg.take().expect("checked")))
}

/// A bidirectional stream as a pipe input: one that carries PIPE_CARRIER,
/// or any the application knows to be a carrier. The handles are used up.
#[pyfunction]
fn stream_pipe(send: &Bound<'_, SendStream>, recv: &Bound<'_, RecvStream>) -> PyResult<PipeIo> {
    let (s, r) = pair(send, recv)?;
    Ok(PipeIo::wrap(zmux::PipeIo::from_stream(s, r)))
}

fn forwarded<'p>(py: Python<'p>, f: &zmux::helpers::Forwarded) -> PyResult<Bound<'p, PyAny>> {
    use zmux::helpers::SpliceEnd as E;
    let (end, code) = match f.end {
        E::Finished => ("finished", None),
        E::Reset(c) => ("reset", Some(c.into_inner())),
        E::Stopped(c) => ("stopped", Some(c.into_inner())),
        E::UpstreamLost => ("upstream_lost", None),
        E::DownstreamLost => ("downstream_lost", None),
        other => return Err(PyValueError::new_err(format!("{other:?}"))),
    };
    types(py)?.getattr("Forwarded")?.call1((
        f.bytes,
        f.datagram_bytes,
        f.datagrams_dropped,
        end,
        code,
    ))
}

/// Forwards two bidirectional streams into each other until both
/// directions ended; the handles are used up.
#[pyfunction]
#[pyo3(signature = (a, b, *, chunk=65536, a_to_b=None, b_to_a=None))]
fn splice<'p>(
    py: Python<'p>,
    a: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    b: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    chunk: usize,
    a_to_b: Option<Py<PyAny>>,
    b_to_a: Option<Py<PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    if chunk == 0 {
        return Err(PyValueError::new_err("chunk is at least 1"));
    }
    if a.0.is(&b.0) || a.1.is(&b.1) {
        return Err(PyValueError::new_err(
            "a stream cannot be spliced into itself",
        ));
    }
    let locals = if a_to_b.is_some() || b_to_a.is_some() {
        Some(get_current_locals(py)?)
    } else {
        None
    };
    let lim = |l: Option<Py<PyAny>>| {
        l.map(|o| PyLimiter::shared(o, locals.clone().expect("a running loop")))
    };
    let mut opts = zmux::helpers::SpliceOptions::default();
    opts.chunk = chunk;
    opts.a_to_b = lim(a_to_b);
    opts.b_to_a = lim(b_to_a);
    let sa = pair(&a.0, &a.1)?;
    let sb = pair(&b.0, &b.1)?;
    future_into_py(py, async move {
        let r = zmux::helpers::splice(sa, sb, opts)
            .await
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        crate::rt::attach(|py| {
            Ok(types(py)?
                .getattr("Spliced")?
                .call1((forwarded(py, &r.a_to_b)?, forwarded(py, &r.b_to_a)?))?
                .unbind())
        })
    })
}

fn dial_err(e: PyErr) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Resolves two sessions between the same endpoints that raced (both
/// dialed at once): keeps one, drains the other, and optionally starts a
/// rejoin of the loser's route into the survivor. `ValueError` when the
/// rule does not apply; nothing is changed then.
#[pyfunction]
#[pyo3(signature = (s1, s2, *, local_identity=None, peer_identity=None, rejoin=None))]
fn resolve_duplicate<'p>(
    py: Python<'p>,
    s1: &Session,
    s2: &Session,
    local_identity: Option<Vec<u8>>,
    peer_identity: Option<Vec<u8>>,
    rejoin: Option<Py<PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let mut opts = zmux::helpers::DuplicateOptions::default();
    opts.local_identity = local_identity;
    opts.peer_identity = peer_identity;
    if let Some(f) = rejoin {
        let locals = Arc::new(get_current_locals(py)?);
        opts.rejoin = Some(zmux::Dial::new(move |_req| {
            let (f, locals) = (f.clone_ref_static(), locals.clone());
            async move {
                let fut = crate::rt::attach(|py| {
                    let coro = f.bind(py).call0()?;
                    crate::rt::into_future(&locals, coro)
                })
                .map_err(dial_err)?;
                let obj = fut.await.map_err(dial_err)?;
                crate::rt::attach(|py| obj.bind(py).cast::<PipeIo>()?.get().take())
                    .map_err(dial_err)
            }
        }));
    }
    let r = {
        let _g = get_runtime().enter();
        zmux::helpers::resolve_duplicate(&s1.0, &s2.0, &opts)
    }
    .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let d = PyDict::new(py);
    d.set_item("survivor", Session::new(r.survivor))?;
    d.set_item("loser", Session::new(r.loser))?;
    d.set_item("rule", snake(&kind_of(&r.rule)))?;
    d.set_item("rejoin_started", r.rejoin_started)?;
    types(py)?.getattr("Resolved")?.call((), Some(&d))
}

/// `SessionNonce` as `session_nonce`.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// A `Py` the dial closure can clone without holding the GIL.
trait CloneStatic {
    fn clone_ref_static(&self) -> Self;
}

impl CloneStatic for Py<PyAny> {
    fn clone_ref_static(&self) -> Self {
        crate::rt::attach(|py| self.clone_ref(py))
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(stream_pipe, m)?)?;
    m.add_function(wrap_pyfunction!(splice, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_duplicate, m)?)?;
    Ok(())
}
