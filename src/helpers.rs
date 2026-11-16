//! The stream helpers of the crate: carrier streams, splicing with Python
//! limiters, and the resolution of duplicate sessions.

use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::rt::{LoopRef, future_into_py};
use crate::{PipeIo, RecvStream, SendStream, Session, kind_of, types};

/// Locks `m`, recovering the data of a poisoned lock: every guarded value is
/// plain state that stays valid when a holder panics, and a panic must not
/// spread to the Python callers that share the lock.
pub(crate) fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A Python `zmux.Limiter` as the Rust limiter of a splice direction. The
/// runtime never calls it itself: its methods run on the loop of the
/// splice, and what they take is held here until the direction uses it.
/// `poll_acquire` asks `acquire(min, max)` on the loop for what is not held
/// and waits for its answer. `try_acquire`, which must answer at once (a
/// datagram passes or is dropped), answers from what is held and asks the
/// loop's `try_acquire` for the shortfall, for the datagrams that follow.
/// What a direction refunds, and what is held when the splice ends, goes
/// back with `refund`. Nothing is answered that the Python limiter did not
/// grant. A failing `acquire` (an exception, or a grant that is not an int
/// in `1..=max`) fails the direction; a failing `try_acquire` grants
/// nothing; a failing `refund` changes nothing. Each failure is reported as
/// unraisable.
struct PyLimiter(Arc<Held>);

/// What a [`PyLimiter`] took from its Python limiter and has not handed on.
struct Held {
    obj: Arc<Py<PyAny>>,
    lp: LoopRef,
    st: StdMutex<HeldState>,
}

#[derive(Default)]
struct HeldState {
    /// Bytes granted and not handed on.
    bytes: u64,
    /// An `acquire` is under way.
    asking: bool,
    /// An `acquire` granted since a `poll_acquire` last took: what is held
    /// is handed on even when it is below the least asked.
    answered: bool,
    /// The failure of the last `acquire`, handed on by the next poll.
    failed: Option<zmux::LimitError>,
    /// A `try_acquire` of the shortfall is under way.
    topping: bool,
    waker: Option<Waker>,
}

impl Held {
    /// Settles an `acquire` on the loop: adds its grant, or keeps its
    /// failure, and wakes the waiting direction.
    fn answer(&self, r: Result<u64, zmux::LimitError>) {
        let waker = {
            let mut st = lock(&self.st);
            match r {
                Ok(n) => st.bytes = st.bytes.saturating_add(n),
                Err(e) => st.failed = Some(e),
            }
            st.asking = false;
            st.answered = true;
            st.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Adds what a `try_acquire` of the shortfall granted, on the loop.
    fn topped(&self, n: u64) {
        let mut st = lock(&self.st);
        st.bytes = st.bytes.saturating_add(n);
        st.topping = false;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let n = std::mem::take(&mut lock(&self.st).bytes);
        if n > 0 {
            let obj = self.obj.clone();
            self.lp.post(move |py| refund(py, &obj, n));
        }
    }
}

/// `refund(n)` of the Python limiter, on its loop; a failure changes
/// nothing.
fn refund(py: Python<'_>, obj: &Py<PyAny>, n: u64) {
    if let Err(e) = obj.call_method1(py, "refund", (n,)) {
        e.write_unraisable(py, Some(obj.bind(py)));
    }
}

/// The grant a limiter call returned, asked for at most `max`: an int in
/// `0..=max`. A grant above `max` is refunded at once.
fn grant(
    py: Python<'_>,
    obj: &Py<PyAny>,
    r: PyResult<Bound<'_, PyAny>>,
    max: u64,
) -> PyResult<u64> {
    let n = r?.extract::<u64>()?;
    if n > max {
        refund(py, obj, n);
        return Err(PyValueError::new_err(format!(
            "the limiter granted {n} bytes, more than the {max} asked"
        )));
    }
    Ok(n)
}

impl PyLimiter {
    fn shared(obj: Py<PyAny>, lp: LoopRef) -> Arc<dyn zmux::Limiter> {
        Arc::new(PyLimiter(Arc::new(Held {
            obj: Arc::new(obj),
            lp,
            st: StdMutex::default(),
        })))
    }
}

impl zmux::Limiter for PyLimiter {
    fn poll_acquire(
        &self,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, zmux::LimitError>> {
        let held = &self.0;
        let mut st = lock(&held.st);
        if let Some(e) = st.failed.take() {
            st.answered = false;
            return Poll::Ready(Err(e));
        }
        // A grant taken meanwhile by `try_acquire` is asked for again.
        if st.bytes >= min || (st.answered && st.bytes > 0) {
            st.answered = false;
            let take = st.bytes.min(max);
            st.bytes -= take;
            return Poll::Ready(Ok(take));
        }
        st.answered = false;
        st.waker = Some(cx.waker().clone());
        if !st.asking {
            st.asking = true;
            // Only what is not held: both stay at least 1, as `min` > held.
            let (lo, hi) = (min - st.bytes, max - st.bytes);
            drop(st);
            let (obj, h, gone) = (held.obj.clone(), held.clone(), held.clone());
            let call = held.lp.settled(
                move |py| obj.bind(py).call_method1("acquire", (lo, hi)),
                move |py, r| {
                    let r = grant(py, &h.obj, r, hi).and_then(|n| {
                        if n == 0 {
                            Err(PyValueError::new_err("the limiter granted 0 bytes"))
                        } else {
                            Ok(n)
                        }
                    });
                    h.answer(r.map_err(|e| {
                        e.clone_ref(py).write_unraisable(py, Some(h.obj.bind(py)));
                        zmux::LimitError::new(e)
                    }));
                    true
                },
                || false,
            );
            // Runs to the answer even when the direction stops waiting:
            // what it grants is held, and refunded at the end. A loop that
            // dropped the call granted nothing.
            tokio::spawn(async move {
                if !call.await {
                    gone.answer(Err(zmux::LimitError::new(PyValueError::new_err(
                        "the event loop dropped the limiter call",
                    ))));
                }
            });
        }
        Poll::Pending
    }

    fn try_acquire(&self, min: u64, max: u64) -> u64 {
        let held = &self.0;
        let mut st = lock(&held.st);
        if st.bytes >= min {
            let take = st.bytes.min(max);
            st.bytes -= take;
            return take;
        }
        if !st.topping {
            st.topping = true;
            let (lo, hi, h) = (min - st.bytes, max - st.bytes, held.clone());
            held.lp.post(move |py| {
                let r = h.obj.bind(py).call_method1("try_acquire", (lo, hi));
                let n = grant(py, &h.obj, r, hi).unwrap_or_else(|e| {
                    e.write_unraisable(py, Some(h.obj.bind(py)));
                    0
                });
                h.topped(n);
            });
        }
        0
    }

    fn refund(&self, n: u64) {
        if n > 0 {
            let obj = self.0.obj.clone();
            self.0.lp.post(move |py| refund(py, &obj, n));
        }
    }
}

/// Aborts the splices given it with a chosen application error code: the
/// first `abort` decides the code and wakes every splice sharing the handle.
#[pyclass(frozen, module = "zmux")]
#[derive(Default)]
pub(crate) struct SpliceAbort(zmux::helpers::SpliceAbort);

#[pymethods]
impl SpliceAbort {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Aborts with `code` (< 2**62, 0 included); later calls change nothing.
    fn abort(&self, code: u64) -> PyResult<()> {
        self.0.abort(crate::varint(code)?);
        Ok(())
    }

    /// The code of the abort, or `None` while not aborted.
    #[getter]
    fn code(&self) -> Option<u64> {
        self.0.code().map(zmux::VarInt::into_inner)
    }

    fn __repr__(&self) -> String {
        match self.code() {
            Some(c) => format!("SpliceAbort(code={c})"),
            None => "SpliceAbort()".to_owned(),
        }
    }
}

/// The parts of a bidirectional stream, taken out of their handles.
pub(crate) fn pair(
    send: &Bound<'_, SendStream>,
    recv: &Bound<'_, RecvStream>,
) -> PyResult<(zmux::SendStream, zmux::RecvStream)> {
    let (s, r) = (&send.get().0, &recv.get().0);
    // Both locks first, so that a failure takes neither part.
    let mut sg = crate::rt::when_free(|| s.try_lock()).map_err(|_| crate::busy())?;
    let mut rg = crate::rt::when_free(|| r.try_lock()).map_err(|_| crate::busy())?;
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

/// A bidirectional stream as a pipe input: one that carries `PIPE_CARRIER`,
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
        E::Cancelled(c) => ("cancelled", Some(c.into_inner())),
        E::LimiterFailed => ("limiter_failed", None),
        other => return Err(PyValueError::new_err(format!("{other:?}"))),
    };
    types(py)?.getattr("Forwarded")?.call1((
        f.bytes,
        f.datagram_bytes,
        f.datagrams_dropped,
        f.datagrams_too_large,
        f.datagrams_limited,
        f.datagrams_as_capsules,
        end,
        code,
    ))
}

/// Forwards two bidirectional streams into each other until both
/// directions ended; the handles are used up.
#[pyfunction]
#[pyo3(signature = (a, b, *, chunk=65536, a_to_b=None, b_to_a=None, abort=None))]
fn splice<'p>(
    py: Python<'p>,
    a: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    b: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    chunk: usize,
    a_to_b: Option<Py<PyAny>>,
    b_to_a: Option<Py<PyAny>>,
    abort: Option<&Bound<'p, SpliceAbort>>,
) -> PyResult<Bound<'p, PyAny>> {
    splice_with(py, a, b, chunk, a_to_b, b_to_a, abort, false)
}

/// Relays two packet streams: `splice`, where a stream datagram that does
/// not fit the next hop goes on as a DATAGRAM capsule.
#[pyfunction]
#[pyo3(signature = (a, b, *, chunk=65536, a_to_b=None, b_to_a=None, abort=None))]
fn splice_packets<'p>(
    py: Python<'p>,
    a: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    b: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    chunk: usize,
    a_to_b: Option<Py<PyAny>>,
    b_to_a: Option<Py<PyAny>>,
    abort: Option<&Bound<'p, SpliceAbort>>,
) -> PyResult<Bound<'p, PyAny>> {
    splice_with(py, a, b, chunk, a_to_b, b_to_a, abort, true)
}

fn splice_with<'p>(
    py: Python<'p>,
    a: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    b: (Bound<'p, SendStream>, Bound<'p, RecvStream>),
    chunk: usize,
    a_to_b: Option<Py<PyAny>>,
    b_to_a: Option<Py<PyAny>>,
    abort: Option<&Bound<'p, SpliceAbort>>,
    packets: bool,
) -> PyResult<Bound<'p, PyAny>> {
    if chunk == 0 {
        return Err(PyValueError::new_err("chunk is at least 1"));
    }
    if a.0.is(&b.0) || a.1.is(&b.1) {
        return Err(PyValueError::new_err(
            "a stream cannot be spliced into itself",
        ));
    }
    let lp = if a_to_b.is_some() || b_to_a.is_some() {
        Some(LoopRef::running(py, "splice with a limiter")?)
    } else {
        None
    };
    let lim =
        |l: Option<Py<PyAny>>| l.map(|o| PyLimiter::shared(o, lp.clone().expect("a running loop")));
    let mut opts = zmux::helpers::SpliceOptions::default();
    opts.chunk = chunk;
    opts.a_to_b = lim(a_to_b);
    opts.b_to_a = lim(b_to_a);
    opts.abort = abort.map(|a| a.get().0.clone());
    let sa = pair(&a.0, &a.1)?;
    let sb = pair(&b.0, &b.1)?;
    future_into_py(py, async move {
        let r = if packets {
            zmux::helpers::splice_packets(sa, sb, opts).await
        } else {
            zmux::helpers::splice(sa, sb, opts).await
        }
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(crate::rt::deferred(move |py| {
            Ok(types(py)?
                .getattr("Spliced")?
                .call1((forwarded(py, &r.a_to_b)?, forwarded(py, &r.b_to_a)?))?
                .unbind())
        }))
    })
}

fn dial_err(e: PyErr) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// `Config(redial=...)`: an async callable given the `Direction` that
/// returns the carrier replacing the lost pipe, run on the Config's loop.
pub(crate) fn redial_of(v: &Bound<'_, PyAny>, lp: &LoopRef) -> zmux::Redial {
    let (f, lp) = (Arc::new(v.clone().unbind()), lp.clone());
    zmux::Redial::new(move |req: zmux::DialRequest| {
        let f = f.clone();
        let need = req.direction;
        let call = call_pipe(&lp, move |py| {
            f.bind(py).call1((crate::direction_obj(py, need),))
        });
        async move { call.await.map_err(dial_err) }
    })
}

/// `f` called on `lp`'s loop and awaited there: the carrier it returns.
pub(crate) fn call_pipe<F>(
    lp: &LoopRef,
    f: F,
) -> impl Future<Output = PyResult<zmux::PipeIo>> + Send + 'static + use<F>
where
    F: for<'py> FnOnce(Python<'py>) -> PyResult<Bound<'py, PyAny>> + Send + 'static,
{
    lp.call(f, |v| v.cast::<PipeIo>()?.get().take())
}

/// Resolves two sessions between the same endpoints that raced (both
/// dialed at once): keeps one, drains the other, and optionally starts a
/// rejoin of the loser's route into the survivor. `ValueError` when the
/// rule does not apply; nothing is changed then.
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
            let call = call_pipe(&lp, move |py| f.bind(py).call0());
            async move { call.await.map_err(dial_err) }
        }));
    }
    let r = {
        let _g = crate::rt::runtime()?.enter();
        zmux::helpers::resolve_duplicate(&s1.get().0, &s2.get().0, &opts)
    }
    .map_err(|e| PyValueError::new_err(e.to_string()))?;
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
    m.add_class::<SpliceAbort>()?;
    m.add_function(wrap_pyfunction!(stream_pipe, m)?)?;
    m.add_function(wrap_pyfunction!(splice, m)?)?;
    m.add_function(wrap_pyfunction!(splice_packets, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_duplicate, m)?)?;
    Ok(())
}
