//! The binding's runtime and its bridge to asyncio.
//!
//! Each event loop has one completion queue ([`Queue`]): a runtime task that
//! ends pushes a job, a Rust closure with its Rust result, and the loop runs
//! the jobs on its own thread, where the results become Python objects and
//! complete the asyncio futures. A queue that turns non-empty wakes its loop
//! once, with a byte on a socket pair the loop reads (`add_reader`), so the
//! runtime's threads do not enter Python to complete an operation. A loop
//! without `add_reader` (the proactor loop on Windows) is woken by a helper
//! thread with `call_soon_threadsafe`.
//!
//! Python's hooks run on a loop too: an observing hook reads a subscription
//! there ([`LoopRef::observe`]), a deciding one answers later
//! ([`LoopRef::decide`]). The few hooks the Rust crates ask synchronously on
//! a runtime thread call Python on that thread, through [`hook`], whose
//! gate closes at exit.

use std::cell::RefCell;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex, OnceLock, mpsc};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyBaseException, PyNotImplementedError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyWeakrefReference};
use pyo3::{PyErrArguments, intern};
use tokio::sync::oneshot;

use crate::helpers::lock;

// ---- the runtime ----------------------------------------------------------------------

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
/// Set in a child forked after the runtime started: its threads are gone.
static FORKED: AtomicBool = AtomicBool::new(false);

/// The runtime, started on first use; `RuntimeError` in a child forked
/// after that, where its threads do not exist.
pub(crate) fn runtime() -> PyResult<&'static tokio::runtime::Runtime> {
    if FORKED.load(Ordering::Relaxed) {
        return Err(PyRuntimeError::new_err(
            "zmux was used before this process forked; the child cannot use it \
             (use it only after the fork, or start the child with spawn)",
        ));
    }
    Ok(RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("zmux")
            .build()
            .expect("the runtime starts")
    }))
}

/// `os.register_at_fork(after_in_child=...)`.
#[pyfunction(name = "_forked")]
fn forked() {
    if RUNTIME.get().is_some() {
        FORKED.store(true, Ordering::Relaxed);
    }
}

// ---- the gate of the synchronous hooks ------------------------------------------------

/// Threads inside [`hook`], and whether the interpreter is exiting.
#[derive(Default)]
struct Gate {
    inside: usize,
    exiting: bool,
}

static GATE: StdMutex<Gate> = StdMutex::new(Gate {
    inside: 0,
    exiting: false,
});
static LEFT: Condvar = Condvar::new();
/// How long the `atexit` hook waits for the calls under way.
const EXIT_WAIT: Duration = Duration::from_secs(1);

/// Runs `f` with the interpreter, from a thread of the runtime (a
/// synchronous hook of the Rust crates, the helper thread); `None` once
/// the interpreter is exiting. `CPython` must not be entered from another
/// thread once it is finalizing: before 3.14 such a thread is ended inside
/// `PyGILState_Ensure` (with `pthread_exit`, which unwinds through Rust
/// frames). The `atexit` hook, registered when the module is imported and
/// so run after the application's own hooks and before finalization,
/// closes the gate and waits (bounded) for the calls under way.
pub(crate) fn hook<F, R>(f: F) -> Option<R>
where
    F: for<'py> FnOnce(Python<'py>) -> R,
{
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            lock(&GATE).inside -= 1;
            LEFT.notify_all();
        }
    }
    {
        let mut g = lock(&GATE);
        if g.exiting {
            return None;
        }
        g.inside += 1;
    }
    let _leave = Leave;
    Some(Python::attach(f))
}

/// [`hook`], or `exiting` once the interpreter is exiting.
pub(crate) fn hook_or<F, R>(exiting: R, f: F) -> R
where
    F: for<'py> FnOnce(Python<'py>) -> R,
{
    hook(f).unwrap_or(exiting)
}

/// The error of a hook called while the interpreter exits.
pub(crate) fn exiting() -> PyErr {
    PyRuntimeError::new_err("the interpreter is exiting")
}

/// The `atexit` hook: closes the gate, then waits, detached, for the calls
/// inside it.
#[pyfunction(name = "_shutdown")]
fn shutdown(py: Python<'_>) {
    py.detach(|| {
        let mut g = lock(&GATE);
        g.exiting = true;
        let _ = LEFT.wait_timeout_while(g, EXIT_WAIT, |g| g.inside > 0);
    });
}

// ---- the helper thread ----------------------------------------------------------------

/// Wakes `q`'s loop, which cannot watch a socket, from the helper thread:
/// the one thread of the binding that enters Python on its own.
fn wake_from_helper(q: Arc<Queue>) {
    static HELPER: OnceLock<Option<mpsc::Sender<Arc<Queue>>>> = OnceLock::new();
    let sender = HELPER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Arc<Queue>>();
        std::thread::Builder::new()
            .name("zmux-wake".into())
            .spawn(move || {
                while let Ok(first) = rx.recv() {
                    // Once the interpreter exits, nothing is woken.
                    let ran = hook(|py| {
                        wake(py, &first);
                        while let Ok(next) = rx.try_recv() {
                            wake(py, &next);
                        }
                    });
                    if ran.is_none() {
                        return;
                    }
                }
            })
            .ok()
            .map(|_| tx)
    });
    if let Some(tx) = sender {
        let _ = tx.send(q);
    }
}

fn wake(py: Python<'_>, q: &Arc<Queue>) {
    if let Wake::Thread(lp) = &q.wake {
        // A closed loop raises: nobody awaits its futures any more.
        let drain = Drain::new(q.clone(), false);
        // A closed loop raises, and the drain dropped unrun closes the queue.
        let _ = lp.call_method1(py, intern!(py, "call_soon_threadsafe"), (drain,));
    }
}

/// Registers the `atexit` and fork hooks; called once, from the module's
/// initialization.
pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_function(wrap_pyfunction!(shutdown, m)?)?;
    m.add_function(wrap_pyfunction!(forked, m)?)?;
    py.import("atexit")?
        .call_method1("register", (m.getattr("_shutdown")?,))?;
    let kw = pyo3::types::PyDict::new(py);
    kw.set_item("after_in_child", m.getattr("_forked")?)?;
    // Absent where processes do not fork.
    if let Ok(at_fork) = py.import("os")?.getattr("register_at_fork") {
        at_fork.call((), Some(&kw))?;
    }
    Ok(())
}

// ---- the completion queue -------------------------------------------------------------

/// Work for a loop's thread, with the interpreter.
type Job = Box<dyn for<'py> FnOnce(Python<'py>) + Send>;

/// The socket of a loop's wake-ups.
#[cfg(unix)]
type Sock = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Sock = std::net::TcpStream;

/// How a queue wakes its loop.
enum Wake {
    /// A byte written to the first socket: the loop watches the second.
    /// `None` once the queue closed, which lets go of both.
    Socket(StdMutex<Option<(Sock, Sock)>>),
    /// `call_soon_threadsafe` on the loop, from the helper thread.
    Thread(Py<PyAny>),
}

/// The completion queue of one event loop. It closes with its loop
/// ([`Queue::close`]): the jobs queued are dropped then, and so is every
/// job pushed after, so what waits for one (a hook's answer, a delivery)
/// sees it dropped at once instead of waiting for a loop that never runs.
pub(crate) struct Queue {
    /// `None` once closed.
    jobs: StdMutex<Option<Vec<Job>>>,
    /// A wake-up is under way: the loop drains the queue soon.
    armed: AtomicBool,
    wake: Wake,
}

impl Queue {
    /// Runs `job` on the loop's thread. Never enters Python.
    /// Dropped, outside the lock, once the queue closed.
    pub(crate) fn push(self: &Arc<Self>, job: Job) {
        let refused = match &mut *lock(&self.jobs) {
            Some(jobs) => {
                jobs.push(job);
                None
            }
            None => Some(job),
        };
        if refused.is_some() {
            return;
        }
        if self.armed.swap(true, Ordering::AcqRel) {
            return;
        }
        match &self.wake {
            Wake::Socket(socks) => {
                if let Some((tx, _)) = &*lock(socks) {
                    // A full socket has a wake-up in it already.
                    let _ = std::io::Write::write(&mut &*tx, &[1]);
                }
            }
            Wake::Thread(_) => wake_from_helper(self.clone()),
        }
    }

    /// Runs the jobs queued, on the loop's thread.
    fn drain(&self, py: Python<'_>) {
        if let Wake::Socket(socks) = &self.wake
            && let Some((_, rx)) = &*lock(socks)
        {
            // The wake-ups first: one written after this belongs to a job
            // queued after the take below, and wakes the loop again.
            let mut buf = [0u8; 256];
            while matches!(std::io::Read::read(&mut &*rx, &mut buf), Ok(n) if n > 0) {}
        }
        self.armed.store(false, Ordering::SeqCst);
        let jobs = lock(&self.jobs)
            .as_mut()
            .map_or_else(Vec::new, std::mem::take);
        for job in jobs {
            if let Err(p) = catch_unwind(AssertUnwindSafe(|| job(py))) {
                PyRuntimeError::new_err(format!("internal error: {}", panic_text(&*p)))
                    .write_unraisable(py, None);
            }
        }
    }
    /// Closes the queue, for good: its loop closed, or is gone. The jobs
    /// queued, and every one pushed after, are dropped, and the sockets
    /// closed.
    fn close(&self) {
        let jobs = lock(&self.jobs).take();
        if let Wake::Socket(socks) = &self.wake {
            drop(lock(socks).take());
        }
        drop(jobs);
    }

    /// Whether the queue closed with its loop.
    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.jobs).is_none()
    }
}

/// Drains a queue: the loop's reader of the wake-up socket, or a callback
/// scheduled with `call_soon_threadsafe`. Dropped, it closes the queue when
/// that means the loop closed: the loop lets go of its reader only once it
/// closes (the selector closes and drops its readers) or is collected, and
/// drops a scheduled callback unrun only once it closes (a closed loop also
/// refuses to schedule one).
#[pyclass(frozen)]
struct Drain {
    queue: Arc<Queue>,
    /// The reader of the socket, not a callback run once.
    reader: bool,
    ran: AtomicBool,
}

impl Drain {
    fn new(queue: Arc<Queue>, reader: bool) -> Self {
        Drain {
            queue,
            reader,
            ran: AtomicBool::new(false),
        }
    }
}

#[pymethods]
impl Drain {
    fn __call__(&self, py: Python<'_>) {
        self.ran.store(true, Ordering::Relaxed);
        self.queue.drain(py);
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if self.reader || !self.ran.load(Ordering::Relaxed) {
            self.queue.close();
        }
    }
}

thread_local! {
    /// The loop this thread ran last, and its queue.
    static LAST: RefCell<Option<(Py<PyWeakrefReference>, Arc<Queue>)>> = const { RefCell::new(None) };
}

/// The queues of the loops, by a weak reference to each: a loop may run on
/// one thread, then another, and several loops run at once on threads of
/// their own (without the GIL too, so the registry is Rust's).
static LOOPS: StdMutex<Vec<(Py<PyWeakrefReference>, Arc<Queue>)>> = StdMutex::new(Vec::new());

/// Whether `r` refers to `lp`.
fn refers(r: &Py<PyWeakrefReference>, lp: &Bound<'_, PyAny>) -> bool {
    r.bind(lp.py()).upgrade().is_some_and(|l| l.is(lp))
}

/// The queue of the loop `lp`, made on first use.
fn queue_of(lp: &Bound<'_, PyAny>) -> PyResult<Arc<Queue>> {
    let py = lp.py();
    let cached = LAST.with_borrow(|last| {
        last.as_ref()
            .filter(|(r, q)| !q.is_closed() && refers(r, lp))
            .map(|(_, q)| q.clone())
    });
    if let Some(q) = cached {
        return Ok(q);
    }
    // Only this thread runs `lp` now: no other thread adds its queue.
    let found = lock(&LOOPS)
        .iter()
        .find(|(r, q)| !q.is_closed() && refers(r, lp))
        .map(|(_, q)| q.clone());
    let q = if let Some(q) = found {
        q
    } else {
        let q = new_queue(lp)?;
        let mut loops = lock(&LOOPS);
        // The queues of collected or closed loops go.
        loops.retain(|(r, q)| !q.is_closed() && r.bind(py).upgrade().is_some());
        loops.push((PyWeakrefReference::new(lp)?.unbind(), q.clone()));
        q
    };
    let r = PyWeakrefReference::new(lp)?.unbind();
    LAST.set(Some((r, q.clone())));
    Ok(q)
}

/// A queue whose wake-ups `lp` reads, or that the helper thread brings.
fn new_queue(lp: &Bound<'_, PyAny>) -> PyResult<Arc<Queue>> {
    let py = lp.py();
    let pair = py.import("socket")?.call_method0("socketpair")?;
    let (r, w): (Bound<'_, PyAny>, Bound<'_, PyAny>) = pair.extract()?;
    let (rx, tx) = (sock_of(&r)?, sock_of(&w)?);
    let fd = sock_fd(&rx);
    let q = Arc::new(Queue {
        jobs: StdMutex::new(Some(Vec::new())),
        armed: AtomicBool::new(false),
        wake: Wake::Socket(StdMutex::new(Some((tx, rx)))),
    });
    match lp.call_method1("add_reader", (fd, Drain::new(q.clone(), true))) {
        Ok(_) => Ok(q),
        Err(e) if e.is_instance_of::<PyNotImplementedError>(py) => Ok(Arc::new(Queue {
            jobs: StdMutex::new(Some(Vec::new())),
            armed: AtomicBool::new(false),
            wake: Wake::Thread(lp.clone().unbind()),
        })),
        Err(e) => Err(e),
    }
}

/// The socket of a Python socket object, which gives it up.
fn sock_of(s: &Bound<'_, PyAny>) -> PyResult<Sock> {
    s.call_method1("setblocking", (false,))?;
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let fd: i32 = s.call_method0("detach")?.extract()?;
        // SAFETY: `detach` hands over the descriptor, open and owned by nobody else.
        Ok(unsafe { Sock::from_raw_fd(fd) })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawSocket, RawSocket};
        let fd: RawSocket = s.call_method0("detach")?.extract()?;
        // SAFETY: `detach` hands over the socket, open and owned by nobody else.
        Ok(unsafe { Sock::from_raw_socket(fd) })
    }
}

/// The descriptor of a socket.
#[cfg(unix)]
fn sock_fd(rx: &Sock) -> i32 {
    use std::os::fd::AsRawFd;
    rx.as_raw_fd()
}

/// The descriptor of a socket.
#[cfg(windows)]
fn sock_fd(rx: &Sock) -> std::os::windows::io::RawSocket {
    use std::os::windows::io::AsRawSocket;
    rx.as_raw_socket()
}

/// `asyncio.get_running_loop()`.
fn running_loop(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    static GET: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    GET.get_or_try_init(py, || {
        py.import("asyncio")?
            .getattr("get_running_loop")
            .map(Bound::unbind)
    })?
    .bind(py)
    .call0()
}

// ---- results and errors made on the loop ----------------------------------------------

/// A result whose Python object is made on the loop's thread, from Rust
/// values: what an operation returns when no plain conversion fits.
pub(crate) struct Deferred(Box<Make>);

/// What makes a [`Deferred`]'s object.
type Make = dyn for<'py> FnOnce(Python<'py>) -> PyResult<Py<PyAny>> + Send;

/// The result `make` builds on the loop's thread.
pub(crate) fn deferred(
    make: impl for<'py> FnOnce(Python<'py>) -> PyResult<Py<PyAny>> + Send + 'static,
) -> Deferred {
    Deferred(Box::new(make))
}

impl<'py> IntoPyObject<'py> for Deferred {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;
    fn into_pyobject(self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.0(py).map(|o| o.into_bound(py))
    }
}

/// Bytes that become a `bytes` object.
pub(crate) struct Bin(pub(crate) Bytes);

impl From<Vec<u8>> for Bin {
    fn from(v: Vec<u8>) -> Self {
        Bin(v.into())
    }
}

impl<'py> IntoPyObject<'py> for Bin {
    type Target = PyBytes;
    type Output = Bound<'py, PyBytes>;
    type Error = std::convert::Infallible;
    fn into_pyobject(self, py: Python<'py>) -> Result<Bound<'py, PyBytes>, Self::Error> {
        Ok(PyBytes::new(py, &self.0))
    }
}

/// The arguments of a lazy exception: the exception itself, made by `F`.
struct Lazy<F>(F);

impl<F> PyErrArguments for Lazy<F>
where
    F: FnOnce(Python<'_>) -> PyErr + Send + Sync,
{
    fn arguments(self, py: Python<'_>) -> Py<PyAny> {
        self.0(py).into_value(py).into_any()
    }
}

/// The exception `make` builds once Python sees it, wherever this is made:
/// raising a `BaseException` with an exception as its argument raises that
/// exception.
pub(crate) fn lazy_err<F>(make: F) -> PyErr
where
    F: FnOnce(Python<'_>) -> PyErr + Send + Sync + 'static,
{
    PyErr::new::<PyBaseException, _>(Lazy(make))
}

/// `err`, changed by `f` once Python sees it.
pub(crate) fn decorate<F>(err: PyErr, f: F) -> PyErr
where
    F: FnOnce(Python<'_>, &Bound<'_, PyBaseException>) + Send + Sync + 'static,
{
    lazy_err(move |py| {
        f(py, err.value(py));
        err
    })
}

/// An awaitable whose result is `value` at once: what a coroutine method
/// returns when it has nothing to wait for (`__aenter__`).
#[pyclass(frozen)]
pub(crate) struct Ready(StdMutex<Option<Py<PyAny>>>);

#[pymethods]
impl Ready {
    fn __await__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }
    fn __next__(&self, py: Python<'_>) -> PyResult<()> {
        let v = lock(&self.0).take().unwrap_or_else(|| py.None());
        Err(pyo3::exceptions::PyStopIteration::new_err((v,)))
    }
}

/// [`Ready`] with `value`.
pub(crate) fn ready(value: Py<PyAny>) -> Ready {
    Ready(StdMutex::new(Some(value)))
}

// ---- operations -----------------------------------------------------------------------

/// What an operation holds until its result is settled: taken by the awaiter
/// once it resumed (returned, or undone after a cancellation), or here when
/// nobody awaits the result any more.
type Held = Arc<StdMutex<Option<Box<dyn std::any::Any + Send>>>>;

/// Lets go of what an operation held, once its awaiter settled the result.
#[pyclass(frozen)]
struct Release(Held);

#[pymethods]
impl Release {
    fn __call__(&self) {
        drop(lock(&self.0).take());
    }
}

/// Completes the asyncio future `fut` with `r`, on its loop: unless it is
/// done already (cancelled), when `undo` takes back what it read.
fn complete<T, G>(
    py: Python<'_>,
    fut: &Bound<'_, PyAny>,
    r: PyResult<(T, G)>,
    undo: Option<Py<PyAny>>,
    held: &Held,
) -> PyResult<()>
where
    T: for<'py> IntoPyObject<'py> + 'static,
    G: Send + 'static,
{
    let converted = r.and_then(|(v, g)| {
        *lock(held) = Some(Box::new(g));
        // `()` is `None` to Python, as for a function, not `()`.
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<()>() {
            return Ok(py.None());
        }
        v.into_py_any(py)
    });
    let (ok, value) = match converted {
        Ok(v) => (true, v),
        Err(e) => (false, e.into_value(py).into_any()),
    };
    // Should `done()` raise, this returns early and `held` is let go by the
    // awaiter's `release()` (the `finally` of `drive`), which always runs:
    // nothing leaks.
    if !fut.call_method0(intern!(py, "done"))?.is_truthy()? {
        // Held until the awaiter resumes: a cancellation that reaches it
        // now still undoes the result before the next operation begins.
        let method = if ok {
            intern!(py, "set_result")
        } else {
            intern!(py, "set_exception")
        };
        return fut.call_method1(method, (value,)).map(drop);
    }
    if ok && let Some(undo) = undo {
        // Cancelled as it completed: what it read goes back.
        undo.call1(py, (value,))?;
    }
    // What the operation held: nothing else goes on until its result is settled.
    drop(lock(held).take());
    Ok(())
}

/// Cancellations reported to their tasks whose futures are not yet dropped.
static CANCELLING: StdMutex<usize> = StdMutex::new(0);
static CANCELLED: Condvar = Condvar::new();
/// How long a call that never waits waits for cancelled operations.
const CANCEL_WAIT: Duration = Duration::from_secs(1);

/// `take()`, which fails while an operation holds what it takes; while a
/// cancelled operation is still letting go (its task drops its future on
/// the runtime, without the interpreter), it is tried again once none is.
/// A call that never waits thus finds a stream free after a cancellation,
/// and the loop waits only then, never for a cancellation as such. It
/// waits detached, so other Python threads (a hook called on a runtime
/// thread among them) run meanwhile.
///
/// The count is global, not per stream: a busy stream may wait for an
/// unrelated cancellation to settle. That costs at most `CANCEL_WAIT`, only
/// on a call that would fail anyway, and keeps the cancellation path free
/// of per-stream bookkeeping.
///
/// Called from Python only, attached: `attach` below just borrows that.
pub(crate) fn when_free<T, E>(mut take: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    let r = take();
    if r.is_ok() || *lock(&CANCELLING) == 0 {
        return r;
    }
    Python::attach(|py| {
        py.detach(|| {
            let g = lock(&CANCELLING);
            drop(CANCELLED.wait_timeout_while(g, CANCEL_WAIT, |n| *n > 0));
        });
    });
    take()
}

/// Reports an asyncio future's cancellation to the Rust task behind it,
/// which drops its future (and what it held) on the runtime; see
/// [`when_free`].
#[pyclass(frozen)]
struct OnCancel(StdMutex<Option<oneshot::Sender<()>>>);

#[pymethods]
impl OnCancel {
    fn __call__(&self, fut: &Bound<'_, PyAny>) -> PyResult<()> {
        if fut
            .call_method0(intern!(fut.py(), "cancelled"))?
            .is_truthy()?
        {
            self.signal();
        }
        Ok(())
    }
}

impl OnCancel {
    fn signal(&self) {
        if let Some(tx) = lock(&self.0).take() {
            *lock(&CANCELLING) += 1;
            if tx.send(()).is_err() {
                *lock(&CANCELLING) -= 1;
                CANCELLED.notify_all();
            }
        }
    }
}

/// The text of a panic's payload.
fn panic_text(p: &(dyn std::any::Any + Send)) -> &str {
    p.downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("panic")
}

/// `fut`, whose panic is an exception for the awaiter: the panicked task would otherwise
/// leave the asyncio future pending for good.
async fn caught<F, T>(fut: F) -> PyResult<T>
where
    F: Future<Output = PyResult<T>>,
{
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))).unwrap_or_else(|p| {
            Poll::Ready(Err(PyRuntimeError::new_err(format!(
                "internal error: {}",
                panic_text(&*p)
            ))))
        })
    })
    .await
}
/// What a coroutine of this binding starts when first awaited.
type Starter = Box<dyn for<'py> FnOnce(Python<'py>) -> PyResult<Py<PyAny>> + Send>;

/// Starts an operation on the running loop, once.
#[pyclass(frozen)]
struct Begin(StdMutex<Option<Starter>>);

#[pymethods]
impl Begin {
    fn __call__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match lock(&self.0).take() {
            Some(start) => start(py),
            None => Err(PyRuntimeError::new_err("the operation already started")),
        }
    }
}

static DRIVE: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

/// The coroutine function that awaits an operation. A cancellation that reaches its task
/// after the result was set gives the result to `undo`; what the operation held is let go
/// after that.
fn drive(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    DRIVE
        .get_or_try_init(py, || {
            let code = c"
import asyncio

class SetupFuture(asyncio.Future):
    def __init__(self, loop, withdraw):
        super().__init__(loop=loop)
        self.withdraw = withdraw

    def cancel(self, msg=None):
        if self.done():
            return False
        error = asyncio.CancelledError() if msg is None else asyncio.CancelledError(msg)
        if self.withdraw(error):
            return super().cancel(msg)
        # Task.cancel delegated here. Rust already owns the result and
        # its event-loop delivery must still wake the original awaiter.
        return True

async def drive(start, undo):
    fut, release = start()
    try:
        return await fut
    except asyncio.CancelledError:
        if undo is not None and fut.done() and not fut.cancelled() and fut.exception() is None:
            undo(fut.result())
        raise
    finally:
        release()

drive.setup_future = SetupFuture
";
            let m = PyModule::from_code(py, code, c"zmux_drive", c"zmux_drive")?;
            Ok::<_, PyErr>(m.getattr("drive")?.unbind())
        })
        .map(|f| f.bind(py))
}

/// A coroutine that runs `fut` on the runtime once awaited. Cancelling it drops `fut`, and
/// so does dropping it unawaited.
pub(crate) fn future_into_py<F, T>(py: Python<'_>, fut: F) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
{
    undoable_future_into_py(py, async move { fut.await.map(|v| (v, ())) }, None)
}

/// [`future_into_py`], where `undo` takes back a result no awaiter will see. The future also
/// gives what stays held until the result is set or undone.
pub(crate) fn undoable_future_into_py<F, T, G>(
    py: Python<'_>,
    fut: F,
    undo: Option<Py<PyAny>>,
) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<(T, G)>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
    G: Send + 'static,
{
    operation(py, fut, undo, None)
}

#[pyclass(frozen)]
struct Withdraw {
    gate: Withdrawal,
    waiter: OnCancel,
}

#[pymethods]
impl Withdraw {
    fn __call__(&self, error: Bound<'_, PyBaseException>) -> bool {
        let won = match &self.gate {
            Withdrawal::Setup(gate) => gate.cancel(),
            Withdrawal::Join(receipt) => receipt.cancel(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                PyErr::from_value(error.into_any()),
            )),
        };
        if won {
            self.waiter.signal();
        }
        won
    }
}

enum Withdrawal {
    Setup(zmux::adapter::SetupCancellation),
    Join(zmux::adapter::JoinCancellation),
}

pub(crate) fn join_future_into_py<F, T>(
    py: Python<'_>,
    fut: F,
    receipt: zmux::adapter::JoinCancellation,
) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
{
    operation(
        py,
        async move { fut.await.map(|v| (v, ())) },
        None,
        Some(Withdrawal::Join(receipt)),
    )
}

pub(crate) fn setup_future_into_py<F>(
    py: Python<'_>,
    fut: F,
    withdrawal: zmux::adapter::SetupCancellation,
) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<()>> + Send + 'static,
{
    operation(
        py,
        async move { fut.await.map(|()| ((), ())) },
        None,
        Some(Withdrawal::Setup(withdrawal)),
    )
}

fn operation<F, T, G>(
    py: Python<'_>,
    fut: F,
    undo: Option<Py<PyAny>>,
    withdrawal: Option<Withdrawal>,
) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<(T, G)>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
    G: Send + 'static,
{
    let completing = undo.as_ref().map(|u| u.clone_ref(py));
    let start: Starter = Box::new(move |py| start_future(py, fut, completing, withdrawal));
    drive(py)?.call1((Begin(StdMutex::new(Some(start))), undo))
}

/// The asyncio future of `fut`, run on the runtime, on the running event loop.
/// With the callable that lets go of what the operation held.
fn start_future<F, T, G>(
    py: Python<'_>,
    fut: F,
    undo: Option<Py<PyAny>>,
    withdrawal: Option<Withdrawal>,
) -> PyResult<Py<PyAny>>
where
    F: Future<Output = PyResult<(T, G)>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
    G: Send + 'static,
{
    let lp = running_loop(py)?;
    let queue = queue_of(&lp)?;
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let waiter = OnCancel(StdMutex::new(Some(cancel_tx)));
    let target = if let Some(gate) = withdrawal {
        drive(py)?
            .getattr("setup_future")?
            .call1((&lp, Withdraw { gate, waiter }))?
    } else {
        let target = lp.call_method0(intern!(py, "create_future"))?;
        target.call_method1(intern!(py, "add_done_callback"), (waiter,))?;
        target
    };
    let fut_py = target.clone().unbind();
    let held = Held::default();
    let release = Release(held.clone());
    runtime()?.spawn(async move {
        let mut cancel_rx = cancel_rx;
        let r = {
            let mut fut = std::pin::pin!(caught(fut));
            tokio::select! {
                biased;
                c = &mut cancel_rx => Err(c.is_ok()),
                r = &mut fut => Ok(r),
            }
        };
        // The future (pinned above) is dropped now: a cancellation reported,
        // even one that came too late, is settled.
        let cancelled = if let Err(c) = &r {
            *c
        } else {
            cancel_rx.close();
            cancel_rx.try_recv().is_ok()
        };
        if cancelled {
            *lock(&CANCELLING) -= 1;
            CANCELLED.notify_all();
        }
        let Ok(r) = r else { return };
        queue.push(Box::new(move |py| {
            let fut = fut_py.bind(py);
            if let Err(e) = complete(py, fut, r, undo, &held) {
                e.write_unraisable(py, Some(fut));
            }
        }));
    });
    Ok((target, release).into_pyobject(py)?.into_any().unbind())
}

// ---- Python calls from the runtime --------------------------------------------------

/// An event loop with the context its calls run in: where the runtime
/// calls Python, as a request the loop answers. It may be bound later
/// ([`LoopRef::lazy`]): to the loop running when an object holding it is
/// first used ([`LoopRef::bind`]); a call made before waits for that.
/// Once the bound loop closes, every call on it, pending or later, is
/// answered at once as dropped (a decider refuses, an observed event is
/// dropped and not reported), and the next use from a running loop binds that
/// one instead.
#[derive(Clone)]
pub(crate) struct LoopRef(Arc<Slot>);

#[derive(Default)]
struct Slot {
    at: StdMutex<Option<At>>,
    bound: tokio::sync::Notify,
}

/// The loop's queue and the context of its calls.
#[derive(Clone)]
struct At {
    queue: Arc<Queue>,
    context: Arc<Py<PyAny>>,
}

impl At {
    fn current(py: Python<'_>) -> PyResult<Self> {
        let lp = running_loop(py)?;
        let context = py.import("contextvars")?.call_method0("copy_context")?;
        Ok(At {
            queue: queue_of(&lp)?,
            context: Arc::new(context.unbind()),
        })
    }
}

/// A call's progress on the loop: its task, once started; `dropped` once
/// the Rust side gave up.
#[derive(Default)]
struct CallState {
    task: Option<Py<PyAny>>,
    dropped: bool,
}

/// What becomes of a call's outcome, on the loop.
type Settle<R> = Box<dyn for<'py> FnOnce(Python<'py>, PyResult<Bound<'py, PyAny>>) -> R + Send>;

/// Hands a finished task's result, taken by `out`, to the Rust side.
#[pyclass(frozen)]
struct Done(StdMutex<Option<Box<Finish>>>);

/// What a [`Done`] does with the finished task.
type Finish = dyn for<'py> FnOnce(&Bound<'py, PyAny>) + Send;

#[pymethods]
impl Done {
    fn __call__(&self, task: &Bound<'_, PyAny>) {
        if let Some(f) = lock(&self.0).take() {
            f(task);
        }
    }
}

/// Runs a closure once, as a Python callable (for `Context.run`).
#[pyclass(frozen)]
struct Invoke(StdMutex<Option<Job>>);

#[pymethods]
impl Invoke {
    fn __call__(&self, py: Python<'_>) {
        if let Some(f) = lock(&self.0).take() {
            f(py);
        }
    }
}

/// Cancels the call's task when the Rust side gives up before its result.
struct CancelOnDrop {
    state: Arc<StdMutex<CallState>>,
    queue: Arc<Queue>,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let task = {
            let mut s = lock(&self.state);
            s.dropped = true;
            s.task.take()
        };
        if let Some(task) = task {
            self.queue.push(Box::new(move |py| {
                let _ = task.call_method0(py, intern!(py, "cancel"));
            }));
        }
    }
}

impl LoopRef {
    /// The running loop, and the current context.
    pub(crate) fn current(py: Python<'_>) -> PyResult<Self> {
        let slot = Slot {
            at: StdMutex::new(Some(At::current(py)?)),
            bound: tokio::sync::Notify::new(),
        };
        Ok(LoopRef(Arc::new(slot)))
    }

    /// [`LoopRef::current`] for `what`, a call that needs a running loop
    /// for its hooks: `NoRunningLoopError` that says so without one.
    pub(crate) fn running(py: Python<'_>, what: &str) -> PyResult<Self> {
        if running_loop(py).is_err() {
            return Err(crate::new_err(
                "NoRunningLoopError",
                format!("{what} must be called inside a running event loop, which runs its hooks"),
            ));
        }
        Self::current(py)
    }

    /// The running loop if there is one, else one bound later.
    pub(crate) fn lazy(py: Python<'_>) -> Self {
        let r = LoopRef(Arc::default());
        r.bind(py);
        r
    }

    /// Whether bound to a loop that has not closed.
    fn bound_open(&self) -> bool {
        lock(&self.0.at)
            .as_ref()
            .is_some_and(|at| !at.queue.is_closed())
    }

    /// Binds to the running loop, and the current context, unless bound
    /// already to a loop that has not closed, or no loop runs.
    pub(crate) fn bind(&self, py: Python<'_>) {
        if self.bound_open() {
            return;
        }
        let Ok(at) = At::current(py) else { return };
        let old = {
            let mut g = lock(&self.0.at);
            if g.as_ref().is_some_and(|a| !a.queue.is_closed()) {
                return;
            }
            g.replace(at)
        };
        drop(old);
        self.0.bound.notify_waiters();
    }

    /// The loop, once bound.
    fn at(&self) -> impl Future<Output = At> + Send + 'static + use<> {
        let slot = self.0.clone();
        async move {
            loop {
                let woken = slot.bound.notified();
                let mut woken = std::pin::pin!(woken);
                woken.as_mut().enable();
                if let Some(at) = lock(&slot.at).clone() {
                    return at;
                }
                woken.await;
            }
        }
    }

    /// Runs `job` on the loop's thread, without waiting; dropped when the
    /// loop is not bound yet, or closed.
    pub(crate) fn post(&self, job: impl for<'py> FnOnce(Python<'py>) + Send + 'static) {
        let at = lock(&self.0.at).clone();
        if let Some(at) = at {
            at.queue.push(Box::new(job));
        }
    }

    /// Calls `f` on the loop, in the context: its result, awaited as a task
    /// when it is awaitable, taken by `out` there. Dropping the future
    /// cancels the task.
    pub(crate) fn call<R, F, O>(
        &self,
        f: F,
        out: O,
    ) -> impl Future<Output = PyResult<R>> + Send + 'static + use<R, F, O>
    where
        R: Send + 'static,
        F: for<'py> FnOnce(Python<'py>) -> PyResult<Bound<'py, PyAny>> + Send + 'static,
        O: for<'py> FnOnce(&Bound<'py, PyAny>) -> PyResult<R> + Send + 'static,
    {
        self.settled(
            f,
            move |_, r| r.and_then(|v| out(&v)),
            || {
                Err(PyRuntimeError::new_err(
                    "the event loop of the hooks closed",
                ))
            },
        )
    }

    /// [`LoopRef::call`], whose outcome, an exception included, `settle`
    /// takes on the loop; `gone` when the loop dropped the call.
    pub(crate) fn settled<R, F, S>(
        &self,
        f: F,
        settle: S,
        gone: fn() -> R,
    ) -> impl Future<Output = R> + Send + 'static + use<R, F, S>
    where
        R: Send + 'static,
        F: for<'py> FnOnce(Python<'py>) -> PyResult<Bound<'py, PyAny>> + Send + 'static,
        S: for<'py> FnOnce(Python<'py>, PyResult<Bound<'py, PyAny>>) -> R + Send + 'static,
    {
        let at = self.at();
        let settle: Settle<R> = Box::new(settle);
        async move {
            // Waits for a loop bound later; dropped meanwhile, nothing ran.
            let At { queue, context } = at.await;
            let (tx, rx) = oneshot::channel::<R>();
            let state = Arc::new(StdMutex::new(CallState::default()));
            let st = state.clone();
            queue.push(Box::new(move |py| {
                let run: Job = Box::new(move |py| start_call(py, f, settle, tx, &st));
                let invoke = Invoke(StdMutex::new(Some(run)));
                if let Err(e) = context.call_method1(py, intern!(py, "run"), (invoke,)) {
                    e.write_unraisable(py, None);
                }
            }));
            let mut guard = CancelOnDrop {
                state,
                queue,
                armed: true,
            };
            let r = rx.await.unwrap_or_else(|_| gone());
            guard.armed = false;
            r
        }
    }
}

impl LoopRef {
    /// A Python hook's answer, as the future of a `Decision::Later`: `call`
    /// given the hook on the loop, awaited there when it returns an
    /// awaitable, and its result taken by `out`. An exception or a result
    /// `out` refuses is reported as unraisable and gives `refuse()`; so
    /// does a loop that dropped the call. Dropping the future (the caller's
    /// deadline) cancels the call's task.
    pub(crate) fn decide<T, C, O>(
        &self,
        hook: &Arc<Py<PyAny>>,
        call: C,
        out: O,
        refuse: fn() -> T,
    ) -> impl Future<Output = T> + Send + 'static + use<T, C, O>
    where
        T: Send + 'static,
        C: for<'py> FnOnce(&Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> + Send + 'static,
        O: for<'py> FnOnce(&Bound<'py, PyAny>) -> PyResult<T> + Send + 'static,
    {
        let (hook, reported) = (hook.clone(), hook.clone());
        self.settled(
            move |py| call(hook.bind(py)),
            move |py, r| {
                r.and_then(|v| out(&v)).unwrap_or_else(|e| {
                    e.write_unraisable(py, Some(reported.bind(py)));
                    refuse()
                })
            },
            refuse,
        )
    }
}

/// The listener's log lines and memory pressure reports a subscription to
/// the observing hooks holds unread: these are not session lines, and the
/// bound is the same 256 as the core's own backlogs of a session's trace
/// records and log lines inside the subscription.
pub(crate) const LOG_QUEUE: usize = 256;

/// The most events one run on the loop delivers before it yields.
const DELIVER_BATCH: usize = 256;

impl LoopRef {
    /// Delivers what `events` reads to `deliver`, on the loop, in order. A
    /// runtime task waits for the events and hands each batch to the loop,
    /// one at a time: a loop that falls behind leaves them in the
    /// subscription, whose per-session backlog of 256 trace events drops
    /// (and counts, as the session's `TraceRecord::Dropped`) the event that
    /// arrives. The one exception is a loop that is closed: what it would
    /// be told is dropped and reported nowhere, `established` and `closed`
    /// included, until the next use from a running loop binds another.
    /// Ends once every writer of the subscription is gone.
    pub(crate) fn observe(
        &self,
        events: zmux::HostEvents,
        deliver: impl for<'py> Fn(Python<'py>, zmux::HostEvent) + Send + Sync + 'static,
    ) -> PyResult<()> {
        let (lp, deliver) = (self.clone(), Arc::new(deliver));
        runtime()?.spawn(async move {
            while let Some(first) = events.next().await {
                // Held in the subscription until the loop is bound.
                let At { queue, .. } = lp.at().await;
                if queue.is_closed() {
                    continue;
                }
                let (done, delivered) = oneshot::channel::<()>();
                let (queued, deliver) = (events.clone(), deliver.clone());
                queue.push(Box::new(move |py| {
                    deliver(py, first);
                    for _ in 1..DELIVER_BATCH {
                        match queued.try_next() {
                            Some(e) => deliver(py, e),
                            None => break,
                        }
                    }
                    let _ = done.send(());
                }));
                drop(queue);
                // A loop that closed with the batch queued drops what it
                // took; the rest stays in the subscription.
                let _ = delivered.await;
            }
        });
        Ok(())
    }
}

/// The loop's side of [`LoopRef::settled`].
fn start_call<R: Send + 'static>(
    py: Python<'_>,
    f: impl for<'py> FnOnce(Python<'py>) -> PyResult<Bound<'py, PyAny>>,
    settle: Settle<R>,
    tx: oneshot::Sender<R>,
    state: &Arc<StdMutex<CallState>>,
) {
    if lock(state).dropped {
        return;
    }
    let started = f(py).and_then(|v| {
        if !v.hasattr(intern!(py, "__await__"))? {
            return Ok(Err(v));
        }
        Ok(Ok(py
            .import("asyncio")?
            .call_method1("ensure_future", (v,))?))
    });
    let task = match started {
        Err(e) => return drop(tx.send(settle(py, Err(e)))),
        Ok(Err(v)) => return drop(tx.send(settle(py, Ok(v)))),
        Ok(Ok(task)) => task,
    };
    let st = state.clone();
    let done = Done(StdMutex::new(Some(Box::new(
        move |t: &Bound<'_, PyAny>| {
            // A call the Rust side gave up (and so cancelled) has no
            // outcome to settle.
            if lock(&st).dropped {
                return;
            }
            let r = t.call_method0(intern!(t.py(), "result"));
            let _ = tx.send(settle(t.py(), r));
        },
    ))));
    if let Err(e) = task.call_method1(intern!(py, "add_done_callback"), (done,)) {
        e.write_unraisable(py, None);
        return;
    }
    let mut s = lock(state);
    if s.dropped {
        let _ = task.call_method0(intern!(py, "cancel"));
    } else {
        s.task = Some(task.unbind());
    }
}
