//! The binding's runtime and its bridges to asyncio, safe at interpreter
//! exit.
//!
//! The Rust runtime's threads call into Python to complete awaited futures,
//! to run callbacks and to build exceptions. `CPython` must not be entered
//! from another thread once it is finalizing: before 3.14 such a thread is
//! ended inside `PyGILState_Ensure` (with `pthread_exit`, which unwinds
//! through Rust frames), and once finalization ended the attach would start
//! a new interpreter. Every attach of a runtime thread goes through
//! [`attach`]: an `atexit` hook, registered when the module is imported and
//! so run after the application's own hooks and before finalization, closes
//! the gate and waits (bounded) for the attaches under way to end; a runtime
//! thread that would attach later parks for the rest of the process.
//! Threads of Python itself are never held.
//!
//! [`future_into_py`] and [`into_future`] are the asyncio bridges, in place
//! of `pyo3_async_runtimes`' (whose completions attach outside the gate).

use std::cell::Cell;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};

use pyo3::IntoPyObjectExt;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyRuntimeError;
use pyo3::exceptions::asyncio::CancelledError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3_async_runtimes::TaskLocals;
use tokio::sync::oneshot;

pub(crate) use pyo3_async_runtimes::tokio::get_runtime;

/// Set by the `atexit` hook: runtime threads no longer enter Python.
static EXITING: AtomicBool = AtomicBool::new(false);
/// Runtime threads attaching or attached now.
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
/// How long the `atexit` hook waits for the attaches under way.
const EXIT_WAIT: Duration = Duration::from_secs(1);

thread_local! {
    /// Whether this thread is one of the runtime's (or a helper thread of
    /// one), never a thread of Python.
    static RUNTIME_THREAD: Cell<bool> = const { Cell::new(false) };
    /// How many [`attach`] calls this thread is inside.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Marks the calling thread as a runtime thread (for a helper thread a
/// runtime thread starts).
pub(crate) fn mark_runtime_thread() {
    RUNTIME_THREAD.set(true);
}

/// `Python::attach`, except that a runtime thread parks for good instead
/// once the interpreter is exiting. A call nested in another runs on: its
/// thread is attached already, and parking attached would stall
/// finalization for good (the GIL never released, or a stop-the-world
/// never reached).
pub(crate) fn attach<F, R>(f: F) -> R
where
    F: for<'py> FnOnce(Python<'py>) -> R,
{
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            DEPTH.set(DEPTH.get() - 1);
            INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        }
    }
    if !RUNTIME_THREAD.get() || DEPTH.get() > 0 {
        return Python::attach(f);
    }
    INFLIGHT.fetch_add(1, Ordering::SeqCst);
    DEPTH.set(1);
    let leave = Leave;
    if EXITING.load(Ordering::SeqCst) {
        drop(leave);
        loop {
            std::thread::park();
        }
    }
    let r = Python::attach(f);
    drop(leave);
    r
}

/// The `atexit` hook: closes the gate, then waits, detached, for the
/// runtime threads attaching or attached now.
#[pyfunction]
fn _shutdown(py: Python<'_>) {
    EXITING.store(true, Ordering::SeqCst);
    py.detach(|| {
        let end = Instant::now() + EXIT_WAIT;
        while INFLIGHT.load(Ordering::SeqCst) > 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
    });
}

/// Releases `buffer` on a thread of its own. Releasing a Python buffer enters the
/// interpreter, and the last owner of a lent chunk may be anywhere, the session's lock held
/// included: a thread of Python that holds the interpreter waits for that lock.
pub(crate) fn release_buffer(buffer: PyBuffer<u8>) {
    static RELEASE: OnceLock<Option<mpsc::Sender<PyBuffer<u8>>>> = OnceLock::new();
    let sender = RELEASE.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<PyBuffer<u8>>();
        std::thread::Builder::new()
            .name("zmux-release".into())
            .spawn(move || {
                mark_runtime_thread();
                while let Ok(first) = rx.recv() {
                    attach(|_| {
                        drop(first);
                        while let Ok(next) = rx.try_recv() {
                            drop(next);
                        }
                    });
                }
            })
            .ok()
            .map(|_| tx)
    });
    // Without the thread the buffer stays exported.
    match sender {
        Some(tx) => {
            if let Err(mpsc::SendError(b)) = tx.send(buffer) {
                std::mem::forget(b);
            }
        }
        None => std::mem::forget(buffer),
    }
}

/// Sets up the runtime (its threads marked) and the `atexit` hook; called
/// once, from the module's initialization.
pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.enable_all()
        .thread_name("zmux")
        .on_thread_start(mark_runtime_thread);
    pyo3_async_runtimes::tokio::init(b);
    m.add_function(wrap_pyfunction!(_shutdown, m)?)?;
    let hook = m.getattr("_shutdown")?;
    m.py().import("atexit")?.call_method1("register", (hook,))?;
    Ok(())
}

/// Completes an asyncio future on its loop, unless it is done already
/// (cancelled).
#[pyclass(frozen)]
struct Complete(
    Option<Py<PyAny>>,
    StdMutex<Option<Box<dyn std::any::Any + Send>>>,
);

#[pymethods]
impl Complete {
    fn __call__(
        &self,
        fut: &Bound<'_, PyAny>,
        method: &str,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        if !fut.call_method0("done")?.is_truthy()? {
            fut.call_method1(method, (value,))?;
        } else if method == "set_result"
            && let Some(undo) = &self.0
        {
            // Cancelled as it completed: what it read goes back.
            undo.call1(fut.py(), (value,))?;
        }
        // What the operation held: nothing else goes on until its result is settled.
        drop(self.1.lock().unwrap().take());
        Ok(())
    }
}

/// Reports an asyncio future's cancellation to the Rust task behind it.
#[pyclass(frozen)]
struct OnCancel(StdMutex<Option<oneshot::Sender<()>>>);

#[pymethods]
impl OnCancel {
    fn __call__(&self, fut: &Bound<'_, PyAny>) -> PyResult<()> {
        if fut.call_method0("cancelled")?.is_truthy()?
            && let Some(tx) = self.0.lock().unwrap().take()
        {
            let _ = tx.send(());
        }
        Ok(())
    }
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
            let what = p
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| p.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("panic");
            Poll::Ready(Err(PyRuntimeError::new_err(format!(
                "internal error: {what}"
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
        match self.0.lock().unwrap().take() {
            Some(start) => start(py),
            None => Err(PyRuntimeError::new_err("the operation already started")),
        }
    }
}

static DRIVE: pyo3::sync::PyOnceLock<Py<PyAny>> = pyo3::sync::PyOnceLock::new();

/// The coroutine function that awaits an operation. A cancellation that reaches its task
/// after the result was set gives the result to `undo`.
fn drive(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    DRIVE
        .get_or_try_init(py, || {
            let code = c"
import asyncio

async def drive(start, undo):
    fut = start()
    try:
        return await fut
    except asyncio.CancelledError:
        if undo is not None and fut.done() and not fut.cancelled() and fut.exception() is None:
            undo(fut.result())
        raise
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
    let completing = undo.as_ref().map(|u| u.clone_ref(py));
    let start: Starter = Box::new(move |py| start_future(py, fut, completing));
    drive(py)?.call1((Begin(StdMutex::new(Some(start))), undo))
}

/// The asyncio future of `fut`, run on the runtime, on the running event loop.
fn start_future<F, T, G>(py: Python<'_>, fut: F, undo: Option<Py<PyAny>>) -> PyResult<Py<PyAny>>
where
    F: Future<Output = PyResult<(T, G)>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
    G: Send + 'static,
{
    let lp = py.import("asyncio")?.call_method0("get_running_loop")?;
    let target = lp.call_method0("create_future")?;
    let (cancel_tx, cancel_rx) = oneshot::channel();
    target.call_method1(
        "add_done_callback",
        (OnCancel(StdMutex::new(Some(cancel_tx))),),
    )?;
    let lp = lp.unbind();
    let fut_py = target.clone().unbind();
    get_runtime().spawn(async move {
        let r = tokio::select! {
            biased;
            // Cancelled, or the future (with its callback) collected.
            _ = cancel_rx => return,
            r = caught(fut) => r,
        };
        tokio::task::spawn_blocking(move || {
            attach(|py| {
                let mut held: Option<Box<dyn std::any::Any + Send>> = None;
                let converted = r.and_then(|(v, g)| {
                    held = Some(Box::new(g));
                    v.into_py_any(py)
                });
                let (method, value) = match converted {
                    Ok(v) => ("set_result", v),
                    Err(e) => ("set_exception", e.into_value(py).into_any()),
                };
                // A closed loop raises: nobody awaits the future any more.
                let _ = lp.call_method1(
                    py,
                    "call_soon_threadsafe",
                    (Complete(undo, StdMutex::new(held)), fut_py, method, value),
                );
            });
        });
    });
    Ok(target.unbind())
}

/// The task of an awaitable given to [`into_future`], once the loop started
/// it; `dropped` once the Rust future is.
#[derive(Default)]
struct Slot {
    task: Option<Py<PyAny>>,
    dropped: bool,
}

/// Starts an awaitable as a task on its loop.
#[pyclass(frozen)]
struct StartAwaitable {
    awaitable: StdMutex<Option<Py<PyAny>>>,
    tx: StdMutex<Option<oneshot::Sender<PyResult<Py<PyAny>>>>>,
    slot: Arc<StdMutex<Slot>>,
}

#[pymethods]
impl StartAwaitable {
    fn __call__(&self, py: Python<'_>) -> PyResult<()> {
        let Some(aw) = self.awaitable.lock().unwrap().take() else {
            return Ok(());
        };
        let mut slot = self.slot.lock().unwrap();
        if slot.dropped {
            // Nobody waits: close a coroutine instead of leaving it unawaited.
            if aw.bind(py).hasattr("close")? {
                let _ = aw.bind(py).call_method0("close");
            }
            return Ok(());
        }
        let task = py.import("asyncio")?.call_method1("ensure_future", (aw,))?;
        let done = Done(StdMutex::new(self.tx.lock().unwrap().take()));
        task.call_method1("add_done_callback", (done,))?;
        slot.task = Some(task.unbind());
        Ok(())
    }
}

/// Hands a finished task's result to the Rust future.
#[pyclass(frozen)]
struct Done(StdMutex<Option<oneshot::Sender<PyResult<Py<PyAny>>>>>);

#[pymethods]
impl Done {
    fn __call__(&self, task: &Bound<'_, PyAny>) {
        let r = task.call_method0("result").map(Bound::unbind);
        if let Some(tx) = self.0.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }
}

/// Cancels the task when the Rust future is dropped before its result.
struct CancelOnDrop {
    slot: Arc<StdMutex<Slot>>,
    lp: Py<PyAny>,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let task = {
            let mut s = self.slot.lock().unwrap();
            s.dropped = true;
            s.task.take()
        };
        if let Some(task) = task {
            attach(|py| {
                if let Ok(cancel) = task.bind(py).getattr("cancel") {
                    let _ = self.lp.call_method1(py, "call_soon_threadsafe", (cancel,));
                }
            });
        }
    }
}

/// The Rust future of a Python awaitable, run as a task on `locals`' loop
/// in its context. Dropping the future cancels the task.
pub(crate) fn into_future(
    locals: &TaskLocals,
    awaitable: Bound<'_, PyAny>,
) -> PyResult<impl Future<Output = PyResult<Py<PyAny>>> + Send + 'static + use<>> {
    let py = awaitable.py();
    let (tx, rx) = oneshot::channel();
    let slot = Arc::new(StdMutex::new(Slot::default()));
    let start = StartAwaitable {
        awaitable: StdMutex::new(Some(awaitable.unbind())),
        tx: StdMutex::new(Some(tx)),
        slot: slot.clone(),
    };
    let lp = locals.event_loop(py);
    let kwargs = PyDict::new(py);
    kwargs.set_item("context", locals.context(py))?;
    lp.call_method("call_soon_threadsafe", (start,), Some(&kwargs))?;
    let guard = CancelOnDrop {
        slot,
        lp: lp.unbind(),
        armed: true,
    };
    Ok(async move {
        // The whole guard moves in, not only its field.
        let mut guard = guard;
        let r = match rx.await {
            Ok(r) => r,
            Err(_) => Err(CancelledError::new_err("the task was dropped")),
        };
        guard.armed = false;
        r
    })
}
