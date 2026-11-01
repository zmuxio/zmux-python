//! The binding's runtime and its bridges to asyncio, safe at interpreter
//! exit.
//!
//! The Rust runtime's threads call into Python to complete awaited futures,
//! to run callbacks and to build exceptions. CPython must not be entered
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use pyo3::IntoPyObjectExt;
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
}

/// Marks the calling thread as a runtime thread (for a helper thread a
/// runtime thread starts).
pub(crate) fn mark_runtime_thread() {
    RUNTIME_THREAD.set(true);
}

/// `Python::attach`, except that a runtime thread parks for good instead
/// once the interpreter is exiting.
pub(crate) fn attach<F, R>(f: F) -> R
where
    F: for<'py> FnOnce(Python<'py>) -> R,
{
    if !RUNTIME_THREAD.get() {
        return Python::attach(f);
    }
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        }
    }
    INFLIGHT.fetch_add(1, Ordering::SeqCst);
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
struct Complete;

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
        }
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

/// The asyncio future of `fut`, run on the runtime, on the running event
/// loop. Cancelling it (or dropping it unawaited) drops `fut`.
pub(crate) fn future_into_py<F, T>(py: Python<'_>, fut: F) -> PyResult<Bound<'_, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
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
            r = fut => r,
        };
        tokio::task::spawn_blocking(move || {
            attach(|py| {
                let (method, value) = match r.and_then(|v| v.into_py_any(py)) {
                    Ok(v) => ("set_result", v),
                    Err(e) => ("set_exception", e.into_value(py).into_any()),
                };
                // A closed loop raises: nobody awaits the future any more.
                let _ = lp.call_method1(
                    py,
                    "call_soon_threadsafe",
                    (Complete, fut_py, method, value),
                );
            })
        });
    });
    Ok(target)
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
struct Start {
    awaitable: StdMutex<Option<Py<PyAny>>>,
    tx: StdMutex<Option<oneshot::Sender<PyResult<Py<PyAny>>>>>,
    slot: Arc<StdMutex<Slot>>,
}

#[pymethods]
impl Start {
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
    let start = Start {
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
