//! The listener's fallback: `ListenerConfig.fallback`, a Python handler
//! given every carrier the admission hands back as a `Takeover`, and
//! `TakeoverMessages`, a message-framed carrier read and written by whole
//! messages.

use std::sync::{Arc, Mutex as StdMutex};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::Mutex;

use crate::admission::{self, CarrierInfo};
use crate::helpers::lock;
use crate::ranged;
use crate::rt::{self, LoopRef, future_into_py};
use crate::{PipeIo, io_err, new_err};

/// Where the carrier of a takeover is.
enum Slot {
    /// With the takeover, until it is taken or the handler returns.
    Held(zmux::Takeover),
    /// Taken by `into_pipe` or `into_messages`.
    Taken,
    /// The handler returned without detaching it: closed.
    Returned,
}

/// Revokes a borrowed takeover on every exit, even if the runtime itself stops.
struct CallbackScope(Arc<StdMutex<Slot>>);
impl Drop for CallbackScope {
    fn drop(&mut self) {
        let returned = {
            let mut slot = lock(&self.0);
            if matches!(&*slot, Slot::Held(t) if !t.is_detached()) {
                Some(std::mem::replace(&mut *slot, Slot::Returned))
            } else {
                None
            }
        };
        drop(returned);
    }
}

/// The listener's fallback of the Python handler `f`, called on the loop
/// `lp` with each `Takeover` and awaited there when it returns an
/// awaitable. Once it returned (or raised: reported as unraisable), what it
/// neither took nor detached is closed.
pub(crate) fn fallback(f: Py<PyAny>, lp: LoopRef) -> zmux::Fallback {
    let f = Arc::new(f);
    zmux::Fallback::try_new(move |t: zmux::Takeover| {
        let (f, lp) = (f.clone(), lp.clone());
        async move {
            let slot = Arc::new(StdMutex::new(Slot::Held(t)));
            let (given, hook) = (slot.clone(), f.clone());
            let scope = CallbackScope(slot);
            let r = lp
                .settled(
                    move |py| {
                        let t = Py::new(py, Takeover::new(py, given)?)?;
                        hook.bind(py).call1((t,))
                    },
                    move |_, result| {
                        drop(scope);
                        result.map(|_| ())
                    },
                    || {
                        Err(pyo3::exceptions::PyRuntimeError::new_err(
                            "fallback loop closed",
                        ))
                    },
                )
                .await;
            if let Err(e) = r {
                let original = Python::attach(|py| e.clone_ref(py));
                lp.post(move |py| {
                    if !e.is_instance_of::<pyo3::exceptions::asyncio::CancelledError>(py) {
                        e.write_unraisable(py, Some(f.bind(py)));
                    }
                });
                return Err(std::io::Error::other(original));
            }
            Ok(())
        }
    })
}

/// A carrier the listener's admission handed to `ListenerConfig.fallback`.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct Takeover {
    info: Py<CarrierInfo>,
    replayed: Py<PyBytes>,
    value: Option<Py<PyAny>>,
    slot: Arc<StdMutex<Slot>>,
}

impl Takeover {
    fn new(py: Python<'_>, slot: Arc<StdMutex<Slot>>) -> PyResult<Self> {
        let (info, replayed, value) = match &*lock(&slot) {
            Slot::Held(t) => (
                t.info().clone(),
                PyBytes::new(py, t.replayed()).unbind(),
                admission::admitted_obj(py, t.value()),
            ),
            _ => unreachable!("a takeover is made with its carrier"),
        };
        Ok(Self {
            info: Py::new(py, CarrierInfo(info))?,
            replayed,
            value,
            slot,
        })
    }

    /// Takes the carrier.
    fn take(&self, records: bool) -> PyResult<zmux::Takeover> {
        let mut s = lock(&self.slot);
        if records
            && matches!(&*s, Slot::Held(t) if t.framing() != zmux::proto::record::Framing::Records)
        {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "the carrier is a byte stream: use into_pipe()",
            ));
        }
        match std::mem::replace(&mut *s, Slot::Taken) {
            Slot::Held(t) => Ok(t),
            other => {
                let e = gone(&other);
                *s = other;
                Err(e)
            }
        }
    }
}

/// The error of a takeover whose carrier is no longer held.
fn gone(s: &Slot) -> PyErr {
    match s {
        Slot::Returned => returned(),
        _ => new_err("PipeUsedError", "the takeover's carrier was taken already"),
    }
}

fn returned() -> PyErr {
    new_err(
        "TakeoverReturnedError",
        "the fallback returned before the takeover was detached",
    )
}

#[pymethods]
impl Takeover {
    /// The carrier's metadata, as the decision saw it.
    #[getter]
    fn info(&self, py: Python<'_>) -> Py<CarrierInfo> {
        self.info.clone_ref(py)
    }
    /// The carrier's framing.
    #[getter]
    fn framing<'p>(&self, py: Python<'p>) -> Bound<'p, PyAny> {
        crate::typed(
            py,
            "Framing",
            admission::framing_name(self.info.get().0.framing).to_owned(),
        )
    }
    /// What the admission read, replayed in front of the carrier.
    #[getter]
    fn replayed(&self, py: Python<'_>) -> Py<PyBytes> {
        self.replayed.clone_ref(py)
    }
    /// The value of the verdict that handed the carrier over.
    #[getter]
    fn value(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.value.as_ref().map(|v| v.clone_ref(py))
    }
    /// Whether `detach` made the carrier the host's.
    #[getter]
    fn detached(&self) -> bool {
        match &*lock(&self.slot) {
            Slot::Held(t) => t.is_detached(),
            _ => false,
        }
    }
    /// Makes the carrier the host's for good.
    fn detach(&self) -> PyResult<()> {
        match &*lock(&self.slot) {
            Slot::Held(t) => t.detach().map_err(|_| returned()),
            s => Err(gone(s)),
        }
    }
    /// The carrier as a pipe input, what was read replayed first.
    #[allow(clippy::wrong_self_convention)] // Python's name; the carrier is taken
    fn into_pipe(&self) -> PyResult<PipeIo> {
        Ok(PipeIo::wrap(self.take(false)?.into_pipe()))
    }
    /// A message-framed carrier read and written by whole messages.
    #[allow(clippy::wrong_self_convention)] // Python's name; the carrier is taken
    fn into_messages(&self) -> PyResult<TakeoverMessages> {
        let messages = self
            .take(true)?
            .into_messages()
            .expect("framing checked during claim");
        Ok(TakeoverMessages::new(messages))
    }
    fn __repr__(&self, py: Python<'_>) -> String {
        let state = match &*lock(&self.slot) {
            Slot::Held(t) if t.is_detached() => "detached",
            Slot::Held(_) => "held",
            Slot::Taken => "taken",
            Slot::Returned => "returned",
        };
        format!(
            "Takeover(replayed={} bytes, {state})",
            self.replayed.bind(py).as_bytes().len()
        )
    }
}

/// A taken-over message-framed carrier: each read a whole message, each
/// write one. Its halves are split, so a read waiting for a message never
/// holds back a write: one read and one write run at a time.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct TakeoverMessages {
    reader: Arc<Mutex<zmux::MessageReader>>,
    writer: Arc<Mutex<zmux::MessageWriter>>,
}

impl TakeoverMessages {
    fn new(m: zmux::Messages) -> Self {
        let (r, w) = m.split();
        Self {
            reader: Arc::new(Mutex::new(r)),
            writer: Arc::new(Mutex::new(w)),
        }
    }
}

// The default of `read_message`, a literal for the signature Python sees.
const _: () = assert!(zmux::MAX_ADMISSION_MESSAGE == 65535);

#[pymethods]
impl TakeoverMessages {
    /// The next message, of at most `max` bytes; `None` at the end.
    #[pyo3(signature = (max=65535))]
    fn read_message<'p>(
        &self,
        py: Python<'p>,
        #[pyo3(from_py_with = ranged)] max: usize,
    ) -> PyResult<Bound<'p, PyAny>> {
        let r = self.reader.clone();
        future_into_py(py, async move {
            Ok(r.lock()
                .await
                .read_message(max)
                .await
                .map_err(io_err)?
                .map(rt::Bin::from))
        })
    }
    /// Writes `message` as one message.
    fn write_message<'p>(
        &self,
        py: Python<'p>,
        message: &Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let (w, data) = (self.writer.clone(), crate::chunk_of(message)?);
        future_into_py(py, async move {
            w.lock().await.write_message(&data).await.map_err(io_err)
        })
    }
    /// Ends the sending half gracefully; the receiving half reads on.
    fn shutdown<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let w = self.writer.clone();
        future_into_py(py, async move {
            w.lock().await.shutdown().await.map_err(io_err)
        })
    }
}

/// Registers the classes.
pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Takeover>()?;
    m.add_class::<TakeoverMessages>()?;
    Ok(())
}
