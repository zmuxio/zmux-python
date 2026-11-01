//! Layers over carriers and the listener's inbound transform:
//! `CarrierStream` (a carrier's halves as one byte stream, which
//! `zmux._layer` turns into asyncio streams), `LayerEnd` (the Python side of
//! the stream a layer returns), `PipeHint` and the transform itself.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3_async_runtimes::TaskLocals;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};

use crate::rt::{self, future_into_py};
use crate::{PipeIo, admission, io_err, pyb};

/// How many writes each way a layer's channel holds.
const DEPTH: usize = 8;

/// A Python error as the I/O error the Rust crate takes.
pub(crate) fn py_io(e: PyErr) -> io::Error {
    io::Error::other(e.to_string())
}

/// A carrier's halves as one byte stream (`PipeIo.into_stream()`): on a
/// carrier with message framing each write is one message and reads return
/// the messages' bytes in order. Each `write` is exactly one write on the
/// carrier. Bytes a listener already read from the carrier come first.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct CarrierStream {
    r: Arc<Mutex<Option<ReadHalf<zmux::PipeStream>>>>,
    w: Arc<Mutex<Option<WriteHalf<zmux::PipeStream>>>>,
}

impl CarrierStream {
    pub(crate) fn new(s: zmux::PipeStream) -> Self {
        let (r, w) = tokio::io::split(s);
        Self {
            r: Arc::new(Mutex::new(Some(r))),
            w: Arc::new(Mutex::new(Some(w))),
        }
    }

    /// Drops the carrier, whoever still holds this object.
    async fn release(&self) {
        self.r.lock().await.take();
        self.w.lock().await.take();
    }

    fn handle(&self) -> Self {
        Self {
            r: self.r.clone(),
            w: self.w.clone(),
        }
    }
}

fn released() -> PyErr {
    PyRuntimeError::new_err("carrier released")
}

#[pymethods]
impl CarrierStream {
    /// Up to `n` bytes; `b""` at the end of the stream (also without a
    /// receiving half).
    #[pyo3(signature = (n=65536))]
    fn read<'p>(&self, py: Python<'p>, n: usize) -> PyResult<Bound<'p, PyAny>> {
        let r = self.r.clone();
        future_into_py(py, async move {
            let mut buf = vec![0; n.max(1)];
            let mut r = r.lock().await;
            let r = r.as_mut().ok_or_else(released)?;
            let k = r.read(&mut buf).await.map_err(io_err)?;
            Ok(pyb(&buf[..k]))
        })
    }
    /// Writes `data` as one write on the carrier (one message on a carrier
    /// with message framing); fails without a sending half.
    fn write<'p>(&self, py: Python<'p>, data: Vec<u8>) -> PyResult<Bound<'p, PyAny>> {
        let w = self.w.clone();
        future_into_py(py, async move {
            let mut w = w.lock().await;
            let w = w.as_mut().ok_or_else(released)?;
            w.write_all(&data).await.map_err(io_err)?;
            w.flush().await.map_err(io_err)
        })
    }
    /// Ends the sending half gracefully.
    fn shutdown<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let w = self.w.clone();
        future_into_py(py, async move {
            let mut w = w.lock().await;
            w.as_mut()
                .ok_or_else(released)?
                .shutdown()
                .await
                .map_err(io_err)
        })
    }
}

/// The Rust side of the stream a Python layer returns: each carrier write
/// is one message to Python, which writes it to the layer once; what the
/// layer reads comes back as messages.
struct ChanIo {
    rx: mpsc::Receiver<Bytes>,
    buf: Bytes,
    tx: Option<mpsc::Sender<Bytes>>,
    reserve: Option<Reserve>,
}

type Reserve = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Bytes>, mpsc::error::SendError<()>>> + Send>,
>;

impl AsyncRead for ChanIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self.buf.is_empty() {
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => self.buf = b,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = self.buf.len().min(out.remaining());
        let chunk = self.buf.split_to(n);
        out.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChanIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let Some(tx) = &this.tx else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let reserve = this
            .reserve
            .get_or_insert_with(|| Box::pin(tx.clone().reserve_owned()));
        match reserve.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => {
                this.reserve = None;
                match r {
                    Ok(permit) => {
                        permit.send(Bytes::copy_from_slice(data));
                        Poll::Ready(Ok(data.len()))
                    }
                    Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx = None;
        self.reserve = None;
        Poll::Ready(Ok(()))
    }
}

/// The Python side of a layer's stream, which `zmux._layer` pumps.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct LayerEnd {
    /// The carrier's writes, one message each.
    rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    /// What the layer read; dropped at its end.
    tx: std::sync::Mutex<Option<mpsc::Sender<Bytes>>>,
}

fn chan_pair() -> (ChanIo, LayerEnd) {
    let (out_tx, out_rx) = mpsc::channel(DEPTH);
    let (in_tx, in_rx) = mpsc::channel(DEPTH);
    (
        ChanIo {
            rx: in_rx,
            buf: Bytes::new(),
            tx: Some(out_tx),
            reserve: None,
        },
        LayerEnd {
            rx: Arc::new(Mutex::new(out_rx)),
            tx: std::sync::Mutex::new(Some(in_tx)),
        },
    )
}

#[pymethods]
impl LayerEnd {
    /// The next write of the carrier; `b""` once it ended.
    fn read<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let rx = self.rx.clone();
        future_into_py(py, async move {
            let b = rx.lock().await.recv().await.unwrap_or_default();
            Ok(pyb(&b))
        })
    }
    /// Bytes the layer read, for the carrier's reads.
    fn write<'p>(&self, py: Python<'p>, data: Vec<u8>) -> PyResult<Bound<'p, PyAny>> {
        let tx = self.tx.lock().unwrap().clone();
        future_into_py(py, async move {
            let tx = tx.ok_or_else(|| PyRuntimeError::new_err("layer end closed"))?;
            if !data.is_empty() {
                // The carrier dropped its reader: nothing reads any more.
                let _ = tx.send(Bytes::from(data)).await;
            }
            Ok(())
        })
    }
    /// The end of what the layer reads.
    fn close(&self) {
        self.tx.lock().unwrap().take();
    }
}

/// `PipeIo.wrap`: runs the Python `layer` over `io` through
/// `zmux._layer.run`, on `locals`' loop.
pub(crate) async fn wrap(
    io: zmux::PipeIo,
    layer: Py<PyAny>,
    server_side: bool,
    locals: TaskLocals,
) -> io::Result<zmux::PipeIo> {
    io.wrap(move |stream| async move {
        let (chan, end) = chan_pair();
        let stream = CarrierStream::new(stream);
        let ours = stream.handle();
        let r = async {
            let fut = rt::attach(|py| {
                let run = py.import("zmux._layer")?.getattr("run")?;
                let coro = run.call1((layer, stream, end, server_side))?;
                rt::into_future(&locals, coro)
            })?;
            fut.await
        }
        .await;
        if let Err(e) = r {
            // Closed now, though Python may still hold the stream.
            ours.release().await;
            return Err(py_io(e));
        }
        Ok(chan)
    })
    .await
}

/// What a listener knows of a carrier when its inbound transform runs.
#[pyclass(frozen, module = "zmux._zmux")]
pub(crate) struct PipeHint {
    source: Option<(String, u16)>,
    peer: Option<(String, u16)>,
    split: bool,
    admitted: Option<zmux::AdmittedValue>,
}

impl PipeHint {
    fn of(h: &zmux::PipeHint) -> Self {
        let addr = |a: Option<std::net::SocketAddr>| a.map(|a| (a.ip().to_string(), a.port()));
        Self {
            source: addr(h.source.or(h.peer)),
            peer: addr(h.peer),
            split: h.pair.is_some(),
            admitted: h.admitted().cloned(),
        }
    }
}

#[pymethods]
impl PipeHint {
    /// The carrier's source, `(host, port)`: the client a trusted
    /// intermediary reported, else the peer.
    #[getter]
    fn source(&self) -> Option<(String, u16)> {
        self.source.clone()
    }
    /// The directly connected peer, `(host, port)`.
    #[getter]
    fn peer(&self) -> Option<(String, u16)> {
        self.peer.clone()
    }
    /// Whether the carrier is one half of a split bootstrap.
    #[getter]
    fn split(&self) -> bool {
        self.split
    }
    /// The admission's value for the carrier (`Verdict.accept(value=...)`).
    #[getter]
    fn admitted(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        admission::admitted_obj(py, self.admitted.as_ref())
    }
    fn __repr__(&self) -> String {
        format!(
            "PipeHint(source={:?}, peer={:?}, split={})",
            self.source, self.peer, self.split
        )
    }
}

/// A listener's inbound transform written in Python: `f(pipe, hint)`
/// returning a `PipeIo`, or a coroutine resolving to one, run on `locals`'
/// loop. An exception other than a cancellation is reported as unraisable.
pub(crate) fn transform(f: Py<PyAny>, locals: TaskLocals) -> zmux::InboundTransform {
    let f = Arc::new(f);
    let locals = Arc::new(locals);
    zmux::InboundTransform::new(move |io, hint| {
        let hint = PipeHint::of(hint);
        let (f, locals) = (f.clone(), locals.clone());
        async move {
            let r = call(&f, &locals, io, hint).await;
            r.map_err(|e| {
                rt::attach(|py| {
                    if !e.is_instance_of::<pyo3::exceptions::asyncio::CancelledError>(py) {
                        e.write_unraisable(py, Some(f.bind(py)));
                    }
                });
                io::Error::other("inbound transform failed")
            })
        }
    })
}

async fn call(
    f: &Py<PyAny>,
    locals: &TaskLocals,
    io: zmux::PipeIo,
    hint: PipeHint,
) -> PyResult<zmux::PipeIo> {
    // The carrier closes with a failure even while Python still holds the
    // object (in a traceback, say): what it has not used up is dropped.
    struct Release(Option<Py<PipeIo>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(p) = self.0.take() {
                drop(p.get().0.lock().unwrap().take());
            }
        }
    }
    let mut given = Release(None);
    let pending = rt::attach(|py| -> PyResult<_> {
        let p = Py::new(py, PipeIo::wrap(io))?;
        given.0 = Some(p.clone_ref(py));
        let r = f.bind(py).call1((p, hint))?;
        if r.hasattr("__await__")? {
            Ok(Err(rt::into_future(locals, r)?))
        } else {
            Ok(Ok(r.unbind()))
        }
    })?;
    let obj = match pending {
        Ok(o) => o,
        Err(fut) => fut.await?,
    };
    rt::attach(|py| obj.bind(py).cast::<PipeIo>()?.get().take())
}

/// Registers the classes.
pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CarrierStream>()?;
    m.add_class::<LayerEnd>()?;
    m.add_class::<PipeHint>()?;
    Ok(())
}
