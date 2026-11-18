//! Packet streams: `zmux.helpers.PacketStream` and its halves, packets
//! carried over a bidirectional stream as stream datagrams or DATAGRAM
//! capsules.

use std::sync::{Arc, Mutex as StdMutex};

use bytes::Bytes;
use pyo3::exceptions::{PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyBytes, PyDict};
use tokio::sync::Mutex;
use zmux::helpers as h;

use crate::helpers::lock;
use crate::ranged;
use crate::rt::{deferred, future_into_py, undoable_future_into_py};
use crate::{Part, RecvStream, Returned, SendStream, held, raise, typed, types};

/// `SendPolicy` by value.
fn policy_of(s: &str) -> PyResult<h::SendPolicy> {
    match s {
        "prefer_datagram" => Ok(h::SendPolicy::PreferDatagram),
        "stream_only" => Ok(h::SendPolicy::StreamOnly),
        "datagram_only" => Ok(h::SendPolicy::DatagramOnly),
        _ => Err(PyValueError::new_err(format!("unknown send policy {s:?}"))),
    }
}

/// The options of `policy` and `max_packet`.
pub(crate) fn options(policy: &str, max_packet: usize) -> PyResult<h::PacketOptions> {
    let mut o = h::PacketOptions::with_policy(policy_of(policy)?);
    o.max_packet = max_packet;
    Ok(o)
}

/// A packet operation's failure, classified by what happened.
fn packet_err(e: h::PacketError) -> PyErr {
    use h::PacketError as E;
    match e {
        E::Stream(s) => crate::stream_err(s),
        E::Datagram(d) => crate::datagram_err(d),
        E::TooLarge { max } => crate::rt::decorate(
            raise("PacketTooLargeError", &e, false, None),
            move |_, v| {
                let _ = v.setattr("max", max);
            },
        ),
        E::InvalidContext => raise("InvalidArgumentError", &e, false, None),
        E::NotNegotiated => raise("NotNegotiatedError", &e, false, None),
        E::Malformed => raise(
            "MalformedPacketError",
            &e,
            false,
            Some(zmux::ApplicationErrorCode::ZMUX_PACKET_ERROR.0),
        ),
        _ => raise("PacketError", &e, false, None),
    }
}

fn sent_obj(py: Python<'_>, s: h::Sent) -> Py<PyAny> {
    let name = match s {
        h::Sent::Datagram => "datagram",
        h::Sent::Capsule => "capsule",
        h::Sent::Dropped => "dropped",
        other => {
            return crate::helpers::snake(&crate::kind_of(&other))
                .into_pyobject(py)
                .unwrap()
                .into_any()
                .unbind();
        }
    };
    typed(py, "Sent", name.into()).unbind()
}

fn stats_obj(py: Python<'_>, s: h::PacketStats) -> PyResult<Py<PyAny>> {
    let d = PyDict::new(py);
    d.set_item("sent_datagrams", s.sent_datagrams)?;
    d.set_item("sent_capsules", s.sent_capsules)?;
    d.set_item("dropped_too_large", s.dropped_too_large)?;
    d.set_item("dropped_limited", s.dropped_limited)?;
    d.set_item("received_datagrams", s.received_datagrams)?;
    d.set_item("received_capsules", s.received_capsules)?;
    d.set_item("skipped_capsules", s.skipped_capsules)?;
    Ok(types(py)?
        .getattr("PacketStats")?
        .call((), Some(&d))?
        .unbind())
}

fn merge(a: h::PacketStats, b: h::PacketStats) -> h::PacketStats {
    let mut m = a;
    m.sent_datagrams += b.sent_datagrams;
    m.sent_capsules += b.sent_capsules;
    m.dropped_too_large += b.dropped_too_large;
    m.dropped_limited += b.dropped_limited;
    m.received_datagrams += b.received_datagrams;
    m.received_capsules += b.received_capsules;
    m.skipped_capsules += b.skipped_capsules;
    m
}

/// A half and the counters it had when its last operation completed, read
/// while another operation holds it.
struct Half<T> {
    part: Part<T>,
    last: Arc<StdMutex<h::PacketStats>>,
}

impl<T> Clone for Half<T> {
    fn clone(&self) -> Self {
        Half {
            part: self.part.clone(),
            last: self.last.clone(),
        }
    }
}

trait Counted {
    fn counters(&self) -> h::PacketStats;
}

impl Counted for h::PacketSender {
    fn counters(&self) -> h::PacketStats {
        self.stats()
    }
}

impl Counted for h::PacketReceiver {
    fn counters(&self) -> h::PacketStats {
        self.stats()
    }
}

impl<T: Counted> Half<T> {
    fn new(v: T) -> Self {
        Half {
            last: Arc::new(StdMutex::new(v.counters())),
            part: Arc::new(Mutex::new(Some(v))),
        }
    }

    fn stats(&self) -> h::PacketStats {
        let last = || *lock(&self.last);
        match self.part.try_lock() {
            Ok(g) => g.as_ref().map_or_else(last, Counted::counters),
            Err(_) => last(),
        }
    }

    fn record(&self, v: &T) {
        *lock(&self.last) = v.counters();
    }
}

/// The sending operations, shared by `PacketStream` and `PacketSender`.
fn send<'p>(
    py: Python<'p>,
    tx: &Half<h::PacketSender>,
    payload: PyBackedBytes,
    context: u64,
) -> PyResult<Bound<'p, PyAny>> {
    let tx = tx.clone();
    future_into_py(py, async move {
        let mut g = held(&tx.part).await?;
        let r = g
            .send_with_context(context, Bytes::from_owner(payload))
            .await;
        tx.record(&g);
        drop(g);
        let s = r.map_err(packet_err)?;
        Ok(deferred(move |py| Ok(sent_obj(py, s))))
    })
}

fn close<'p>(py: Python<'p>, tx: &Half<h::PacketSender>) -> PyResult<Bound<'p, PyAny>> {
    let tx = tx.clone();
    future_into_py(py, async move {
        let mut g = held(&tx.part).await?;
        let r = g.close().await;
        tx.record(&g);
        r.map_err(packet_err)
    })
}

/// The receiving half and the packets taken back from cancelled receives,
/// one queue for the stream and the receiver split from it.
#[derive(Clone)]
struct Rx {
    half: Half<h::PacketReceiver>,
    back: Arc<Returned<Py<PyAny>>>,
}

impl Rx {
    fn new(r: h::PacketReceiver) -> Self {
        Rx {
            half: Half::new(r),
            back: Arc::default(),
        }
    }

    /// The next packet, or `None` at the end; with `iter` the end is
    /// `StopAsyncIteration`. A packet whose awaiter was cancelled after it
    /// arrived is returned again by the next call.
    fn recv<'p>(&self, py: Python<'p>, iter: bool) -> PyResult<Bound<'p, PyAny>> {
        let rx = self.clone();
        let undo = self.back.undo(py)?;
        let (back, wake) = (self.back.queue(), self.back.woken());
        undoable_future_into_py(
            py,
            async move {
                let mut g = held(&rx.half.part).await?;
                // A packet taken back while this waits is taken instead:
                // the receive is cancel-safe and packets are unordered.
                let got = loop {
                    if let Some(v) = lock(&back).pop_front() {
                        break Ok(v);
                    }
                    tokio::select! {
                        r = g.recv() => break Err(r),
                        () = wake.notified() => {}
                    }
                };
                let got = match got {
                    Ok(v) => Ok(v),
                    Err(r) => {
                        rx.half.record(&g);
                        Err(r.map_err(packet_err)?)
                    }
                };
                drop(g);
                let v = deferred(move |py| match got {
                    // Taken back: the end too, when its awaiter was cancelled.
                    Ok(v) if iter && v.is_none(py) => Err(PyStopAsyncIteration::new_err(())),
                    Ok(v) => Ok(v),
                    Err(Some(p)) => Ok(types(py)?
                        .getattr("Packet")?
                        .call1((p.context, PyBytes::new(py, &p.payload)))?
                        .unbind()),
                    Err(None) if iter => Err(PyStopAsyncIteration::new_err(())),
                    Err(None) => Ok(py.None()),
                });
                Ok((v, ()))
            },
            undo,
        )
    }
}

/// A packet stream: packets over a bidirectional stream, as stream
/// datagrams or DATAGRAM capsules.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PacketStream {
    tx: Half<h::PacketSender>,
    rx: Rx,
}

impl From<h::PacketStream> for PacketStream {
    fn from(p: h::PacketStream) -> Self {
        let (s, r) = p.split();
        PacketStream {
            tx: Half::new(s),
            rx: Rx::new(r),
        }
    }
}

#[pymethods]
impl PacketStream {
    #[new]
    #[pyo3(signature = (send, recv, *, policy="prefer_datagram", max_packet=h::DEFAULT_MAX_PACKET))]
    fn new(
        send: &Bound<'_, SendStream>,
        recv: &Bound<'_, RecvStream>,
        policy: &str,
        #[pyo3(from_py_with = ranged)] max_packet: usize,
    ) -> PyResult<Self> {
        let opts = options(policy, max_packet)?;
        let (s, r) = crate::helpers::pair(send, recv)?;
        Ok(h::PacketStream::with_options(s, r, opts).into())
    }

    #[pyo3(signature = (payload, *, context=0))]
    fn send<'p>(
        &self,
        py: Python<'p>,
        payload: PyBackedBytes,
        #[pyo3(from_py_with = ranged)] context: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        send(py, &self.tx, payload, context)
    }

    fn recv<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.rx.recv(py, false)
    }

    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.rx.recv(py, true)
    }

    fn close<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        close(py, &self.tx)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        stats_obj(py, merge(self.tx.stats(), self.rx.half.stats()))
    }

    fn split(&self) -> PyResult<(PacketSender, PacketReceiver)> {
        let (s, r) = (&self.tx.part, &self.rx.half.part);
        let mut sg = crate::rt::when_free(|| s.try_lock()).map_err(|_| crate::busy())?;
        let mut rg = crate::rt::when_free(|| r.try_lock()).map_err(|_| crate::busy())?;
        match (sg.take(), rg.take()) {
            (Some(s), Some(r)) => {
                // The same queue of packets taken back: a receive started
                // before the split and cancelled after it requeues where
                // the receiver takes from.
                let rx = Rx {
                    half: Half::new(r),
                    back: self.rx.back.clone(),
                };
                Ok((PacketSender(Half::new(s)), PacketReceiver(rx)))
            }
            (s, r) => {
                *sg = s;
                *rg = r;
                Err(crate::stream_err(zmux::StreamError::ClosedLocally))
            }
        }
    }
}

/// The sending half of a packet stream.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PacketSender(Half<h::PacketSender>);

#[pymethods]
impl PacketSender {
    #[pyo3(signature = (payload, *, context=0))]
    fn send<'p>(
        &self,
        py: Python<'p>,
        payload: PyBackedBytes,
        #[pyo3(from_py_with = ranged)] context: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        send(py, &self.0, payload, context)
    }

    fn close<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        close(py, &self.0)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        stats_obj(py, self.0.stats())
    }
}

/// The receiving half of a packet stream.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct PacketReceiver(Rx);

#[pymethods]
impl PacketReceiver {
    fn recv<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.0.recv(py, false)
    }

    fn __aiter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __anext__<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.0.recv(py, true)
    }

    fn stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        stats_obj(py, self.0.half.stats())
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketStream>()?;
    m.add_class::<PacketSender>()?;
    m.add_class::<PacketReceiver>()?;
    Ok(())
}
