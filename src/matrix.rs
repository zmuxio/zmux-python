//! Test-only carrier observation and access to the FINAL matrix fixture seams.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use zmux::proto::frame::{Frame, Gates};
use zmux::proto::params::ZMUX_MAX_RECORD_SIZE;
use zmux::proto::record::{Event, Framing, RecordReader};
use zmux::proto::seal::{self, Suite, join};

use crate::rt::Bin;
use crate::{Listener, PipeIo, Session, future_into_py, host_port, io_err, lock, value_err};

#[derive(Clone, Copy)]
enum Phase {
    Hello,
    Reply,
    Confirm,
    Records,
}

struct Direction {
    phase: Phase,
    handshake: Vec<u8>,
    records: RecordReader,
    eliciting: bool,
    probe: bool,
    eliciting_end: u64,
    probe_end: u64,
    acks: BTreeMap<u64, u64>,
    streams: BTreeMap<u64, bool>,
    padding: usize,
    datagrams: usize,
}

impl Direction {
    fn new(phase: Phase) -> Self {
        Self {
            phase,
            handshake: Vec::new(),
            records: RecordReader::new(ZMUX_MAX_RECORD_SIZE),
            eliciting: false,
            probe: false,
            eliciting_end: 0,
            probe_end: 0,
            acks: BTreeMap::new(),
            streams: BTreeMap::new(),
            padding: 0,
            datagrams: 0,
        }
    }

    fn observe_join(&mut self, bytes: &[u8]) -> Result<usize, seal::Error> {
        let framing = Framing::ByteStream;
        let (next, used) = match self.phase {
            Phase::Hello => {
                let hello = join::JoinHello::parse(framing, bytes)?;
                if hello.mode() != zmux::RecordMode::Trusted {
                    return Err(seal::Error::BadFlags);
                }
                (Phase::Confirm, hello.consumed())
            }
            Phase::Reply => {
                let suite = Suite::from_value(1).expect("mandatory AES suite");
                let (_, _, used) = join::parse_reply(suite, framing, bytes)?;
                (Phase::Records, used)
            }
            Phase::Confirm => {
                let (_, used) = seal::cut_unit(framing, bytes)?;
                (Phase::Records, used)
            }
            Phase::Records => unreachable!(),
        };
        self.phase = next;
        Ok(used)
    }

    fn observe(&mut self, bytes: &[u8]) -> Result<(), String> {
        if matches!(self.phase, Phase::Records) {
            return self.observe_records(bytes);
        }
        // Join units on the trusted byte stream precede its ordinary records.
        let mut pending = std::mem::take(&mut self.handshake);
        pending.extend_from_slice(bytes);
        let mut bytes = pending.as_slice();
        while !matches!(self.phase, Phase::Records) {
            match self.observe_join(bytes) {
                Ok(used) => bytes = &bytes[used..],
                Err(seal::Error::Incomplete { .. }) if bytes.len() <= seal::MAX_UNIT => {
                    self.handshake.extend_from_slice(bytes);
                    return Ok(());
                }
                Err(err) => return Err(err.to_string()),
            }
        }
        self.observe_records(bytes)
    }

    fn observe_records(&mut self, mut bytes: &[u8]) -> Result<(), String> {
        while let Some(event) = self
            .records
            .read(&mut bytes, &Gates::ALL)
            .map_err(|e| e.to_string())?
        {
            match event {
                Event::Frame(frame) => {
                    self.eliciting |= frame.is_ack_eliciting();
                    match frame {
                        Frame::PipePing => self.probe = true,
                        Frame::PipeAck(ack) => {
                            for entry in ack.entries().filter(|entry| entry.lane == 0) {
                                let position = self.acks.entry(entry.pipe_id).or_default();
                                *position = (*position).max(entry.position);
                            }
                        }
                        Frame::Stream(stream) => {
                            *self.streams.entry(stream.stream_id).or_default() |= stream.fin;
                        }
                        Frame::Padding(padding) => self.padding += padding.len,
                        Frame::Datagram(_) => self.datagrams += 1,
                        _ => {}
                    }
                }
                Event::RecordEnd { .. } => {
                    if std::mem::take(&mut self.eliciting) {
                        self.eliciting_end = self.records.position();
                    }
                    if std::mem::take(&mut self.probe) {
                        self.probe_end = self.records.position();
                    }
                }
            }
        }
        Ok(())
    }
}

struct State {
    sent: Direction,
    received: Direction,
    error: Option<String>,
    read_held: bool,
    reader: Option<Waker>,
    write_held: bool,
    writer: Option<Waker>,
}

/// Records actual socket handoffs in both directions, including ACKs and padding.
#[pyclass(name = "_MatrixWire", frozen)]
#[derive(Clone)]
struct Wire {
    state: Arc<Mutex<State>>,
    revision: watch::Sender<u64>,
}

type Observation = (
    u64,
    u64,
    BTreeMap<u64, u64>,
    BTreeMap<u64, bool>,
    usize,
    usize,
    usize,
);

#[pymethods]
impl Wire {
    #[new]
    #[pyo3(signature = (*, join=false, client=false, signal=None))]
    fn new(join: bool, client: bool, signal: Option<&Self>) -> Self {
        let (sent, received) = match (join, client) {
            (false, _) => (Phase::Records, Phase::Records),
            (true, true) => (Phase::Hello, Phase::Reply),
            (true, false) => (Phase::Reply, Phase::Hello),
        };
        Self {
            state: Arc::new(Mutex::new(State {
                sent: Direction::new(sent),
                received: Direction::new(received),
                error: None,
                read_held: false,
                reader: None,
                write_held: false,
                writer: None,
            })),
            revision: signal.map_or_else(|| watch::Sender::new(0), |wire| wire.revision.clone()),
        }
    }

    /// Reads the shared change watermark before inspecting the observed wires.
    #[getter]
    fn revision(&self) -> u64 {
        *self.revision.borrow()
    }

    /// Waits for a socket handoff after the observed watermark.
    fn changed<'py>(&self, py: Python<'py>, observed: u64) -> PyResult<Bound<'py, PyAny>> {
        let mut revision = self.revision.subscribe();
        future_into_py(py, async move {
            let _ = revision.wait_for(|value| *value != observed).await;
            Ok(())
        })
    }

    /// Returns probe and eliciting ends, received ACK positions, outbound streams, padding and datagrams.
    fn snapshot(&self) -> PyResult<Observation> {
        let state = lock(&self.state);
        if let Some(error) = &state.error {
            return Err(PyValueError::new_err(format!(
                "matrix carrier recorder: {error}"
            )));
        }
        Ok((
            state.sent.probe_end,
            state.sent.eliciting_end,
            state.received.acks.clone(),
            state.sent.streams.clone(),
            state.sent.padding,
            state.sent.datagrams,
            state.received.datagrams,
        ))
    }

    /// Holds or releases reads and returns the last complete inbound record position.
    fn hold_reads(&self, held: bool) -> u64 {
        let (position, wake) = {
            let mut state = lock(&self.state);
            state.read_held = held;
            let wake = if held { None } else { state.reader.take() };
            (state.received.records.position(), wake)
        };
        if let Some(wake) = wake {
            wake.wake();
        }
        position
    }

    /// Holds or releases writes while leaving the socket and its receive half open.
    fn hold_writes(&self, held: bool) {
        let wake = {
            let mut state = lock(&self.state);
            state.write_held = held;
            if held { None } else { state.writer.take() }
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

impl Wire {
    fn observe(&self, state: &mut State, sent: bool, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if state.error.is_none() {
            let direction = if sent {
                &mut state.sent
            } else {
                &mut state.received
            };
            state.error = direction.observe(bytes).err();
        }
        self.revision.send_modify(|revision| *revision += 1);
    }

    async fn pipe(self, socket: TcpStream) -> PyResult<PipeIo> {
        let pipe = zmux::PipeIo::from_tcp(socket)
            .wrap(|inner| async move { Ok(Tap { inner, wire: self }) })
            .await
            .map_err(io_err)?;
        Ok(PipeIo::wrap(pipe))
    }
}

struct Tap<T> {
    inner: T,
    wire: Wire,
}

impl<T: AsyncRead + Unpin> AsyncRead for Tap<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let tap = self.as_mut().get_mut();
        let mut state = lock(&tap.wire.state);
        if state.read_held {
            state.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut tap.inner).poll_read(cx, buf))?;
        tap.wire.observe(&mut state, false, &buf.filled()[before..]);
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tap<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        {
            let mut state = lock(&self.wire.state);
            if state.write_held {
                state.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        self.wire
            .observe(&mut lock(&self.wire.state), true, &buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A loopback listening socket owned by the matrix server.
#[pyclass(name = "_MatrixTcp", frozen)]
struct Tcp(Arc<TcpListener>);

#[pymethods]
impl Tcp {
    /// Binds a loopback listener on an ephemeral port.
    #[staticmethod]
    fn bind(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        future_into_py(py, async {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(io_err)?;
            Ok(Self(Arc::new(tcp)))
        })
    }

    /// The bound address as published to the driver.
    #[getter]
    fn address(&self) -> PyResult<String> {
        Ok(self.0.local_addr().map_err(io_err)?.to_string())
    }

    /// Accepts a TCP carrier and installs its observer.
    fn accept<'py>(&self, py: Python<'py>, wire: &Wire) -> PyResult<Bound<'py, PyAny>> {
        let (tcp, wire) = (self.0.clone(), wire.clone());
        future_into_py(py, async move {
            let (socket, peer) = tcp.accept().await.map_err(io_err)?;
            Ok((wire.pipe(socket).await?, host_port(peer)))
        })
    }

    /// Upgrades a WebSocket through the production head admission path.
    fn upgrade<'py>(&self, py: Python<'py>, listener: &Listener) -> PyResult<Bound<'py, PyAny>> {
        listener.bind(py);
        let (tcp, listener) = (self.0.clone(), listener.inner.clone());
        future_into_py(py, async move {
            let (socket, peer) = tcp.accept().await.map_err(io_err)?;
            let entry = listener
                .adapter()
                .enter(peer, Some(peer))
                .ok_or_else(|| PyValueError::new_err("matrix WebSocket entry refused"))?;
            let upgrade = zmux_websocket::accept(
                socket,
                entry,
                |_| zmux::CarrierInfo::new(),
                &listener,
                &zmux_websocket::Options::default(),
            )
            .await
            .map_err(io_err)?;
            match upgrade {
                zmux_websocket::Upgrade::Upgraded(upgrade) => {
                    Ok(Upgrade(Mutex::new(Some((upgrade, listener)))))
                }
                _ => Err(PyValueError::new_err("matrix WebSocket upgrade refused")),
            }
        })
    }
}

/// An upgraded WebSocket awaiting first-message admission.
#[pyclass(name = "_MatrixUpgrade", frozen)]
struct Upgrade(Mutex<Option<(zmux_websocket::Upgraded, zmux::Listener)>>);

#[pymethods]
impl Upgrade {
    /// Runs first-message admission to completion and attaches the carrier if accepted.
    fn admit<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let (upgrade, listener) = lock(&self.0)
            .take()
            .ok_or_else(|| PyValueError::new_err("matrix upgrade already consumed"))?;
        future_into_py(py, async move {
            let Some((pipe, hint)) = upgrade.admit().await else {
                return Ok(false);
            };
            listener
                .handle_pipe(pipe, hint)
                .await
                .map_err(|err| crate::raise("ConnectError", &err, false, None))?;
            Ok(true)
        })
    }
}

/// Connects a TCP carrier and installs its observer.
#[pyfunction(name = "_matrix_dial_tcp")]
#[pyo3(signature = (address, *, wire))]
fn matrix_dial_tcp<'py>(
    py: Python<'py>,
    address: &str,
    wire: &Wire,
) -> PyResult<Bound<'py, PyAny>> {
    let address: SocketAddr = address.parse().map_err(value_err)?;
    let wire = wire.clone();
    future_into_py(py, async move {
        wire.pipe(TcpStream::connect(address).await.map_err(io_err)?)
            .await
    })
}

/// Writes whole messages before returning the carrier for its next operation.
#[pyfunction(name = "_matrix_write_messages")]
#[pyo3(signature = (pipe, *, messages))]
fn matrix_write_messages<'py>(
    py: Python<'py>,
    pipe: &PipeIo,
    messages: Vec<Vec<u8>>,
) -> PyResult<Bound<'py, PyAny>> {
    let mut pipe = pipe.take()?;
    future_into_py(py, async move {
        for message in messages {
            pipe.write_handshake(&message).await.map_err(io_err)?;
        }
        Ok(PipeIo::wrap(pipe))
    })
}

/// Reads up to the given number of whole messages, ending early when the carrier closes.
#[pyfunction(name = "_matrix_read_messages")]
#[pyo3(signature = (pipe, *, count))]
fn matrix_read_messages<'py>(
    py: Python<'py>,
    pipe: &PipeIo,
    count: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let mut pipe = pipe.take()?;
    future_into_py(py, async move {
        let mut messages = Vec::new();
        for _ in 0..count {
            let mut message = Vec::new();
            match pipe.read_handshake(&mut message).await {
                Ok(0) => break,
                Ok(_) => messages.push(Bin::from(message)),
                Err(err)
                    if message.is_empty()
                        && matches!(
                            err.kind(),
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                        ) =>
                {
                    break;
                }
                Err(err) => return Err(io_err(err)),
            }
        }
        Ok(messages)
    })
}

/// Waits for completed establishment through the native driver.
#[pyfunction(name = "_matrix_established")]
fn matrix_established<'py>(py: Python<'py>, session: &Session) -> PyResult<Bound<'py, PyAny>> {
    let session = session.0.clone();
    future_into_py(py, async move {
        session.established().await.map_err(crate::session_err)
    })
}

/// Installs deterministic ACK progress evidence through the core's fixture seam.
#[pyfunction(name = "_matrix_stall_evidence")]
#[pyo3(signature = (session, *, pipe, cost, waiting))]
fn matrix_stall_evidence(session: &Session, pipe: u64, cost: f64, waiting: bool) -> PyResult<()> {
    zmux::test_hooks::inject_stall_evidence(
        &session.0,
        zmux::PipeId::new(pipe),
        crate::seconds("cost", cost)?,
        waiting,
    )
    .map_err(PyValueError::new_err)
}

/// Fires the ordinary session timers at the current fixture-clock instant.
#[pyfunction(name = "_matrix_fire_timers")]
fn matrix_fire_timers(session: &Session) {
    zmux::test_hooks::fire_session_timers(&session.0);
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Wire>()?;
    m.add_class::<Tcp>()?;
    m.add_class::<Upgrade>()?;
    m.add_function(wrap_pyfunction!(matrix_dial_tcp, m)?)?;
    m.add_function(wrap_pyfunction!(matrix_write_messages, m)?)?;
    m.add_function(wrap_pyfunction!(matrix_read_messages, m)?)?;
    m.add_function(wrap_pyfunction!(matrix_established, m)?)?;
    m.add_function(wrap_pyfunction!(matrix_stall_evidence, m)?)?;
    m.add_function(wrap_pyfunction!(matrix_fire_timers, m)?)?;
    Ok(())
}
