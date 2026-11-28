//! Python callbacks and controls for the Rust splice helpers.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use pyo3::exceptions::{PyIndexError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::Instant;
use zmux::VarInt;
use zmux::helpers as core;

use crate::helpers::lock;
use crate::rt::{self, LoopRef, deferred, future_into_py, future_on_loop};
use crate::{RecvStream, SendStream, ranged, types, value_err, varint};

type Acquisition = Pin<Box<dyn Future<Output = Result<Grant, zmux::LimitError>> + Send>>;
type AcquisitionSlot = Mutex<Option<Acquisition>>;

/// A grant still owned by the Python call, including while its result is
/// queued. Cancellation, a change in requested capacity or an unobserved
/// result returns the portion the relay did not take.
struct Grant {
    limiter: Arc<Limiter>,
    bytes: u64,
}

impl Drop for Grant {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.limiter
                .pre_admission_refunds
                .fetch_add(self.bytes, Ordering::Relaxed);
            self.limiter.refund(self.bytes);
        }
    }
}

struct Limiter {
    object: Py<PyAny>,
    lp: LoopRef,
    pre_admission_refunds: Arc<AtomicU64>,
}

impl Limiter {
    fn refund(self: &Arc<Self>, n: u64) {
        if n > 0 {
            let this = self.clone();
            self.lp.post_in_context(move |py| this.refund_now(py, n));
        }
    }

    fn refund_now(&self, py: Python<'_>, n: u64) {
        if let Err(e) = self.object.call_method1(py, "refund", (n,)) {
            e.write_unraisable(py, Some(self.object.bind(py)));
        }
    }

    fn grant(
        &self,
        py: Python<'_>,
        result: PyResult<Bound<'_, PyAny>>,
        min: u64,
        max: u64,
        nonblocking: bool,
    ) -> PyResult<u64> {
        let n = result?.extract::<u64>()?;
        if (min..=max).contains(&n) || (nonblocking && n == 0) {
            return Ok(n);
        }
        if n > 0 {
            self.pre_admission_refunds.fetch_add(n, Ordering::Relaxed);
            self.refund_now(py, n);
        }
        Err(PyValueError::new_err(format!(
            "the limiter granted {n} bytes, outside {min}..={max}"
        )))
    }

    fn acquire(self: &Arc<Self>, min: u64, max: u64) -> Acquisition {
        let called = self.clone();
        let settled = self.clone();
        Box::pin(self.lp.settled_with(
            move |py| called.object.bind(py).call_method1("acquire", (min, max)),
            move |py, r| {
                settled.grant(py, r, min, max, false).map_or_else(
                    |e| {
                        if !py
                            .import("asyncio")
                            .ok()
                            .and_then(|m| m.getattr("CancelledError").ok())
                            .is_some_and(|ty| e.is_instance(py, &ty))
                        {
                            e.clone_ref(py)
                                .write_unraisable(py, Some(settled.object.bind(py)));
                        }
                        Err(zmux::LimitError::new(e))
                    },
                    |bytes| {
                        Ok(Grant {
                            limiter: settled.clone(),
                            bytes,
                        })
                    },
                )
            },
            || {
                Err(zmux::LimitError::new(PyRuntimeError::new_err(
                    "the limiter's loop closed",
                )))
            },
            true,
        ))
    }
}

struct PyLimiter {
    limiter: Arc<Limiter>,
    // The relay owns the in-flight Python acquire. The target can retain this
    // limiter for refunds after the direction ends.
    pending: Weak<AcquisitionSlot>,
    max_burst_bytes: u64,
    loop_thread: std::thread::ThreadId,
}

impl zmux::Limiter for PyLimiter {
    fn max_burst_bytes(&self) -> Option<u64> {
        Some(self.max_burst_bytes)
    }

    fn poll_acquire(
        &self,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, zmux::LimitError>> {
        let Some(pending) = self.pending.upgrade() else {
            return Poll::Ready(Err(zmux::LimitError::new(std::io::Error::from(
                std::io::ErrorKind::Interrupted,
            ))));
        };
        let mut acquisition = lock(&pending);
        loop {
            let pending = acquisition.get_or_insert_with(|| self.limiter.acquire(min, max));
            let Poll::Ready(result) = pending.as_mut().poll(cx) else {
                return Poll::Pending;
            };
            *acquisition = None;
            let mut grant = result?;
            if grant.bytes >= min {
                let accepted = grant.bytes.min(max);
                grant.bytes -= accepted;
                return Poll::Ready(Ok(accepted));
            }
        }
    }

    fn try_acquire(&self, min: u64, max: u64) -> u64 {
        let grant = move |l: &Limiter, py: Python<'_>| {
            let result = l.object.bind(py).call_method1("try_acquire", (min, max));
            l.grant(py, result, min, max, true).unwrap_or_else(|e| {
                e.write_unraisable(py, Some(l.object.bind(py)));
                0
            })
        };
        let l = &self.limiter;
        if std::thread::current().id() == self.loop_thread {
            return rt::hook_or(0, |py| grant(l, py));
        }
        // The controlled relay dispatches datagram acquisitions on a Rust worker.
        // Hold that worker's cleanup slot until the Python callback settles.
        let limiter = l.clone();
        tokio::runtime::Handle::current()
            .block_on(l.lp.call(
                move |py| Ok(grant(&limiter, py).into_pyobject(py)?.into_any()),
                |value| value.extract(),
            ))
            .unwrap_or(0)
    }

    fn refund(&self, n: u64) {
        self.limiter.refund(n);
    }
}

/// Aborts all splices sharing the handle with the first application code.
#[pyclass(frozen, module = "zmux")]
#[derive(Default)]
struct SpliceAbort(core::SpliceAbort);

#[pymethods]
impl SpliceAbort {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Abort with this application error code, including zero.
    fn abort(&self, #[pyo3(from_py_with = ranged)] code: u64) -> PyResult<()> {
        self.0.abort(varint(code)?);
        Ok(())
    }

    /// The chosen code, if the handle was aborted.
    #[getter]
    fn code(&self) -> Option<u64> {
        self.0.code().map(VarInt::into_inner)
    }

    fn __repr__(&self) -> String {
        match self.code() {
            Some(c) => format!("SpliceAbort(code={c})"),
            None => "SpliceAbort()".to_owned(),
        }
    }
}

/// One-shot readiness signal for a hook.
#[pyclass(frozen, module = "zmux")]
#[derive(Default)]
struct SpliceSignal(core::SpliceSignal);

#[pymethods]
impl SpliceSignal {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Release the signal, even if the splice has not started waiting yet.
    fn resume(&self) {
        self.0.resume();
    }
}

#[derive(Clone, Default)]
struct Wait {
    delay: Option<Duration>,
    timeout: Option<Duration>,
    signal: Option<core::SpliceSignal>,
}

fn duration(seconds: f64) -> PyResult<Duration> {
    let value = Duration::try_from_secs_f64(seconds).map_err(value_err)?;
    if Instant::now().checked_add(value).is_none() {
        return Err(PyValueError::new_err("splice duration is out of range"));
    }
    Ok(value)
}

impl Wait {
    fn new(
        delay: Option<f64>,
        timeout: Option<f64>,
        resume: Option<&Bound<'_, SpliceSignal>>,
    ) -> PyResult<Self> {
        Ok(Self {
            delay: delay.map(duration).transpose()?,
            timeout: timeout.map(duration).transpose()?,
            signal: resume.map(|r| r.get().0.clone()),
        })
    }

    fn at(&self, now: Instant) -> core::SpliceWait {
        core::SpliceWait {
            ready_at: self.delay.and_then(|d| now.checked_add(d)),
            expires_at: self.timeout.and_then(|d| now.checked_add(d)),
            resume: self.signal.clone(),
        }
    }
}

enum Decision {
    Pass(Wait),
    Replace(Wait),
    Drop,
    Reset(VarInt),
}

/// A hook's immutable decision for the current group.
#[pyclass(frozen, module = "zmux")]
struct SpliceDecision(Decision);

#[pymethods]
impl SpliceDecision {
    /// Pass the current group, with optional readiness conditions.
    #[staticmethod]
    #[pyo3(signature = (*, delay=None, timeout=None, resume=None))]
    fn pass_(
        delay: Option<f64>,
        timeout: Option<f64>,
        resume: Option<&Bound<'_, SpliceSignal>>,
    ) -> PyResult<Self> {
        Ok(Self(Decision::Pass(Wait::new(delay, timeout, resume)?)))
    }

    /// Submit the ordered outputs built during this callback.
    #[staticmethod]
    #[pyo3(signature = (*, delay=None, timeout=None, resume=None))]
    fn replace(
        delay: Option<f64>,
        timeout: Option<f64>,
        resume: Option<&Bound<'_, SpliceSignal>>,
    ) -> PyResult<Self> {
        Ok(Self(Decision::Replace(Wait::new(delay, timeout, resume)?)))
    }

    /// Discard the current group.
    #[staticmethod]
    fn drop() -> Self {
        Self(Decision::Drop)
    }

    /// Reset the destination and stop the source with the given code.
    #[staticmethod]
    fn reset(#[pyo3(from_py_with = ranged)] code: u64) -> PyResult<Self> {
        Ok(Self(Decision::Reset(varint(code)?)))
    }
}

impl SpliceDecision {
    fn resolve(&self) -> core::SpliceDecision {
        match &self.0 {
            Decision::Pass(wait) => core::SpliceDecision::Pass(wait.at(Instant::now())),
            Decision::Replace(wait) => core::SpliceDecision::Replace(wait.at(Instant::now())),
            Decision::Drop => core::SpliceDecision::Drop,
            Decision::Reset(code) => core::SpliceDecision::Reset(*code),
        }
    }
}

/// Scoped payload reader and bounded replacement builder for one hook.
#[pyclass(frozen, module = "zmux")]
struct SpliceUnit {
    meta: Py<PyAny>,
    editor: Mutex<Option<core::SpliceEditor>>,
}

impl SpliceUnit {
    fn edit<T>(&self, edit: impl FnOnce(&mut core::SplicePayloads) -> PyResult<T>) -> PyResult<T> {
        let editor = lock(&self.editor);
        editor
            .as_ref()
            .and_then(|editor| editor.with(edit))
            .ok_or_else(|| PyRuntimeError::new_err("the splice hook has returned"))?
    }
}

fn index_error() -> PyErr {
    PyIndexError::new_err("splice payload index out of range")
}

#[pymethods]
impl SpliceUnit {
    /// Immutable metadata. It may be retained after the hook returns.
    #[getter]
    fn meta(&self, py: Python<'_>) -> Py<PyAny> {
        self.meta.clone_ref(py)
    }

    /// Number of input items in the current group.
    fn __len__(&self) -> PyResult<usize> {
        self.edit(|p| Ok(p.items()))
    }

    /// Size of an input item.
    #[pyo3(signature = (item=0))]
    fn size(&self, item: usize) -> PyResult<usize> {
        self.edit(|p| p.len(item).ok_or_else(index_error))
    }

    /// Read one payload byte without exporting a buffer.
    #[pyo3(signature = (offset, *, item=0))]
    fn byte_at(&self, mut offset: usize, item: usize) -> PyResult<u8> {
        self.edit(|p| {
            for segment in p.segments(item).ok_or_else(index_error)? {
                if let Some(value) = segment.get(offset) {
                    return Ok(*value);
                }
                offset -= segment.len();
            }
            Err(index_error())
        })
    }

    /// Copy an item to independent Python bytes.
    #[pyo3(signature = (item=0))]
    fn read<'p>(&self, py: Python<'p>, item: usize) -> PyResult<Bound<'p, PyBytes>> {
        PyBytes::new_with(py, self.size(item)?, |out| {
            self.edit(|p| {
                let mut offset = 0;
                for segment in p.segments(item).ok_or_else(index_error)? {
                    out[offset..offset + segment.len()].copy_from_slice(segment);
                    offset += segment.len();
                }
                Ok(())
            })
        })
    }

    /// Append an immutable subrange of an input item without copying it.
    #[pyo3(signature = (start=0, *, stop=None, item=0))]
    fn append_slice(&self, start: usize, stop: Option<usize>, item: usize) -> PyResult<()> {
        self.edit(|p| {
            p.slice(
                item,
                start..stop.unwrap_or_else(|| p.len(item).unwrap_or(0)),
            )
            .map_err(value_err)
        })
    }

    /// Append immutable bytes as one output, subject to the core's budget.
    fn append(&self, data: &Bound<'_, PyBytes>) -> PyResult<()> {
        let bytes = data.as_bytes();
        self.edit(|p| {
            p.write(bytes.len(), |out| out.copy_from_slice(bytes))
                .map_err(value_err)
        })
    }
}

fn kind(kind: core::SpliceKind) -> (&'static str, Option<u64>, Option<u64>) {
    match kind {
        core::SpliceKind::Stream => ("stream", None, None),
        core::SpliceKind::Capsule { ty, context } => (
            "capsule",
            Some(ty.into_inner()),
            context.map(VarInt::into_inner),
        ),
        core::SpliceKind::Datagram { context } => ("datagram", None, Some(context.into_inner())),
    }
}

fn metadata(py: Python<'_>, meta: &core::SpliceMeta<'_>) -> PyResult<Py<PyAny>> {
    let (shape, capsule, context) = kind(meta.kind);
    let route = match meta.route {
        core::SpliceRoute::AtoB => "a_to_b",
        core::SpliceRoute::BtoA => "b_to_a",
    };
    let d = PyDict::new(py);
    d.set_item("route", route)?;
    d.set_item("kind", shape)?;
    d.set_item("capsule_type", capsule)?;
    d.set_item("context", context)?;
    d.set_item("sequence", meta.sequence)?;
    d.set_item("generation", meta.generation)?;
    d.set_item("source_offset", meta.source_offset)?;
    d.set_item("injected", meta.injected)?;
    d.set_item(
        "source_stream",
        meta.source_stream.map(zmux::StreamId::into_inner),
    )?;
    d.set_item(
        "target_stream",
        meta.target_stream.map(zmux::StreamId::into_inner),
    )?;
    d.set_item("replayable", meta.replayable)?;
    d.set_item("preamble", crate::preamble_obj(py, meta.preamble)?)?;
    d.set_item("label", meta.label)?;
    Ok(types(py)?
        .getattr("SpliceMeta")?
        .call((), Some(&d))?
        .unbind())
}

fn hook(f: Py<PyAny>, lp: LoopRef) -> core::SpliceHook {
    let f = Arc::new(f);
    Arc::new(move |unit| {
        let meta =
            rt::hook_or(Err(rt::exiting()), |py| metadata(py, unit.meta)).map_err(|error| {
                lp.report_callback_error(f.clone(), error);
                core::SpliceBudget
            })?;
        unit.edit(|editor| {
            let callable = f.clone();
            let result = tokio::runtime::Handle::current().block_on(lp.call(
                move |py| {
                    let input = Bound::new(
                        py,
                        SpliceUnit {
                            meta,
                            editor: Mutex::new(Some(editor)),
                        },
                    )?;
                    let returned = callable.bind(py).call1((&input,));
                    lock(&input.get().editor).take();
                    let returned = returned?;
                    if returned.is_instance_of::<SpliceDecision>() {
                        return Ok(returned);
                    }
                    if returned
                        .get_type()
                        .is(&py.import("types")?.getattr("CoroutineType")?)
                    {
                        returned.call_method0("close")?;
                    }
                    Err(PyValueError::new_err(
                        "a splice hook must return SpliceDecision synchronously",
                    ))
                },
                |value| Ok(value.cast::<SpliceDecision>()?.get().resolve()),
            ));
            result.map_err(|error| {
                lp.report_callback_error(f.clone(), error);
                core::SpliceBudget
            })
        })
    })
}

fn hooks(obj: Option<&Bound<'_, PyAny>>, lp: &LoopRef) -> PyResult<core::SpliceHooks> {
    let Some(obj) = obj else {
        return Ok(core::SpliceHooks::default());
    };
    let chain = |name| {
        obj.getattr(name)?
            .try_iter()?
            .map(|f| {
                let f = f?;
                if !f.is_callable() {
                    return Err(PyValueError::new_err("splice hooks must be callable"));
                }
                Ok(hook(f.unbind(), lp.clone()))
            })
            .collect::<PyResult<Vec<_>>>()
    };
    Ok(core::SpliceHooks {
        stream: chain("stream")?,
        capsule: chain("capsule")?,
        datagram: chain("datagram")?,
    })
}

fn event_sink(callback: Py<PyAny>) -> PyResult<core::SpliceEventSink> {
    if !Python::attach(|py| callback.bind(py).is_callable()) {
        return Err(PyValueError::new_err("on_event must be callable"));
    }
    Ok(core::SpliceEventSink::new(move |route, event| {
        let joined: PyResult<()> = rt::hook_or(Ok(()), |py| {
            let route = match route {
                core::SpliceRoute::AtoB => "a_to_b",
                core::SpliceRoute::BtoA => "b_to_a",
            };
            let (kind, generation, token, why) = match event {
                core::SpliceEvent::HooksReplaced { generation } => {
                    ("hooks_replaced", Some(generation), None, None)
                }
                core::SpliceEvent::PauseAcknowledged { token } => {
                    ("pause_acknowledged", None, Some(token), None)
                }
                core::SpliceEvent::DirectionFinished { end } => {
                    ("direction_finished", None, None, Some(end))
                }
            };
            let (reason, code) = why.map(end).unzip();
            let obj = types(py)?.getattr("SpliceEvent")?.call1((
                route,
                kind,
                generation,
                token,
                reason.map(|why| crate::typed(py, "SpliceEnd", why.into())),
                code.flatten(),
            ))?;
            callback.bind(py).call1((obj,))?;
            Ok(())
        });
        if let Err(e) = joined {
            rt::hook_or((), |py| e.write_unraisable(py, Some(callback.bind(py))));
        }
    }))
}

fn splice_limits(obj: Option<&Bound<'_, PyAny>>) -> PyResult<core::SpliceLimits> {
    let mut limits = core::SpliceLimits::default();
    if let Some(obj) = obj {
        let get = |name| obj.getattr(name)?.extract::<Option<usize>>();
        limits.hook_steps = get("hook_steps")?.unwrap_or(limits.hook_steps);
        limits.group_items = get("group_items")?.unwrap_or(limits.group_items);
        limits.group_bytes = get("group_bytes")?;
        limits.group_backing_bytes = get("group_backing_bytes")?;
        limits.descriptors = get("descriptors")?.unwrap_or(limits.descriptors);
        limits.queue_items = get("queue_items")?.unwrap_or(limits.queue_items);
        limits.queue_bytes = get("queue_bytes")?;
        limits.reliable_cleanup_slots =
            get("reliable_cleanup_slots")?.unwrap_or(limits.reliable_cleanup_slots);
        limits.datagram_cleanup_slots =
            get("datagram_cleanup_slots")?.unwrap_or(limits.datagram_cleanup_slots);
        limits.datagram_delay = obj.getattr("datagram_delay")?.extract()?;
        limits.wait_cap = obj
            .getattr("wait_cap")?
            .extract::<Option<f64>>()?
            .map(duration)
            .transpose()?;
    }
    Ok(limits)
}

fn end(end: core::SpliceEnd) -> (&'static str, Option<u64>) {
    (end.as_str(), end.application_code().map(VarInt::into_inner))
}

/// Live settlement of bytes accepted by a splice direction.
#[pyclass(frozen, module = "zmux.helpers")]
struct SpliceHandoffs(core::SpliceHandoffs);

#[pymethods]
impl SpliceHandoffs {
    /// Read one consistent snapshot of local carrier handoffs and refunds.
    fn snapshot<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let s = self.0.get();
        types(py)?.getattr("SpliceHandoffStats")?.call1((
            s.accepted_bytes,
            s.first_carrier_bytes,
            s.unsent_bytes,
            s.pending_bytes,
            s.unsent_refunded_bytes,
            s.native_count,
            s.record_count,
        ))
    }
}

fn direction<'p>(
    py: Python<'p>,
    f: &core::SpliceDirection,
    shim_refunds: &AtomicU64,
) -> PyResult<Bound<'p, PyAny>> {
    let (reason, code) = end(f.end);
    let kw = PyDict::new(py);
    let drops = PyDict::new(py);
    macro_rules! counters {
        ($dict:ident, $source:expr, $($field:ident),+ $(,)?) => {
            $($dict.set_item(stringify!($field), $source.$field)?;)+
        };
    }
    counters!(
        kw,
        f,
        bytes,
        datagram_bytes,
        datagrams_as_capsules,
        input_units,
        input_bytes,
        enqueued_items,
        replacements,
        mirror_misses,
        capsule_count,
        accepted_bytes,
        payload_copy_bytes,
        encode_bytes,
        mirror_copy_bytes
    );
    counters!(
        drops,
        f.drops,
        dropped_hook,
        dropped_expired,
        dropped_queue_full,
        dropped_limiter,
        dropped_blocked,
        dropped_too_large,
        dropped_no_path,
        dropped_sequence_exhausted,
        dropped_flow_closed,
        dropped_codel
    );
    kw.set_item(
        "drops",
        types(py)?.getattr("SpliceDrops")?.call((), Some(&drops))?,
    )?;
    kw.set_item("end", crate::typed(py, "SpliceEnd", reason.into()))?;
    kw.set_item("code", code)?;
    kw.set_item("wait_time", f.wait_us as f64 / 1e6)?;
    kw.set_item("cause", f.cause.map(|cause| cause.to_string()))?;
    kw.set_item("handoffs", f.handoffs.clone().map(SpliceHandoffs))?;
    kw.set_item(
        "pre_admission_refunded_bytes",
        f.pre_admission_refunded_bytes + shim_refunds.load(Ordering::Relaxed),
    )?;
    types(py)?.getattr("SpliceDirection")?.call((), Some(&kw))
}

fn result(
    py: Python<'_>,
    r: &core::SpliceResult,
    shim_refunds: &[Arc<AtomicU64>; 2],
) -> PyResult<Py<PyAny>> {
    Ok(types(py)?
        .getattr("SpliceResult")?
        .call1((
            direction(py, &r.a_to_b, &shim_refunds[0])?,
            direction(py, &r.b_to_a, &shim_refunds[1])?,
        ))?
        .unbind())
}

fn command_error(e: core::SpliceCommandError) -> PyErr {
    use core::SpliceCommandError as E;
    let reason = match e {
        E::Closed => "closed",
        E::InvalidParameter => "invalid_parameter",
        E::SpliceBudget => "splice_budget",
        E::Cancelled => "cancelled",
        E::Paused => "paused",
        E::StalePause => "stale_pause",
    };
    rt::lazy_err(move |py| {
        PyErr::from_type(
            crate::err_type(py, "SpliceCommandError"),
            (reason, e.to_string()),
        )
    })
}

/// A bounded queue of diagnostic samples for one splice direction.
#[pyclass(frozen, module = "zmux")]
struct SpliceMirror {
    sender: Mutex<Option<core::SpliceMirror>>,
    receiver: Arc<AsyncMutex<core::SpliceMirrorReceiver>>,
    leased: bool,
}

/// Restores a mirror's sender if stream transfer or validation fails.
struct MirrorClaim<'a> {
    mirror: &'a SpliceMirror,
    sender: Option<core::SpliceMirror>,
}

impl<'a> MirrorClaim<'a> {
    fn new(mirror: &'a SpliceMirror) -> PyResult<Self> {
        let sender = lock(&mirror.sender)
            .take()
            .ok_or_else(|| value_err("splice mirror already used"))?;
        Ok(Self {
            mirror,
            sender: Some(sender),
        })
    }
}

impl Drop for MirrorClaim<'_> {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            *lock(&self.mirror.sender) = Some(sender);
        }
    }
}

#[pymethods]
impl SpliceMirror {
    #[new]
    /// A bounded mirror with a copied or shared prefix.
    #[pyo3(signature = (items, *, prefix=0, mode="copy", backing_bytes=None))]
    fn new(
        items: usize,
        prefix: usize,
        mode: &str,
        backing_bytes: Option<usize>,
    ) -> PyResult<Self> {
        let (mode, leased) = match mode {
            "copy" => (core::SpliceMirrorMode::Copy, false),
            "lease" => (core::SpliceMirrorMode::Lease, true),
            _ => return Err(PyValueError::new_err("unknown splice mirror mode")),
        };
        let capacity = backing_bytes
            .or_else(|| (!leased).then(|| items.checked_mul(prefix)).flatten())
            .ok_or_else(|| {
                PyValueError::new_err("mirror requires a representable backing_bytes bound")
            })?;
        let (sender, receiver) =
            core::SpliceMirror::bounded(items, capacity, prefix, mode).map_err(value_err)?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            receiver: Arc::new(AsyncMutex::new(receiver)),
            leased,
        })
    }

    /// Receive the next unread sample, or None after the splice ends.
    fn recv<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let receiver = self.receiver.clone();
        let leased = self.leased;
        future_on_loop(py, async move {
            let sample = receiver.lock().await.recv().await;
            Ok(deferred(move |py| {
                let Some(s) = sample else {
                    return Ok(py.None());
                };
                let (shape, capsule, context) = kind(s.kind);
                let prefix = if leased {
                    crate::chunk_view(py, s.prefix)?
                } else {
                    PyBytes::new(py, &s.prefix).into_any()
                };
                Ok(types(py)?
                    .getattr("SpliceSample")?
                    .call1((shape, capsule, context, s.sequence, s.generation, prefix))?
                    .unbind())
            }))
        })
    }
}

/// An admitted injection and its eventual local target disposition.
#[pyclass(frozen, module = "zmux")]
struct SpliceReceipt {
    /// The direction-local input sequence.
    #[pyo3(get)]
    sequence: u64,
    /// The hook generation used by the injection.
    #[pyo3(get)]
    generation: u64,
    state: Arc<AsyncMutex<Receipt>>,
}

type Disposition = Result<core::SpliceDisposition, core::SpliceCommandError>;
type ReceiptFuture = Pin<Box<dyn Future<Output = Disposition> + Send>>;

enum Receipt {
    Pending(ReceiptFuture),
    Done(Disposition),
}

impl From<core::SpliceReceipt> for SpliceReceipt {
    fn from(receipt: core::SpliceReceipt) -> Self {
        Self {
            sequence: receipt.sequence,
            generation: receipt.generation,
            state: Arc::new(AsyncMutex::new(Receipt::Pending(Box::pin(
                receipt.disposition(),
            )))),
        }
    }
}

#[pymethods]
impl SpliceReceipt {
    /// Wait for the target disposition. A cancelled wait may be retried.
    fn disposition<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let state = self.state.clone();
        future_into_py(py, async move {
            let mut state = state.lock().await;
            let outcome = match &mut *state {
                Receipt::Pending(pending) => {
                    let outcome = pending.as_mut().await;
                    *state = Receipt::Done(outcome);
                    outcome
                }
                Receipt::Done(outcome) => *outcome,
            };
            let d = outcome.map_err(command_error)?;
            Ok(deferred(move |py| {
                let (status, drop, ended) = match d.status {
                    core::SpliceInjectionStatus::Submitted => ("submitted", None, None),
                    core::SpliceInjectionStatus::Dropped(reason) => {
                        ("dropped", Some(reason.as_str()), None)
                    }
                    core::SpliceInjectionStatus::DirectionEnded(why) => {
                        ("direction_ended", None, Some(why))
                    }
                };
                let (reason, code) = ended.map(end).unzip();
                Ok(types(py)?
                    .getattr("SpliceDisposition")?
                    .call1((
                        status,
                        d.sequence,
                        d.generation,
                        d.accepted_bytes,
                        d.enqueued_items,
                        drop.map(|why| crate::typed(py, "SpliceDropReason", why.into())),
                        reason.map(|why| crate::typed(py, "SpliceEnd", why.into())),
                        code.flatten(),
                    ))?
                    .unbind())
            }))
        })
    }
}

/// Owns one pause generation. Releasing the token also releases the pause.
#[pyclass(frozen, module = "zmux")]
struct SplicePause(Arc<core::SplicePause>);

#[pymethods]
impl SplicePause {
    /// The direction-local pause generation.
    #[getter]
    fn generation(&self) -> u64 {
        self.0.generation
    }

    /// Wait until the direction reaches a safe output boundary.
    fn acknowledged<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let pause = self.0.clone();
        future_into_py(py, async move {
            pause.acknowledged().await.map_err(command_error)
        })
    }
}

/// The ordered command channel of one controlled splice direction.
#[pyclass(frozen, module = "zmux")]
#[derive(Clone)]
struct SpliceControl(core::SpliceControl, LoopRef, Arc<AtomicU64>);

#[pymethods]
impl SpliceControl {
    /// Observe local carrier settlement during and after this direction.
    #[getter]
    fn handoffs(&self) -> SpliceHandoffs {
        SpliceHandoffs(self.0.handoffs().clone())
    }

    /// Read refunds made by the relay before target acceptance, including late grants.
    #[getter]
    fn pre_admission_refunded_bytes(&self) -> u64 {
        self.0.pre_admission_refunded_bytes() + self.2.load(Ordering::Relaxed)
    }

    /// Replace the whole chain, returning its admission generation.
    fn replace_hooks<'p>(
        &self,
        py: Python<'p>,
        chain: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let chain = hooks(Some(chain), &self.1)?;
        let this = self.0.clone();
        future_into_py(py, async move {
            this.replace_hooks(chain).await.map_err(command_error)
        })
    }

    /// Request a pause and return the token that owns it.
    fn pause<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let this = self.0.clone();
        future_on_loop(py, async move {
            let pause = this.pause().await.map_err(command_error)?;
            Ok(deferred(move |py| {
                Ok(Py::new(py, SplicePause(Arc::new(pause)))?.into_any())
            }))
        })
    }

    /// Resume this direction if the supplied pause token is current.
    fn resume<'p>(
        &self,
        py: Python<'p>,
        pause: &Bound<'_, SplicePause>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let this = self.0.clone();
        let pause = pause.get().0.clone();
        future_into_py(py, async move {
            this.resume(&pause).await.map_err(command_error)
        })
    }

    /// Admit a typed input to the current chain and return its receipt.
    #[pyo3(signature = (payload, *, kind="stream", capsule_type=None, context=None))]
    fn inject<'p>(
        &self,
        py: Python<'p>,
        payload: &Bound<'_, PyAny>,
        kind: &str,
        capsule_type: Option<u64>,
        context: Option<u64>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let invalid = || command_error(core::SpliceCommandError::InvalidParameter);
        let context = context.map(varint).transpose()?;
        let kind = match (kind, capsule_type.map(varint).transpose()?, context) {
            ("stream", None, None) => core::SpliceKind::Stream,
            ("capsule", Some(ty), context) => core::SpliceKind::Capsule { ty, context },
            ("datagram", None, Some(context)) => core::SpliceKind::Datagram { context },
            _ => return Err(invalid()),
        };
        let payload = crate::stream_chunk(payload)?;
        let this = self.0.clone();
        future_into_py(py, async move {
            this.inject(core::SpliceInjection { kind, payload })
                .await
                .map(SpliceReceipt::from)
                .map_err(command_error)
        })
    }

    /// Observe a direction's reliable end and its optional application code.
    fn finished<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let this = self.0.clone();
        future_into_py(py, async move {
            let (reason, code) = end(this.finished().await.map_err(command_error)?);
            Ok(deferred(move |py| {
                let why = types(py)?.getattr("SpliceEnd")?.call1((reason,))?;
                Ok(PyTuple::new(
                    py,
                    [why.unbind(), code.into_pyobject(py)?.into_any().unbind()],
                )?
                .into_any()
                .unbind())
            }))
        })
    }
}

/// The two direction handles and abort control for a running splice.
#[pyclass(frozen, module = "zmux")]
struct SpliceController(core::SpliceController, LoopRef, [Arc<AtomicU64>; 2]);

#[pymethods]
impl SpliceController {
    /// The direction from the first stream to the second.
    #[getter]
    fn a_to_b(&self) -> SpliceControl {
        SpliceControl(self.0.a_to_b.clone(), self.1.clone(), self.2[0].clone())
    }

    /// The direction from the second stream to the first.
    #[getter]
    fn b_to_a(&self) -> SpliceControl {
        SpliceControl(self.0.b_to_a.clone(), self.1.clone(), self.2[1].clone())
    }

    /// Abort both remaining directions with an application error code.
    fn abort(&self, #[pyo3(from_py_with = ranged)] code: u64) -> PyResult<()> {
        self.0.abort(varint(code)?);
        Ok(())
    }
}

type Handles<'p> = (Bound<'p, SendStream>, Bound<'p, RecvStream>);

async fn release_acquisition_at_end(
    control: core::SpliceControl,
    pending: Option<Arc<AcquisitionSlot>>,
) {
    if let Some(pending) = pending {
        let _ = control.finished().await;
        drop(pending);
    }
}

#[pyfunction(name = "_splice_start")]
#[pyo3(signature = (a, b, *, packets, controlled, chunk=None, a_to_b=None, b_to_a=None, abort=None, a_to_b_datagrams=None, b_to_a_datagrams=None, a_to_b_hooks=None, b_to_a_hooks=None, a_to_b_label="", b_to_a_label="", a_to_b_mirror=None, b_to_a_mirror=None, limits=None, max_packet_payload=None, max_opaque_value=None, on_event=None))]
fn splice_start<'p>(
    py: Python<'p>,
    a: Handles<'p>,
    b: Handles<'p>,
    packets: bool,
    controlled: bool,
    chunk: Option<usize>,
    a_to_b: Option<Py<PyAny>>,
    b_to_a: Option<Py<PyAny>>,
    abort: Option<&Bound<'_, SpliceAbort>>,
    a_to_b_datagrams: Option<&Bound<'_, PyAny>>,
    b_to_a_datagrams: Option<&Bound<'_, PyAny>>,
    a_to_b_hooks: Option<&Bound<'_, PyAny>>,
    b_to_a_hooks: Option<&Bound<'_, PyAny>>,
    a_to_b_label: &str,
    b_to_a_label: &str,
    a_to_b_mirror: Option<&Bound<'_, SpliceMirror>>,
    b_to_a_mirror: Option<&Bound<'_, SpliceMirror>>,
    limits: Option<&Bound<'_, PyAny>>,
    max_packet_payload: Option<usize>,
    max_opaque_value: Option<usize>,
    on_event: Option<Py<PyAny>>,
) -> PyResult<(Option<SpliceController>, Bound<'p, PyAny>)> {
    if !controlled
        && (a_to_b_hooks.is_some()
            || b_to_a_hooks.is_some()
            || !a_to_b_label.is_empty()
            || !b_to_a_label.is_empty()
            || a_to_b_mirror.is_some()
            || b_to_a_mirror.is_some()
            || limits.is_some()
            || on_event.is_some())
    {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "hooks, labels, mirrors, limits and events require a controlled splice",
        ));
    }
    let mut opts = core::SpliceOptions::default();
    opts.chunk = chunk.unwrap_or(opts.chunk);
    opts.abort = abort.map(|a| a.get().0.clone());
    opts.a_to_b_datagrams = crate::datagram::options(a_to_b_datagrams)?;
    opts.b_to_a_datagrams = crate::datagram::options(b_to_a_datagrams)?;
    opts.max_packet_payload = max_packet_payload.unwrap_or(opts.max_packet_payload);
    opts.max_opaque_value = max_opaque_value.unwrap_or(opts.max_opaque_value);
    let on_loop = controlled || a_to_b.is_some() || b_to_a.is_some();
    let lp = on_loop
        .then(|| LoopRef::running(py, "splice with Python callbacks or controls"))
        .transpose()?;
    let ab_pending = a_to_b.as_ref().map(|_| Arc::new(Mutex::new(None)));
    let ba_pending = b_to_a.as_ref().map(|_| Arc::new(Mutex::new(None)));
    // The native counters start at the Rust limiter boundary. Include grants
    // the Python bridge returns before that boundary without counting Rust
    // refunds a second time.
    let shim_refunds: [Arc<AtomicU64>; 2] = [Arc::default(), Arc::default()];
    let limiter = |object: Option<Py<PyAny>>,
                   pending: Option<&Arc<AcquisitionSlot>>,
                   pre_admission_refunds: Arc<AtomicU64>|
     -> PyResult<Option<Arc<dyn zmux::Limiter>>> {
        object
            .zip(pending)
            .map(|(object, pending)| {
                let max_burst_bytes = crate::field_count(
                    "max_burst_bytes",
                    &object.bind(py).getattr("max_burst_bytes")?,
                )?;
                Ok(Arc::new(PyLimiter {
                    limiter: Arc::new(Limiter {
                        object,
                        lp: lp.clone().expect("captured loop"),
                        pre_admission_refunds,
                    }),
                    pending: Arc::downgrade(pending),
                    max_burst_bytes,
                    loop_thread: std::thread::current().id(),
                }) as Arc<dyn zmux::Limiter>)
            })
            .transpose()
    };
    opts.a_to_b = limiter(a_to_b, ab_pending.as_ref(), shim_refunds[0].clone())?;
    opts.b_to_a = limiter(b_to_a, ba_pending.as_ref(), shim_refunds[1].clone())?;
    let mut policy = core::ControlledSpliceOptions::default();
    let mut ab = None;
    let mut ba = None;
    if controlled {
        let lp = lp.as_ref().expect("controlled splice loop");
        policy.a_to_b_hooks = hooks(a_to_b_hooks, lp)?;
        policy.b_to_a_hooks = hooks(b_to_a_hooks, lp)?;
        policy.a_to_b_label = a_to_b_label.into();
        policy.b_to_a_label = b_to_a_label.into();
        policy.limits = splice_limits(limits)?;
        policy.events = on_event.map(event_sink).transpose()?;
        ab = a_to_b_mirror
            .map(|m| MirrorClaim::new(m.get()))
            .transpose()?;
        ba = b_to_a_mirror
            .map(|m| MirrorClaim::new(m.get()))
            .transpose()?;
        policy.a_to_b_mirror = ab.as_ref().and_then(|m| m.sender.clone());
        policy.b_to_a_mirror = ba.as_ref().and_then(|m| m.sender.clone());
    }
    let (a, b) = crate::helpers::splice_pairs(&a, &b)?;
    if controlled {
        policy.forwarding = opts;
        let (ctl, future): (_, Pin<Box<dyn Future<Output = core::SpliceResult> + Send>>) =
            if packets {
                let (ctl, fut) =
                    core::controlled_splice_packets(a, b, policy).map_err(value_err)?;
                (ctl, Box::pin(fut))
            } else {
                let (ctl, fut) = core::controlled_splice(a, b, policy).map_err(value_err)?;
                (ctl, Box::pin(fut))
            };
        for claim in [&mut ab, &mut ba].into_iter().flatten() {
            claim.sender.take();
        }
        let ab = release_acquisition_at_end(ctl.a_to_b.clone(), ab_pending);
        let ba = release_acquisition_at_end(ctl.b_to_a.clone(), ba_pending);
        return Ok((
            Some(SpliceController(
                ctl,
                lp.expect("controlled splice loop"),
                shim_refunds.clone(),
            )),
            future_on_loop(py, async move {
                let (completed, (), ()) = tokio::join!(future, ab, ba);
                Ok(deferred(move |py| result(py, &completed, &shim_refunds)))
            })?,
        ));
    }
    let future = async move {
        let r = if packets {
            core::splice_packets(a, b, opts).await
        } else {
            core::splice(a, b, opts).await
        }
        .map_err(value_err)?;
        drop((ab_pending, ba_pending));
        Ok(deferred(move |py| result(py, &r, &shim_refunds)))
    };
    Ok((
        None,
        if on_loop {
            future_on_loop(py, future)?
        } else {
            future_into_py(py, future)?
        },
    ))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("DEFAULT_MAX_PACKET", core::DEFAULT_MAX_PACKET)?;
    m.add_class::<SpliceAbort>()?;
    m.add_class::<SpliceControl>()?;
    m.add_class::<SpliceController>()?;
    m.add_class::<SpliceDecision>()?;
    m.add_class::<SpliceHandoffs>()?;
    m.add_class::<SpliceMirror>()?;
    m.add_class::<SplicePause>()?;
    m.add_class::<SpliceReceipt>()?;
    m.add_class::<SpliceSignal>()?;
    m.add_class::<SpliceUnit>()?;
    m.add_function(wrap_pyfunction!(splice_start, m)?)?;
    Ok(())
}
