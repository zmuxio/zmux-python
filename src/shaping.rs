//! Shaping bounds, the seeded random source of `set_shaper` and the
//! factory that picks a definition by carrier variant and kind.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyMapping;
use zmux::shaping::{Account, Budget, Factory, ShapedPipe, Shaper, ShapingBudget};
use zmux_shaping::{MachineFactory, Options, SizeLimits, Source};

fn attr<'py, T: FromPyObjectOwned<'py>>(o: &Bound<'py, PyAny>, name: &str) -> PyResult<T> {
    o.getattr(name)?.extract().map_err(Into::into)
}

/// A wait bound: seconds, or `None` for none.
fn wait_of(o: &Bound<'_, PyAny>) -> PyResult<Option<Duration>> {
    let v: Option<f64> = attr(o, "max_delay")?;
    v.map(|v| crate::seconds("max_delay", v)).transpose()
}

fn wait_obj(d: Option<Duration>) -> Option<f64> {
    d.map(|d| d.as_secs_f64())
}

fn account_of(o: &Bound<'_, PyAny>) -> PyResult<Account> {
    let w = o.getattr("wire")?;
    Ok(Account::new(
        attr(&w, "initial")?,
        attr(&w, "per_mb")?,
        attr(&w, "per_sec")?,
    ))
}

fn account_obj<'p>(py: Python<'p>, a: &Account) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("initial", a.initial)?;
    d.set_item("per_mb", a.per_mb)?;
    d.set_item("per_sec", a.per_sec)?;
    crate::types(py)?
        .getattr("ShapingAccount")?
        .call((), Some(&d))
}

/// The local limits of a `zmux.ShapingLimits`.
pub(crate) fn limits_of(o: &Bound<'_, PyAny>) -> PyResult<zmux::shaping::Limits> {
    let mut l = zmux::shaping::Limits::default();
    l.wire = account_of(o)?;
    l.max_delay = wait_of(o)?;
    l.no_padding = attr(o, "no_padding")?;
    l.no_pause = attr(o, "no_pause")?;
    l.no_injection = attr(o, "no_injection")?;
    l.validate()
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(l)
}

/// The `zmux.ShapingLimits` of local limits.
pub(crate) fn limits_obj<'p>(
    py: Python<'p>,
    l: &zmux::shaping::Limits,
) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("wire", account_obj(py, &l.wire)?)?;
    d.set_item("max_delay", wait_obj(l.max_delay))?;
    d.set_item("no_padding", l.no_padding)?;
    d.set_item("no_pause", l.no_pause)?;
    d.set_item("no_injection", l.no_injection)?;
    crate::types(py)?
        .getattr("ShapingLimits")?
        .call((), Some(&d))
}

fn budget_obj<'p>(py: Python<'p>, b: &Budget) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("wire", account_obj(py, &b.wire)?)?;
    d.set_item("max_delay", wait_obj(b.max_delay))?;
    d.set_item("no_injection", b.no_injection)?;
    crate::types(py)?
        .getattr("ShapingBudget")?
        .call((), Some(&d))
}

/// The budget source of a callable returning `zmux.ShapingBudget`. An exception is no budget.
pub(crate) fn budget_hook(f: Py<PyAny>) -> ShapingBudget {
    ShapingBudget::new(move || {
        crate::rt::attach(|py| {
            let asked = (|| -> PyResult<Budget> {
                let r = f.bind(py).call0()?;
                Ok(Budget::new(
                    account_of(&r)?,
                    wait_of(&r)?,
                    attr(&r, "no_injection")?,
                ))
            })();
            asked.unwrap_or_else(|e| {
                e.write_unraisable(py, Some(f.bind(py)));
                Budget::default()
            })
        })
    })
}

/// Reads local limits from JSON.
#[pyfunction]
pub(crate) fn shaping_limits_from_json<'p>(
    py: Python<'p>,
    text: &str,
) -> PyResult<Bound<'p, PyAny>> {
    let l = zmux_shaping::parse_limits(text.as_bytes())
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    limits_obj(py, &l)
}

/// The definition bounds of a `zmux.ShapingSizeLimits`.
fn size_limits(o: &Bound<'_, PyAny>) -> PyResult<SizeLimits> {
    let mut l = SizeLimits::default();
    l.max_bytes = attr(o, "max_bytes")?;
    l.max_machines = attr(o, "max_machines")?;
    l.max_states = attr(o, "max_states")?;
    l.max_actions = attr(o, "max_actions")?;
    l.max_transitions = attr(o, "max_transitions")?;
    l.max_segments = attr(o, "max_segments")?;
    l.max_slots = attr(o, "max_slots")?;
    Ok(l)
}

/// SplitMix64: a deterministic source for tests, not for traffic.
struct SplitMix(u64);

impl Source for SplitMix {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The state of `seed`: its bytes folded 8 at a time through SplitMix64.
fn fold(seed: &[u8]) -> u64 {
    let mut m = SplitMix(seed.len() as u64);
    let mut s = m.next_u64();
    for c in seed.chunks(8) {
        let mut b = [0u8; 8];
        b[..c.len()].copy_from_slice(c);
        m.0 ^= u64::from_le_bytes(b);
        s ^= m.next_u64();
    }
    s
}

/// The executor options of `limits` (definition bounds, default when
/// absent) and `seed` (absent: the operating system's generator).
pub(crate) fn options(
    limits: Option<&Bound<'_, PyAny>>,
    seed: Option<Vec<u8>>,
) -> PyResult<Options> {
    let mut o = Options::default();
    if let Some(l) = limits {
        o = o.with_limits(size_limits(l)?);
    }
    if let Some(seed) = seed {
        let s = fold(&seed);
        o = o.with_source(move || Box::new(SplitMix(s)));
    }
    Ok(o)
}

/// A factory that picks a definition by the pipe's carrier: its variant's
/// own, else its kind's, else the default (`None` key), else no shaping.
pub(crate) struct ByKind {
    variants: HashMap<Arc<str>, MachineFactory>,
    kinds: HashMap<zmux::CarrierKind, MachineFactory>,
    default: Option<MachineFactory>,
}

impl Factory for ByKind {
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        let f = pipe
            .variant
            .as_ref()
            .and_then(|v| self.variants.get(v))
            .or_else(|| pipe.carrier.and_then(|k| self.kinds.get(&k)))
            .or(self.default.as_ref())?;
        Some(Box::new(f.shaper()))
    }
}

/// The carrier kind a `CarrierKind` member or its name gives.
pub(crate) fn carrier_kind(k: &Bound<'_, PyAny>) -> PyResult<zmux::CarrierKind> {
    let name: String = match k.getattr("value") {
        Ok(v) if !k.is_instance_of::<pyo3::types::PyString>() => v.extract()?,
        _ => k.extract()?,
    };
    zmux::CarrierKind::from_name(&name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown carrier kind {name:?}")))
}

/// The items of the mapping `m`, the argument `name`.
fn items<'p>(name: &str, m: &Bound<'p, PyAny>) -> PyResult<Bound<'p, pyo3::types::PyList>> {
    m.cast::<PyMapping>()
        .map_err(|_| PyValueError::new_err(format!("{name} is a mapping")))?
        .items()
}

/// The factory of `by_kind`, a mapping of carrier kinds (members or names,
/// `None` for the default), and `by_variant`, a mapping of variants, to
/// definitions in the JSON form, each parsed and checked with `o`.
pub(crate) fn by_carrier(
    by_kind: Option<&Bound<'_, PyAny>>,
    by_variant: Option<&Bound<'_, PyAny>>,
    o: &Options,
) -> PyResult<ByKind> {
    let mut f = ByKind {
        variants: HashMap::new(),
        kinds: HashMap::new(),
        default: None,
    };
    let parse = |v: String| {
        MachineFactory::from_json(v.as_bytes(), o.clone())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    };
    if let Some(m) = by_kind {
        for item in items("by_kind", m)?.iter() {
            let (k, v): (Bound<'_, PyAny>, String) = item.extract()?;
            let m = parse(v)?;
            if k.is_none() {
                f.default = Some(m);
            } else {
                f.kinds.insert(carrier_kind(&k)?, m);
            }
        }
    }
    if let Some(m) = by_variant {
        for item in items("by_variant", m)?.iter() {
            let (k, v): (String, String) = item.extract()?;
            f.variants.insert(k.into(), parse(v)?);
        }
    }
    Ok(f)
}

fn plan_obj<'p>(py: Python<'p>, p: &zmux::shaping::UnitPlan) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("pad_to", p.pad_to)?;
    d.set_item("pad_multiple", p.pad_multiple)?;
    d.set_item("pad", p.pad)?;
    d.set_item("delay", p.delay.as_secs_f64())?;
    crate::types(py)?.getattr("UnitPlan")?.call((), Some(&d))
}

/// The hook of a Python callable: given a `zmux.HandshakeView`, a `zmux.UnitPlan` or `None`.
/// A callable that raises reports it and counts as a failed call.
pub(crate) fn handshake_hook(f: Py<PyAny>) -> zmux::shaping::HandshakeShaper {
    zmux::shaping::HandshakeShaper::new(move |v| {
        crate::rt::attach(|py| {
            let asked = (|| -> PyResult<Option<zmux::shaping::UnitPlan>> {
                let d = pyo3::types::PyDict::new(py);
                let types = crate::types(py)?;
                let kind = match v.kind {
                    Some(k) => Some(types.getattr("CarrierKind")?.call1((k.name(),))?),
                    None => None,
                };
                d.set_item("kind", kind)?;
                d.set_item("handshake", v.handshake)?;
                d.set_item("message", v.message)?;
                let view = types.getattr("HandshakeView")?.call((), Some(&d))?;
                let r = f.bind(py).call1((view,))?;
                if r.is_none() {
                    return Ok(None);
                }
                let delay: f64 = r.getattr("delay")?.extract()?;
                let delay = Duration::try_from_secs_f64(delay).map_err(crate::value_err)?;
                Ok(Some(
                    zmux::shaping::UnitPlan::new(
                        r.getattr("pad_to")?.extract()?,
                        r.getattr("pad_multiple")?.extract()?,
                        r.getattr("pad")?.extract()?,
                    )
                    .with_delay(delay),
                ))
            })();
            asked.unwrap_or_else(|e| {
                e.write_unraisable(py, Some(f.bind(py)));
                std::panic::resume_unwind(Box::new(()))
            })
        })
    })
}

/// A shaper hook from what Python gave: a `ShapingBundle` or a callable.
pub(crate) fn hook_of(v: &Bound<'_, PyAny>) -> zmux::shaping::HandshakeShaper {
    if let Ok(b) = v.cast::<ShapingBundle>() {
        return b.get().0.handshake_shaper();
    }
    handshake_hook(v.clone().unbind())
}

/// A configuration bundle: per carrier kind, the machines, handshake plans, budget and pool.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct ShapingBundle(pub(crate) Arc<zmux_shaping::Bundle>);

#[pymethods]
impl ShapingBundle {
    /// Reads a bundle (`str` or `bytes`). Any error raises `ValueError`.
    #[staticmethod]
    #[pyo3(signature = (definition, *, features=Vec::new(), allow_unshaped=false, limits=None, seed=None))]
    fn from_json(
        definition: &Bound<'_, PyAny>,
        features: Vec<String>,
        allow_unshaped: bool,
        limits: Option<&Bound<'_, PyAny>>,
        seed: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let b: Vec<u8> = match definition.extract::<String>() {
            Ok(s) => s.into_bytes(),
            Err(_) => definition.extract()?,
        };
        let o = options(limits, seed)?
            .with_features(features)
            .with_allow_unshaped(allow_unshaped);
        let bundle = zmux_shaping::Bundle::from_json(&b, &o)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self(Arc::new(bundle)))
    }

    /// The index of the candidate chosen for `kind`, or `None`.
    fn selected(&self, kind: &str) -> Option<usize> {
        self.0.selected(kind)
    }

    /// The kinds all of whose candidates were skipped.
    fn unshaped(&self) -> Vec<String> {
        self.0.unshaped().iter().map(|s| (*s).to_owned()).collect()
    }

    /// The plan of a message on carriers of `kind` (`default` when it has no entry), or `None`.
    fn plan<'p>(
        &self,
        py: Python<'p>,
        kind: &str,
        handshake: &str,
        message: &str,
    ) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0
            .resolve(kind)
            .and_then(|c| c.plan(handshake, message))
            .map(|p| plan_obj(py, &p))
            .transpose()
    }

    /// One draw of the budget of `kind`, or `None` without one.
    fn budget<'p>(&self, py: Python<'p>, kind: &str) -> PyResult<Option<Bound<'p, PyAny>>> {
        self.0
            .resolve(kind)
            .and_then(|c| c.budget())
            .map(|b| budget_obj(py, &b.ask()))
            .transpose()
    }
}
