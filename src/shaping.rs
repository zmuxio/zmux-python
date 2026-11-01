//! Shaping bounds, the seeded random source of `set_shaper` and the
//! factory that picks a definition by carrier kind.

use std::collections::HashMap;
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyMapping;
use zmux::shaping::{Factory, ShapedPipe, Shaper};
use zmux_shaping::{MachineFactory, Options, SizeLimits, Source};

fn attr<'py, T: FromPyObjectOwned<'py>>(o: &Bound<'py, PyAny>, name: &str) -> PyResult<T> {
    o.getattr(name)?.extract().map_err(Into::into)
}

fn secs(o: &Bound<'_, PyAny>, name: &str) -> PyResult<Option<Duration>> {
    let v: Option<f64> = attr(o, name)?;
    v.map(|v| {
        Duration::try_from_secs_f64(v).map_err(|_| {
            PyValueError::new_err(format!("{name} is a non-negative number of seconds"))
        })
    })
    .transpose()
}

/// The session limits of a `zmux.ShapingLimits`.
pub(crate) fn session_limits(o: &Bound<'_, PyAny>) -> PyResult<zmux::shaping::Limits> {
    let mut l = zmux::shaping::Limits::default();
    l.max_padding_bytes = attr(o, "max_padding_bytes")?;
    l.max_padding_ratio = attr(o, "max_padding_ratio")?;
    l.max_injected = attr(o, "max_injected")?;
    l.max_pause_total = secs(o, "max_pause_total")?;
    l.max_delay = secs(o, "max_delay")?;
    l.validate().map_err(PyValueError::new_err)?;
    Ok(l)
}

/// The definition bounds of a `zmux.ShapingSizeLimits`.
fn size_limits(o: &Bound<'_, PyAny>) -> PyResult<SizeLimits> {
    let mut l = SizeLimits::default();
    l.max_bytes = attr(o, "max_bytes")?;
    l.max_machines = attr(o, "max_machines")?;
    l.max_states = attr(o, "max_states")?;
    l.max_actions = attr(o, "max_actions")?;
    l.max_transitions = attr(o, "max_transitions")?;
    l.max_points = attr(o, "max_points")?;
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

/// A factory that picks a definition by the pipe's carrier kind: the
/// kind's own, else the default (`None` key), else no shaping.
pub(crate) struct ByKind {
    kinds: HashMap<zmux::CarrierKind, MachineFactory>,
    default: Option<MachineFactory>,
}

impl Factory for ByKind {
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        let f = pipe
            .carrier
            .and_then(|k| self.kinds.get(&k))
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

/// The factory of `by_kind`: a mapping of carrier kinds (members or names,
/// `None` for the default) to definitions in the JSON form, each parsed
/// and checked with `o`.
pub(crate) fn by_kind(by_kind: &Bound<'_, PyAny>, o: &Options) -> PyResult<ByKind> {
    let map = by_kind
        .cast::<PyMapping>()
        .map_err(|_| PyValueError::new_err("by_kind is a mapping"))?;
    let mut f = ByKind {
        kinds: HashMap::new(),
        default: None,
    };
    for item in map.items()?.iter() {
        let (k, v): (Bound<'_, PyAny>, String) = item.extract()?;
        let m = MachineFactory::from_json(v.as_bytes(), o.clone())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        if k.is_none() {
            f.default = Some(m);
        } else {
            f.kinds.insert(carrier_kind(&k)?, m);
        }
    }
    Ok(f)
}
