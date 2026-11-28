//! Shaping bounds, the seeded random source of `Session.shaper` and the
//! factory that picks a definition by carrier variant and kind.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyInt, PyMapping};
use zmux::shaping::{Account, Budget, Factory, ProfileLimits, ShapedPipe, Shaper, ShapingBudget};
use zmux_shaping::{MachineFactory, Options, SizeLimits, Source};

fn attr<'py, T: FromPyObjectOwned<'py>>(o: &Bound<'py, PyAny>, name: &str) -> PyResult<T> {
    o.getattr(name)?.extract().map_err(Into::into)
}

fn account(w: &Bound<'_, PyAny>) -> PyResult<Account> {
    use zmux::shaping::{MAX_ACCOUNT_INITIAL, MAX_ACCOUNT_RATE};
    let field = |name, max| {
        let v = w.getattr(name)?;
        v.extract::<u64>()
            .ok()
            .filter(|n| v.is_instance_of::<PyInt>() && !v.is_instance_of::<PyBool>() && *n <= max)
            .ok_or_else(|| PyValueError::new_err(format!("{name} is an integer in [0, {max}]")))
    };
    Ok(Account::new(
        field("ceiling", MAX_ACCOUNT_INITIAL)?,
        field("initial", MAX_ACCOUNT_INITIAL)?,
        field("per_mb", MAX_ACCOUNT_RATE)?,
        field("per_sec", MAX_ACCOUNT_RATE)?,
    ))
}

#[pyfunction(name = "_check_shaping_account")]
pub(crate) fn check_account(o: &Bound<'_, PyAny>) -> PyResult<()> {
    let mut l = zmux::shaping::Limits::default();
    l.wire = Some(account(o)?);
    l.validate().map_err(crate::value_err)
}

#[pyfunction(name = "_check_shaping_profile")]
pub(crate) fn check_profile(o: &Bound<'_, PyAny>) -> PyResult<()> {
    Budget::new(None, Some(profile_value(o)?), false)
        .validate()
        .map_err(crate::value_err)
}

fn account_obj<'p>(py: Python<'p>, a: &Account) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("ceiling", a.ceiling)?;
    d.set_item("initial", a.initial)?;
    d.set_item("per_mb", a.per_mb)?;
    d.set_item("per_sec", a.per_sec)?;
    crate::types(py)?
        .getattr("ShapingAccount")?
        .call((), Some(&d))
}

fn optional_account(value: &Bound<'_, PyAny>) -> PyResult<Option<Account>> {
    crate::optional(value).map(account).transpose()
}

fn profile_value(value: &Bound<'_, PyAny>) -> PyResult<ProfileLimits> {
    let delay = value.getattr("max_added_delay")?;
    if delay.is_instance_of::<PyBool>() {
        return Err(PyValueError::new_err(
            "max_added_delay is a duration in seconds",
        ));
    }
    Ok(ProfileLimits::new(
        crate::field_count("window_seconds", &value.getattr("window_seconds")?)?,
        crate::field_count("extra_bytes_ppm", &value.getattr("extra_bytes_ppm")?)?,
        crate::field_count("floor_bytes", &value.getattr("floor_bytes")?)?,
        crate::field_secs("max_added_delay", &delay)?,
    ))
}

fn profile(value: &Bound<'_, PyAny>) -> PyResult<Option<ProfileLimits>> {
    crate::optional(value).map(profile_value).transpose()
}

pub(crate) fn profile_obj(py: Python<'_>, value: ProfileLimits) -> PyResult<Bound<'_, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("window_seconds", value.window_seconds)?;
    d.set_item("extra_bytes_ppm", value.extra_bytes_ppm)?;
    d.set_item("floor_bytes", value.floor_bytes)?;
    d.set_item("max_added_delay", value.max_added_delay.as_secs_f64())?;
    crate::types(py)?
        .getattr("ShapingProfileLimits")?
        .call((), Some(&d))
}

/// The local limits of a `zmux.ShapingLimits`.
pub(crate) fn limits_of(o: &Bound<'_, PyAny>) -> PyResult<zmux::shaping::Limits> {
    let mut l = zmux::shaping::Limits::default();
    l.wire = optional_account(&o.getattr("wire")?)?;
    l.profile = profile(&o.getattr("profile")?)?;
    l.no_padding = attr(o, "no_padding")?;
    l.no_pause = attr(o, "no_pause")?;
    l.no_injection = attr(o, "no_injection")?;
    l.validate().map_err(crate::value_err)?;
    Ok(l)
}

/// The `zmux.ShapingLimits` of local limits.
pub(crate) fn limits_obj<'p>(
    py: Python<'p>,
    l: &zmux::shaping::Limits,
) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item(
        "wire",
        l.wire.as_ref().map(|a| account_obj(py, a)).transpose()?,
    )?;
    d.set_item(
        "profile",
        l.profile.map(|p| profile_obj(py, p)).transpose()?,
    )?;
    d.set_item("no_padding", l.no_padding)?;
    d.set_item("no_pause", l.no_pause)?;
    d.set_item("no_injection", l.no_injection)?;
    crate::types(py)?
        .getattr("ShapingLimits")?
        .call((), Some(&d))
}

fn budget_obj<'p>(py: Python<'p>, b: &Budget) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item(
        "wire",
        b.wire.as_ref().map(|a| account_obj(py, a)).transpose()?,
    )?;
    d.set_item(
        "profile",
        b.profile.map(|p| profile_obj(py, p)).transpose()?,
    )?;
    d.set_item("no_injection", b.no_injection)?;
    crate::types(py)?
        .getattr("ShapingBudget")?
        .call((), Some(&d))
}

/// The budget of a `zmux.ShapingBudget`, the same for every session: a
/// value, so that no session asks Python on the runtime's threads (a
/// shaping bundle draws one per session).
pub(crate) fn budget_of(v: &Bound<'_, PyAny>) -> PyResult<ShapingBudget> {
    let b = Budget::new(
        optional_account(&v.getattr("wire")?)?,
        profile(&v.getattr("profile")?)?,
        attr(v, "no_injection")?,
    );
    b.validate().map_err(crate::value_err)?;
    Ok(ShapingBudget::new(move || b))
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

/// `SplitMix64`: a deterministic source for tests, not for traffic.
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

/// The state of `seed`: its bytes folded 8 at a time through `SplitMix64`.
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
fn options(limits: Option<&Bound<'_, PyAny>>, seed: Option<Vec<u8>>) -> PyResult<Options> {
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
struct ByKind {
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
    crate::choice::kind(&name)
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
fn by_carrier(
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

/// Outbound shaping and the budget and handshake plans that came with it.
#[derive(Default)]
struct Outbound {
    factory: Option<Arc<dyn Factory>>,
    budget: Option<ShapingBudget>,
    handshake: Option<zmux::shaping::HandshakeShaper>,
}

impl Outbound {
    fn bundle(v: &Bound<'_, PyAny>) -> PyResult<Self> {
        let b = v.cast::<ShapingBundle>()?.get().0.clone();
        Ok(Self {
            budget: b
                .resolve("default")
                .and_then(zmux_shaping::Compiled::budget),
            handshake: Some(b.handshake_shaper()),
            factory: Some(b),
        })
    }
}

#[derive(Default)]
struct Mappings<'py> {
    kinds: Option<Bound<'py, PyAny>>,
    variants: Option<Bound<'py, PyAny>>,
}

impl<'py> Mappings<'py> {
    fn of(v: &Bound<'py, PyAny>) -> PyResult<Self> {
        Ok(Self {
            kinds: crate::optional(&v.getattr("by_kind")?).cloned(),
            variants: crate::optional(&v.getattr("by_variant")?).cloned(),
        })
    }

    fn exclusive(&self, single: bool, message: &str) -> PyResult<()> {
        if single && (self.kinds.is_some() || self.variants.is_some()) {
            return Err(PyValueError::new_err(message.to_owned()));
        }
        Ok(())
    }

    fn factory(&self, o: &Options) -> PyResult<Option<Arc<dyn Factory>>> {
        if self.kinds.is_none() && self.variants.is_none() {
            return Ok(None);
        }
        Ok(Some(Arc::new(by_carrier(
            self.kinds.as_ref(),
            self.variants.as_ref(),
            o,
        )?)))
    }
}

/// Collect Config inputs before selecting one outbound source and its budget.
#[derive(Default)]
pub(crate) struct ConfigShaping<'py> {
    pub(crate) bundle: Option<Bound<'py, PyAny>>,
    pub(crate) kinds: Option<Bound<'py, PyAny>>,
    pub(crate) variants: Option<Bound<'py, PyAny>>,
    pub(crate) budget: Option<Bound<'py, PyAny>>,
    pub(crate) handshake: Option<Bound<'py, PyAny>>,
}

impl ConfigShaping<'_> {
    pub(crate) fn apply(self, c: &mut zmux::Config) -> PyResult<()> {
        let mappings = Mappings {
            kinds: self.kinds,
            variants: self.variants,
        };
        mappings.exclusive(
            self.bundle.is_some(),
            "shaping_bundle cannot be combined with another outbound shaping source",
        )?;
        let outbound = match self.bundle.as_ref() {
            Some(b) => Outbound::bundle(b)?,
            None => Outbound {
                factory: mappings.factory(&Options::default())?,
                ..Outbound::default()
            },
        };
        if let Some(factory) = outbound.factory {
            c.shaper = Some(factory);
        }
        if let Some(budget) = self
            .budget
            .as_ref()
            .map(budget_of)
            .transpose()?
            .or(outbound.budget)
        {
            c.shaping_budget = Some(budget);
        }
        if let Some(handshake) = self
            .handshake
            .as_ref()
            .map(hook_of)
            .transpose()?
            .or(outbound.handshake)
        {
            c.handshake_shaper = Some(handshake);
        }
        Ok(())
    }
}

fn shaper_sources<'py>(v: &Bound<'py, PyAny>) -> PyResult<(Option<String>, Mappings<'py>)> {
    let definition: Option<String> = attr(v, "definition")?;
    let mappings = Mappings::of(v)?;
    mappings.exclusive(
        definition.is_some(),
        "definition and by_kind or by_variant exclude each other",
    )?;
    Ok((definition, mappings))
}

#[pyfunction(name = "_check_shaper_sources")]
pub(crate) fn check_sources(v: &Bound<'_, PyAny>) -> PyResult<()> {
    shaper_sources(v).map(|_| ())
}

pub(crate) fn set_shaper(session: &zmux::Session, v: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
    let Some(v) = v else {
        return session.set_shaper(None, None).map_err(crate::value_err);
    };
    if let Ok(i) = v.cast::<InstalledShaper>() {
        return session
            .set_shaper(Some(i.get().0.clone()), None)
            .map_err(crate::value_err);
    }
    let outbound = if v.is_instance_of::<ShapingBundle>() {
        Outbound::bundle(v)?
    } else {
        let (definition, mappings) = shaper_sources(v)?;
        let limits = v.getattr("limits")?;
        let o = options(crate::optional(&limits), attr(v, "seed")?)?;
        let factory: Option<Arc<dyn Factory>> = match definition {
            Some(json) => Some(Arc::new(
                MachineFactory::from_json(json.as_bytes(), o).map_err(crate::value_err)?,
            )),
            None => mappings.factory(&o)?,
        };
        Outbound {
            factory,
            budget: crate::optional(&v.getattr("budget")?)
                .map(budget_of)
                .transpose()?,
            handshake: None,
        }
    };
    session
        .set_shaper(outbound.factory, outbound.budget)
        .map_err(crate::value_err)
}

fn plan_obj<'p>(py: Python<'p>, p: &zmux::shaping::UnitPlan) -> PyResult<Bound<'p, PyAny>> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("pad_to", p.pad_to)?;
    d.set_item("pad_multiple", p.pad_multiple)?;
    d.set_item("pad", p.pad)?;
    d.set_item("delay", p.delay.as_secs_f64())?;
    crate::types(py)?.getattr("UnitPlan")?.call((), Some(&d))
}

/// The handshake shaper of a `ShapingBundle`: its plans, drawn in Rust per
/// handshake message. A Python callable would be asked on the runtime's
/// threads for every message, so none is taken.
pub(crate) fn hook_of(v: &Bound<'_, PyAny>) -> PyResult<zmux::shaping::HandshakeShaper> {
    Ok(v.cast::<ShapingBundle>()?.get().0.handshake_shaper())
}

/// The shaper in force on a session's outbound pipes, as `Session.shaper`
/// reads it: opaque, and assignable to `Session.shaper` of another session.
#[pyclass(frozen, module = "zmux")]
pub(crate) struct InstalledShaper(pub(crate) Arc<dyn Factory>);

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
        let b = if let Some(text) = crate::json_text(definition)? {
            std::borrow::Cow::Borrowed(text)
        } else {
            std::borrow::Cow::Owned(definition.extract::<Vec<u8>>()?)
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
            .and_then(zmux_shaping::Compiled::budget)
            .map(|b| budget_obj(py, &b.ask().map_err(crate::value_err)?))
            .transpose()
    }
}
