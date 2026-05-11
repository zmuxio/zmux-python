"""Conformance claim and profile names recognized by this package."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from .protocol import (
    CLAIM_API_SEMANTICS_PROFILE_V1,
    CLAIM_OPEN_METADATA,
    CLAIM_PRIORITY_UPDATE,
    CLAIM_STREAM_ADAPTER_PROFILE_V1,
    CLAIM_WIRE_V1,
    PROFILE_REFERENCE_V1,
    PROFILE_V1,
)


class ParseConformanceError(ValueError):
    """Raised when a conformance name is not recognized."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        messages = {
            "claim": "unknown zmux conformance claim",
            "profile": "unknown zmux implementation profile",
            "suite": "unknown zmux conformance suite",
        }
        super().__init__(messages.get(kind, "unknown zmux conformance name"))


class Claim(str, Enum):
    """Repository-defined conformance claim."""

    WIRE_V1 = CLAIM_WIRE_V1
    API_SEMANTICS_PROFILE_V1 = CLAIM_API_SEMANTICS_PROFILE_V1
    STREAM_ADAPTER_PROFILE_V1 = CLAIM_STREAM_ADAPTER_PROFILE_V1
    OPEN_METADATA = CLAIM_OPEN_METADATA
    PRIORITY_UPDATE = CLAIM_PRIORITY_UPDATE

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_name(cls, value: str) -> Optional["Claim"]:
        try:
            return cls(value)
        except ValueError:
            return None

    @classmethod
    def is_known_name(cls, value: str) -> bool:
        return cls.from_name(value) is not None

    @classmethod
    def parse(cls, value: str) -> "Claim":
        found = cls.from_name(value)
        if found is None:
            raise ParseConformanceError("claim")
        return found

    def acceptance_checklist(self) -> tuple[str, ...]:
        if self is Claim.WIRE_V1:
            return (
                "pass core wire interoperability",
                "pass invalid-input handling",
                "pass extension-tolerance behavior",
            )
        if self is Claim.OPEN_METADATA:
            return (
                "satisfy zmux-wire-v1",
                "negotiate open_metadata",
                "accept valid DATA|OPEN_METADATA on first opening DATA",
                "reject unnegotiated or misplaced OPEN_METADATA",
                "ignore unknown metadata TLVs",
                "drop duplicate singleton metadata while preserving the enclosing DATA",
            )
        if self is Claim.PRIORITY_UPDATE:
            return (
                "satisfy zmux-wire-v1",
                "negotiate priority_update",
                "process stream_priority and stream_group",
                "ignore open_info inside PRIORITY_UPDATE",
                "ignore unknown advisory TLVs",
                "ignore duplicate singleton advisory updates as one dropped update",
            )
        if self is Claim.API_SEMANTICS_PROFILE_V1:
            return (
                "document and implement the repository-default semantic operation families from API_SEMANTICS.md, including full local close helper, graceful send-half completion, read-side stop, send-side reset, whole-stream abort, structured error surfacing, open/cancel behavior, and accept visibility rules",
                "document whether the binding exposes a stream-style convenience profile, a full-control protocol surface, or both",
                "exact API spellings are not required",
            )
        if self is Claim.STREAM_ADAPTER_PROFILE_V1:
            return (
                "satisfy the stream-adapter subset from API_SEMANTICS.md, including bidirectional/unidirectional open and accept mapping",
                "provide one consistent convenience mapping or fuller documented control layer or both",
                "document limits/non-goals",
            )
        raise AssertionError("unhandled conformance claim: %r" % (self,))

    def required_conformance_suites(self) -> tuple["ConformanceSuite", ...]:
        if self is Claim.WIRE_V1:
            return (
                ConformanceSuite.CORE_WIRE_INTEROPERABILITY,
                ConformanceSuite.INVALID_INPUT_HANDLING,
                ConformanceSuite.EXTENSION_TOLERANCE,
            )
        if self is Claim.OPEN_METADATA:
            return (
                ConformanceSuite.CORE_WIRE_INTEROPERABILITY,
                ConformanceSuite.INVALID_INPUT_HANDLING,
                ConformanceSuite.EXTENSION_TOLERANCE,
                ConformanceSuite.OPEN_METADATA,
            )
        if self is Claim.PRIORITY_UPDATE:
            return (
                ConformanceSuite.CORE_WIRE_INTEROPERABILITY,
                ConformanceSuite.INVALID_INPUT_HANDLING,
                ConformanceSuite.EXTENSION_TOLERANCE,
                ConformanceSuite.PRIORITY_UPDATE,
            )
        if self is Claim.API_SEMANTICS_PROFILE_V1:
            return (ConformanceSuite.API_SEMANTICS_PROFILE,)
        if self is Claim.STREAM_ADAPTER_PROFILE_V1:
            return (ConformanceSuite.STREAM_ADAPTER_PROFILE,)
        raise AssertionError("unhandled conformance claim: %r" % (self,))


class ImplementationProfile(str, Enum):
    """Repository-defined implementation profile."""

    V1 = PROFILE_V1
    REFERENCE_PROFILE_V1 = PROFILE_REFERENCE_V1

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_name(cls, value: str) -> Optional["ImplementationProfile"]:
        try:
            return cls(value)
        except ValueError:
            return None

    @classmethod
    def is_known_name(cls, value: str) -> bool:
        return cls.from_name(value) is not None

    @classmethod
    def parse(cls, value: str) -> "ImplementationProfile":
        found = cls.from_name(value)
        if found is None:
            raise ParseConformanceError("profile")
        return found

    def claims(self) -> tuple[Claim, ...]:
        if self is ImplementationProfile.V1:
            return Claim.WIRE_V1, Claim.OPEN_METADATA, Claim.PRIORITY_UPDATE
        if self is ImplementationProfile.REFERENCE_PROFILE_V1:
            return (
                Claim.WIRE_V1,
                Claim.API_SEMANTICS_PROFILE_V1,
                Claim.STREAM_ADAPTER_PROFILE_V1,
                Claim.OPEN_METADATA,
                Claim.PRIORITY_UPDATE,
            )
        raise AssertionError("unhandled implementation profile: %r" % (self,))

    def acceptance_checklist(self) -> tuple[str, ...]:
        if self is ImplementationProfile.V1:
            return (
                "satisfy zmux-wire-v1",
                "interoperate on explicit-role and role=auto establishment",
                "pass core stream-lifecycle scenarios",
                "pass core flow-control scenarios",
                "pass core session-lifecycle scenarios",
                "satisfy every currently active same-version optional surface in this repository",
                "negotiate and handle open_metadata, priority_update, priority_hints, and stream_groups correctly",
            )
        if self is ImplementationProfile.REFERENCE_PROFILE_V1:
            return (
                "satisfy zmux-v1",
                "satisfy the repository-defined reference-profile claim gate",
                "preserve the documented repository-default sender, memory, liveness, API, and scheduling behavior closely enough for release claims",
            )
        raise AssertionError("unhandled implementation profile: %r" % (self,))

    def required_conformance_suites(self) -> tuple["ConformanceSuite", ...]:
        if self is ImplementationProfile.V1:
            return (
                ConformanceSuite.CORE_WIRE_INTEROPERABILITY,
                ConformanceSuite.INVALID_INPUT_HANDLING,
                ConformanceSuite.EXTENSION_TOLERANCE,
                ConformanceSuite.CORE_STREAM_LIFECYCLE,
                ConformanceSuite.CORE_FLOW_CONTROL,
                ConformanceSuite.CORE_SESSION_LIFECYCLE,
                ConformanceSuite.OPEN_METADATA,
                ConformanceSuite.PRIORITY_UPDATE,
                ConformanceSuite.PRIORITY_HINTS_AND_STREAM_GROUPS,
                ConformanceSuite.V1_PROFILE_COMPATIBILITY,
            )
        if self is ImplementationProfile.REFERENCE_PROFILE_V1:
            return (
                ConformanceSuite.CORE_WIRE_INTEROPERABILITY,
                ConformanceSuite.INVALID_INPUT_HANDLING,
                ConformanceSuite.EXTENSION_TOLERANCE,
                ConformanceSuite.CORE_STREAM_LIFECYCLE,
                ConformanceSuite.CORE_FLOW_CONTROL,
                ConformanceSuite.CORE_SESSION_LIFECYCLE,
                ConformanceSuite.OPEN_METADATA,
                ConformanceSuite.PRIORITY_UPDATE,
                ConformanceSuite.PRIORITY_HINTS_AND_STREAM_GROUPS,
                ConformanceSuite.V1_PROFILE_COMPATIBILITY,
                ConformanceSuite.API_SEMANTICS_PROFILE,
                ConformanceSuite.STREAM_ADAPTER_PROFILE,
                ConformanceSuite.REFERENCE_PROFILE_CLAIM_GATE,
                ConformanceSuite.REFERENCE_QUALITY_BEHAVIORS,
            )
        raise AssertionError("unhandled implementation profile: %r" % (self,))

    def release_certification_gate(self) -> tuple["ConformanceSuite", ...]:
        return self.required_conformance_suites()


class ConformanceSuite(str, Enum):
    """Repository-defined conformance suite."""

    CORE_WIRE_INTEROPERABILITY = "core-wire-interoperability"
    INVALID_INPUT_HANDLING = "invalid-input-handling"
    EXTENSION_TOLERANCE = "extension-tolerance"
    CORE_STREAM_LIFECYCLE = "core-stream-lifecycle"
    CORE_FLOW_CONTROL = "core-flow-control"
    CORE_SESSION_LIFECYCLE = "core-session-lifecycle"
    OPEN_METADATA = "open_metadata"
    PRIORITY_UPDATE = "priority_update"
    PRIORITY_HINTS_AND_STREAM_GROUPS = "priority-hints-and-stream-groups"
    V1_PROFILE_COMPATIBILITY = "v1-profile-compatibility"
    API_SEMANTICS_PROFILE = "api-semantics-profile"
    STREAM_ADAPTER_PROFILE = "stream-adapter-profile"
    REFERENCE_PROFILE_CLAIM_GATE = "reference-profile-claim-gate"
    REFERENCE_QUALITY_BEHAVIORS = "reference-quality-behaviors"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_name(cls, value: str) -> Optional["ConformanceSuite"]:
        try:
            return cls(value)
        except ValueError:
            return None

    @classmethod
    def is_known_name(cls, value: str) -> bool:
        return cls.from_name(value) is not None

    @classmethod
    def parse(cls, value: str) -> "ConformanceSuite":
        found = cls.from_name(value)
        if found is None:
            raise ParseConformanceError("suite")
        return found


def _merge_required_suites(
        claims: tuple[Claim, ...],
        profiles: tuple[ImplementationProfile, ...],
) -> tuple[ConformanceSuite, ...]:
    required = set()
    for claim in claims:
        required.update(claim.required_conformance_suites())
    for profile in profiles:
        required.update(profile.required_conformance_suites())
    return tuple(suite for suite in ConformanceSuite if suite in required)


SUITE_CORE_WIRE_INTEROPERABILITY = ConformanceSuite.CORE_WIRE_INTEROPERABILITY.value
SUITE_INVALID_INPUT_HANDLING = ConformanceSuite.INVALID_INPUT_HANDLING.value
SUITE_EXTENSION_TOLERANCE = ConformanceSuite.EXTENSION_TOLERANCE.value
SUITE_CORE_STREAM_LIFECYCLE = ConformanceSuite.CORE_STREAM_LIFECYCLE.value
SUITE_CORE_FLOW_CONTROL = ConformanceSuite.CORE_FLOW_CONTROL.value
SUITE_CORE_SESSION_LIFECYCLE = ConformanceSuite.CORE_SESSION_LIFECYCLE.value
SUITE_OPEN_METADATA = ConformanceSuite.OPEN_METADATA.value
SUITE_PRIORITY_UPDATE = ConformanceSuite.PRIORITY_UPDATE.value
SUITE_PRIORITY_HINTS_AND_STREAM_GROUPS = ConformanceSuite.PRIORITY_HINTS_AND_STREAM_GROUPS.value
SUITE_V1_PROFILE_COMPATIBILITY = ConformanceSuite.V1_PROFILE_COMPATIBILITY.value
SUITE_API_SEMANTICS_PROFILE = ConformanceSuite.API_SEMANTICS_PROFILE.value
SUITE_STREAM_ADAPTER_PROFILE = ConformanceSuite.STREAM_ADAPTER_PROFILE.value
SUITE_REFERENCE_PROFILE_CLAIM_GATE = ConformanceSuite.REFERENCE_PROFILE_CLAIM_GATE.value
SUITE_REFERENCE_QUALITY_BEHAVIORS = ConformanceSuite.REFERENCE_QUALITY_BEHAVIORS.value

KNOWN_CLAIMS: tuple[str, ...] = tuple(claim.value for claim in Claim)
KNOWN_IMPLEMENTATION_PROFILES: tuple[str, ...] = tuple(
    profile.value for profile in ImplementationProfile
)
KNOWN_CONFORMANCE_SUITES: tuple[str, ...] = tuple(suite.value for suite in ConformanceSuite)

_CORE_MODULE_TARGET_CLAIMS = (
    Claim.WIRE_V1,
    Claim.API_SEMANTICS_PROFILE_V1,
    Claim.OPEN_METADATA,
    Claim.PRIORITY_UPDATE,
)

_CORE_MODULE_TARGET_IMPLEMENTATION_PROFILES = (
    ImplementationProfile.V1,
)

CORE_MODULE_TARGET_CLAIMS: tuple[str, ...] = tuple(
    claim.value for claim in _CORE_MODULE_TARGET_CLAIMS
)

CORE_MODULE_TARGET_IMPLEMENTATION_PROFILES: tuple[str, ...] = tuple(
    profile.value for profile in _CORE_MODULE_TARGET_IMPLEMENTATION_PROFILES
)

CORE_MODULE_TARGET_SUITES: tuple[str, ...] = tuple(
    suite.value
    for suite in _merge_required_suites(
        _CORE_MODULE_TARGET_CLAIMS,
        _CORE_MODULE_TARGET_IMPLEMENTATION_PROFILES,
    )
)

REFERENCE_PROFILE_CLAIM_GATE: tuple[str, ...] = (
    "repository-default stream-style CloseRead() emits STOP_SENDING(CANCELLED) when that convenience profile is exposed, while fuller control surfaces MAY additionally expose caller-selected codes and diagnostics for STOP_SENDING, RESET, and ABORT",
    "repository-default Close() acts as a full local close helper",
    "repository-default Close() on a unidirectional stream silently ignores the locally absent direction rather than failing solely because that half does not exist",
    "each exposed API surface keeps one documented primary spelling per operation family, with any extra convenience spellings documented as wrappers over the same semantic action rather than as distinct lifecycle operations",
    "before session-ready, repository-default sender behavior emits only the local preface and a fatal establishment CLOSE, and emits none of new-stream DATA, stream-scoped control, ordinary session-scoped control, or EXT",
    "repository-default sender and receiver memory rules enforce the documented hidden-state, provisional-open, and late-tail bounds",
    "repository-default liveness rules keep at most one outstanding protocol PING and do not treat weak local signals as strong progress",
)


def known_claims() -> tuple[str, ...]:
    """Return repository-defined conformance claim names."""

    return KNOWN_CLAIMS


def known_implementation_profiles() -> tuple[str, ...]:
    """Return repository-defined implementation profile names."""

    return KNOWN_IMPLEMENTATION_PROFILES


def known_conformance_suites() -> tuple[str, ...]:
    """Return repository-defined conformance suite names."""

    return KNOWN_CONFORMANCE_SUITES


def reference_profile_claim_gate() -> tuple[str, ...]:
    """Return repository-defined reference-profile release-gate statements."""

    return REFERENCE_PROFILE_CLAIM_GATE


def core_module_target_claims() -> tuple[str, ...]:
    """Return the claim targets for the core Python distribution."""

    return CORE_MODULE_TARGET_CLAIMS


def core_module_target_implementation_profiles() -> tuple[str, ...]:
    """Return the implementation profile targets for the core package."""

    return CORE_MODULE_TARGET_IMPLEMENTATION_PROFILES


def core_module_target_suites() -> tuple[str, ...]:
    """Return ordered conformance suites for the core package targets."""

    return CORE_MODULE_TARGET_SUITES


__all__ = [
    "CORE_MODULE_TARGET_CLAIMS",
    "CORE_MODULE_TARGET_IMPLEMENTATION_PROFILES",
    "CORE_MODULE_TARGET_SUITES",
    "KNOWN_CLAIMS",
    "KNOWN_CONFORMANCE_SUITES",
    "KNOWN_IMPLEMENTATION_PROFILES",
    "REFERENCE_PROFILE_CLAIM_GATE",
    "SUITE_API_SEMANTICS_PROFILE",
    "SUITE_CORE_FLOW_CONTROL",
    "SUITE_CORE_SESSION_LIFECYCLE",
    "SUITE_CORE_STREAM_LIFECYCLE",
    "SUITE_CORE_WIRE_INTEROPERABILITY",
    "SUITE_EXTENSION_TOLERANCE",
    "SUITE_INVALID_INPUT_HANDLING",
    "SUITE_OPEN_METADATA",
    "SUITE_PRIORITY_HINTS_AND_STREAM_GROUPS",
    "SUITE_PRIORITY_UPDATE",
    "SUITE_REFERENCE_PROFILE_CLAIM_GATE",
    "SUITE_REFERENCE_QUALITY_BEHAVIORS",
    "SUITE_STREAM_ADAPTER_PROFILE",
    "SUITE_V1_PROFILE_COMPATIBILITY",
    "Claim",
    "ConformanceSuite",
    "ImplementationProfile",
    "ParseConformanceError",
    "core_module_target_claims",
    "core_module_target_implementation_profiles",
    "core_module_target_suites",
    "known_claims",
    "known_conformance_suites",
    "known_implementation_profiles",
    "reference_profile_claim_gate",
]
