"""Versioned, read-only compatibility registry for exact candidate identities."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

REGISTRY_SCHEMA = "lab-compatibility-registry/v1"
MAX_REGISTRY_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMMUTABLE_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class RegistryError(ValueError):
    """Invalid, contradictory, or unsupported compatibility registry data."""


class SupportState(StrEnum):
    UNKNOWN = "unknown"
    INVENTORIED = "inventoried"
    STATIC_COMPATIBLE = "static-compatible"
    PARTIAL = "partial"
    VERIFIED_EMULATOR = "verified-emulator"
    VERIFIED_DEVICE = "verified-device"
    REJECTED = "rejected"
    STALE = "stale"


class ScenarioOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT RUN"
    BLOCKED = "BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"


class Provenance(StrEnum):
    UPSTREAM = "upstream"
    LAB_RUN = "lab-run"


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_min_length=1,
        str_strip_whitespace=True,
    )


class HostRuntime(StrictModel):
    os_name: str | None
    os_version: str | None
    architecture: str | None
    runtime_name: str | None
    runtime_version: str | None


class CandidateIdentity(StrictModel):
    product_id: str | None
    device_model: str | None
    hardware_revision: str | None
    firmware_main: str | None
    firmware_recovery: str | None
    original_firmware_sha256: str | None
    rootfs_sha256: str | None
    stock_mq_player_sha256: str | None
    runner_id: str | None
    runner_revision: str | None = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    shim_revision: str | None = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    ui_binary_sha256: str | None
    ui_source_revision: str | None = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    adapter_revision: str | None = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    scenario_id: str
    scenario_revision: str | None = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    host_runtime: HostRuntime

    @model_validator(mode="after")
    def validate_hashes(self) -> Self:
        for name in (
            "original_firmware_sha256",
            "rootfs_sha256",
            "stock_mq_player_sha256",
            "ui_binary_sha256",
        ):
            value = getattr(self, name)
            if value is not None and not _SHA256.fullmatch(value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest or null")
        for name in (
            "runner_revision",
            "shim_revision",
            "ui_source_revision",
            "adapter_revision",
            "scenario_revision",
        ):
            value = getattr(self, name)
            if value is not None and not _IMMUTABLE_REVISION.fullmatch(value):
                raise ValueError(f"{name} must be a full lowercase commit or digest")
        return self


class EvidenceReference(StrictModel):
    reference_id: str = Field(min_length=1)
    provenance: Provenance
    kind: str = Field(min_length=1)
    uri: str | None
    sha256: str | None

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.sha256 is not None and not _SHA256.fullmatch(self.sha256):
            raise ValueError("evidence sha256 must be a lowercase SHA-256 digest or null")
        return self


class ClaimOrObservation(StrictModel):
    field: str = Field(min_length=1)
    value: str = Field(min_length=1)
    provenance: Provenance
    evidence_reference_id: str = Field(min_length=1)


class CompatibilityRecord(StrictModel):
    record_id: str = Field(min_length=1)
    schema_version: Literal["lab-compatibility-registry/v1"]
    identity: CandidateIdentity
    support_state: SupportState
    scenario_outcome: ScenarioOutcome
    evidence: tuple[EvidenceReference, ...]
    claims_and_observations: tuple[ClaimOrObservation, ...]
    limitations: tuple[str, ...]
    execution_authority: bool = False

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if self.schema_version != REGISTRY_SCHEMA:
            raise ValueError(f"schema_version must be {REGISTRY_SCHEMA!r}")
        if self.execution_authority is not False:
            raise ValueError("registry records never grant execution authority")
        evidence_ids = [item.reference_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("duplicate evidence reference_id")
        evidence_set = set(evidence_ids)
        if any(
            item.evidence_reference_id not in evidence_set for item in self.claims_and_observations
        ):
            raise ValueError("claim/observation references missing evidence")
        lab_run_ids = {
            item.reference_id for item in self.evidence if item.provenance is Provenance.LAB_RUN
        }
        evidence_provenance = {item.reference_id: item.provenance for item in self.evidence}
        if any(
            item.provenance is not evidence_provenance[item.evidence_reference_id]
            for item in self.claims_and_observations
        ):
            raise ValueError("claim/observation provenance must match its evidence reference")
        outcome_observed = any(
            item.field == "scenario_outcome"
            and item.value == self.scenario_outcome.value
            and item.provenance is Provenance.LAB_RUN
            and item.evidence_reference_id in lab_run_ids
            for item in self.claims_and_observations
        )
        if (
            self.scenario_outcome in {ScenarioOutcome.PASS, ScenarioOutcome.FAIL}
            and not outcome_observed
        ):
            raise ValueError("PASS/FAIL require a lab-run scenario_outcome observation")
        if (
            self.support_state is SupportState.INVENTORIED
            and self.scenario_outcome is not ScenarioOutcome.NOT_RUN
        ):
            raise ValueError("inventoried records must remain NOT RUN")
        if self.support_state in {SupportState.STATIC_COMPATIBLE, SupportState.PARTIAL}:
            raise ValueError(
                "static-compatible and partial promotion are deferred until "
                "trusted evidence assessment exists"
            )
        if (
            self.support_state is SupportState.REJECTED
            and self.scenario_outcome is not ScenarioOutcome.FAIL
        ):
            raise ValueError("rejected requires a recorded FAIL scenario outcome")
        if (
            self.support_state in {SupportState.REJECTED, SupportState.STALE}
            and not self.limitations
        ):
            raise ValueError("rejected and stale records require an explicit reason in limitations")
        if self.support_state in {SupportState.VERIFIED_EMULATOR, SupportState.VERIFIED_DEVICE}:
            raise ValueError(
                "verified-state import is deferred until authenticated acceptance is implemented"
            )
        return self


class CompatibilityRegistry(StrictModel):
    schema_version: Literal["lab-compatibility-registry/v1"]
    records: tuple[CompatibilityRecord, ...]

    @model_validator(mode="after")
    def validate_registry(self) -> Self:
        if self.schema_version != REGISTRY_SCHEMA:
            raise ValueError(f"schema_version must be {REGISTRY_SCHEMA!r}")
        ids: set[str] = set()
        identities: dict[tuple[Any, ...], CompatibilityRecord] = {}
        for record in self.records:
            if record.record_id in ids:
                raise ValueError(f"duplicate record_id: {record.record_id}")
            ids.add(record.record_id)
            key = (record.identity,)
            previous = identities.get(key)
            if previous is not None:
                raise ValueError(
                    "duplicate or contradictory records for the same exact candidate scenario"
                )
            identities[key] = record
        return self


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_registry_json(source: str | bytes) -> CompatibilityRegistry:
    """Parse strict JSON and refuse duplicate keys, unsupported promotion, and extras."""
    try:
        size = len(source.encode("utf-8")) if isinstance(source, str) else len(source)
        if size > MAX_REGISTRY_BYTES:
            raise RegistryError("compatibility registry exceeds the 1 MiB limit")
        json.loads(source, object_pairs_hook=_reject_duplicate_keys)
        return CompatibilityRegistry.model_validate_json(source)
    except (json.JSONDecodeError, ValidationError, TypeError, ValueError, RegistryError) as exc:
        if isinstance(exc, RegistryError):
            raise
        raise RegistryError("invalid compatibility registry JSON or schema") from exc


def build_registry(records: Iterable[CompatibilityRecord]) -> CompatibilityRegistry:
    """Build a new validated immutable registry from records."""
    try:
        raw_records = [record.model_dump(mode="json") for record in records]
        return CompatibilityRegistry.model_validate_json(
            json.dumps({"schema_version": REGISTRY_SCHEMA, "records": raw_records})
        )
    except (ValidationError, AttributeError, TypeError, ValueError) as exc:
        raise RegistryError("invalid compatibility registry data") from exc


def _checked_registry(registry: CompatibilityRegistry) -> CompatibilityRegistry:
    """Revalidate at public boundaries because Pydantic model_copy can bypass validators."""
    try:
        return CompatibilityRegistry.model_validate(registry.model_dump(mode="python"))
    except (ValidationError, AttributeError, TypeError) as exc:
        raise RegistryError("invalid compatibility registry data") from exc


def _identity_is_complete(identity: CandidateIdentity) -> bool:
    values = identity.model_dump(mode="python")
    host_runtime = values.pop("host_runtime")
    return all(value is not None for value in values.values()) and all(
        value is not None for value in host_runtime.values()
    )


def registry_json(registry: CompatibilityRegistry) -> str:
    """Serialize records with stable ordering and formatting."""
    checked = _checked_registry(registry)
    payload = checked.model_dump(mode="json")
    payload["records"].sort(key=lambda record: record["record_id"])
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def query_registry(
    registry: CompatibilityRegistry, filters: Mapping[str, str | None] | None = None
) -> tuple[CompatibilityRecord, ...]:
    """Return records matching exact identity values; null filters mean exact unknown only."""
    registry = _checked_registry(registry)
    filters = filters or {}
    valid_fields = set(CandidateIdentity.model_fields) - {"host_runtime"}
    valid_fields |= {f"host_runtime.{name}" for name in HostRuntime.model_fields}
    unknown = set(filters) - valid_fields
    if unknown:
        raise RegistryError(f"unknown identity filter(s): {', '.join(sorted(unknown))}")
    matches = [
        record
        for record in registry.records
        if all(
            (
                getattr(record.identity.host_runtime, name.removeprefix("host_runtime."))
                if name.startswith("host_runtime.")
                else getattr(record.identity, name)
            )
            == value
            for name, value in filters.items()
        )
    ]
    return tuple(
        sorted(matches, key=lambda record: (record.identity.scenario_id, record.record_id))
    )


def compare_records(earlier: CompatibilityRecord, later: CompatibilityRecord) -> dict[str, Any]:
    """Compare exact candidate records without treating missing identity as a wildcard."""
    try:
        earlier = CompatibilityRecord.model_validate(earlier.model_dump(mode="python"))
        later = CompatibilityRecord.model_validate(later.model_dump(mode="python"))
    except (ValidationError, AttributeError, TypeError) as exc:
        raise RegistryError("invalid comparison record") from exc
    comparable = earlier.identity == later.identity and _identity_is_complete(earlier.identity)
    previous = earlier.scenario_outcome.value
    current = later.scenario_outcome.value
    if not comparable:
        classification = "incomparable"
    elif previous == current:
        classification = "unchanged"
    elif previous == "PASS" and current == "FAIL":
        classification = "regression"
    elif previous == "FAIL" and current == "PASS":
        classification = "improvement"
    else:
        classification = "incomparable"
    return {
        "schema_version": "lab-compatibility-comparison/v1",
        "comparable": comparable,
        "classification": classification,
        "earlier_record_id": earlier.record_id,
        "later_record_id": later.record_id,
        "scenario_id": earlier.identity.scenario_id,
        "earlier_outcome": previous,
        "later_outcome": current,
        "overall_support_state": "unknown" if not comparable else later.support_state.value,
        "execution_authority": False,
    }
