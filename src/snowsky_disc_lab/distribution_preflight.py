"""Read-only metadata assessment for a possible source-only distribution."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from snowsky_disc_lab.source_lock import SourceLock, load_source_lock

FindingStatus = Literal["IDENTIFIED", "PENDING_REVIEW", "UNKNOWN", "BLOCKED"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Evidence(_StrictModel):
    path: str
    sha256: str
    url: str


class _InventorySource(_StrictModel):
    sourceId: str
    commit: str


class _InventoryRow(_StrictModel):
    sourceId: str
    commit: str
    component: str = Field(min_length=1)
    paths: list[str] = Field(min_length=1)
    spdxExpression: str = Field(min_length=1)
    evidence: list[_Evidence] = Field(min_length=1)
    reviewStatus: Literal["identified", "pending"]
    notes: str


class _Inventory(_StrictModel):
    formatVersion: Literal[1]
    reviewedOn: str
    sources: list[_InventorySource] = Field(min_length=1)
    inventoryRows: list[_InventoryRow] = Field(min_length=1)


@dataclass(frozen=True)
class Finding:
    code: str
    status: FindingStatus
    message: str


@dataclass(frozen=True)
class DistributionReadinessReport:
    status: FindingStatus
    sources: tuple[tuple[str, str], ...]
    findings: tuple[Finding, ...]

    def to_json(self) -> str:
        """Return stable JSON containing only validated identities and fixed findings."""
        payload = {
            "formatVersion": 1,
            "status": self.status,
            "sources": [
                {"sourceId": source_id, "commit": commit} for source_id, commit in self.sources
            ],
            "findings": [asdict(finding) for finding in self.findings],
        }
        return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"

    def to_markdown(self) -> str:
        lines = [
            "# Source-only distribution readiness",
            "",
            f"**Assessment:** `{self.status}`",
            "",
            "This report checks pinned source and license metadata only. It does not "
            "establish file-level legal clearance or authorize redistribution.",
            "",
            "## Pinned sources",
            "",
        ]
        lines.extend(f"- `{source_id}` at `{commit}`" for source_id, commit in self.sources)
        lines.extend(["", "## Findings", ""])
        lines.extend(
            f"- **{finding.status}** (`{finding.code}`): {finding.message}"
            for finding in self.findings
        )
        return "\n".join(lines) + "\n"


def _safe_path(value: str) -> bool:
    return bool(
        value
        and len(value) <= 256
        and re.fullmatch(
            r"[A-Za-z0-9_*][A-Za-z0-9._*-]*(?:/[A-Za-z0-9_*][A-Za-z0-9._*-]*)*/?",
            value,
        )
    )


def _in_projection(path: str, include_paths: list[str]) -> bool:
    return any(
        path == selected.rstrip("/") or (selected.endswith("/") and path.startswith(selected))
        for selected in include_paths
    )


def _blocked(message: str) -> DistributionReadinessReport:
    finding = Finding("metadata_integrity", "BLOCKED", message)
    return DistributionReadinessReport("BLOCKED", (), (finding,))


def _read_inventory(path: Path) -> _Inventory:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate object key")
            result[key] = value
        return result

    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        if (
            not isinstance(payload, dict)
            or type(payload.get("formatVersion")) is not int
            or payload["formatVersion"] != 1
        ):
            raise ValueError("unsupported inventory schema version")
        return _Inventory.model_validate(payload)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValidationError,
        TypeError,
        ValueError,
        RecursionError,
    ):
        raise ValueError("inventory metadata is unavailable or does not match its schema") from None


def _validate_metadata(lock: SourceLock, inventory: _Inventory) -> str | None:
    locked = {source.id: source for source in lock.sources}
    identities = {source.sourceId: source.commit for source in inventory.sources}
    if len(identities) != len(inventory.sources) or identities != {
        source_id: source.commit for source_id, source in locked.items()
    }:
        return "source identities must match the immutable source lock exactly"

    row_ids: set[tuple[str, str]] = set()
    seen_evidence: dict[tuple[str, str], tuple[str, str]] = {}
    covered_license_evidence: set[tuple[str, str, str]] = set()
    for row in inventory.inventoryRows:
        identity = (row.sourceId, row.component)
        if identity in row_ids:
            return "inventory component identities must be unique"
        row_ids.add(identity)
        pin = locked.get(row.sourceId)
        if pin is None or row.commit != pin.commit or not _COMMIT.fullmatch(row.commit):
            return "inventory component identity contradicts its immutable source pin"
        if row.spdxExpression.strip() != row.spdxExpression or not row.component.strip():
            return "inventory identity and license fields must not contain surrounding whitespace"
        if row.spdxExpression == "NOASSERTION" and row.reviewStatus != "pending":
            return "NOASSERTION inventory rows must remain pending review"
        if any(
            not _safe_path(path) or not _in_projection(path, pin.include_paths)
            for path in row.paths
        ):
            return "inventory component paths must stay inside the pinned source projection"
        if len(set(row.paths)) != len(row.paths):
            return "inventory component paths must be unique"
        evidence_paths: set[str] = set()
        for evidence in row.evidence:
            if (
                not _safe_path(evidence.path)
                or not _in_projection(evidence.path, pin.include_paths)
                or not _SHA256.fullmatch(evidence.sha256)
            ):
                return "evidence paths and digests must identify projected source metadata"
            if evidence.path in evidence_paths:
                return "evidence paths must be unique within each inventory component"
            evidence_paths.add(evidence.path)
            expected_url = (
                f"{pin.repository.removesuffix('.git')}/blob/{pin.commit}/{evidence.path}"
            )
            if evidence.url != expected_url:
                return "evidence URLs must identify the exact pinned repository, commit, and path"
            key = (row.sourceId, evidence.path)
            evidence_identity = (evidence.sha256, evidence.url)
            if key in seen_evidence and seen_evidence[key] != evidence_identity:
                return "repeated evidence identities must have matching digest and URL"
            seen_evidence[key] = evidence_identity
            for license_record in pin.licenses:
                if license_record.path == evidence.path:
                    if license_record.sha256 != evidence.sha256:
                        return "selected license evidence digest must match the source lock"
                    covered_license_evidence.add(
                        (row.sourceId, license_record.path, license_record.sha256)
                    )

    required_license_evidence = {
        (source.id, license_record.path, license_record.sha256)
        for source in lock.sources
        for license_record in source.licenses
    }
    if covered_license_evidence != required_license_evidence:
        return "every selected source-lock license text must have matching inventory evidence"
    return None


def assess_distribution_readiness(root: Path) -> DistributionReadinessReport:
    """Assess source and license metadata without opening projected third-party files."""
    try:
        lock = load_source_lock(root / "upstreams.lock.yaml")
        inventory = _read_inventory(root / "docs" / "license-inventory.json")
    except (OSError, UnicodeError, ValueError):
        return _blocked("source lock or license inventory is unavailable or invalid")

    problem = _validate_metadata(lock, inventory)
    if problem:
        return _blocked(problem)

    sources = tuple(sorted((source.id, source.commit) for source in lock.sources))
    findings = [
        Finding(
            "pinned_metadata",
            "IDENTIFIED",
            "Inventory source identities, selected license evidence, URLs, and digests "
            "match the immutable source lock.",
        ),
        Finding(
            "lab_root_license",
            "PENDING_REVIEW",
            "The Lab repository has no selected root license; public source access does not "
            "grant redistribution rights.",
        ),
        Finding(
            "vendor_firmware",
            "IDENTIFIED",
            "Vendor firmware and proprietary binaries are excluded from the source-only "
            "assessment.",
        ),
        Finding(
            "external_dependencies",
            "PENDING_REVIEW",
            "Optional third-party dependencies and the QEMU patch distribution terms need review.",
        ),
        Finding(
            "file_level_clearance",
            "UNKNOWN",
            "Metadata consistency does not establish rights for every file or release artifact.",
        ),
    ]
    for index, row in enumerate(inventory.inventoryRows, start=1):
        row_reference = f"{row.sourceId} inventory row {index}"
        if row.reviewStatus == "pending":
            findings.append(
                Finding(
                    "pending_component_review",
                    "PENDING_REVIEW",
                    f"{row_reference} remains pending review; component license, notice, "
                    "attribution, or file scope is unresolved.",
                )
            )
        if row.spdxExpression == "NOASSERTION":
            findings.append(
                Finding(
                    "noassertion_license",
                    "PENDING_REVIEW",
                    f"{row_reference} has NOASSERTION; applicable license and notice "
                    "coverage remains unresolved.",
                )
            )
    status: FindingStatus = "PENDING_REVIEW"
    return DistributionReadinessReport(status, sources, tuple(findings))
