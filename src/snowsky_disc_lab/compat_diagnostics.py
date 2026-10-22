"""Explicitly versioned domain diagnostics for comparable compatibility regressions."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from snowsky_disc_lab.compat_compare import CompatibilityComparisonError, compare_reports

_DOMAIN_NAMES = (
    "build",
    "abi",
    "input",
    "framebuffer",
    "ipc",
    "audio",
    "power-lifecycle",
    "environment",
)
_SCENARIO_DOMAINS = {
    "synthetic-ipc-handoff": "ipc",
}
_SCENARIO_EVIDENCE = {
    "synthetic-ipc-handoff": "receipt-declared handoff evidence; artifact provenance is unverified",
}
_SAFE_SCENARIO = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def diagnose_regressions(earlier: Any, later: Any) -> dict[str, Any]:
    """Return sanitized, opt-in domain diagnoses for comparable PASS-to-FAIL changes.

    The only current mapping requires identity-linked synthetic IPC handoff
    evidence. Other scenario names remain UNCLASSIFIED because their evidence
    does not isolate a roadmap failure domain.
    """
    comparison = compare_reports(earlier, later)
    if not comparison["conditions_match"]:
        return {
            "diagnostics_schema": "firmware-free-synthetic-compatibility-diagnostics/v1",
            "status": "incomparable",
            "conditions_match": False,
            "regressions": [],
            "reason": "comparison conditions differ; no domain diagnosis was attempted",
            "domains": list(_DOMAIN_NAMES),
            "limitations": [
                "Different identities or receipt schemas are not compared as matching conditions.",
                "Synthetic diagnostics do not establish stock firmware compatibility.",
            ],
        }

    regressions = []
    for name, result in comparison["scenarios"].items():
        if result["classification"] != "regression":
            continue
        domain = (
            _SCENARIO_DOMAINS.get(name, "UNCLASSIFIED")
            if _has_fixed_ipc_evidence(earlier, name, result["before"])
            and _has_fixed_ipc_evidence(later, name, result["after"])
            else "UNCLASSIFIED"
        )
        item = {
            "scenario": name if _SAFE_SCENARIO.fullmatch(name) else "unclassified-scenario",
            "before": result["before"],
            "after": result["after"],
            "classification": "regression",
            "domain": domain,
        }
        if domain == "UNCLASSIFIED":
            item["reason"] = "scenario evidence does not identify a roadmap failure domain"
            if not _SAFE_SCENARIO.fullmatch(name):
                item["scenario_id"] = hashlib.sha256(name.encode("utf-8")).hexdigest()
        else:
            item["reason"] = "fixed synthetic IPC scenario"
        regressions.append(item)

    return {
        "diagnostics_schema": "firmware-free-synthetic-compatibility-diagnostics/v1",
        "status": "regressions-found" if regressions else "no-regressions",
        "conditions_match": True,
        "regressions": regressions,
        "domains": list(_DOMAIN_NAMES),
        "limitations": [
            "Only explicit PASS-to-FAIL changes are listed as regressions.",
            "Unmapped scenario evidence remains UNCLASSIFIED.",
            "Synthetic diagnostics do not establish stock firmware compatibility.",
        ],
    }


def _has_fixed_ipc_evidence(report: dict[str, Any], scenario: str, status: str) -> bool:
    """Require the parser's fixed marker and identity-linked parsed IPC evidence."""
    if scenario != "synthetic-ipc-handoff":
        return False
    result = report["scenarios"].get(scenario)
    handoff = report.get("synthetic_ipc_handoff")
    if not isinstance(result, dict) or result.get("evidence") != _SCENARIO_EVIDENCE[scenario]:
        return False
    if not isinstance(handoff, dict) or handoff.get("status") != status:
        return False
    identities = handoff.get("identities")
    artifacts = report.get("artifacts")
    sessions = handoff.get("sessions")
    return (
        isinstance(identities, dict)
        and isinstance(artifacts, dict)
        and "qemu-mipsel" in identities
        and "qemu-mipsel" in artifacts
        and "guest-elf" in identities
        and "ipc-handoff-guest" in artifacts
        and isinstance(identities["qemu-mipsel"], str)
        and _SHA256.fullmatch(identities["qemu-mipsel"]) is not None
        and isinstance(identities["guest-elf"], str)
        and _SHA256.fullmatch(identities["guest-elf"]) is not None
        and identities["qemu-mipsel"] == artifacts["qemu-mipsel"]
        and identities["guest-elf"] == artifacts["ipc-handoff-guest"]
        and handoff.get("roles") == ["consumer", "producer"]
        and type(sessions) is int
        and sessions in (1, 2)
        and handoff.get("independently_authenticated") is False
    )


__all__ = ["CompatibilityComparisonError", "diagnose_regressions"]
