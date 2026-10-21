"""Deterministic, read-only comparison of parsed compatibility reports."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

_STATUSES = {"PASS", "FAIL", "NOT RUN", "BLOCKED", "UNSUPPORTED"}
_STOCK_SCENARIOS = {"stock-v257-boot", "stock-ipc-compatibility"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class CompatibilityComparisonError(ValueError):
    """A report is malformed or contains contradictory compatibility claims."""


def _validate_report(report: Any, label: str) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise CompatibilityComparisonError(f"{label} report must be an object")
    scenarios = report.get("scenarios")
    artifacts = report.get("artifacts")
    if not isinstance(scenarios, dict) or not isinstance(artifacts, dict) or not artifacts:
        raise CompatibilityComparisonError(f"{label} report lacks scenarios or artifact identities")
    if not isinstance(report.get("receipt_schema"), str) or not report["receipt_schema"]:
        raise CompatibilityComparisonError(f"{label} report has invalid receipt schema")
    for name, digest in artifacts.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
        ):
            raise CompatibilityComparisonError(f"{label} report has malformed artifact identities")
    if report.get("execution_scope") != "firmware-free synthetic execution":
        raise CompatibilityComparisonError(f"{label} report has unsupported execution scope")
    if report.get("support_status") != "unknown":
        raise CompatibilityComparisonError(f"{label} report has contradictory support status")
    authentication = report.get("evidence_authentication")
    if (
        not isinstance(authentication, dict)
        or authentication.get("receipt_values") != "declared"
        or authentication.get("independent_authentication") != "not performed"
        or authentication.get("artifact_bytes_rehashed") is not False
    ):
        raise CompatibilityComparisonError(f"{label} report has contradictory receipt provenance")
    for name, result in scenarios.items():
        if not isinstance(name, str) or not name or not isinstance(result, dict):
            raise CompatibilityComparisonError(f"{label} report has malformed scenario results")
        status = result.get("status")
        if not isinstance(status, str) or status not in _STATUSES:
            raise CompatibilityComparisonError(f"{label} report has unknown scenario status")
        if name in _STOCK_SCENARIOS and status != "NOT RUN":
            raise CompatibilityComparisonError("stock firmware scenarios must remain NOT RUN")
    return report


def _classify(before: str, after: str) -> str:
    if before == after:
        return "unchanged"
    if before == "FAIL" and after == "PASS":
        return "improvement"
    if before == "PASS" and after == "FAIL":
        return "regression"
    return "incomparable"


def compare_reports(earlier: Any, later: Any) -> dict[str, Any]:
    """Compare two sanitized report dictionaries without mutating either input."""
    earlier = _validate_report(earlier, "earlier")
    later = _validate_report(later, "later")
    same_conditions = (
        earlier.get("receipt_schema") == later.get("receipt_schema")
        and earlier["artifacts"] == later["artifacts"]
    )
    scenario_names = sorted(set(earlier["scenarios"]) | set(later["scenarios"]))
    results: dict[str, dict[str, str]] = {}
    for name in scenario_names:
        before = earlier["scenarios"].get(name, {}).get("status", "NOT RUN")
        after = later["scenarios"].get(name, {}).get("status", "NOT RUN")
        classification = _classify(before, after) if same_conditions else "incomparable"
        reason = (
            "artifact identities differ" if earlier["artifacts"] != later["artifacts"] else None
        )
        if not same_conditions and reason is None:
            reason = "receipt schemas differ"
        results[name] = {
            "before": before,
            "after": after,
            "classification": classification,
            **({"reason": reason} if reason else {}),
        }
    return {
        "comparison_schema": "firmware-free-synthetic-compatibility-comparison/v1",
        "execution_scope": "firmware-free synthetic execution",
        "conditions_match": same_conditions,
        "historical_report": deepcopy(earlier),
        "later_source": later.get("source"),
        "evidence_authentication": deepcopy(earlier["evidence_authentication"]),
        "support_status": "unknown",
        "scenarios": results,
        "limitations": [
            "Synthetic comparison does not establish stock firmware compatibility.",
            "Receipt values are declared and independently unauthenticated.",
        ],
    }
