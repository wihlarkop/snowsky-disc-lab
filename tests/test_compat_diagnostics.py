from __future__ import annotations

import json
from copy import deepcopy

import pytest
from test_compat_evidence import _failed_ipc_handoff_receipt, _ipc_handoff_receipt

from snowsky_disc_lab.compat_compare import CompatibilityComparisonError
from snowsky_disc_lab.compat_diagnostics import diagnose_regressions
from snowsky_disc_lab.compat_evidence import parse_receipt


def _report(status: str = "PASS", *, qemu: str = "a" * 64) -> dict:
    return {
        "receipt_schema": "firmware-free-synthetic-runtime-acceptance/v1",
        "receipt_status": "passed" if status == "PASS" else "failed",
        "execution_scope": "firmware-free synthetic execution",
        "support_status": "unknown",
        "artifacts": {"qemu-mipsel": qemu, "guest-elf": "b" * 64},
        "evidence_authentication": {
            "receipt_values": "declared",
            "independent_authentication": "not performed",
            "artifact_bytes_rehashed": False,
        },
        "scenarios": {"synthetic-filesystem": {"status": status, "evidence": "receipt"}},
    }


def _ipc_report(status: str) -> dict:
    report = _report()
    guest = "c" * 64
    report["artifacts"]["ipc-handoff-guest"] = guest
    report["scenarios"]["synthetic-ipc-handoff"] = {
        "status": status,
        "evidence": "receipt-declared handoff evidence; artifact provenance is unverified",
    }
    report["synthetic_ipc_handoff"] = {
        "status": status,
        "sessions": 2,
        "roles": ["consumer", "producer"],
        "identities": {"qemu-mipsel": "a" * 64, "guest-elf": guest},
        "independently_authenticated": False,
    }
    return report


def test_ipc_regression_has_explicit_domain_and_keeps_provenance_inputs_unchanged() -> None:
    earlier = _ipc_report("PASS")
    later = _ipc_report("FAIL")
    before = deepcopy((earlier, later))

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["status"] == "regressions-found"
    assert diagnostics["regressions"] == [
        {
            "scenario": "synthetic-ipc-handoff",
            "before": "PASS",
            "after": "FAIL",
            "classification": "regression",
            "domain": "ipc",
            "reason": "fixed synthetic IPC scenario",
        }
    ]
    assert (earlier, later) == before
    assert diagnostics["diagnostics_schema"].endswith("/v1")


def test_parser_produced_ipc_handoff_failure_maps_to_ipc() -> None:
    earlier = parse_receipt(json.dumps(_ipc_handoff_receipt()), source="earlier")
    later = parse_receipt(
        json.dumps(_failed_ipc_handoff_receipt(cleanup_failed=False)), source="later"
    )

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["regressions"][0]["scenario"] == "synthetic-ipc-handoff"
    assert diagnostics["regressions"][0]["domain"] == "ipc"


def test_generic_synthetic_failure_stays_unclassified() -> None:
    earlier = _report()
    later = _report("FAIL")

    result = diagnose_regressions(earlier, later)["regressions"][0]

    assert result["scenario"] == "synthetic-filesystem"
    assert result["domain"] == "UNCLASSIFIED"
    assert result["reason"] == "scenario evidence does not identify a roadmap failure domain"


def test_improvement_does_not_create_a_regression_diagnostic() -> None:
    earlier = _report("FAIL")
    later = _report("PASS")

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["conditions_match"] is True
    assert diagnostics["status"] == "no-regressions"
    assert diagnostics["regressions"] == []


def test_improvement_and_missing_evidence_are_not_regressions() -> None:
    earlier = _report("FAIL")
    later = _report()
    del later["scenarios"]["synthetic-filesystem"]

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["status"] == "no-regressions"
    assert diagnostics["regressions"] == []


def test_identity_mismatch_prevents_diagnosis_even_when_statuses_reverse() -> None:
    earlier = _report()
    later = _report("FAIL", qemu="c" * 64)

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["status"] == "incomparable"
    assert diagnostics["conditions_match"] is False
    assert diagnostics["regressions"] == []
    assert (
        diagnostics["reason"] == "comparison conditions differ; no domain diagnosis was attempted"
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report.update(support_status="verified-emulator"),
        lambda report: report["scenarios"].update(
            {"stock-v257-boot": {"status": "PASS", "evidence": None}}
        ),
        lambda report: report["scenarios"]["synthetic-filesystem"].update(status="UNKNOWN"),
    ],
)
def test_invalid_or_contradictory_inputs_are_rejected(mutate) -> None:
    bad = _report()
    mutate(bad)

    with pytest.raises(CompatibilityComparisonError):
        diagnose_regressions(bad, _report())


def test_untrusted_scenario_name_is_not_echoed_verbatim() -> None:
    earlier = _report()
    later = _report()
    hostile = "private path <script>\u202e"
    earlier["scenarios"][hostile] = {"status": "PASS", "evidence": "receipt"}
    later["scenarios"][hostile] = {"status": "FAIL", "evidence": "receipt"}

    result = diagnose_regressions(earlier, later)["regressions"][0]

    assert result["scenario"] == "unclassified-scenario"
    assert result["scenario_id"]
    assert hostile not in repr(result)


@pytest.mark.parametrize("evidence", [None, "guest failed due to IPC", "private <script>"])
def test_ipc_name_without_fixed_identity_linked_evidence_stays_unclassified(evidence) -> None:
    earlier = _ipc_report("PASS")
    later = _ipc_report("FAIL")
    later["scenarios"]["synthetic-ipc-handoff"]["evidence"] = evidence

    result = diagnose_regressions(earlier, later)["regressions"][0]

    assert result["domain"] == "UNCLASSIFIED"


def test_ipc_name_with_missing_nested_evidence_stays_unclassified() -> None:
    earlier = _ipc_report("PASS")
    later = _ipc_report("FAIL")
    del later["synthetic_ipc_handoff"]

    result = diagnose_regressions(earlier, later)["regressions"][0]

    assert result["domain"] == "UNCLASSIFIED"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report["artifacts"].pop("ipc-handoff-guest"),
        lambda report: report["synthetic_ipc_handoff"]["identities"].pop("guest-elf"),
        lambda report: report["synthetic_ipc_handoff"]["identities"].pop("qemu-mipsel"),
        lambda report: report["synthetic_ipc_handoff"].update(sessions=True),
        lambda report: report["synthetic_ipc_handoff"].update(sessions=[]),
        lambda report: report["synthetic_ipc_handoff"].update(status="PASS"),
    ],
)
def test_missing_or_contradictory_ipc_identity_and_status_stays_unclassified(mutate) -> None:
    earlier = _ipc_report("PASS")
    later = _ipc_report("FAIL")
    mutate(later)
    if "ipc-handoff-guest" not in later["artifacts"]:
        earlier["artifacts"].pop("ipc-handoff-guest")

    diagnostics = diagnose_regressions(earlier, later)

    if diagnostics["conditions_match"]:
        assert diagnostics["regressions"][0]["domain"] == "UNCLASSIFIED"
    else:
        assert diagnostics["regressions"] == []


@pytest.mark.parametrize("side", ["earlier", "later"])
def test_missing_nested_guest_identity_on_either_side_stays_unclassified(side) -> None:
    earlier = _ipc_report("PASS")
    later = _ipc_report("FAIL")
    target = earlier if side == "earlier" else later
    del target["synthetic_ipc_handoff"]["identities"]["guest-elf"]

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["regressions"][0]["domain"] == "UNCLASSIFIED"


def test_absent_guest_identity_on_both_sides_does_not_match_none_to_none() -> None:
    earlier = _ipc_report("PASS")
    later = _ipc_report("FAIL")
    for report in (earlier, later):
        report["artifacts"].pop("ipc-handoff-guest")
        report["synthetic_ipc_handoff"]["identities"].pop("guest-elf")

    diagnostics = diagnose_regressions(earlier, later)

    assert diagnostics["regressions"][0]["domain"] == "UNCLASSIFIED"
