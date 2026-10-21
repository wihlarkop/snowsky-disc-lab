from __future__ import annotations

from copy import deepcopy

import pytest

from snowsky_disc_lab.compat_compare import CompatibilityComparisonError, compare_reports


def _report(*, scenario_status: str = "PASS", qemu: str = "a" * 64) -> dict:
    return {
        "source": "historical.json",
        "receipt_schema": "firmware-free-synthetic-runtime-acceptance/v1",
        "receipt_status": "passed",
        "execution_scope": "firmware-free synthetic execution",
        "support_status": "unknown",
        "artifacts": {"qemu-mipsel": qemu, "guest-elf": "b" * 64},
        "evidence_authentication": {
            "receipt_values": "declared",
            "independent_authentication": "not performed",
            "artifact_bytes_rehashed": False,
        },
        "scenarios": {
            "synthetic-filesystem": {
                "status": scenario_status,
                "evidence": "synthetic runtime receipt",
            },
            "stock-v257-boot": {"status": "NOT RUN", "evidence": None},
        },
    }


def test_same_conditions_are_unchanged_and_history_is_preserved() -> None:
    earlier = _report()
    later = deepcopy(earlier)
    later["source"] = "current.json"

    comparison = compare_reports(earlier, later)

    assert comparison["historical_report"] == earlier
    assert comparison["scenarios"]["synthetic-filesystem"]["classification"] == "unchanged"
    assert comparison["scenarios"]["stock-v257-boot"]["classification"] == "unchanged"
    assert comparison["execution_scope"] == "firmware-free synthetic execution"
    assert comparison["evidence_authentication"]["independent_authentication"] == "not performed"


def test_regression_and_improvement_are_classified() -> None:
    regression = compare_reports(_report(scenario_status="PASS"), _report(scenario_status="FAIL"))
    improvement = compare_reports(_report(scenario_status="FAIL"), _report(scenario_status="PASS"))

    assert regression["scenarios"]["synthetic-filesystem"]["classification"] == "regression"
    assert improvement["scenarios"]["synthetic-filesystem"]["classification"] == "improvement"


def test_mismatched_artifact_identity_makes_scenario_incomparable() -> None:
    comparison = compare_reports(_report(), _report(qemu="c" * 64))

    result = comparison["scenarios"]["synthetic-filesystem"]
    assert result["classification"] == "incomparable"
    assert result["reason"] == "artifact identities differ"


def _build_source(*, commit: str = "c" * 40) -> dict:
    return {
        "repository": "https://github.com/example/qemu.git",
        "commit": commit,
        "projection_digest": "d" * 64,
        "source_lock_changed": False,
        "firmware_tree_fetched": False,
        "reviewed_file_sha256": {"configure": "e" * 64},
        "reviewed_file_bytes": {"configure": 10},
        "build_input_manifest_sha256": "f" * 64,
    }


def test_mismatched_build_source_identity_is_incomparable() -> None:
    earlier = _report()
    later = _report()
    earlier["build_source"] = _build_source()
    later["build_source"] = _build_source(commit="a" * 40)

    comparison = compare_reports(earlier, later)

    assert comparison["conditions_match"] is False
    assert comparison["scenarios"]["synthetic-filesystem"]["classification"] == "incomparable"
    assert (
        comparison["scenarios"]["synthetic-filesystem"]["reason"]
        == "build source identities differ"
    )


def test_build_source_presence_must_match() -> None:
    earlier = _report()
    later = _report()
    later["build_source"] = _build_source()

    comparison = compare_reports(earlier, later)

    assert comparison["conditions_match"] is False
    assert comparison["scenarios"]["synthetic-filesystem"]["classification"] == "incomparable"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda source: source.pop("commit"),
        lambda source: source.update(commit=[]),
        lambda source: source.update(firmware_tree_fetched=True),
        lambda source: source["reviewed_file_bytes"].update(configure=True),
    ],
)
def test_rejects_malformed_build_source(mutate) -> None:
    report = _report()
    report["build_source"] = _build_source()
    mutate(report["build_source"])

    with pytest.raises(CompatibilityComparisonError, match="build source"):
        compare_reports(report, _report())


def test_requires_qemu_artifact_identity() -> None:
    report = _report()
    report["artifacts"] = {"guest-elf": "b" * 64}

    with pytest.raises(CompatibilityComparisonError, match="qemu-mipsel"):
        compare_reports(report, _report())


def test_missing_and_unrecognized_outcomes_never_become_pass() -> None:
    earlier = _report()
    later = _report()
    del later["scenarios"]["synthetic-filesystem"]
    later["scenarios"]["new-scenario"] = {"status": "PASS", "evidence": "x"}

    comparison = compare_reports(earlier, later)

    assert comparison["scenarios"]["synthetic-filesystem"]["after"] == "NOT RUN"
    assert comparison["scenarios"]["synthetic-filesystem"]["classification"] == "incomparable"
    assert comparison["scenarios"]["new-scenario"]["before"] == "NOT RUN"
    assert comparison["scenarios"]["new-scenario"]["classification"] == "incomparable"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {"scenarios": {}},
        {"scenarios": {"x": {"status": "PASS"}}},
        {**_report(), "scenarios": {"x": {"status": []}}},
        {**_report(), "artifacts": {"qemu": "not-a-digest"}},
    ],
)
def test_rejects_malformed_or_incomplete_reports(bad: object) -> None:
    with pytest.raises(CompatibilityComparisonError):
        compare_reports(bad, _report())


def test_rejects_contradictory_stock_firmware_claim() -> None:
    report = _report()
    report["scenarios"]["stock-v257-boot"]["status"] = "PASS"

    with pytest.raises(CompatibilityComparisonError, match="stock firmware"):
        compare_reports(report, _report())
