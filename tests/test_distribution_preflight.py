from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from snowsky_disc_lab.distribution_preflight import assess_distribution_readiness

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def distribution_root(tmp_path: Path) -> Path:
    (tmp_path / "docs").mkdir()
    shutil.copy2(ROOT / "docs" / "license-inventory.json", tmp_path / "docs")
    shutil.copy2(ROOT / "upstreams.lock.yaml", tmp_path / "upstreams.lock.yaml")
    return tmp_path


def _inventory(root: Path) -> dict[str, Any]:
    path = root / "docs" / "license-inventory.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _write_inventory(root: Path, payload: dict[str, Any]) -> None:
    (root / "docs" / "license-inventory.json").write_text(json.dumps(payload), encoding="utf-8")


def test_pinned_inventory_produces_deterministic_conservative_report(
    distribution_root: Path,
) -> None:
    report = assess_distribution_readiness(distribution_root)

    assert report.status == "PENDING_REVIEW"
    assert report == assess_distribution_readiness(distribution_root)
    rendered = report.to_json()
    assert json.loads(rendered)["status"] == "PENDING_REVIEW"
    assert "NOASSERTION" in report.to_markdown()
    assert "firmware" in report.to_markdown().lower()
    assert "file-level" in report.to_markdown().lower()
    assert str(distribution_root) not in rendered + report.to_markdown()


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda value: value.update(formatVersion=2), "BLOCKED"),
        (lambda value: value["sources"].append(value["sources"][0]), "BLOCKED"),
        (lambda value: value["inventoryRows"].append(value["inventoryRows"][0]), "BLOCKED"),
        (lambda value: value["sources"].pop(), "BLOCKED"),
        (lambda value: value["inventoryRows"][0].update(sourceId="missing-source"), "BLOCKED"),
        (lambda value: value["inventoryRows"][0].update(commit="0" * 40), "BLOCKED"),
        (lambda value: value["inventoryRows"][0]["evidence"][0].update(sha256="f" * 64), "BLOCKED"),
        (
            lambda value: value["inventoryRows"][0]["evidence"][0].update(path="../LICENSE"),
            "BLOCKED",
        ),
        (
            lambda value: value["inventoryRows"][0]["evidence"][0].update(path="LICENSE//COPYING"),
            "BLOCKED",
        ),
        (
            lambda value: value["inventoryRows"][0]["evidence"][0].update(path="LICENSE\x1b"),
            "BLOCKED",
        ),
        (
            lambda value: value["inventoryRows"][0]["evidence"][0].update(
                url="https://example.invalid/evidence"
            ),
            "BLOCKED",
        ),
        (lambda value: value["inventoryRows"][0].update(evidence=[]), "BLOCKED"),
        (lambda value: value["inventoryRows"][0].update(reviewStatus="approved"), "BLOCKED"),
        (
            lambda value: value["inventoryRows"][0].update(
                reviewStatus="identified", spdxExpression="NOASSERTION"
            ),
            "BLOCKED",
        ),
    ],
)
def test_malformed_or_contradictory_inventory_fails_closed(
    distribution_root: Path, mutate: Any, expected: str
) -> None:
    payload = _inventory(distribution_root)
    mutate(payload)
    _write_inventory(distribution_root, payload)

    report = assess_distribution_readiness(distribution_root)

    assert report.status == expected
    assert report.findings


def test_non_object_and_wrong_typed_metadata_fail_closed(distribution_root: Path) -> None:
    (distribution_root / "docs" / "license-inventory.json").write_text("[]", encoding="utf-8")

    report = assess_distribution_readiness(distribution_root)

    assert report.status == "BLOCKED"
    assert str(distribution_root) not in report.to_json()


def test_untrusted_component_text_cannot_inject_markdown_or_control_output(
    distribution_root: Path,
) -> None:
    payload = _inventory(distribution_root)
    payload["inventoryRows"][0]["component"] = "`\n# injected\n\x1b[31m"
    payload["inventoryRows"][0]["notes"] = "local path C:\\Users\\secret\x1b[0m"
    _write_inventory(distribution_root, payload)

    report = assess_distribution_readiness(distribution_root)
    output = report.to_json() + report.to_markdown()

    assert report.status == "PENDING_REVIEW"
    assert "# injected" not in output
    assert "secret" not in output
    assert "\x1b" not in output


def test_source_lock_schema_version_mismatch_fails_closed(distribution_root: Path) -> None:
    path = distribution_root / "upstreams.lock.yaml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "apiVersion: lab-upstreams/v1", "apiVersion: lab-upstreams/v2"
        ),
        encoding="utf-8",
    )

    report = assess_distribution_readiness(distribution_root)

    assert report.status == "BLOCKED"
    assert str(distribution_root) not in report.to_json()


def test_duplicate_json_keys_fail_closed(distribution_root: Path) -> None:
    path = distribution_root / "docs" / "license-inventory.json"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            '"formatVersion": 1,', '"formatVersion": 1, "formatVersion": 1,', 1
        ),
        encoding="utf-8",
    )

    report = assess_distribution_readiness(distribution_root)

    assert report.status == "BLOCKED"
    assert str(distribution_root) not in report.to_json()


def test_overdeep_json_fails_closed_without_leaking_input_path(distribution_root: Path) -> None:
    (distribution_root / "docs" / "license-inventory.json").write_text(
        "[" * 2000 + "0" + "]" * 2000, encoding="utf-8"
    )

    report = assess_distribution_readiness(distribution_root)

    assert report.status == "BLOCKED"
    assert str(distribution_root) not in report.to_json()


def test_missing_selected_lock_evidence_fails_closed(distribution_root: Path) -> None:
    payload = _inventory(distribution_root)
    payload["inventoryRows"] = [
        row
        for row in payload["inventoryRows"]
        if not (row["sourceId"] == "diskos" and row["paths"] == ["LICENSE"])
    ]
    _write_inventory(distribution_root, payload)

    report = assess_distribution_readiness(distribution_root)

    assert report.status == "BLOCKED"


@pytest.mark.parametrize("version", [True, 1.0])
def test_non_integer_inventory_schema_version_fails_closed(
    distribution_root: Path, version: Any
) -> None:
    payload = _inventory(distribution_root)
    payload["formatVersion"] = version
    _write_inventory(distribution_root, payload)

    report = assess_distribution_readiness(distribution_root)

    assert report.status == "BLOCKED"


def test_pending_rows_are_reported_by_source_and_index(distribution_root: Path) -> None:
    report = assess_distribution_readiness(distribution_root)
    pending = [finding for finding in report.findings if finding.code == "noassertion_license"]

    assert pending
    assert all("inventory row" in finding.message for finding in pending)
    assert all("NOASSERTION" in finding.message for finding in pending)
