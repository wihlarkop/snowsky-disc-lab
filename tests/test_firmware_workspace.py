"""Synthetic, firmware-free checks for private firmware workspaces."""

from __future__ import annotations

import json
import runpy
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from snowsky_disc_lab import firmware_workspace
from snowsky_disc_lab.cli import app
from snowsky_disc_lab.firmware_workspace import FirmwareWorkspaceManager

runner = CliRunner()
_helpers = runpy.run_path(str(Path(__file__).with_name("test_firmware_intake.py")))


def _package(path: Path) -> Path:
    package, _ = _helpers["_make_package"](path)
    return package


def _conditions(receipt: Any) -> dict[str, str]:
    return {item.check: item.status for item in receipt.conditions}


def test_prepare_snapshots_and_revalidates_synthetic_directory_without_authority(
    tmp_path: Path,
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    original_manifest = (candidate / "main_os" / "ota_v257" / "manifest.sha256").read_bytes()
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")

    receipt = manager.create(candidate)

    assert receipt.operation_status == "accepted", receipt.model_dump_json()
    assert receipt.state == "finalized"
    assert receipt.snapshot_files == 79
    assert receipt.snapshot_bytes > 0
    assert receipt.may_proceed is False
    assert receipt.extraction_authorized is False
    assert receipt.execution_authorized is False
    assert receipt.compatibility == "unverified"
    assert receipt.vendor_authenticity == "unverified"
    assert _conditions(receipt)["input_snapshot"] == "verified"
    assert (candidate / "main_os" / "ota_v257" / "manifest.sha256").read_bytes() == (
        original_manifest
    )

    verified = manager.verify(receipt.workspace_id or "")
    assert verified.operation_status == "accepted"
    assert verified.state == "finalized"
    assert verified.input_digest == receipt.input_digest
    assert verified.extraction_authorized is False

    sessions = manager.list()
    assert [item.workspace_id for item in sessions] == [receipt.workspace_id]
    serialized = receipt.model_dump_json()
    assert str(candidate) not in serialized
    assert "synthetic-package" not in serialized
    session_path = (
        manager.root / "workspaces" / str(receipt.firmware_id) / str(receipt.workspace_id)
    )
    assert session_path.is_dir()


def test_prepare_zip_retains_original_archive_bytes_without_extracting(tmp_path: Path) -> None:
    package = _package(tmp_path / "synthetic-package")
    archive = _helpers["_zip_package"](package, tmp_path / "synthetic.zip")
    original = archive.read_bytes()
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")

    receipt = manager.create(archive)

    assert receipt.operation_status == "accepted"
    assert receipt.input_format == "zip"
    assert receipt.snapshot_files == 1
    snapshot = manager.root / "workspaces" / str(receipt.firmware_id) / str(receipt.workspace_id)
    assert (snapshot / "inputs" / "original.zip").read_bytes() == original
    assert not (snapshot / "inputs" / "package").exists()
    assert archive.read_bytes() == original


def test_snapshot_mismatch_is_quarantined_and_retained(tmp_path: Path) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    staged = manager.stage(candidate)
    assert staged.state == "staging"
    session = manager.root / "staging" / str(staged.workspace_id)
    chunk = next((session / "inputs" / "package").rglob("*.enc"))
    chunk.chmod(0o600)
    chunk.write_bytes(b"changed synthetic bytes")

    result = manager.finalize(staged.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "quarantined"
    quarantined = manager.root / "quarantine" / str(staged.workspace_id)
    assert quarantined.is_dir()
    assert next((quarantined / "inputs" / "package").rglob("*.enc")).read_bytes() == (
        b"changed synthetic bytes"
    )
    assert manager.list()[0].state == "quarantined"


def test_cleanup_refuses_to_remove_retained_input_or_finalized_workspace(tmp_path: Path) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    staged = manager.stage(candidate)
    staging_input = manager.root / "staging" / str(staged.workspace_id) / "inputs" / "package"
    before = sorted(path.relative_to(staging_input).as_posix() for path in staging_input.rglob("*"))

    refused = manager.cleanup(staged.workspace_id or "")

    after = sorted(path.relative_to(staging_input).as_posix() for path in staging_input.rglob("*"))
    assert refused.operation_status == "refused"
    assert before == after
    assert manager.finalize(staged.workspace_id or "").state == "finalized"
    completed_cleanup = manager.cleanup(staged.workspace_id or "")
    assert completed_cleanup.operation_status == "refused"
    completed = manager.root / "workspaces" / str(staged.firmware_id) / str(staged.workspace_id)
    assert completed.exists()


def test_refused_candidate_does_not_create_workspace_or_touch_input(tmp_path: Path) -> None:
    candidate = tmp_path / "not-a-package"
    candidate.write_text("synthetic", encoding="utf-8")
    before = candidate.read_bytes()
    root = tmp_path / "private-store"

    receipt = FirmwareWorkspaceManager(root).stage(candidate)

    assert receipt.operation_status == "refused"
    assert receipt.state == "none"
    assert _conditions(receipt)["workspace"] == "rejected"
    assert _conditions(receipt)["workspace_ownership"] == "unverified"
    assert _conditions(receipt)["workspace_quota"] == "unverified"
    assert candidate.read_bytes() == before
    assert not root.exists()


def test_interrupted_quarantine_repairs_receipt_after_atomic_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    staged = manager.stage(candidate)
    original_publish = firmware_workspace._publish_no_replace

    def publish_then_interrupt(source: Path, target: Path) -> None:
        original_publish(source, target)
        raise KeyboardInterrupt

    monkeypatch.setattr(firmware_workspace, "_publish_no_replace", publish_then_interrupt)

    recovered = manager.quarantine(staged.workspace_id or "")

    assert recovered.operation_status == "refused"
    assert recovered.state == "quarantined"
    assert _conditions(recovered)["workspace_ownership"] == "verified"
    assert _conditions(recovered)["workspace_quota"] == "unverified"
    quarantined = manager.root / "quarantine" / str(staged.workspace_id)
    persisted = json.loads((quarantined / "workspace.json").read_text(encoding="utf-8"))
    assert persisted["state"] == "quarantined"
    assert manager.list()[0].state == "quarantined"


def test_quota_refusal_is_explicit_and_does_not_allocate_a_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    monkeypatch.setattr(firmware_workspace, "MAX_STORE_SESSIONS", 0)

    receipt = manager.stage(candidate)

    assert receipt.operation_status == "refused"
    assert any(condition.code == "workspace_session_limit" for condition in receipt.conditions)
    assert list((manager.root / "staging").iterdir()) == []


def test_store_entry_reservation_refuses_before_allocating_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    monkeypatch.setattr(firmware_workspace, "MAX_STORE_ENTRIES", 1)

    receipt = manager.stage(candidate)

    assert receipt.operation_status == "refused"
    assert any(condition.code == "workspace_store_entry_limit" for condition in receipt.conditions)
    assert list((manager.root / "staging").iterdir()) == []


def test_workspace_cli_json_is_pathless_and_keeps_authority_false(tmp_path: Path) -> None:
    candidate = _package(tmp_path / "synthetic-private-candidate")
    result = runner.invoke(
        app,
        [
            "firmware",
            "workspace",
            "prepare",
            str(candidate),
            "--workspace-root",
            str(tmp_path / "private-store"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout)
    assert receipt["api_version"] == "lab-firmware-workspace/v1"
    assert receipt["operation_status"] == "accepted"
    assert receipt["state"] == "finalized"
    assert receipt["may_proceed"] is False
    assert receipt["extraction_authorized"] is False
    assert receipt["execution_authorized"] is False
    assert receipt["compatibility"] == "unverified"
    assert receipt["vendor_authenticity"] == "unverified"
    assert str(candidate) not in result.stdout
    assert "synthetic-private-candidate" not in result.stdout


def test_invalid_session_id_never_echoes_or_accepts_arbitrary_path(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "firmware",
            "workspace",
            "verify",
            "..",
            "--workspace-root",
            str(tmp_path / "private-store"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert ".." not in result.stdout
    receipt = json.loads(result.stdout)
    assert receipt["operation_status"] == "refused"
    assert receipt["workspace_id"] is None


def test_workspace_receipt_schema_is_generated_from_its_strict_model() -> None:
    schema_path = (
        Path(__file__).resolve().parents[1] / "schemas" / "lab-firmware-workspace-v1.schema.json"
    )
    published = json.loads(schema_path.read_text(encoding="utf-8"))

    assert firmware_workspace.WorkspaceReceipt.model_json_schema() == published
