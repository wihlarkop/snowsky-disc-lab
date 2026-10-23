"""Synthetic, firmware-free checks for private firmware workspaces."""

from __future__ import annotations

import hashlib
import json
import runpy
import threading
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


def _workspace(manager: FirmwareWorkspaceManager, candidate: Path) -> Any:
    receipt = manager.create(candidate)
    assert receipt.operation_status == "accepted", receipt.model_dump_json()
    assert receipt.state == "finalized"
    return receipt


def _workspace_path(manager: FirmwareWorkspaceManager, receipt: Any) -> Path:
    return manager.root / "workspaces" / str(receipt.firmware_id) / str(receipt.workspace_id)


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


@pytest.mark.parametrize("field", ["status", "code"])
def test_workspace_receipt_rejects_changed_authenticity_condition(
    tmp_path: Path, field: str
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    receipt = manager.stage(candidate)
    assert receipt.operation_status == "accepted"
    payload = json.loads(receipt.model_dump_json())
    condition = next(
        item for item in payload["conditions"] if item["check"] == "vendor_authenticity"
    )
    condition[field] = "verified" if field == "status" else "invented_trust_code"

    with pytest.raises(ValueError, match="fixed trust gates"):
        firmware_workspace.WorkspaceReceipt.model_validate_json(json.dumps(payload))


def test_finalize_refuses_a_semantically_valid_but_rebound_intake_receipt(
    tmp_path: Path,
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    staged = manager.stage(candidate)
    assert staged.operation_status == "accepted"
    workspace = manager.root / "staging" / str(staged.workspace_id)
    receipt_path = workspace / "workspace.json"
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["intake"]["metadata_hashes"]["ota_config"] = "0" * 64
    canonical_intake = json.dumps(
        payload["intake"], ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    payload["intake_receipt_sha256"] = hashlib.sha256(canonical_intake).hexdigest()
    receipt_path.chmod(0o600)
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")

    result = manager.finalize(staged.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "quarantined"
    assert any(condition.code == "workspace_snapshot_mismatch" for condition in result.conditions)
    assert (manager.root / "quarantine" / str(staged.workspace_id)).is_dir()


def test_workspace_loader_refuses_duplicate_json_receipt_keys(tmp_path: Path) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    staged = manager.stage(candidate)
    workspace = manager.root / "staging" / str(staged.workspace_id)
    receipt_path = workspace / "workspace.json"
    raw = receipt_path.read_text(encoding="utf-8")
    raw = raw.replace(
        '"operation_status": "accepted"',
        '"operation_status": "accepted", "operation_status": "refused"',
        1,
    )
    receipt_path.chmod(0o600)
    receipt_path.write_text(raw, encoding="utf-8")

    result = manager.finalize(staged.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "quarantined"
    assert any(condition.code == "workspace_receipt_invalid" for condition in result.conditions)


def test_workspace_loader_refuses_deeply_nested_receipt_json(tmp_path: Path) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    staged = manager.stage(candidate)
    workspace = manager.root / "staging" / str(staged.workspace_id)
    receipt_path = workspace / "workspace.json"
    receipt_path.chmod(0o600)
    receipt_path.write_text('{"payload":' + "[" * 1100 + "0" + "]" * 1100 + "}")

    result = manager.finalize(staged.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "quarantined"
    assert any(condition.code == "workspace_receipt_invalid" for condition in result.conditions)


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


def test_synthetic_extraction_is_bound_to_known_fixture_and_publishes_deterministic_outputs(
    tmp_path: Path,
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    before = sorted(
        (path.relative_to(candidate).as_posix(), path.read_bytes())
        for path in candidate.rglob("*")
        if path.is_file()
    )
    workspace = _workspace(manager, candidate)
    session_path = _workspace_path(manager, workspace)

    result = manager.extract_synthetic(workspace.workspace_id or "")

    assert result.operation_status == "accepted", result.model_dump_json()
    assert result.state == "published"
    assert result.workspace_id == workspace.workspace_id
    assert result.firmware_id == workspace.firmware_id
    assert result.input_digest == "21ae742cbc9cf0e191b818e9558109360f9aa4a3fdea1a16bb4ebe5f0c05644b"
    assert result.operation == "synthetic_fixture_materialization_v1"
    assert result.operation_id is not None
    assert result.output_file_count == len(result.output_manifest) == 2
    assert result.output_bytes == sum(item.size for item in result.output_manifest)
    assert result.session_bytes_before is not None
    assert result.session_bytes_after is not None
    assert result.store_bytes_before is not None
    assert result.store_bytes_after is not None
    assert result.session_bytes_after > result.session_bytes_before
    assert result.store_bytes_after > result.store_bytes_before
    measured_session_entries, measured_session_bytes = manager._measure_workspace(session_path)
    _measured_sessions, measured_store_entries, measured_store_bytes = (
        firmware_workspace._measure_store(
            manager.root,
            deadline=firmware_workspace.time.monotonic() + firmware_workspace.MAX_IO_SECONDS,
        )
    )
    assert result.session_bytes_after == measured_session_bytes
    assert result.store_bytes_after == measured_store_bytes
    assert result.session_entries_after == measured_session_entries
    assert result.store_entries_after == measured_store_entries
    assert result.may_proceed is False
    assert result.extraction_authorized is False
    assert result.execution_authorized is False
    assert result.compatibility == "unverified"
    assert result.vendor_authenticity == "unverified"
    assert _conditions(result)["synthetic_fixture_identity"] == "verified"
    assert _conditions(result)["output_integrity"] == "verified"
    assert _conditions(result)["output_publication"] == "verified"

    output_root = session_path / "extraction" / "synthetic-v1" / "outputs"
    actual = {
        path.relative_to(output_root).as_posix(): path.read_bytes()
        for path in output_root.iterdir()
        if path.is_file()
    }
    assert set(actual) == {item.path for item in result.output_manifest}
    assert all(
        item.sha256 == hashlib.sha256(actual[item.path]).hexdigest()
        for item in result.output_manifest
    )
    assert (
        sorted(
            (path.relative_to(candidate).as_posix(), path.read_bytes())
            for path in candidate.rglob("*")
            if path.is_file()
        )
        == before
    )
    persisted = json.loads(
        (session_path / "extraction" / "synthetic-v1" / "operation.json").read_text(
            encoding="utf-8"
        )
    )
    assert persisted == result.model_dump(mode="json")
    assert str(candidate) not in json.dumps(persisted)
    assert "synthetic-package" not in json.dumps(persisted)

    verified = manager.verify_synthetic_extraction(workspace.workspace_id or "")
    assert verified.operation_status == "accepted"
    assert verified.state == "published"
    assert _conditions(verified)["output_integrity"] == "verified"

    second_workspace = _workspace(manager, _package(tmp_path / "synthetic-package-again"))
    second_result = manager.extract_synthetic(second_workspace.workspace_id or "")
    assert second_result.operation_status == "accepted"
    assert second_result.output_manifest == result.output_manifest


def test_synthetic_harness_refuses_a_structurally_valid_unpinned_package(
    tmp_path: Path,
) -> None:
    candidate = _package(tmp_path / "alternate-synthetic-package")
    chunk = next((candidate / "main_os" / "ota_v257").glob("*.enc"))
    replacement = b"a different first-party synthetic chunk\n"
    chunk.write_bytes(replacement)
    manifest = chunk.parent / "manifest.sha256"
    lines = manifest.read_text(encoding="utf-8").splitlines()
    record_name = chunk.name
    lines = [
        f"SHA256(ota/{record_name})= {hashlib.sha256(replacement).hexdigest()}"
        if line.startswith(f"SHA256(ota/{record_name})=")
        else line
        for line in lines
    ]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    session_path = _workspace_path(manager, workspace)

    result = manager.extract_synthetic(workspace.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "refused"
    assert result.input_digest == workspace.input_digest
    assert result.failure_code == "synthetic_fixture_identity_mismatch"
    assert _conditions(result)["synthetic_fixture_identity"] == "rejected"
    assert list((session_path / "extraction").iterdir()) == []


def test_synthetic_extraction_rejects_repeated_publication_without_replacement(
    tmp_path: Path,
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    output_root = _workspace_path(manager, workspace) / "extraction" / "synthetic-v1"

    first = manager.extract_synthetic(workspace.workspace_id or "")
    before = sorted(
        (path.relative_to(output_root).as_posix(), path.read_bytes())
        for path in output_root.rglob("*")
        if path.is_file()
    )
    second = manager.extract_synthetic(workspace.workspace_id or "")

    assert first.operation_status == "accepted"
    assert second.operation_status == "refused"
    assert second.failure_code == "synthetic_output_already_exists"
    assert (
        sorted(
            (path.relative_to(output_root).as_posix(), path.read_bytes())
            for path in output_root.rglob("*")
            if path.is_file()
        )
        == before
    )


@pytest.mark.parametrize("damage", ["corrupt", "missing"])
def test_synthetic_output_verification_refuses_corruption_and_missing_files(
    tmp_path: Path, damage: str
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    published = manager.extract_synthetic(workspace.workspace_id or "")
    assert published.operation_status == "accepted"
    output_root = _workspace_path(manager, workspace) / "extraction" / "synthetic-v1" / "outputs"
    target = output_root / published.output_manifest[0].path
    target.chmod(0o600)
    if damage == "corrupt":
        target.write_bytes(b"changed after publication")
    else:
        target.unlink()

    verified = manager.verify_synthetic_extraction(workspace.workspace_id or "")

    assert verified.operation_status == "refused"
    assert verified.state == "published"
    assert verified.failure_code in {"synthetic_output_digest_mismatch", "synthetic_output_missing"}
    assert verified.operation_id == published.operation_id
    assert verified.expected_output_manifest == published.expected_output_manifest
    assert _conditions(verified)["output_integrity"] == "rejected"
    assert verified.extraction_authorized is False
    assert verified.execution_authorized is False


def test_invalid_synthetic_output_path_is_refused_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    session_path = _workspace_path(manager, workspace)
    monkeypatch.setattr(
        firmware_workspace,
        "_SYNTHETIC_OUTPUT_PATHS",
        ("../outside.bin",),
    )

    result = manager.extract_synthetic(workspace.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.failure_code == "unsafe_synthetic_output_path"
    assert _conditions(result)["output_path_safety"] == "rejected"
    assert result.session_bytes_before == result.session_bytes_after
    assert result.store_bytes_before == result.store_bytes_after
    assert list((session_path / "extraction").iterdir()) == []
    assert not (session_path.parent.parent.parent / "outside.bin").exists()


def test_partial_interrupted_synthetic_output_is_retained_as_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    original_write = firmware_workspace._write_synthetic_output
    calls = 0

    def write_one_then_interrupt(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        return original_write(*args, **kwargs)

    monkeypatch.setattr(firmware_workspace, "_write_synthetic_output", write_one_then_interrupt)

    result = manager.extract_synthetic(workspace.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "incomplete"
    assert result.failure_code == "operation_interrupted"
    assert result.operation_id is not None
    incomplete = (
        _workspace_path(manager, workspace) / "extraction" / f"incomplete-{result.operation_id}"
    )
    assert incomplete.is_dir()
    assert json.loads((incomplete / "operation.json").read_text(encoding="utf-8"))["state"] == (
        "incomplete"
    )
    assert list((incomplete / "outputs").iterdir())
    assert manager.extract_synthetic(workspace.workspace_id or "").failure_code == (
        "synthetic_output_incomplete_exists"
    )
    observed_incomplete = manager.verify_synthetic_extraction(workspace.workspace_id or "")
    assert observed_incomplete.operation_status == "refused"
    assert observed_incomplete.state == "incomplete"
    assert observed_incomplete.operation_id == result.operation_id


def test_partial_file_write_is_hashed_and_retained_as_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    partial_bytes = b'{"api_versio'

    def write_partial(
        output_root: Path,
        relative: str,
        content: bytes,
        *,
        expected_device: int,
    ) -> Any:
        target = output_root / relative
        target.write_bytes(partial_bytes)
        raise firmware_workspace.WorkspaceError("synthetic_output_write_failed")

    monkeypatch.setattr(firmware_workspace, "_write_synthetic_output", write_partial)

    result = manager.extract_synthetic(workspace.workspace_id or "")

    assert result.operation_status == "refused"
    assert result.state == "incomplete"
    assert result.failure_code == "synthetic_output_write_failed"
    assert result.output_file_count == 1
    assert result.output_bytes == 12
    assert result.output_manifest[0].size == 12
    assert result.output_manifest[0].sha256 == hashlib.sha256(partial_bytes).hexdigest()
    incomplete = (
        _workspace_path(manager, workspace) / "extraction" / f"incomplete-{result.operation_id}"
    )
    assert (incomplete / "outputs" / result.output_manifest[0].path).read_bytes() == (partial_bytes)


def test_synthetic_extraction_respects_workspace_and_store_quotas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    session_path = _workspace_path(manager, workspace)
    existing_bytes, _existing_entries = manager._measure_workspace(session_path)
    monkeypatch.setattr(firmware_workspace, "MAX_SESSION_BYTES", existing_bytes + 1)

    session_limited = manager.extract_synthetic(workspace.workspace_id or "")

    assert session_limited.operation_status == "refused"
    assert session_limited.failure_code == "workspace_quota_exceeded"
    assert _conditions(session_limited)["workspace_quota"] == "rejected"
    assert list((session_path / "extraction").iterdir()) == []

    monkeypatch.setattr(firmware_workspace, "MAX_SESSION_BYTES", 4 * 1024**3)
    monkeypatch.setattr(firmware_workspace, "MAX_STORE_BYTES", 1)
    store_limited = manager.extract_synthetic(workspace.workspace_id or "")
    assert store_limited.operation_status == "refused"
    assert store_limited.failure_code == "workspace_store_quota_exceeded"
    assert list((session_path / "extraction").iterdir()) == []


def test_synthetic_output_operation_refuses_concurrent_store_mutation(
    tmp_path: Path,
) -> None:
    candidate = _package(tmp_path / "synthetic-package")
    manager = FirmwareWorkspaceManager(tmp_path / "private-store")
    workspace = _workspace(manager, candidate)
    session_path = _workspace_path(manager, workspace)
    result: list[Any] = []

    def run_operation() -> None:
        result.append(manager.extract_synthetic(workspace.workspace_id or ""))

    with firmware_workspace._store_lock(manager.root):
        worker = threading.Thread(target=run_operation)
        worker.start()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert result[0].operation_status == "refused"
    assert result[0].failure_code == "workspace_busy"
    assert list((session_path / "extraction").iterdir()) == []


def test_synthetic_extraction_receipt_schema_is_generated_from_its_strict_model() -> None:
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "lab-firmware-synthetic-extraction-v1.schema.json"
    )
    published = json.loads(schema_path.read_text(encoding="utf-8"))

    assert firmware_workspace.SyntheticExtractionReceipt.model_json_schema() == published
