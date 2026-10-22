"""Synthetic regressions for the non-executing M2-03 source-mode boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import validate

from snowsky_disc_lab.source_lock import SourcePin
from snowsky_disc_lab.sources import sync_source
from snowsky_disc_lab.ui_source_mode import (
    SourceModeError,
    SourceModePlan,
    inspect_local_projection,
    inspect_source_mode,
    schema_documents,
    source_mode_plan_sha256,
    validate_build_record,
)

pytest_plugins = ("test_source_manager",)


def _plan(root: Path) -> dict[str, Any]:
    identity = inspect_local_projection(root, ["ui/"])
    return {
        "apiVersion": "lab-ui-source-mode/v1",
        "kind": "UISourceModePlan",
        "source": {
            "mode": "local",
            "sourceId": "synthetic-ui",
            "provenance": {"reference": "review:synthetic-ui", "reviewedOn": "2026-10-22"},
            "projection": ["ui/"],
            "manifestSha256": identity["manifestSha256"],
        },
        "recipe": {
            "recipeId": "synthetic-first-party",
            "revision": "a" * 40,
            "reviewReference": "review:synthetic-recipe",
            "reviewStatus": "reviewed",
        },
        "inputs": [{"name": "compiler", "version": "synthetic-1", "sha256": "c" * 64}],
        "output": {"path": "out/ui.elf", "sha256": "b" * 64},
    }


def _source(root: Path) -> Path:
    source = root / "source"
    (source / "ui").mkdir(parents=True)
    (source / "ui" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return source


def test_local_projection_identity_is_inspected_and_execution_stays_not_run(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)

    report = inspect_source_mode(plan, local_root=source)

    assert report["status"] == "VALIDATED"
    assert report["source"]["status"] == "INSPECTED"
    assert report["source"]["manifestSha256"] == plan["source"]["manifestSha256"]
    assert report["evidence"] == {
        "sourceBytes": "INSPECTED",
        "gitCommitBinding": "NOT APPLICABLE",
        "authentication": "NOT RUN",
        "buildExecution": "NOT RUN",
        "reproducibility": "NOT MEASURED",
        "launchAuthorized": False,
    }
    assert report["output"]["preflightStatus"] == "NOT RUN"
    validate(report, schema_documents()["lab-ui-source-mode-report-v1.schema.json"])


def test_changed_or_missing_projected_bytes_refuse_the_declared_identity(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    (source / "ui" / "main.c").write_text("changed\n", encoding="utf-8")

    with pytest.raises(SourceModeError, match="manifest identity"):
        inspect_source_mode(plan, local_root=source)

    exact = inspect_local_projection(source, ["ui/main.c"])
    (source / "ui" / "main.c").unlink()
    plan["source"]["projection"] = ["ui/main.c"]
    plan["source"]["manifestSha256"] = exact["manifestSha256"]
    with pytest.raises(SourceModeError, match="missing"):
        inspect_source_mode(plan, local_root=source)


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "git", "repository": "http://github.com/owner/repo.git", "commit": "a" * 40},
        {
            "mode": "git",
            "repository": "https://user:secret@github.com/owner/repo.git",
            "commit": "a" * 40,
        },
        {"mode": "git", "repository": "file:///tmp/repo.git", "commit": "a" * 40},
        {"mode": "git", "repository": "https://github.com/owner/repo.git", "commit": "A" * 40},
        {"mode": "local", "projection": ["ui/../secret"], "sourceId": "synthetic-ui"},
    ],
)
def test_unsafe_source_identities_and_paths_are_rejected(
    tmp_path: Path, change: dict[str, object]
) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    if change["mode"] == "git":
        plan["source"] = {
            **change,
            "provenance": {"reference": "tag:v1", "reviewedOn": "2026-10-22"},
            "sourceId": "synthetic-ui",
            "manifestSha256": "d" * 64,
        }
    else:
        plan["source"].update(change)

    with pytest.raises(SourceModeError):
        inspect_source_mode(plan, local_root=source)


def test_unreviewed_recipe_and_unsupported_version_are_refused(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    plan["recipe"]["reviewStatus"] = "unreviewed"
    with pytest.raises(SourceModeError, match="explicitly reviewed"):
        inspect_source_mode(plan, local_root=source)

    plan = _plan(source)
    plan["apiVersion"] = "lab-ui-source-mode/v2"
    with pytest.raises(SourceModeError, match="apiVersion"):
        inspect_source_mode(plan, local_root=source)

    valid_model = SourceModePlan.model_validate(_plan(source))
    bypassed = valid_model.model_copy(
        update={"recipe": valid_model.recipe.model_copy(update={"review_status": "unreviewed"})}
    )
    with pytest.raises(SourceModeError, match="reviewed"):
        inspect_source_mode(bypassed, local_root=source)


def test_build_record_cannot_promote_execution_reproducibility_or_launch(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    record = {
        "apiVersion": "lab-ui-build-record/v1",
        "kind": "UIBuildRecord",
        "planSha256": source_mode_plan_sha256(plan),
        "sourceManifestSha256": plan["source"]["manifestSha256"],
        "recipeRevision": plan["recipe"]["revision"],
        "outputSha256": plan["output"]["sha256"],
        "execution": "NOT RUN",
        "reproducibility": "NOT MEASURED",
        "authentication": "NOT RUN",
        "launchAuthorized": False,
    }
    assert validate_build_record(record, plan)["execution"] == "NOT RUN"
    for changed_plan in (
        {**plan, "recipe": {**plan["recipe"], "recipeId": "other-recipe"}},
        {**plan, "output": {**plan["output"], "path": "out/other.elf"}},
        {
            **plan,
            "inputs": [{"name": "compiler", "version": "other", "sha256": "d" * 64}],
        },
        {
            **plan,
            "source": {
                **plan["source"],
                "provenance": {"reference": "review:other-source", "reviewedOn": "2026-10-22"},
            },
        },
    ):
        with pytest.raises(SourceModeError, match="plan identity"):
            validate_build_record(record, changed_plan)
    record["execution"] = "SUCCESS"
    with pytest.raises(SourceModeError, match="execution"):
        validate_build_record(record, plan)


@pytest.mark.parametrize("value", [0, 1, True, "false"])
def test_build_record_requires_exact_false_boolean_authority(tmp_path: Path, value: object) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    record = {
        "apiVersion": "lab-ui-build-record/v1",
        "kind": "UIBuildRecord",
        "planSha256": source_mode_plan_sha256(plan),
        "sourceManifestSha256": plan["source"]["manifestSha256"],
        "recipeRevision": plan["recipe"]["revision"],
        "outputSha256": plan["output"]["sha256"],
        "execution": "NOT RUN",
        "reproducibility": "NOT MEASURED",
        "authentication": "NOT RUN",
        "launchAuthorized": value,
    }
    with pytest.raises(SourceModeError, match="contract"):
        validate_build_record(record, plan)


def test_output_elf_reuses_binary_preflight_and_binds_digest(tmp_path: Path) -> None:
    from test_elf_inspection import _elf32_mips

    source = _source(tmp_path)
    plan = _plan(source)
    raw = _elf32_mips(fp_abi=3, load=b"synthetic")
    digest = hashlib.sha256(raw).hexdigest()
    plan["output"]["sha256"] = digest
    build = tmp_path / "build"
    (build / "out").mkdir(parents=True)
    (build / "out" / "ui.elf").write_bytes(raw)

    report = inspect_source_mode(plan, local_root=source, build_root=build)
    assert report["output"]["inspectedSha256"] == digest
    assert report["output"]["preflightStatus"] == "UNKNOWN"
    assert report["output"]["launchAuthorized"] is False

    (build / "out" / "ui.elf").write_bytes(raw + b"changed")
    with pytest.raises(SourceModeError, match="digest"):
        inspect_source_mode(plan, local_root=source, build_root=build)


def test_schema_files_match_models_and_plan_schema_rejects_extra_fields(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    plan["unexpected"] = True
    with pytest.raises(SourceModeError):
        inspect_source_mode(plan, local_root=source)

    for filename, schema in schema_documents().items():
        checked_in = json.loads(
            (Path(__file__).parents[1] / "schemas" / filename).read_text(encoding="utf-8")
        )
        assert checked_in == schema


def test_projected_directory_symlinks_are_refused(tmp_path: Path) -> None:
    source = _source(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    try:
        os.symlink(external, source / "ui" / "linked", target_is_directory=True)
    except OSError:
        pytest.skip("This Windows environment does not permit symlink creation.")

    with pytest.raises(SourceModeError, match="unsafe directory|symlink"):
        inspect_local_projection(source, ["ui/"])


def test_invalid_calendar_date_is_rejected(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    plan["source"]["provenance"]["reviewedOn"] = "2026-99-99"
    with pytest.raises(SourceModeError):
        inspect_source_mode(plan, local_root=source)


def _git_plan(root: Path, pin: SourcePin) -> dict[str, Any]:
    projection = inspect_local_projection(root, pin.include_paths)
    return {
        "apiVersion": "lab-ui-source-mode/v1",
        "kind": "UISourceModePlan",
        "source": {
            "mode": "git",
            "sourceId": pin.id,
            "repository": pin.repository,
            "commit": pin.commit,
            "provenance": {
                "reference": pin.provenance.reference,
                "reviewedOn": pin.provenance.reviewed_on,
            },
            "manifestSha256": projection["manifestSha256"],
        },
        "recipe": {
            "recipeId": "synthetic-first-party",
            "revision": "a" * 40,
            "reviewReference": "review:synthetic-recipe",
            "reviewStatus": "reviewed",
        },
        "inputs": [{"name": "compiler", "version": "synthetic-1", "sha256": "c" * 64}],
        "output": {"path": "out/ui.elf", "sha256": "b" * 64},
    }


def _write_source_lock(path: Path, pin: SourcePin) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "lab-upstreams/v1",
                "kind": "SourceLock",
                "sources": [pin.model_dump(by_alias=True, mode="json")],
            }
        ),
        encoding="utf-8",
    )


def test_pinned_git_mode_reuses_verified_source_cache(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_source_manager import _install_local_fetch

    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cache_root = tmp_path / "cache"
    cached = sync_source(pin, cache_root)
    lock_path = tmp_path / "lock.yaml"
    _write_source_lock(lock_path, pin)

    report = inspect_source_mode(_git_plan(cached, pin), lock_path=lock_path, cache_root=cache_root)

    assert report["source"]["mode"] == "git"
    assert report["source"]["status"] == "VERIFIED_CACHE"
    assert report["source"]["commit"] == pin.commit
    assert report["evidence"]["gitCommitBinding"] == "VERIFIED"


@pytest.mark.parametrize("field", ["repository", "commit", "provenance"])
def test_git_mode_requires_exact_lock_identity(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    from test_source_manager import _install_local_fetch

    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cache_root = tmp_path / "cache"
    cached = sync_source(pin, cache_root)
    lock_path = tmp_path / "lock.yaml"
    _write_source_lock(lock_path, pin)
    plan = _git_plan(cached, pin)
    if field == "repository":
        plan["source"]["repository"] = "https://github.com/example/other.git"
    elif field == "commit":
        plan["source"]["commit"] = "b" * 40
    else:
        plan["source"]["provenance"]["reference"] = "tag:other"

    with pytest.raises(SourceModeError, match="differs"):
        inspect_source_mode(plan, lock_path=lock_path, cache_root=cache_root)


def test_git_mode_refuses_corrupted_verified_cache(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_source_manager import _install_local_fetch

    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cache_root = tmp_path / "cache"
    cached = sync_source(pin, cache_root)
    lock_path = tmp_path / "lock.yaml"
    _write_source_lock(lock_path, pin)
    plan = _git_plan(cached, pin)
    changed = cached / "ui" / "main.c"
    changed.chmod(changed.stat().st_mode | 0o200)
    changed.write_text("changed synthetic source\n", encoding="utf-8")

    with pytest.raises(SourceModeError, match="offline verification"):
        inspect_source_mode(plan, lock_path=lock_path, cache_root=cache_root)


def test_intermediate_symlink_is_refused_for_source_and_output(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "outside"
    (outside / "ui").mkdir(parents=True)
    (outside / "ui" / "main.c").write_text("outside\n", encoding="utf-8")
    try:
        os.symlink(outside, source / "redirect", target_is_directory=True)
    except OSError:
        pytest.skip("This Windows environment does not permit symlink creation.")

    plan = _plan(source)
    plan["source"]["projection"] = ["redirect/ui/"]
    with pytest.raises(SourceModeError, match="symlink"):
        inspect_source_mode(plan, local_root=source)

    plan = _plan(source)
    build = tmp_path / "build"
    build.mkdir()
    os.symlink(outside, build / "out", target_is_directory=True)
    with pytest.raises(SourceModeError, match="symlink"):
        inspect_source_mode(plan, local_root=source, build_root=build)


def test_projection_limits_and_portable_names_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import snowsky_disc_lab.ui_source_mode as source_mode

    source = _source(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(source_mode, "_MAX_FILE_BYTES", 1)
        with pytest.raises(SourceModeError, match="per-file"):
            inspect_local_projection(source, ["ui/"])
    plan = _plan(source)
    plan["output"]["path"] = "out/NUL.txt"
    with pytest.raises(SourceModeError):
        inspect_source_mode(plan, local_root=source)


def test_file_count_limit_and_hardlinks_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import snowsky_disc_lab.ui_source_mode as source_mode

    source = _source(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(source_mode, "_MAX_FILES", 0)
        with pytest.raises(SourceModeError, match="file-count"):
            inspect_local_projection(source, ["ui/"])

    try:
        os.link(source / "ui" / "main.c", source / "ui" / "copy.c")
    except OSError:
        pytest.skip("This Windows environment does not permit hard-link creation.")
    with pytest.raises(SourceModeError, match="link"):
        inspect_local_projection(source, ["ui/"])


def test_untrusted_extra_field_name_is_not_echoed(tmp_path: Path) -> None:
    source = _source(tmp_path)
    plan = _plan(source)
    secret_name = "private-token-should-not-appear"
    plan[secret_name] = "value"

    with pytest.raises(SourceModeError) as error:
        inspect_source_mode(plan, local_root=source)
    assert secret_name not in str(error.value)
