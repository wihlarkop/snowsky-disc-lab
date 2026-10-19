"""Public lock validation and CLI contracts; no upstream network access."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import validate
from pydantic import ValidationError
from typer.testing import CliRunner

from snowsky_disc_lab.source_lock import SourceLock, SourcePin, load_source_lock

ROOT = Path(__file__).resolve().parents[1]


def pin_data() -> dict[str, Any]:
    return {
        "id": "synthetic",
        "repository": "https://github.com/example/source.git",
        "commit": "a" * 40,
        "includePaths": ["LICENSE", "src/"],
        "licenses": [{"path": "LICENSE", "sha256": "b" * 64, "spdx": "MIT", "scope": "source"}],
        "provenance": {
            "reference": "v1.0",
            "url": "https://github.com/example/source/commit/" + "a" * 40,
            "reviewedOn": "2026-10-19",
            "method": "Synthetic fixture; no upstream identity claim.",
        },
    }


def write_lock(path: Path, pin: dict[str, Any] | None = None) -> None:
    path.write_text(
        yaml.safe_dump(
            {"apiVersion": "lab-upstreams/v1", "kind": "SourceLock", "sources": [pin or pin_data()]}
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "repository",
    [
        "http://github.com/example/source.git",
        "file:///etc/passwd",
        "git@github.com:example/source",
        "https://user:password@github.com/example/source.git",
        "https://github.com/example/source.git?q=x",
        "https://github.com:443/example/source.git",
        "https://github.com.evil.test/example/source.git",
        "https://github.com/example/../source.git",
        "--upload-pack=evil",
        "https://localhost/repo.git",
    ],
)
def test_lock_rejects_unsafe_repository(repository: str) -> None:
    data = pin_data()
    data["repository"] = repository
    with pytest.raises(ValidationError):
        SourcePin.model_validate(data)


@pytest.mark.parametrize("commit", ["main", "v1.0", "abc123", "f" * 39, "A" * 40])
def test_lock_requires_exact_commit(commit: str) -> None:
    data = pin_data()
    data["commit"] = commit
    with pytest.raises(ValidationError):
        SourcePin.model_validate(data)


@pytest.mark.parametrize(
    "paths",
    [
        ["../outside"],
        ["/tmp/source"],
        ["C:/source"],
        ["src\\x"],
        ["src/", "src/nested/"],
        ["src/", "src/"],
        [],
    ],
)
def test_projection_is_safe_and_covers_license(paths: list[str]) -> None:
    data = pin_data()
    data["includePaths"] = paths
    with pytest.raises(ValidationError):
        SourcePin.model_validate(data)


@pytest.mark.parametrize(
    "paths",
    [
        ["LICENSE", "src", "src/nested/"],
        ["LICENSE", "src", "src/"],
        ["LICENSE", "-option"],
        ["LICENSE", "NUL/"],
        ["LICENSE", "source./"],
    ],
)
def test_projection_rejects_ambiguous_or_nonportable_paths(paths: list[str]) -> None:
    data = pin_data()
    data["includePaths"] = paths
    with pytest.raises(ValidationError):
        SourcePin.model_validate(data)


def test_lock_rejects_forged_provenance() -> None:
    data = pin_data()
    data["provenance"]["url"] = "https://github.com/example/source/commit/" + "b" * 40
    with pytest.raises(ValidationError):
        SourcePin.model_validate(data)


def test_lock_rejects_duplicate_source_ids(tmp_path: Path) -> None:
    path = tmp_path / "lock.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "lab-upstreams/v1",
                "kind": "SourceLock",
                "sources": [pin_data(), pin_data()],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid source lock"):
        load_source_lock(path)


@pytest.mark.parametrize("change", ["version", "extra", "missing"])
def test_lock_rejects_schema_changes(tmp_path: Path, change: str) -> None:
    path = tmp_path / "lock.yaml"
    write_lock(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if change == "version":
        data["apiVersion"] = "lab-upstreams/v2"
    elif change == "extra":
        data["execute"] = "private-token-should-never-appear"
    else:
        del data["sources"][0]["commit"]
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError) as error:
        load_source_lock(path)
    assert "private-token" not in str(error.value)


def test_repository_lock_and_schema() -> None:
    lock = load_source_lock(ROOT / "upstreams.lock.yaml")
    assert {pin.id for pin in lock.sources} == {"diskos", "disco", "snowsky-disc-qemu"}
    schema = json.loads((ROOT / "schemas/lab-upstreams-v1.schema.json").read_text(encoding="utf-8"))
    assert schema == SourceLock.model_json_schema(by_alias=True)
    validate(yaml.safe_load((ROOT / "upstreams.lock.yaml").read_text(encoding="utf-8")), schema)


def test_list_is_offline_and_does_not_create_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from snowsky_disc_lab.cli import app

    lock = tmp_path / "lock.yaml"
    write_lock(lock)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("list must never fetch or verify")

    monkeypatch.setattr("snowsky_disc_lab.cli.sync_source", forbidden)
    monkeypatch.setattr("snowsky_disc_lab.cli.verify_source", forbidden)
    result = CliRunner().invoke(app, ["sources", "list", "--lock", str(lock)])
    assert result.exit_code == 0, result.output
    assert "synthetic" in result.output
    assert "not verified by list" in " ".join(result.output.split())
    assert not (tmp_path / ".lab").exists()


@pytest.mark.parametrize("command", ["sync", "verify"])
def test_missing_cache_fails_without_network(tmp_path: Path, command: str) -> None:
    from snowsky_disc_lab.cli import app

    lock = tmp_path / "lock.yaml"
    write_lock(lock)
    args = ["sources", command, "--lock", str(lock)]
    if command == "sync":
        args.append("--offline")
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / ".lab").exists()


@pytest.mark.parametrize(
    "path", ["../outside", "/tmp/cache", "C:/cache", ".git/objects", ".git./objects", "a\\b"]
)
def test_cli_rejects_unsafe_cache_path(tmp_path: Path, path: str) -> None:
    from snowsky_disc_lab.cli import app

    lock = tmp_path / "lock.yaml"
    write_lock(lock)
    result = CliRunner().invoke(app, ["sources", "list", "--lock", str(lock), "--cache-dir", path])
    assert result.exit_code == 2


def test_cli_unknown_source_preserves_lock(tmp_path: Path) -> None:
    from snowsky_disc_lab.cli import app

    lock = tmp_path / "lock.yaml"
    write_lock(lock)
    before = lock.read_bytes()
    result = CliRunner().invoke(
        app, ["sources", "sync", "--lock", str(lock), "--source", "unknown"]
    )
    assert result.exit_code == 2
    assert "Unknown source" in result.output
    assert lock.read_bytes() == before
    assert not (tmp_path / ".lab").exists()
