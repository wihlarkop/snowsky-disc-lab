from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from snowsky_disc_lab.source_lock import LicenseRecord, SourcePin, SourceProvenance
from snowsky_disc_lab.sources import (
    SourceError,
    _fetch_source,
    _publish_no_replace,
    _selected_entries,
    _TreeEntry,
    source_path,
    sync_source,
    verify_source,
)
from snowsky_disc_lab.sources import (
    _git as _source_git,
)


def _git(cwd: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Source Manager Test",
            "GIT_AUTHOR_EMAIL": "source-test@example.invalid",
            "GIT_COMMITTER_NAME": "Source Manager Test",
            "GIT_COMMITTER_EMAIL": "source-test@example.invalid",
        }
    )
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, text=True, capture_output=True
    ).stdout.strip()


def _install_local_fetch(monkeypatch: pytest.MonkeyPatch, origin: Path, pin: SourcePin) -> None:
    def local_fetch(staging: Path, selected_pin: SourcePin) -> None:
        _fetch_source(
            staging,
            selected_pin,
            fetch_url=origin.as_uri(),
            preflight=False,
            allow_file_protocol=True,
        )
        tree = subprocess.run(
            ["git", "ls-tree", "-r", "--full-tree", "-z", pin.commit],
            cwd=origin,
            check=True,
            capture_output=True,
        ).stdout
        for record in tree.split(b"\0"):
            if not record:
                continue
            header, _, path_bytes = record.partition(b"\t")
            mode, kind, oid = header.decode("ascii").split(" ")
            name = path_bytes.decode("utf-8")
            selected = any(
                name.startswith(include) if include.endswith("/") else name == include
                for include in pin.include_paths
            )
            if selected and kind == "blob" and mode in {"100644", "100755", "120000"}:
                written = _git(staging, "hash-object", "-w", str(origin.joinpath(*name.split("/"))))
                assert written == oid

        excluded_oid = _git(origin, "rev-parse", f"{pin.commit}:flash/vendor-firmware.bin")
        excluded = _source_git(
            staging,
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            input_bytes=(excluded_oid + "\n").encode("ascii"),
        )
        assert excluded.decode("ascii").strip() == f"{excluded_oid} missing"

    monkeypatch.setattr("snowsky_disc_lab.sources._fetch_source", local_fetch)


@pytest.fixture
def source_fixture(tmp_path: Path) -> tuple[Path, SourcePin]:
    repo = tmp_path / "origin"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    _git(repo, "config", "uploadpack.allowFilter", "true")
    _git(repo, "config", "uploadpack.allowReachableSHA1InWant", "true")
    (repo / "ui").mkdir()
    (repo / "docs").mkdir()
    (repo / "flash").mkdir()
    (repo / "README.md").write_bytes(b"Pinned source tree\n")
    (repo / "LICENSE").write_bytes(b"MIT\n")
    (repo / "ui" / "main.c").write_bytes(b"int main(void) { return 0; }\n")
    (repo / "docs" / "usage.md").write_bytes(b"Usage\n")
    (repo / "flash" / "vendor-firmware.bin").write_bytes(b"firmware payload must stay remote")
    _git(repo, "add", "README.md", "LICENSE", "ui", "docs", "flash")
    _git(repo, "commit", "--quiet", "-m", "fixture")
    commit = _git(repo, "rev-parse", "HEAD")
    pin = SourcePin(
        id="fixture-ui",
        repository="https://github.com/example/fixture-ui.git",
        commit=commit,
        includePaths=["ui/", "docs/", "README.md", "LICENSE"],
        licenses=[
            LicenseRecord(
                path="LICENSE",
                sha256=hashlib.sha256(b"MIT\n").hexdigest(),
                spdx="MIT",
                scope="fixture project",
            )
        ],
        provenance=SourceProvenance(
            reference="fixture commit",
            url=f"https://github.com/example/fixture-ui/commit/{commit}",
            reviewedOn="2026-10-19",
            method="local synthetic test fixture",
        ),
    )
    return repo, pin


def test_source_path_is_stable_and_changes_with_projection(
    tmp_path: Path, source_fixture: tuple[Path, SourcePin]
) -> None:
    _, pin = source_fixture

    first = source_path(tmp_path / "cache", pin)
    same = source_path(tmp_path / "cache", pin)
    other_projection = pin.model_copy(update={"include_paths": ["ui/", "LICENSE"]})

    assert first == same
    assert first.parent == tmp_path / "cache" / pin.id
    assert pin.commit in first.name
    assert source_path(tmp_path / "cache", other_projection) != first


def test_sync_materializes_only_locked_projection_and_verifies_license(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cached = sync_source(pin, tmp_path / "cache")

    assert verify_source(pin, tmp_path / "cache") == cached
    assert (cached / "ui" / "main.c").is_file()
    assert (cached / "docs" / "usage.md").is_file()
    assert (cached / "LICENSE").read_text(encoding="utf-8") == "MIT\n"
    assert not (cached / "flash").exists()


def test_offline_sync_refuses_a_missing_source_without_fetching(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, pin = source_fixture

    def should_not_fetch(*_args: object) -> None:
        pytest.fail("offline sync attempted a fetch")

    monkeypatch.setattr("snowsky_disc_lab.sources._fetch_source", should_not_fetch)

    with pytest.raises(SourceError, match="offline"):
        sync_source(pin, tmp_path / "cache", offline=True)


def test_verification_detects_modified_tracked_bytes_even_when_git_hides_them(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cached = sync_source(pin, tmp_path / "cache")
    target = cached / "ui" / "main.c"
    target.chmod(target.stat().st_mode | 0o200)
    target.write_text("modified but skipped\n", encoding="utf-8")
    _git(cached, "update-index", "--assume-unchanged", "ui/main.c")

    with pytest.raises(SourceError, match="content|modified|hash|assume-unchanged"):
        verify_source(pin, tmp_path / "cache")


def test_sync_does_not_repair_or_replace_an_invalid_existing_entry(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cached = sync_source(pin, tmp_path / "cache")
    target = cached / "LICENSE"
    original = target.read_bytes()
    target.chmod(target.stat().st_mode | 0o200)
    target.write_bytes(b"changed\n")

    with pytest.raises(SourceError):
        sync_source(pin, tmp_path / "cache")

    assert target.read_bytes() == b"changed\n"
    assert target.read_bytes() != original


@pytest.mark.parametrize("mutation", ["remote", "head"])
def test_verification_rejects_wrong_remote_or_head(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cached = sync_source(pin, tmp_path / "cache")

    if mutation == "remote":
        _git(cached, "remote", "set-url", "origin", "https://github.com/attacker/other.git")
    else:
        (cached / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")

    with pytest.raises(SourceError, match="configuration|detached|exact locked commit"):
        verify_source(pin, tmp_path / "cache")


def test_verification_rejects_a_missing_selected_git_blob_object(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cached = sync_source(pin, tmp_path / "cache")
    oid = _git(cached, "hash-object", "ui/main.c")
    object_path = cached / ".git" / "objects" / oid[:2] / oid[2:]
    assert object_path.is_file()
    object_path.chmod(object_path.stat().st_mode | 0o200)
    object_path.unlink()

    with pytest.raises(SourceError, match="selected Git blob object"):
        verify_source(pin, tmp_path / "cache")


def test_unsafe_projection_path_is_rejected_before_cache_creation(
    tmp_path: Path, source_fixture: tuple[Path, SourcePin]
) -> None:
    _, pin = source_fixture
    unsafe_pin = pin.model_copy(update={"include_paths": ["ui/../outside"]})
    cache = tmp_path / "cache"

    with pytest.raises(SourceError, match="unsafe path components"):
        sync_source(unsafe_pin, cache)

    assert not cache.exists()


def test_selected_symlink_entries_are_refused(
    source_fixture: tuple[Path, SourcePin],
) -> None:
    _, pin = source_fixture
    entries = [
        _TreeEntry("100644", "blob", "1" * 40, "ui/main.c"),
        _TreeEntry("120000", "blob", "2" * 40, "ui/link"),
        _TreeEntry("100644", "blob", "3" * 40, "docs/usage.md"),
        _TreeEntry("100644", "blob", "4" * 40, "README.md"),
        _TreeEntry("100644", "blob", "5" * 40, "LICENSE"),
    ]

    with pytest.raises(SourceError, match="unsupported file or submodule"):
        _selected_entries(entries, pin)


def test_no_replace_publish_leaves_an_existing_empty_directory_untouched(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staging"
    final_path = tmp_path / "published"
    staging.mkdir()
    final_path.mkdir()

    with pytest.raises(FileExistsError):
        _publish_no_replace(staging, final_path)

    assert staging.is_dir()
    assert final_path.is_dir()
    assert list(final_path.iterdir()) == []


def test_cache_cannot_be_placed_inside_git_metadata(
    tmp_path: Path, source_fixture: tuple[Path, SourcePin]
) -> None:
    _, pin = source_fixture
    with pytest.raises(SourceError, match="Git metadata"):
        sync_source(pin, tmp_path / ".git" / "cache")
    assert not (tmp_path / ".git").exists()


def test_verification_refuses_a_worktree_file_replaced_by_symlink(
    tmp_path: Path,
    source_fixture: tuple[Path, SourcePin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin, pin = source_fixture
    _install_local_fetch(monkeypatch, origin, pin)
    cached = sync_source(pin, tmp_path / "cache")
    target = cached / "ui" / "main.c"
    target.chmod(target.stat().st_mode | 0o200)
    target.unlink()
    try:
        target.symlink_to(cached / ".git" / "config")
    except OSError:
        pytest.skip("Symlink creation is unavailable on this host")
    with pytest.raises(SourceError, match="symlink|junction"):
        verify_source(pin, tmp_path / "cache")
