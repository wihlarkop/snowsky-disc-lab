from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci import qemu_runtime_build


def test_source_audit_exports_container_owned_evidence_without_writable_host_mount(
    monkeypatch, tmp_path: Path
) -> None:
    sources = tmp_path / "debian.sources"
    sources.write_text("Types: deb\nURI: https://snapshot.debian.org/one\n\nTypes: deb\n")
    audit = tmp_path / "audit"
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "cp"]:
            target = Path(args[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("sanitized fixture evidence\n", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    qemu_runtime_build.source_audit_container(sources, audit)

    create_calls = [args for args in calls if args[:2] == ["docker", "create"]]
    assert len(create_calls) == 1, "audit must run in a named container for safe evidence copying"
    create = create_calls[0]
    source_mount = next(arg for arg in create if arg.startswith("type=bind,"))
    tmpfs_index = create.index("--tmpfs")
    assert create[tmpfs_index + 1] == "/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777"
    assert "install -d -m 0700 /audit" in create[-1]
    assert "install -d -m 0700 /audit/source" in create[-1]
    assert "install -d -m 0700 /audit/source /audit/unpacked" not in create[-1]
    assert "-o APT::Sandbox::User=root" in create[-1]
    assert 'source_tmp="$(mktemp -d /tmp/qemu-source-download.XXXXXX)"' in create[-1]
    assert 'cd "$source_tmp"' in create[-1]
    assert 'apt-get "${apt_opts[@]}" source --download-only --only-source' in create[-1]
    assert "sha256sum --check --status" in create[-1]
    assert " && printf" not in create[-1]
    assert 'mv "${dsc[0]}" /audit/source/' in create[-1]
    assert "/audit/source/qemu_7.2+dfsg-7+deb12u18.dsc" in create[-1]
    assert source_mount.endswith(",readonly")
    assert not any("dst=/audit" in arg and arg.startswith("type=bind,") for arg in create)
    assert "--cap-drop=ALL" in create
    assert create[create.index("--security-opt") + 1] == "no-new-privileges:true"
    assert "--rm" not in create

    operations = [args[:2] for args in calls]
    assert operations.index(["docker", "create"]) < operations.index(["docker", "start"])
    assert operations.index(["docker", "start"]) < operations.index(["docker", "cp"])
    assert operations[-1] == ["docker", "rm"]
    assert (audit / "inrelease.tsv").is_file()
    assert (audit / "source" / "qemu_7.2+dfsg.orig.tar.xz").is_file()


def test_source_audit_failure_copies_container_logs_before_removing_container(
    monkeypatch, tmp_path: Path
) -> None:
    sources = tmp_path / "debian.sources"
    sources.write_text("Types: deb\nURI: https://snapshot.debian.org/one\n\nTypes: deb\n")
    audit = tmp_path / "audit"
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "start"]:
            raise qemu_runtime_build.StopBuild("container command failed")
        if args[:2] == ["docker", "cp"]:
            source = args[-2].split(":", 1)[-1]
            target = Path(args[-1])
            if source == "/audit/apt-update.log":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("apt update diagnostic fixture\n", encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, stdout="")
            return subprocess.CompletedProcess(args, 1, stdout="not present")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    with pytest.raises(qemu_runtime_build.StopBuild, match="apt update diagnostic fixture"):
        qemu_runtime_build.source_audit_container(sources, audit)

    operations = [args[:2] for args in calls]
    assert operations[-1] == ["docker", "rm"]
    assert (audit / "apt-update.log").is_file()


def test_source_audit_attempts_cleanup_if_create_times_out_after_daemon_creation(
    monkeypatch, tmp_path: Path
) -> None:
    sources = tmp_path / "debian.sources"
    sources.write_text("Types: deb\nURI: https://snapshot.debian.org/one\n\nTypes: deb\n")
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "create"]:
            raise subprocess.TimeoutExpired(args, timeout=120)
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    with pytest.raises(subprocess.TimeoutExpired):
        qemu_runtime_build.source_audit_container(sources, tmp_path / "audit")

    assert calls[-1][:2] == ["docker", "rm"]
    assert calls[-1][2:4] == ["--force", calls[0][calls[0].index("--name") + 1]]


def test_source_audit_rejects_evidence_larger_than_documented_limit(
    monkeypatch, tmp_path: Path
) -> None:
    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        Path(args[-1]).write_bytes(
            b"x" * (qemu_runtime_build.AUDIT_FILE_MAX_BYTES["inrelease.tsv"] + 1)
        )
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    with pytest.raises(qemu_runtime_build.StopBuild, match="exceeds its size limit"):
        qemu_runtime_build.copy_audit_files(
            "qemu-source-audit-test",
            tmp_path,
            (("/audit/inrelease.tsv", "inrelease.tsv"),),
            required=True,
        )
