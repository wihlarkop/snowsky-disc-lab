"""Host classification and read-only preflight behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from snowsky_disc_lab.doctor import collect_diagnostics
from snowsky_disc_lab.host_platform import classify_host, normalize_architecture
from snowsky_disc_lab.sources import SourceError


@pytest.mark.parametrize(
    ("system", "release", "expected"),
    [
        ("Windows", "10.0.22631", "native Windows"),
        ("Linux", "5.15.167.4-microsoft-standard-WSL2", "WSL2"),
        ("Linux", "5.15.90.1-microsoft-standard", "WSL2"),
        ("Linux", "4.4.0.19041-Microsoft", "WSL1"),
        ("Linux", "6.1.21-Microsoft", "WSL generation NOT VERIFIED"),
        ("Linux", "6.12.0-generic", "native Linux"),
    ],
)
def test_classifies_supported_host_kinds(system: str, release: str, expected: str) -> None:
    assert classify_host(system, release) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AMD64", "x86_64"),
        ("win-amd64", "x86_64"),
        ("x86_64", "x86_64"),
        ("aarch64", "arm64"),
        ("arm64", "arm64"),
        ("win-arm64", "arm64"),
        ("armv8l", "armv8l"),
    ],
)
def test_normalizes_candidate_architectures(raw: str, expected: str) -> None:
    assert normalize_architecture(raw) == expected


@pytest.mark.parametrize(
    ("release", "status"), [("10.0.19045", "WARNING"), ("10.0.26200", "NOT VERIFIED")]
)
def test_windows_build_is_not_a_runtime_or_edition_guarantee(
    monkeypatch: pytest.MonkeyPatch, release: str, status: str
) -> None:
    monkeypatch.setattr(
        "snowsky_disc_lab.doctor.host_details", lambda: ("Windows", release, "AMD64")
    )
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)
    target = next(row for row in collect_diagnostics() if row.name == "Windows target")
    assert target.status == status
    assert target.remediation


def test_unknown_architecture_is_reported_as_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.host_details", lambda: ("Linux", "6.1", "mips"))
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)

    rows = collect_diagnostics()

    architecture = next(row for row in rows if row.name == "Architecture")
    assert architecture.status == "WARNING"
    assert "mips" in architecture.detail


def test_unsupported_host_os_is_reported_as_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.host_details", lambda: ("FreeBSD", "14", "amd64"))
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)

    rows = collect_diagnostics()

    host = next(row for row in rows if row.name == "Host")
    assert host.status == "WARNING"
    assert "Review" in host.remediation


def test_default_preflight_runs_only_fixed_version_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("snowsky_disc_lab.doctor.host_details", lambda: ("Windows", "11", "AMD64"))
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda name: f"/tools/{name}")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 5
        return subprocess.CompletedProcess(command, 0, "tool 1.0", "")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", run)

    rows = collect_diagnostics()

    assert calls == [
        ["/tools/git", "--version"],
        ["/tools/uv", "--version"],
        ["/tools/docker", "--version"],
        ["/tools/docker", "compose", "version"],
        ["/tools/wsl", "--version"],
    ]
    assert all(row.status != "UNAVAILABLE" for row in rows)
    assert any(row.status == "NOT VERIFIED" for row in rows)


def test_missing_tools_do_not_invoke_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Missing tools must not invoke subprocess")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", forbidden)
    rows = collect_diagnostics()

    assert {row.name for row in rows} >= {"Git", "uv", "Docker CLI", "Docker Compose"}
    assert all(
        row.status == "UNAVAILABLE"
        for row in rows
        if row.name in {"Git", "uv", "Docker CLI", "Docker Compose"}
    )


def test_low_cache_space_warns_and_reports_source_cache_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "missing" / "source-cache"
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "snowsky_disc_lab.doctor.shutil.disk_usage",
        lambda path: type("Usage", (), {"total": 1000, "used": 400, "free": 600})(),
    )
    monkeypatch.setattr("snowsky_disc_lab.doctor.os.access", lambda *_: True)

    rows = collect_diagnostics(target)

    disk = next(row for row in rows if row.name == "Cache disk space")
    permission = next(row for row in rows if row.name == "Cache permissions")
    assert disk.status == "WARNING"
    assert "0.0 GiB" in disk.detail
    assert "10 GiB" in disk.detail
    assert "not an M1 minimum" in disk.detail
    assert permission.status == "NOT VERIFIED"
    assert "write" in permission.detail.lower()
    cache = next(row for row in rows if row.name == "Source cache")
    assert cache.status == "NOT VERIFIED"
    assert str(target.absolute()) in cache.detail
    assert "sources verify" in cache.remediation


def test_healthy_cache_space_is_available_without_write_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "snowsky_disc_lab.doctor.shutil.disk_usage",
        lambda _: type(
            "Usage", (), {"total": 20 * 1024**3, "used": 2 * 1024**3, "free": 18 * 1024**3}
        )(),
    )
    monkeypatch.setattr("snowsky_disc_lab.doctor.os.access", lambda *_: True)
    monkeypatch.setattr(
        Path,
        "write_bytes",
        lambda *_: pytest.fail("cache diagnostics must not write a probe file"),
    )
    monkeypatch.setattr(
        Path,
        "write_text",
        lambda *_: pytest.fail("cache diagnostics must not write a probe file"),
    )
    monkeypatch.setattr(
        Path,
        "mkdir",
        lambda *_args, **_kwargs: pytest.fail("cache diagnostics must not create directories"),
    )

    rows = collect_diagnostics(tmp_path / "cache")

    disk = next(row for row in rows if row.name == "Cache disk space")
    assert disk.status == "AVAILABLE"
    assert "18.0 GiB" in disk.detail


def test_cache_metadata_failures_are_warnings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "snowsky_disc_lab.doctor.shutil.disk_usage",
        lambda _: (_ for _ in ()).throw(OSError("inaccessible")),
    )
    monkeypatch.setattr("snowsky_disc_lab.doctor.os.access", lambda *_: False)

    rows = collect_diagnostics(tmp_path / "cache")

    assert next(row for row in rows if row.name == "Cache disk space").status == "WARNING"
    assert next(row for row in rows if row.name == "Cache permissions").status == "WARNING"
    assert next(row for row in rows if row.name == "Cache path").status == "AVAILABLE"


def test_invalid_cache_metadata_warns_and_existing_file_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "cache-file"
    target.write_text("existing", encoding="utf-8")
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.disk_usage", lambda _: None)

    rows = collect_diagnostics(target)

    cache_path = next(row for row in rows if row.name == "Cache path")
    cache = next(row for row in rows if row.name == "Source cache")
    assert cache_path.status == "WARNING"
    assert cache.status == "NOT VERIFIED"
    assert "Choose a directory" in cache.remediation


def test_unsafe_cache_metadata_does_not_report_path_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)

    def reject_path(*_args: object, **_kwargs: object) -> None:
        raise SourceError("unsafe path")

    monkeypatch.setattr(
        "snowsky_disc_lab.doctor._check_components",
        reject_path,
    )

    rows = collect_diagnostics(tmp_path / "cache")

    assert next(row for row in rows if row.name == "Cache path").status == "WARNING"


def test_daemon_probe_only_runs_when_explicitly_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: "/tools/docker")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "27.0.1", "")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", run)

    collect_diagnostics(docker_daemon=True)

    assert ["/tools/docker", "info", "--format", "{{.ServerVersion}}"] in calls


@pytest.mark.parametrize(
    ("compose_version", "expected_status"),
    [
        ("Docker Compose version v2.36.0", "AVAILABLE"),
        ("Docker Compose version v2.35.1", "WARNING"),
        ("compose version unavailable", "NOT VERIFIED"),
    ],
)
def test_compose_minimum_and_unparseable_version(
    monkeypatch: pytest.MonkeyPatch, compose_version: str, expected_status: str
) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: "/tools/docker")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        output = (
            compose_version if command[1:3] == ["compose", "version"] else "Docker version 28.1.0"
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", run)

    rows = collect_diagnostics()

    assert next(row for row in rows if row.name == "Docker Compose").status == expected_status


@pytest.mark.parametrize(
    ("server_version", "expected_status"),
    [
        ("28.1.0", "AVAILABLE"),
        ("28.0.9", "WARNING"),
        ("unknown", "NOT VERIFIED"),
    ],
)
def test_opt_in_engine_check_only_reports_version(
    monkeypatch: pytest.MonkeyPatch, server_version: str, expected_status: str
) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: "/tools/docker")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        output = server_version if "info" in command else "Docker version 28.1.0"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", run)

    rows = collect_diagnostics(docker_daemon=True)

    engine = next(row for row in rows if row.name == "Docker Engine")
    assert engine.status == expected_status
    assert "Linux-container" in engine.detail or "Linux containers" in engine.remediation
