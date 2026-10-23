"""Read-only operator probes and fail-closed capacity observations."""

from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

import pytest

from snowsky_disc_lab import windows_readiness as readiness


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readiness.sys, "platform", "win32")
    monkeypatch.setattr(readiness.shutil, "which", lambda name: f"/tools/{name}")


def test_default_queries_only_allowlisted_host_resources(
    windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        assert kwargs == {"capture_output": True, "timeout": 10, "check": False, "shell": False}
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "cpus": 12,
                    "total_bytes": 16 * 1024**3,
                    "available_bytes": 3 * 1024**3,
                    "private_path": "secret",
                }
            ).encode(),
            b"",
        )

    monkeypatch.setattr(readiness.subprocess, "run", run)
    report = readiness.collect_observations()
    assert len(calls) == 1
    assert calls[0] == [
        "/tools/powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        readiness._HOST_QUERY,
    ]
    assert report["host"]["build_capacity"] == "insufficient"
    assert report["docker_engine"]["status"] == "not-requested"
    assert report["wsl"]["status"] == "not-requested"
    assert "secret" not in json.dumps(report)


@pytest.mark.parametrize(
    ("tool", "message", "expected"),
    [
        ("docker", "open //private/pipe: Access is denied.", "access-denied"),
        ("docker", "Cannot connect to the Docker daemon", "daemon-unavailable"),
        ("docker", "unrecognized private diagnostic", "query-failed"),
        ("wsl", "Wsl/E_ACCESSDENIED", "access-denied"),
        ("wsl", "Wsl/0x80370102", "configuration-error"),
        ("wsl", "Wsl/WSL_E_VIRTUALIZATION_REQUIRED", "configuration-error"),
    ],
)
def test_failure_categories_without_raw_diagnostics(
    windows: None, monkeypatch: pytest.MonkeyPatch, tool: str, message: str, expected: str
) -> None:
    monkeypatch.setattr(
        readiness.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, b"", message.encode("utf-16-le")
        ),
    )
    assert readiness._query(tool, []) == (expected, "")


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (PermissionError("private"), "access-denied"),
        (OSError("private"), "unavailable"),
        (subprocess.TimeoutExpired("private", 10), "timed-out"),
    ],
)
def test_probe_failures_are_bounded_and_sanitized(
    windows: None, monkeypatch: pytest.MonkeyPatch, exception: Exception, expected: str
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise exception

    monkeypatch.setattr(readiness.subprocess, "run", fail)
    assert readiness._query("docker", []) == (expected, "")


@pytest.mark.parametrize(
    ("total", "cpus", "expected"),
    [
        (8242479104, 12, "insufficient"),
        (8 * 1024**3, 12, "available-memory-not-measured"),
        (16 * 1024**3, 1, "insufficient"),
    ],
)
def test_docker_total_memory_only_refuses_or_leaves_available_unmeasured(
    total: int, cpus: int, expected: str
) -> None:
    result = readiness._resources(
        json.dumps({"cpus": cpus, "total_bytes": total, "os": "linux", "architecture": "x86_64"}),
        docker=True,
    )
    assert result["build_capacity"] == expected
    assert result["build_admitted"] is False


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "null",
        "invalid",
        '{"cpus":true,"total_bytes":99}',
        '{"cpus":2,"total_bytes":99,"available_bytes":100}',
    ],
)
def test_malformed_resources_cannot_imply_capacity(raw: str) -> None:
    assert readiness._resources(raw, docker=False) == {"status": "invalid-observation"}


def test_opt_in_never_starts_distribution_or_container_and_redacts_names(
    windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        if command[0].endswith("wsl"):
            raw = "  NAME STATE VERSION\r\n* PrivateName Running 2\r\n  PrivateOld Stopped 1\r\n"
            output = raw.encode("utf-16-le")
        elif command[0].endswith("docker"):
            output = b'{"cpus":12,"total_bytes":8242479104,"os":"linux","architecture":"x86_64"}'
        else:
            output = b'{"cpus":12,"total_bytes":17000000000,"available_bytes":12000000000}'
        return subprocess.CompletedProcess(command, 0, output, b"")

    monkeypatch.setattr(readiness.subprocess, "run", run)
    report = readiness.collect_observations(wsl=True, docker_daemon=True)
    assert calls[1] == ["/tools/wsl", "--list", "--verbose"]
    assert calls[2] == ["/tools/docker", "info", "--format", readiness._DOCKER_QUERY]
    assert report["wsl"]["wsl2_distribution_count"] == 1
    assert report["wsl"]["wsl1_distribution_count"] == 1
    assert report["host"]["build_capacity"] == "snapshot-minimum-met"
    assert report["host"]["build_admitted"] is False
    assert report["docker_engine"]["build_capacity"] == "insufficient"
    assert report["trusted_execution_isolation"] == "unverified"
    assert report["execution_authorized"] is False
    assert report["stock_execution"] == "not-run"
    assert "Private" not in json.dumps(report)


def test_build_thresholds_stay_in_sync() -> None:
    source = Path(__file__).parents[1] / "scripts/ci/qemu_runtime_build.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    constants = {
        node.targets[0].id: ast.unparse(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
    }
    assert constants["MIN_CPUS"] == str(readiness.MIN_CPUS)
    assert constants["MIN_AVAILABLE_MEMORY"] == "8 * 1024 ** 3"
    assert readiness.MIN_AVAILABLE_MEMORY == 8 * 1024**3


def test_cim_access_failure_is_not_a_resource_or_configuration_failure(
    windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        readiness.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, b"", b"Access to a CIM resource was not available to the client."
        ),
    )
    assert readiness.collect_observations()["host"] == {"status": "access-denied"}


def test_zero_available_memory_is_observed_insufficient() -> None:
    result = readiness._resources(
        '{"cpus":2,"total_bytes":16000000000,"available_bytes":0}', docker=False
    )
    assert result["status"] == "observed"
    assert result["build_capacity"] == "insufficient"


def test_missing_tools_do_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readiness.shutil, "which", lambda name: None)
    assert readiness._query("docker", []) == ("missing-tool", "")


def test_non_windows_never_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readiness.sys, "platform", "linux")
    monkeypatch.setattr(readiness.shutil, "which", lambda name: pytest.fail("probe on Linux"))
    assert readiness.collect_observations(wsl=True, docker_daemon=True)["host"]["status"] == (
        "unsupported-host"
    )
