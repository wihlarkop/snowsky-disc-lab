"""CLI integration and read-only diagnostic regressions."""

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app
from snowsky_disc_lab.doctor import collect_diagnostics

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "ui" in result.stdout
    assert "firmware" in result.stdout


def test_doctor_without_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: None)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Missing tools must not invoke any subprocess")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", forbidden)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "UNAVAILABLE" in result.stdout
    assert "NOT RUN" in result.stdout


def test_doctor_only_fixed_read_only_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr("snowsky_disc_lab.doctor.host_details", lambda: ("Windows", "11", "amd64"))
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda name: f"/tools/{name}")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 5
        return subprocess.CompletedProcess(command, 0, "tool 1.0", "")

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", run)
    assert all(row.status != "UNAVAILABLE" for row in collect_diagnostics())
    assert calls == [
        ["/tools/git", "--version"],
        ["/tools/uv", "--version"],
        ["/tools/docker", "--version"],
        ["/tools/docker", "compose", "version"],
        ["/tools/wsl", "--version"],
    ]


@pytest.mark.parametrize("failure", [OSError("missing"), subprocess.TimeoutExpired("docker", 5)])
def test_doctor_query_failure(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    monkeypatch.setattr("snowsky_disc_lab.doctor.shutil.which", lambda _: "/tools/docker")

    def run(*args: object, **kwargs: object) -> None:
        raise failure

    monkeypatch.setattr("snowsky_disc_lab.doctor.subprocess.run", run)
    assert runner.invoke(app, ["doctor"]).exit_code == 0


@pytest.mark.parametrize("kind", ["ui", "firmware"])
def test_valid_fixture(kind: str) -> None:
    result = runner.invoke(app, [kind, "validate", str(ROOT / "examples" / f"{kind}-valid.yaml")])
    assert result.exit_code == 0, result.output
    assert "NOT VERIFIED" in result.stdout


@pytest.mark.parametrize("kind", ["ui", "firmware"])
def test_missing_file(kind: str, tmp_path: Path) -> None:
    result = runner.invoke(app, [kind, "validate", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 2
    assert "Invalid manifest" in result.output
    assert "Traceback" not in result.output


def test_cli_rejects_bad_examples() -> None:
    fixtures = list((ROOT / "examples" / "invalid").glob("*.yaml"))
    assert len(fixtures) >= 3
    for fixture in fixtures:
        kind = "firmware" if fixture.name.startswith("firmware") else "ui"
        result = runner.invoke(app, [kind, "validate", str(fixture)])
        assert result.exit_code == 2, (fixture, result.output)
