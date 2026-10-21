"""CLI integration and read-only diagnostic regressions."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from test_elf_inspection import _elf32_mips
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


def test_ui_inspect_text_and_json_report_selected_elf(tmp_path: Path) -> None:
    path = tmp_path / "candidate.elf"
    raw = _elf32_mips()
    path.write_bytes(raw)

    text_result = runner.invoke(app, ["ui", "inspect", str(path)])
    assert text_result.exit_code == 0, text_result.output
    for value in ("ELF32", "little", "MIPS", "O32", "UNKNOWN", hashlib.sha256(raw).hexdigest()):
        assert value in text_result.stdout

    json_result = runner.invoke(app, ["ui", "inspect", str(path), "--format", "json"])
    assert json_result.exit_code == 0, json_result.output
    report = json.loads(json_result.stdout)
    assert report["size_bytes"] == len(raw)
    assert report["sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["compatibility"] == "UNKNOWN"
    assert report["mips_abi"] == "O32"


@pytest.mark.parametrize("contents", [b"not an elf", b"\x7fELF\x01\x01\x01"])
def test_ui_inspect_invalid_or_truncated_elf_is_concise(tmp_path: Path, contents: bytes) -> None:
    path = tmp_path / "bad.elf"
    path.write_bytes(contents)
    result = runner.invoke(app, ["ui", "inspect", str(path)])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "ELF" in result.output


def test_ui_inspect_oversized_elf_is_concise(tmp_path: Path) -> None:
    path = tmp_path / "large.elf"
    path.write_bytes(b"\x7fELF" + b"\0" * (128 * 1024 * 1024))
    result = runner.invoke(app, ["ui", "inspect", str(path)])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "size limit" in result.output
