"""CLI wiring keeps diagnostics opt-in and shares source-cache configuration."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app
from snowsky_disc_lab.doctor import Diagnostic
from snowsky_disc_lab.sources import source_cache_root


@pytest.mark.parametrize("daemon", [False, True])
def test_doctor_wires_cache_and_explicit_daemon_option(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, daemon: bool
) -> None:
    lock = tmp_path / "missing-lock.yaml"
    observations: list[tuple[Path | None, bool]] = []

    def collect(cache_root: Path | None = None, *, docker_daemon: bool = False) -> list[Diagnostic]:
        observations.append((cache_root, docker_daemon))
        return [
            Diagnostic(
                "Runtime",
                "NOT VERIFIED",
                "[/untrusted] No runtime " + "x" * 150 + " complete-path-tail",
                "Review M1 gates",
            )
        ]

    monkeypatch.setattr("snowsky_disc_lab.cli.collect_diagnostics", collect)
    arguments = ["doctor", "--lock", str(lock), "--cache-dir", "cache/source"]
    if daemon:
        arguments.append("--docker-daemon")
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    assert observations == [(source_cache_root(lock, "cache/source"), daemon)]
    assert "Review M1 gates" in " ".join(result.output.split())
    assert "[/untrusted]" in result.output
    assert "complete-path-tail" in result.output
    assert "NOT VERIFIED" in " ".join(result.output.split())
    assert not (tmp_path / "cache").exists()
    assert not lock.exists()


def test_doctor_rejects_unsafe_cache_setting_before_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("An invalid cache path must be refused before running diagnostics")

    monkeypatch.setattr("snowsky_disc_lab.cli.collect_diagnostics", forbidden)
    result = CliRunner().invoke(
        app, ["doctor", "--lock", str(tmp_path / "lock.yaml"), "--cache-dir", "../outside"]
    )
    assert result.exit_code == 2
    assert "safe relative" in " ".join(result.output.split())
