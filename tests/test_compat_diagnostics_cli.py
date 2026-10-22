import json
from pathlib import Path

from test_compat_evidence import _receipt
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app

runner = CliRunner()


def _write(path: Path, receipt: dict) -> None:
    path.write_text(json.dumps(receipt), encoding="utf-8")


def test_json_diagnostics_are_opt_in_and_keep_existing_comparison_fields(tmp_path: Path) -> None:
    earlier_receipt = _receipt()
    later_receipt = _receipt()
    later_receipt["status"] = "failed"
    later_receipt["failure"] = {"category": "fixed-probe-or-container-check-failed"}
    later_receipt["sessions"][0]["status"] = "quarantined"
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write(earlier, earlier_receipt)
    _write(later, later_receipt)

    default = runner.invoke(
        app, ["compat", "compare", str(earlier), str(later), "--format", "json"]
    )
    opted_in = runner.invoke(
        app,
        ["compat", "compare", str(earlier), str(later), "--format", "json", "--diagnostics"],
    )

    assert default.exit_code == opted_in.exit_code == 0
    default_report = json.loads(default.stdout)
    opted_report = json.loads(opted_in.stdout)
    assert "diagnostics" not in default_report
    assert opted_report["diagnostics"]["diagnostics_schema"].endswith("/v1")
    assert opted_report["scenarios"] == default_report["scenarios"]
    assert opted_report["diagnostics"]["regressions"][0]["domain"] == "UNCLASSIFIED"


def test_markdown_diagnostics_are_opt_in(tmp_path: Path) -> None:
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write(earlier, _receipt())
    _write(later, _receipt())

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later), "--diagnostics"])

    assert result.exit_code == 0
    assert "Regression diagnostics (v1)" in result.stdout
    assert "UNCLASSIFIED" not in result.stdout
