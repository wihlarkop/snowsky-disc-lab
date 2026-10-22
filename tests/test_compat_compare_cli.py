import json
from pathlib import Path

import pytest
from test_compat_evidence import _ipc_handoff_receipt, _qemu_receipt, _receipt
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app
from snowsky_disc_lab.compat_evidence import MAX_RECEIPT_BYTES

runner = CliRunner()


def _write_receipt(path: Path, receipt: dict | None = None) -> None:
    path.write_text(json.dumps(receipt if receipt is not None else _receipt()), encoding="utf-8")


def test_compare_json_contains_both_artifact_identities_and_unknown_stock_status(
    tmp_path: Path,
) -> None:
    earlier = tmp_path / "private-earlier.json"
    later = tmp_path / "private-later.json"
    _write_receipt(earlier)
    _write_receipt(later)

    result = runner.invoke(
        app,
        ["compat", "compare", str(earlier), str(later), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["historical_report"]["artifacts"]["qemu-mipsel"] == "a" * 64
    assert report["later_report"]["artifacts"]["qemu-mipsel"] == "a" * 64
    assert report["scenarios"]["synthetic-filesystem"]["classification"] == "unchanged"
    assert report["scenarios"]["stock-v257-boot"]["after"] == "NOT RUN"
    assert report["support_status"] == "unknown"
    assert report["evidence_authentication"]["independent_authentication"] == "not performed"
    assert str(tmp_path) not in result.stdout


def test_compare_markdown_reports_condition_mismatch_and_both_artifacts(tmp_path: Path) -> None:
    earlier_receipt = _receipt()
    later_receipt = _receipt()
    later_receipt["identities"]["qemu-mipsel"] = "c" * 64
    later_receipt["posix_mqueue"]["identities"]["qemu_mipsel_sha256"] = "c" * 64
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier, earlier_receipt)
    _write_receipt(later, later_receipt)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 0, result.output
    assert "incomparable" in result.stdout
    assert "artifact identities differ" in result.stdout
    assert "a" * 64 in result.stdout
    assert "c" * 64 in result.stdout
    assert "stock-v257-boot" in result.stdout
    assert "NOT RUN" in result.stdout
    assert "unauthenticated" in result.stdout.lower()
    assert "unknown" in result.stdout.lower()


@pytest.mark.parametrize(
    ("earlier_status", "later_status", "classification"),
    [("PASS", "FAIL", "regression"), ("FAIL", "PASS", "improvement")],
)
def test_compare_cli_classifies_regression_and_improvement(
    tmp_path: Path, earlier_status: str, later_status: str, classification: str
) -> None:
    earlier_receipt = _receipt()
    later_receipt = _receipt()
    failed_receipt = later_receipt if later_status == "FAIL" else earlier_receipt
    failed_receipt["status"] = "failed"
    failed_receipt["failure"] = {"category": "fixed-probe-or-container-check-failed"}
    failed_receipt["sessions"][0]["status"] = "quarantined"
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier, earlier_receipt)
    _write_receipt(later, later_receipt)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later), "--format", "json"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["scenarios"]["synthetic-filesystem"]["classification"] == classification
    assert report["conditions_match"] is True


def test_compare_cli_treats_absent_scenario_as_not_run(tmp_path: Path) -> None:
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier, _ipc_handoff_receipt())
    _write_receipt(later, _receipt())

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later), "--format", "json"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["scenarios"]["synthetic-ipc-handoff"]["after"] == "NOT RUN"
    assert report["scenarios"]["synthetic-ipc-handoff"]["classification"] == "incomparable"


def test_compare_markdown_shows_both_qemu_build_source_identities(tmp_path: Path) -> None:
    earlier_receipt = _qemu_receipt()
    later_receipt = _qemu_receipt()
    later_receipt["source_identity"]["commit"] = "2" * 40
    hostile_name = "input | `x` <script>\u202e"
    later_receipt["source_identity"]["reviewed_file_sha256"] = {hostile_name: "3" * 64}
    later_receipt["source_identity"]["reviewed_file_bytes"] = {hostile_name: 1}
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier, earlier_receipt)
    _write_receipt(later, later_receipt)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 0, result.output
    assert "build source identities differ" in result.stdout
    assert "1" * 40 in result.stdout
    assert "2" * 40 in result.stdout
    assert "\\|" in result.stdout
    assert "\\<script\\>" in result.stdout
    assert "\u202e" not in result.stdout


def test_compare_cli_output_is_deterministic_and_does_not_modify_inputs(tmp_path: Path) -> None:
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier)
    _write_receipt(later)
    before = (earlier.read_bytes(), later.read_bytes())

    first = runner.invoke(app, ["compat", "compare", str(earlier), str(later), "--format", "json"])
    second = runner.invoke(app, ["compat", "compare", str(earlier), str(later), "--format", "json"])

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert (earlier.read_bytes(), later.read_bytes()) == before


@pytest.mark.parametrize("format_name", ["xml", "text", ""])
def test_compare_rejects_unknown_format_without_traceback(tmp_path: Path, format_name: str) -> None:
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier)
    _write_receipt(later)

    result = runner.invoke(
        app,
        ["compat", "compare", str(earlier), str(later), "--format", format_name],
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_compare_refuses_missing_input_without_echoing_path(tmp_path: Path) -> None:
    earlier = tmp_path / "missing-private-earlier.json"
    later = tmp_path / "later.json"
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output


def test_compare_refuses_non_regular_input(tmp_path: Path) -> None:
    directory = tmp_path / "receipt-directory"
    directory.mkdir()
    later = tmp_path / "later.json"
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(directory), str(later)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_compare_refuses_oversized_receipt_concisely(tmp_path: Path) -> None:
    earlier = tmp_path / "oversized.json"
    earlier.write_bytes(b" " * (MAX_RECEIPT_BYTES + 1))
    later = tmp_path / "later.json"
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 2
    assert "1 MiB" in result.output
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output


def test_compare_sanitizes_duplicate_key_error_and_never_echoes_source_paths(
    tmp_path: Path,
) -> None:
    earlier = tmp_path / "earlier.json"
    earlier.write_text('{"secret-private-key-name":"a","secret-private-key-name":"b"}')
    later = tmp_path / "later.json"
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 2
    assert "secret-private-key-name" not in result.output
    assert str(tmp_path) not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt.update(status=[]),
        lambda receipt: receipt.update(status={"unexpected": "object"}),
        lambda receipt: receipt.update(identities=[]),
        lambda receipt: receipt["sessions"][0].update(case=[]),
    ],
)
def test_compare_rejects_wrong_typed_receipt_fields_without_traceback(
    tmp_path: Path, mutate
) -> None:
    bad_receipt = _receipt()
    mutate(bad_receipt)
    earlier = tmp_path / "bad.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier, bad_receipt)
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output


def test_compare_rejects_deeply_malformed_json_without_traceback(tmp_path: Path) -> None:
    earlier = tmp_path / "deep.json"
    earlier.write_text("[" * 1500 + "0" + "]" * 1500, encoding="utf-8")
    later = tmp_path / "later.json"
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_compare_rejects_contradictory_receipt_without_traceback(tmp_path: Path) -> None:
    bad_receipt = _receipt()
    bad_receipt["status"] = "failed"
    earlier = tmp_path / "contradictory.json"
    later = tmp_path / "later.json"
    _write_receipt(earlier, bad_receipt)
    _write_receipt(later)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_compare_requires_exactly_two_receipts(tmp_path: Path) -> None:
    earlier = tmp_path / "earlier.json"
    later = tmp_path / "later.json"
    extra = tmp_path / "extra.json"
    for path in (earlier, later, extra):
        _write_receipt(path)

    result = runner.invoke(app, ["compat", "compare", str(earlier), str(later), str(extra)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output

    missing = runner.invoke(app, ["compat", "compare", str(earlier)])

    assert missing.exit_code == 2
    assert "Traceback" not in missing.output
