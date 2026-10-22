"""Focused parser and receipt regressions for bounded child supervision."""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/snowsky_disc_lab/synthetic_ipc_supervision.py"


def _supervision_module() -> ModuleType:
    assert MODULE_PATH.is_file(), "the fixed IPC supervision module is not implemented"
    return importlib.import_module("snowsky_disc_lab.synthetic_ipc_supervision")


def test_fixed_matrix_parser_records_independent_guest_status_and_signal_evidence() -> None:
    supervision = _supervision_module()

    observed = supervision.parse_execution_output(supervision.EXPECTED_CONTAINER_OUTPUT)

    assert observed["status"] == "passed"
    assert [case["scenario"] for case in observed["scenarios"]] == [
        "normal",
        "consumer-exits-before-request",
        "producer-exits-before-ack",
        "producer-exceeds-deadline",
        "producer-failure-cancels-sibling",
    ]
    assert observed["scenarios"][0]["children"]["consumer"]["pid"] == 101
    assert observed["scenarios"][0]["children"]["consumer"]["status"] == 0
    assert observed["scenarios"][0]["children"]["consumer"]["exit_reason"] == "exit:0"
    assert observed["scenarios"][0]["children"]["consumer"]["reaped"] is True
    assert observed["scenarios"][0]["children"]["producer"]["pid"] == 102
    assert observed["scenarios"][1]["failure"] == {
        "kind": "guest-exit",
        "role": "consumer",
        "reason": "exit:42",
    }
    assert observed["scenarios"][1]["term_sent"] == ["producer"]
    assert observed["scenarios"][2]["failure"]["role"] == "producer"
    assert observed["scenarios"][2]["acknowledgment_state"] == "queued-unconsumed"
    assert observed["scenarios"][2]["protocol"] == "producer-exit-before-ack"
    assert observed["scenarios"][3]["deadline"] == {
        "seconds": 2,
        "expired": True,
        "term_sent": ["consumer", "producer"],
        "kill_sent": [],
    }
    assert observed["scenarios"][4]["sibling_reaped"] is True


def test_wrapper_failure_is_distinguished_and_raw_output_is_not_retained() -> None:
    supervision = _supervision_module()

    observed = supervision.parse_execution_output("QEMU is missing from /sensitive/path\n")

    assert observed["status"] == "failed"
    assert observed["failure"] == {"category": "supervisor-wrapper", "stage": "output_mismatch"}
    assert "/sensitive/path" not in repr(observed)
    assert "QEMU is missing" not in repr(observed)


def test_term_delivery_race_is_reported_as_a_sanitized_wrapper_stage() -> None:
    supervision = _supervision_module()

    observed = supervision.parse_execution_output("", wrapper_exit_code=95)

    assert observed == {
        "status": "failed",
        "failure": {"category": "supervisor-wrapper", "stage": "term_delivery"},
    }


def test_acceptance_repeats_the_matrix_in_fresh_owned_containers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    supervision = _supervision_module()
    runtime = importlib.import_module("snowsky_disc_lab.synthetic_runtime")
    observed = supervision.parse_execution_output(supervision.EXPECTED_CONTAINER_OUTPUT)
    launches: list[dict[str, str]] = []

    def launch(
        _inputs: Path,
        _evidence: dict[str, object],
        _store: Path,
        session_id: str,
        *,
        _case: str,
    ) -> dict[str, object]:
        launches.append({"session_id": session_id, "case": _case})
        return {
            "session_id": session_id,
            "session_identity": f"owned-session-{len(launches)}",
            "case": _case,
            "status": "passed",
            "execution": {"supervision": observed},
            "isolation": {
                "verified_host_config": {"NetworkMode": "none", "IpcMode": "none"},
                "uid_gid": "65534:65534",
                "all_capabilities_dropped": True,
                "no_new_privileges": True,
            },
            "cleanup": {
                "container_removed": True,
                "container_stopped": True,
                "private_tmpfs_released": True,
                "ownership_verified_before_removal": True,
            },
        }

    monkeypatch.setattr(runtime, "launch", launch)
    store = tmp_path / "store"
    store.mkdir()
    receipt = supervision.acceptance(tmp_path / "inputs", {}, store)

    assert receipt["schema_version"] == supervision.SCHEMA_VERSION
    assert receipt["status"] == "passed"
    assert [entry["case"] for entry in launches] == ["ipc-supervision", "ipc-supervision"]
    assert receipt["fresh_container_repeat"] == {
        "first_container_removed_before_second": True,
        "distinct_session_identities": True,
        "same_fixed_queue_names_recreated": True,
        "no_child_processes_left": True,
    }
    assert receipt["observations_are_actual_qemu"] is True
    assert (
        receipt["sessions"][0]["observations"]["actual_vs_simulated"]["unit_test_fixtures"]
        == "simulated; not counted as acceptance evidence"
    )
    assert receipt["stock_compatibility"] == "UNVERIFIED"


def test_acceptance_keeps_container_cleanup_failure_distinct(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    supervision = _supervision_module()
    runtime = importlib.import_module("snowsky_disc_lab.synthetic_runtime")

    def launch(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise runtime.RuntimeRefused("owned container cleanup failed")

    monkeypatch.setattr(runtime, "launch", launch)

    with pytest.raises(runtime.RuntimeRefused, match="supervision acceptance failed") as failure:
        supervision.acceptance(tmp_path / "inputs", {}, tmp_path / "store")

    receipt = failure.value.receipt
    assert receipt is not None
    assert receipt["status"] == "failed"
    assert receipt["failure"] == {"category": "container-cleanup"}
    assert receipt["container_cleanup"]["queue_state_persists_after_container_removal"] is None
    assert receipt["fresh_container_repeat"]["no_child_processes_left"] is False
    assert "/inputs" not in repr(receipt)
