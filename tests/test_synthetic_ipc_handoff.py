"""Focused first-party two-process POSIX queue handoff regressions."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/snowsky_disc_lab/synthetic_ipc_handoff.py"
FIXTURE_PATH = ROOT / "scripts/ci/fixtures/mips32le_posix_ipc_handoff.c"


def _handoff_module() -> ModuleType:
    assert MODULE_PATH.is_file(), "the fixed IPC handoff module is not implemented"
    return importlib.import_module("snowsky_disc_lab.synthetic_ipc_handoff")


def test_guest_source_has_a_fixed_first_party_identity() -> None:
    handoff = _handoff_module()

    assert FIXTURE_PATH.is_file()
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == handoff.GUEST_SOURCE_SHA256
    assert handoff.GUEST_SOURCE == "scripts/ci/fixtures/mips32le_posix_ipc_handoff.c"
    assert handoff.GUEST_ELF == "mips32le-posix-ipc-handoff.elf"
    assert handoff.REQUEST_QUEUE == "/snowsky_disc_lab_handoff_req_v1"
    assert handoff.ACK_QUEUE == "/snowsky_disc_lab_handoff_ack_v1"
    assert hashlib.sha256(handoff.REQUEST_PAYLOAD).hexdigest() == handoff.REQUEST_PAYLOAD_SHA256
    assert hashlib.sha256(handoff.ACK_PAYLOAD).hexdigest() == handoff.ACK_PAYLOAD_SHA256


def test_success_output_proves_the_fixed_two_process_round_trip() -> None:
    handoff = _handoff_module()

    observed = handoff.parse_execution_output(handoff.EXPECTED_CONTAINER_OUTPUT)

    assert observed["status"] == "passed"
    assert observed["guest_exit_codes"] == {"consumer": 0, "producer": 0}
    assert observed["processes"] == {
        "count": 2,
        "roles": ["consumer", "producer"],
        "distinct_qemu_processes": True,
        "shared_container": True,
        "shared_private_ipc_namespace": True,
        "overlap_proven_by_request_ack_round_trip": True,
    }
    assert observed["messages"]["request"] == {
        "verified": True,
        "bytes": len(handoff.REQUEST_PAYLOAD),
        "sha256": handoff.REQUEST_PAYLOAD_SHA256,
        "priority": handoff.REQUEST_PRIORITY,
    }
    assert observed["messages"]["acknowledgment"] == {
        "verified": True,
        "bytes": len(handoff.ACK_PAYLOAD),
        "sha256": handoff.ACK_PAYLOAD_SHA256,
        "priority": handoff.ACK_PRIORITY,
    }
    assert observed["queue_cleanup"] == {
        "consumer_closed_both": True,
        "consumer_unlinked_both": True,
        "linked_at_exit": False,
    }
    assert observed["guest_exit_codes"] == {"consumer": 0, "producer": 0}
    assert observed["role_outputs"]["consumer"]["sha256"]
    assert observed["role_outputs"]["producer"]["sha256"]


@pytest.mark.parametrize(
    ("role", "stage", "errno_name", "errno_number"),
    [
        ("consumer", "request_payload", "NONE", 0),
        ("consumer", "request_priority", "NONE", 0),
        ("producer", "acknowledgment_payload", "NONE", 0),
        ("producer", "acknowledgment_priority", "NONE", 0),
        ("producer", "queue_readiness_timeout", "ENOENT", 2),
        ("producer", "acknowledgment_timeout", "EAGAIN", 11),
    ],
)
def test_failure_output_is_reduced_to_bounded_stage_and_errno(
    role: str, stage: str, errno_name: str, errno_number: int
) -> None:
    handoff = _handoff_module()
    output = (
        f"HANDOFF_ERROR_ROLE={role}\n"
        f"HANDOFF_ERROR_STAGE={stage}\n"
        f"HANDOFF_ERROR_NAME={errno_name}\n"
        f"HANDOFF_ERROR_ERRNO={errno_number}\n"
        "GUEST_EXIT_CODE_CONSUMER=40\n"
        "GUEST_EXIT_CODE_PRODUCER=41\n"
    )

    observed = handoff.parse_execution_output(output)

    assert observed["status"] == "failed"
    assert observed["failure"] == {
        "role": role,
        "stage": stage,
        "errno": errno_name,
        "errno_number": errno_number,
    }
    assert output.encode("ascii")
    assert len(output.encode("ascii")) <= handoff.OUTPUT_LIMIT_BYTES
    assert str(ROOT) not in repr(observed)


@pytest.mark.parametrize(
    ("role", "exit_code", "expected_stage"),
    [
        ("producer", 127, "producer_exit"),
        ("consumer", 127, "consumer_exit"),
        ("producer", 124, "producer_timeout"),
        ("consumer", 124, "consumer_timeout"),
    ],
)
def test_missing_or_premature_guest_exit_is_observed_without_raw_output(
    role: str, exit_code: int, expected_stage: str
) -> None:
    handoff = _handoff_module()
    consumer_code = exit_code if role == "consumer" else 0
    producer_code = exit_code if role == "producer" else 0
    output = f"GUEST_EXIT_CODE_CONSUMER={consumer_code}\nGUEST_EXIT_CODE_PRODUCER={producer_code}\n"

    observed = handoff.parse_execution_output(output)

    assert observed["status"] == "failed"
    assert observed["failure"]["stage"] == expected_stage
    assert observed["failure"]["exit_code"] == exit_code
    assert str(ROOT) not in repr(observed)


def test_acceptance_repeats_two_distinct_sessions_and_sanitizes_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    handoff = _handoff_module()
    runtime = importlib.import_module("snowsky_disc_lab.synthetic_runtime")
    observed = handoff.parse_execution_output(handoff.EXPECTED_CONTAINER_OUTPUT)
    calls: list[str] = []

    def launch(
        _inputs: Path, _evidence: dict[str, Any], _store: Path, session_id: str, *, _case: str
    ):
        calls.append(_case)
        number = len(calls)
        return {
            "session_id": session_id,
            "session_identity": f"session-{number}",
            "case": _case,
            "status": "passed",
            "lifecycle": ["reserved", "created", "validated", "exited", "removed"],
            "execution": {
                "exit_code": 0,
                "duration_seconds": 0.25,
                "stdout_bytes": len(handoff.EXPECTED_CONTAINER_OUTPUT.encode("ascii")),
                "stdout_sha256": hashlib.sha256(
                    handoff.EXPECTED_CONTAINER_OUTPUT.encode("ascii")
                ).hexdigest(),
                "handoff": observed,
            },
            "isolation": {
                "verified_host_config": {"NetworkMode": "none", "IpcMode": "none"},
                "uid_gid": "65534:65534",
                "all_capabilities_dropped": True,
                "no_new_privileges": True,
            },
            "cleanup": {"container_removed": True, "private_tmpfs_released": True},
        }

    monkeypatch.setattr(runtime, "launch", launch)
    evidence = {
        "artifacts": [{"name": "qemu-mipsel", "sha256": "a" * 64}],
        "synthetic_ipc_handoff_guest": {
            "source": {"sha256": handoff.GUEST_SOURCE_SHA256},
            "elf": {"sha256": "b" * 64},
        },
    }
    store = tmp_path / "sessions"
    store.mkdir()

    receipt = handoff.acceptance(tmp_path / "inputs", evidence, store)

    assert receipt["schema_version"] == handoff.SCHEMA_VERSION
    assert receipt["status"] == "passed"
    assert calls == ["ipc-handoff", "ipc-handoff"]
    assert receipt["processes"]["distinct_qemu_processes"] is True
    assert receipt["processes"]["shared_container_per_session"] is True
    assert receipt["processes"]["shared_private_ipc_namespace"] is True
    assert receipt["sessions"][0]["session_identity"] != receipt["sessions"][1]["session_identity"]
    assert receipt["fresh_session_isolation"]["same_protocol_succeeded"] is True
    assert receipt["cleanup"]["all_containers_removed"] is True
    assert receipt["stock_compatibility"] == {
        "stock_ipc_compatibility": "UNVERIFIED",
        "m1_04_stock_boot": "NOT RUN",
    }
    serialized = repr(receipt)
    assert str(tmp_path) not in serialized
    assert "/ui" not in serialized and "/player" not in serialized
    assert (store / "synthetic-ipc-handoff-acceptance.json").is_file()


def test_acceptance_reports_owned_container_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    handoff = _handoff_module()
    runtime = importlib.import_module("snowsky_disc_lab.synthetic_runtime")
    store = tmp_path / "sessions"
    store.mkdir()

    def launch(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        receipt = {
            "session_id": "handoff-first",
            "session_identity": "session-1",
            "case": "ipc-handoff",
            "status": "quarantined",
            "execution": {"exit_code": 0, "handoff": {"status": "passed"}},
            "cleanup": {"container_removed": False, "private_tmpfs_released": False},
        }
        error = runtime.RuntimeRefused("owned container cleanup failed")
        error.receipt = receipt
        raise error

    monkeypatch.setattr(runtime, "launch", launch)
    evidence = {
        "artifacts": [{"name": "qemu-mipsel", "sha256": "a" * 64}],
        "synthetic_ipc_handoff_guest": {
            "source": {"sha256": handoff.GUEST_SOURCE_SHA256},
            "elf": {"sha256": "b" * 64},
        },
    }

    with pytest.raises(runtime.RuntimeRefused, match="handoff acceptance failed") as failure:
        handoff.acceptance(tmp_path / "inputs", evidence, store)

    receipt = failure.value.receipt
    assert receipt is not None
    assert receipt["status"] == "failed"
    assert receipt["cleanup"]["all_containers_removed"] is False
    assert str(tmp_path) not in repr(receipt)
