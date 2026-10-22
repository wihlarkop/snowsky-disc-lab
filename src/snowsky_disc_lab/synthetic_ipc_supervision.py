"""Fixed, first-party two-process supervision acceptance and sanitized receipt."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import synthetic_ipc_handoff as handoff

SCHEMA_VERSION = "firmware-free-mips32le-synthetic-ipc-supervision/v1"
GUEST_SOURCE = "scripts/ci/fixtures/mips32le_posix_ipc_supervision.c"
GUEST_SOURCE_SHA256 = "1d151ccbe7fb4c0965ad6d9bf290de8e6caaed0ca0a2dc7067aba91749c52e9f"
GUEST_ELF = "mips32le-posix-ipc-supervision.elf"
OUTPUT_LIMIT_BYTES = 6144
DEADLINE_SECONDS = {
    "normal": 5,
    "consumer-exits-before-request": 5,
    "producer-exits-before-ack": 5,
    "producer-exceeds-deadline": 2,
    "producer-failure-cancels-sibling": 5,
}
SCENARIOS = tuple(DEADLINE_SECONDS)
QUEUE_NAMES = {
    "normal": {"request": handoff.REQUEST_QUEUE, "acknowledgment": handoff.ACK_QUEUE},
    "consumer-exits-before-request": {
        "request": "/snowsky_disc_lab_supervision_consumer_exit_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_consumer_exit_ack_v1",
    },
    "producer-exits-before-ack": {
        "request": "/snowsky_disc_lab_supervision_producer_exit_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_producer_exit_ack_v1",
    },
    "producer-exceeds-deadline": {
        "request": "/snowsky_disc_lab_supervision_deadline_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_deadline_ack_v1",
    },
    "producer-failure-cancels-sibling": {
        "request": "/snowsky_disc_lab_supervision_sibling_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_sibling_ack_v1",
    },
}

_COMPANION_OUTPUTS = {
    "consumer-exits-before-request": {
        "consumer": "SYNTHETIC_SUPERVISION_ROLE=consumer\n"
        "SYNTHETIC_SUPERVISION_EVENT=exit-before-request\n"
        "SYNTHETIC_SUPERVISION_QUEUE=not-attempted\n",
        "producer": "SYNTHETIC_SUPERVISION_ROLE=producer\n"
        "SYNTHETIC_SUPERVISION_EVENT=wait-request\n"
        "SYNTHETIC_SUPERVISION_QUEUE=created\n",
    },
    "producer-exits-before-ack": {
        "consumer": "SYNTHETIC_SUPERVISION_ROLE=consumer\n"
        "SYNTHETIC_SUPERVISION_EVENT=receive-request-send-ack-wait\n"
        "SYNTHETIC_SUPERVISION_QUEUE=opened\n",
        "producer": "SYNTHETIC_SUPERVISION_ROLE=producer\n"
        "SYNTHETIC_SUPERVISION_EVENT=send-request-exit-with-ack-pending\n"
        "SYNTHETIC_SUPERVISION_QUEUE=created-ack-pending\n",
    },
    "producer-exceeds-deadline": {
        "consumer": "SYNTHETIC_SUPERVISION_ROLE=consumer\n"
        "SYNTHETIC_SUPERVISION_EVENT=receive-request-send-ack-wait\n"
        "SYNTHETIC_SUPERVISION_QUEUE=opened\n",
        "producer": "SYNTHETIC_SUPERVISION_ROLE=producer\n"
        "SYNTHETIC_SUPERVISION_EVENT=request-sent-deadline-loop\n"
        "SYNTHETIC_SUPERVISION_QUEUE=created\n",
    },
    "producer-failure-cancels-sibling": {
        "consumer": "SYNTHETIC_SUPERVISION_ROLE=consumer\n"
        "SYNTHETIC_SUPERVISION_EVENT=wait-request\n"
        "SYNTHETIC_SUPERVISION_QUEUE=not-created\n",
        "producer": "SYNTHETIC_SUPERVISION_ROLE=producer\n"
        "SYNTHETIC_SUPERVISION_EVENT=exit-before-request\n"
        "SYNTHETIC_SUPERVISION_QUEUE=not-attempted\n",
    },
}
_EXPECTED_OUTPUTS = {
    "normal": {
        "consumer": handoff.CONSUMER_OUTPUT,
        "producer": handoff.PRODUCER_OUTPUT,
    },
    **_COMPANION_OUTPUTS,
}
_ACKNOWLEDGMENT_STATES = {
    "normal": "consumed",
    "consumer-exits-before-request": "not-sent",
    "producer-exits-before-ack": "queued-unconsumed",
    "producer-exceeds-deadline": "queued-unconsumed",
    "producer-failure-cancels-sibling": "not-created",
}


def _output_hash(scenario: str, role: str) -> str:
    return hashlib.sha256(_EXPECTED_OUTPUTS[scenario][role].encode("ascii")).hexdigest()


_POLICIES: dict[str, dict[str, Any]] = {
    "normal": {
        "failure_kind": "none",
        "failure_role": "none",
        "failure_reason": "none",
        "consumer_status": 0,
        "producer_status": 0,
        "term_sent": "none",
        "deadline_expired": "no",
        "protocol": "request-ack-verified",
        "queue_created": True,
    },
    "consumer-exits-before-request": {
        "failure_kind": "guest-exit",
        "failure_role": "consumer",
        "failure_reason": "exit:42",
        "consumer_status": 42,
        "producer_status": "signal",
        "term_sent": "producer",
        "deadline_expired": "no",
        "protocol": "consumer-exit-before-request",
        "queue_created": True,
    },
    "producer-exits-before-ack": {
        "failure_kind": "guest-exit",
        "failure_role": "producer",
        "failure_reason": "exit:43",
        "consumer_status": "signal",
        "producer_status": 43,
        "term_sent": "consumer",
        "deadline_expired": "no",
        "protocol": "producer-exit-before-ack",
        "queue_created": True,
    },
    "producer-exceeds-deadline": {
        "failure_kind": "deadline",
        "failure_role": "producer",
        "failure_reason": "deadline",
        "consumer_status": "signal",
        "producer_status": "signal",
        "term_sent": "consumer,producer",
        "deadline_expired": "yes",
        "protocol": "producer-deadline-exceeded",
        "queue_created": True,
    },
    "producer-failure-cancels-sibling": {
        "failure_kind": "guest-exit",
        "failure_role": "producer",
        "failure_reason": "exit:44",
        "consumer_status": "signal",
        "producer_status": 44,
        "term_sent": "consumer",
        "deadline_expired": "no",
        "protocol": "producer-failure-cancelled-consumer",
        "queue_created": False,
    },
}


def _sample_record(scenario: str, pids: tuple[int, int] = (101, 102)) -> str:
    policy = _POLICIES[scenario]
    consumer_status = policy["consumer_status"]
    producer_status = policy["producer_status"]
    if consumer_status == "signal":
        consumer_status = 143
    if producer_status == "signal":
        producer_status = 143
    consumer_reason = "signal:TERM" if consumer_status == 143 else f"exit:{consumer_status}"
    producer_reason = "signal:TERM" if producer_status == 143 else f"exit:{producer_status}"
    values = {
        "CASE": scenario,
        "CONSUMER_PID": str(pids[0]),
        "CONSUMER_STATUS": str(consumer_status),
        "CONSUMER_EXIT_REASON": consumer_reason,
        "CONSUMER_OUTPUT_SHA256": _output_hash(scenario, "consumer"),
        "CONSUMER_STARTED": "yes",
        "PRODUCER_PID": str(pids[1]),
        "PRODUCER_STATUS": str(producer_status),
        "PRODUCER_EXIT_REASON": producer_reason,
        "PRODUCER_OUTPUT_SHA256": _output_hash(scenario, "producer"),
        "PRODUCER_STARTED": "yes",
        "FAILURE_KIND": policy["failure_kind"],
        "FAILURE_ROLE": policy["failure_role"],
        "FAILURE_REASON": policy["failure_reason"],
        "DEADLINE_SECONDS": str(DEADLINE_SECONDS[scenario]),
        "DEADLINE_EXPIRED": policy["deadline_expired"],
        "TERM_SENT": policy["term_sent"],
        "KILL_SENT": "none",
        "CHILDREN_REAPED": "yes",
        "PROTOCOL": policy["protocol"],
    }
    return "".join(f"SUPERVISION_{key}={value}\n" for key, value in values.items()) + (
        "SUPERVISION_CASE_END\n"
    )


EXPECTED_CONTAINER_OUTPUT = "".join(_sample_record(scenario) for scenario in SCENARIOS)


def _failure(category: str, stage: str) -> dict[str, Any]:
    return {"status": "failed", "failure": {"category": category, "stage": stage}}


def _status_reason(status: int, reason: str) -> bool:
    if status == 143:
        return reason == "signal:TERM"
    if status == 137:
        return reason == "signal:KILL"
    return reason == f"exit:{status}"


def _role_status(value: Any, expected: Any, reason: str) -> bool:
    if expected == "signal":
        return value in {143, 137} and _status_reason(value, reason)
    return isinstance(value, int) and value == expected and _status_reason(value, reason)


def _read_record(fields: dict[str, str], scenario: str) -> dict[str, Any] | None:
    policy = _POLICIES[scenario]
    try:
        consumer_pid = int(fields["CONSUMER_PID"])
        producer_pid = int(fields["PRODUCER_PID"])
        consumer_status = int(fields["CONSUMER_STATUS"])
        producer_status = int(fields["PRODUCER_STATUS"])
        deadline_seconds = int(fields["DEADLINE_SECONDS"])
    except (KeyError, ValueError):
        return None
    if (
        not (1 <= consumer_pid <= 1_000_000)
        or not (1 <= producer_pid <= 1_000_000)
        or consumer_pid == producer_pid
        or not (0 <= consumer_status <= 255)
        or not (0 <= producer_status <= 255)
        or deadline_seconds != DEADLINE_SECONDS[scenario]
        or fields.get("CONSUMER_STARTED") != "yes"
        or fields.get("PRODUCER_STARTED") != "yes"
        or fields.get("CHILDREN_REAPED") != "yes"
        or fields.get("CONSUMER_OUTPUT_SHA256") != _output_hash(scenario, "consumer")
        or fields.get("PRODUCER_OUTPUT_SHA256") != _output_hash(scenario, "producer")
        or fields.get("PROTOCOL") != policy["protocol"]
        or fields.get("FAILURE_KIND") != policy["failure_kind"]
        or fields.get("FAILURE_ROLE") != policy["failure_role"]
        or fields.get("FAILURE_REASON") != policy["failure_reason"]
        or fields.get("DEADLINE_EXPIRED") != policy["deadline_expired"]
        or fields.get("TERM_SENT") != policy["term_sent"]
    ):
        return None

    consumer_reason = fields.get("CONSUMER_EXIT_REASON", "")
    producer_reason = fields.get("PRODUCER_EXIT_REASON", "")
    if not _role_status(consumer_status, policy["consumer_status"], consumer_reason):
        return None
    if not _role_status(producer_status, policy["producer_status"], producer_reason):
        return None
    kill_sent = fields.get("KILL_SENT", "")
    if kill_sent not in {"none", "consumer", "producer", "consumer,producer"}:
        return None
    expected_kills = [
        role
        for role, status in (("consumer", consumer_status), ("producer", producer_status))
        if status == 137
    ]
    normalized_kills = [] if kill_sent == "none" else kill_sent.split(",")
    if normalized_kills != expected_kills:
        return None

    children = {
        "consumer": {
            "pid": consumer_pid,
            "status": consumer_status,
            "exit_reason": consumer_reason,
            "reaped": True,
            "stdout_sha256": fields["CONSUMER_OUTPUT_SHA256"],
        },
        "producer": {
            "pid": producer_pid,
            "status": producer_status,
            "exit_reason": producer_reason,
            "reaped": True,
            "stdout_sha256": fields["PRODUCER_OUTPUT_SHA256"],
        },
    }
    failure = None
    if policy["failure_kind"] != "none":
        failure = {
            "kind": policy["failure_kind"],
            "role": policy["failure_role"],
            "reason": policy["failure_reason"],
        }
    term_sent = [] if policy["term_sent"] == "none" else policy["term_sent"].split(",")
    return {
        "scenario": scenario,
        "status": "passed",
        "protocol": policy["protocol"],
        "acknowledgment_state": _ACKNOWLEDGMENT_STATES[scenario],
        "children": children,
        "failure": failure,
        "deadline": {
            "seconds": deadline_seconds,
            "expired": policy["deadline_expired"] == "yes",
            "term_sent": term_sent,
            "kill_sent": normalized_kills,
        },
        "term_sent": term_sent,
        "kill_sent": normalized_kills,
        "sibling_reaped": failure is not None
        and all(child["reaped"] for child in children.values()),
        "queue_names": dict(QUEUE_NAMES[scenario]),
        "queue_creation_observed": policy["queue_created"],
        "actual_qemu_processes": True,
    }


def parse_execution_output(output: str, *, wrapper_exit_code: int = 0) -> dict[str, Any]:
    """Accept only the fixed matrix; suppress all unrecognized diagnostics."""
    if wrapper_exit_code != 0:
        return _failure("supervisor-wrapper", "supervisor_exit")
    try:
        encoded = output.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        return _failure("supervisor-wrapper", "output_not_ascii")
    if len(encoded) > OUTPUT_LIMIT_BYTES:
        return _failure("supervisor-wrapper", "output_limit")

    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in output.splitlines():
        if line.startswith("SUPERVISION_CASE="):
            if current is not None:
                return _failure("supervisor-wrapper", "record_nesting")
            scenario = line.partition("=")[2]
            if scenario not in SCENARIOS:
                return _failure("supervisor-wrapper", "scenario_unknown")
            current = {"CASE": scenario}
            continue
        if line == "SUPERVISION_CASE_END":
            if current is None:
                return _failure("supervisor-wrapper", "record_end")
            records.append(current)
            current = None
            continue
        if current is None or not line.startswith("SUPERVISION_"):
            return _failure("supervisor-wrapper", "output_mismatch")
        key, separator, value = line[len("SUPERVISION_") :].partition("=")
        if not separator or not re.fullmatch(r"[A-Z0-9_]{1,40}", key) or key in current:
            return _failure("supervisor-wrapper", "field_malformed")
        current[key] = value
    if current is not None or len(records) != len(SCENARIOS):
        return _failure("supervisor-wrapper", "matrix_incomplete")

    scenarios: list[dict[str, Any]] = []
    for expected_scenario, fields in zip(SCENARIOS, records, strict=True):
        if fields.get("CASE") != expected_scenario:
            return _failure("supervisor-wrapper", "matrix_order")
        expected_fields = {
            "CASE",
            "CONSUMER_PID",
            "CONSUMER_STATUS",
            "CONSUMER_EXIT_REASON",
            "CONSUMER_OUTPUT_SHA256",
            "CONSUMER_STARTED",
            "PRODUCER_PID",
            "PRODUCER_STATUS",
            "PRODUCER_EXIT_REASON",
            "PRODUCER_OUTPUT_SHA256",
            "PRODUCER_STARTED",
            "FAILURE_KIND",
            "FAILURE_ROLE",
            "FAILURE_REASON",
            "DEADLINE_SECONDS",
            "DEADLINE_EXPIRED",
            "TERM_SENT",
            "KILL_SENT",
            "CHILDREN_REAPED",
            "PROTOCOL",
        }
        if set(fields) != expected_fields:
            return _failure("supervisor-wrapper", "field_set")
        record = _read_record(fields, expected_scenario)
        if record is None:
            category = (
                "supervisor-wrapper"
                if "no" in (fields.get("CONSUMER_STARTED"), fields.get("PRODUCER_STARTED"))
                else "guest-observation"
            )
            return _failure(category, "child_status_or_observation")
        scenarios.append(record)
    return {
        "status": "passed",
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "actual_vs_simulated": {
            "guest_process_status": "actual fixed QEMU child wait statuses",
            "deadline_and_signals": "actual bounded supervisor timer and child PID signals",
            "container_lifecycle": (
                "actual owned Docker inspection and cleanup in hosted acceptance"
            ),
            "unit_test_fixtures": "simulated; not counted as acceptance evidence",
            "raw_guest_diagnostics_exported": False,
        },
    }


def _session_summary(session: dict[str, Any]) -> dict[str, Any]:
    execution = session.get("execution", {})
    return {
        "session_id": session.get("session_id"),
        "session_identity": session.get("session_identity"),
        "case": session.get("case"),
        "status": session.get("status"),
        "lifecycle": session.get("lifecycle", []),
        "execution": {
            key: execution[key]
            for key in (
                "exit_code",
                "duration_seconds",
                "stdout_sha256",
                "stdout_bytes",
                "timed_out",
                "terminated",
            )
            if key in execution
        },
        "observations": execution.get("supervision", {}),
        "isolation": session.get("isolation", {}),
        "cleanup": session.get("cleanup", {}),
    }


def _receipt(
    evidence: dict[str, Any], sessions: list[dict[str, Any]], *, status: str
) -> dict[str, Any]:
    guest = evidence.get("synthetic_ipc_supervision_guest", {})
    artifacts = [
        item for item in evidence.get("artifacts", []) if item.get("name") == "qemu-mipsel"
    ]
    first, second = (sessions + [{}, {}])[:2]
    first_cleanup = first.get("cleanup", {})
    first_observations = first.get("execution", {}).get("supervision", {})
    second_observations = second.get("execution", {}).get("supervision", {})
    scenario_rows = first_observations.get("scenarios", [])
    second_scenario_rows = second_observations.get("scenarios", [])
    both_matrices_passed = (
        len(scenario_rows) == len(SCENARIOS)
        and len(second_scenario_rows) == len(SCENARIOS)
        and first_observations.get("status") == "passed"
        and second_observations.get("status") == "passed"
    )
    both_reaped = both_matrices_passed and all(
        scenario.get("sibling_reaped") is True or scenario.get("failure") is None
        for session in (first, second)
        for scenario in session.get("execution", {}).get("supervision", {}).get("scenarios", [])
    )
    both_containers_removed = len(sessions) == 2 and all(
        session.get("cleanup", {}).get("container_removed") is True for session in sessions
    )
    fresh = {
        "first_container_removed_before_second": first_cleanup.get("container_removed") is True,
        "distinct_session_identities": bool(
            first.get("session_identity")
            and second.get("session_identity")
            and first.get("session_identity") != second.get("session_identity")
        ),
        "same_fixed_queue_names_recreated": bool(
            both_matrices_passed
            and all(
                scenario.get("queue_creation_observed") is True
                for scenario in second_observations.get("scenarios", [])
                if scenario.get("scenario") != "producer-failure-cancels-sibling"
            )
        ),
        "no_child_processes_left": both_reaped,
    }
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "scope": "fixed first-party MIPS32LE two-process failure supervision",
        "identities": {
            "qemu_mipsel_sha256": artifacts[0].get("sha256") if len(artifacts) == 1 else None,
            "guest_source_sha256": guest.get("source", {}).get("sha256"),
            "guest_elf_sha256": guest.get("elf", {}).get("sha256"),
        },
        "roles": {
            "consumer": "fixed request reader and acknowledgment sender",
            "producer": "fixed request sender and acknowledgment observer",
            "process_identity": "container-local QEMU PID recorded independently per role",
        },
        "scenarios": scenario_rows,
        "sessions": [_session_summary(session) for session in sessions],
        "fresh_container_repeat": fresh,
        "container_cleanup": {
            "all_containers_stopped_and_removed": all(
                session.get("cleanup", {}).get("container_removed") is True
                and session.get("cleanup", {}).get("container_stopped") is True
                for session in sessions
            )
            and len(sessions) == 2,
            "ownership_verified_before_removal": all(
                session.get("cleanup", {}).get("ownership_verified_before_removal") is True
                for session in sessions
            )
            and len(sessions) == 2,
            "all_private_tmpfs_released": all(
                session.get("cleanup", {}).get("private_tmpfs_released") is True
                for session in sessions
            )
            and len(sessions) == 2,
            "queue_state_persists_after_container_removal": (
                False if both_containers_removed else None
            ),
        },
        "container_isolation": {
            "profiles": [session.get("isolation", {}) for session in sessions],
            "ipc_mode": "none",
            "network_mode": "none",
            "new_mounts_or_sysctls": False,
        },
        "observations_are_actual_qemu": both_matrices_passed,
        "stock_compatibility": "UNVERIFIED",
        "m1_04_stock_boot": "NOT RUN",
    }
    if status == "failed":
        failed = next((session for session in sessions if session.get("status") != "passed"), {})
        cleanup = failed.get("cleanup", {})
        if (
            cleanup.get("container_removed") is False
            or cleanup.get("ownership_verified_before_removal") is not True
        ):
            result["failure"] = {"category": "container-cleanup"}
        else:
            observation = failed.get("execution", {}).get("supervision", {}).get("failure", {})
            result["failure"] = observation or {"category": "runtime-session"}
    return result


def _persist_receipt(store: Path, receipt: dict[str, Any]) -> None:
    with (store / "synthetic-ipc-supervision-acceptance.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")


def acceptance(inputs: Path, evidence: dict[str, Any], store: Path) -> dict[str, Any]:
    """Run the closed matrix in two separately inspected and removed containers."""
    from .synthetic_runtime import RuntimeRefused, launch

    sessions: list[dict[str, Any]] = []
    try:
        for suffix in ("first", "fresh"):
            session = launch(
                inputs,
                evidence,
                store,
                session_id=f"ipc-supervision-{suffix}",
                _case="ipc-supervision",
            )
            sessions.append(session)
            if (
                session.get("status") != "passed"
                or session.get("execution", {}).get("supervision", {}).get("status") != "passed"
                or session.get("cleanup", {}).get("container_removed") is not True
                or session.get("cleanup", {}).get("ownership_verified_before_removal") is not True
            ):
                raise RuntimeRefused("supervision session did not complete owned cleanup")
        if sessions[0].get("session_identity") == sessions[1].get("session_identity"):
            raise RuntimeRefused("supervision repeats did not receive separate identities")
        receipt = _receipt(evidence, sessions, status="passed")
        cleanup = receipt["container_cleanup"]
        if not all(receipt["fresh_container_repeat"].values()) or not all(
            cleanup[key]
            for key in (
                "all_containers_stopped_and_removed",
                "ownership_verified_before_removal",
                "all_private_tmpfs_released",
            )
        ):
            raise RuntimeRefused("supervision repeat or container cleanup was incomplete")
    except RuntimeRefused as exc:
        failed_session = getattr(exc, "receipt", None)
        if isinstance(failed_session, dict):
            sessions.append(failed_session)
        receipt = _receipt(evidence, sessions, status="failed")
        if store.is_dir():
            _persist_receipt(store, receipt)
        error = RuntimeRefused("synthetic IPC supervision acceptance failed")
        error.receipt = receipt
        raise error from exc
    _persist_receipt(store, receipt)
    return receipt
