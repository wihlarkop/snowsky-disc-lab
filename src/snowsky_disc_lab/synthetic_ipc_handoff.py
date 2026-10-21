"""Fixed two-process first-party POSIX queue acceptance and sanitized receipt."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "firmware-free-mips32le-synthetic-ipc-handoff/v1"
GUEST_SOURCE = "scripts/ci/fixtures/mips32le_posix_ipc_handoff.c"
GUEST_SOURCE_SHA256 = "f03c5fdd638038dfc96ee9684fe6a044cba2a16accbf219c31a3d81c042ed6aa"
GUEST_ELF = "mips32le-posix-ipc-handoff.elf"
OUTPUT_LIMIT_BYTES = 1024

REQUEST_QUEUE = "/snowsky_disc_lab_handoff_req_v1"
ACK_QUEUE = "/snowsky_disc_lab_handoff_ack_v1"
REQUEST_PAYLOAD = b"SNOWSKY_HANDOFF_REQUEST_V1"
ACK_PAYLOAD = b"SNOWSKY_HANDOFF_ACK_V1"
REQUEST_PAYLOAD_SHA256 = "a27944201ce35b61283b9b24f246c935070e81d7f2fc241170c8a47bb9b12354"
ACK_PAYLOAD_SHA256 = "35cc983cb77d4d7b5f3f2b489a92d3f5324d131328f354f23fb0a352545dfa7c"
REQUEST_PRIORITY = 7
ACK_PRIORITY = 3
QUEUE_ATTRIBUTES = {
    "permissions": "0600",
    "max_messages": 2,
    "max_message_bytes": 64,
}

CONSUMER_OUTPUT = (
    "HANDOFF_ROLE=consumer\n"
    "QUEUE_CREATE_REQUEST=ok\n"
    "QUEUE_CREATE_ACK=ok\n"
    "QUEUE_ATTRIBUTES_REQUEST=mode:0600,maxmsg:2,msgsize:64,curmsgs:0\n"
    "QUEUE_ATTRIBUTES_ACK=mode:0600,maxmsg:2,msgsize:64,curmsgs:0\n"
    "REQUEST_RECEIVE=ok\n"
    f"REQUEST_BYTES={len(REQUEST_PAYLOAD)}\n"
    f"REQUEST_SHA256={REQUEST_PAYLOAD_SHA256}\n"
    f"REQUEST_PRIORITY={REQUEST_PRIORITY}\n"
    "ACK_SEND=ok\n"
    "QUEUE_CLOSE_REQUEST=ok\n"
    "QUEUE_CLOSE_ACK=ok\n"
    "QUEUE_UNLINK_REQUEST=ok\n"
    "QUEUE_UNLINK_ACK=ok\n"
)
PRODUCER_OUTPUT = (
    "HANDOFF_ROLE=producer\n"
    "QUEUE_OPEN_REQUEST=ok\n"
    "QUEUE_OPEN_ACK=ok\n"
    "REQUEST_SEND=ok\n"
    "ACK_RECEIVE=ok\n"
    f"ACK_BYTES={len(ACK_PAYLOAD)}\n"
    f"ACK_SHA256={ACK_PAYLOAD_SHA256}\n"
    f"ACK_PRIORITY={ACK_PRIORITY}\n"
    "QUEUE_CLOSE_REQUEST=ok\n"
    "QUEUE_CLOSE_ACK=ok\n"
)
CONSUMER_SYSCALLS = [
    "mq_open",
    "mq_getsetattr",
    "mq_timedreceive",
    "mq_timedsend",
    "mq_unlink",
    "close",
]
PRODUCER_SYSCALLS = [
    "mq_open",
    "mq_getsetattr",
    "mq_timedsend",
    "mq_timedreceive",
    "close",
]
EXPECTED_CONTAINER_OUTPUT = (
    "HANDOFF_CONTAINER_SESSION=single\n"
    "GUEST_EXIT_CODE_CONSUMER=0\n"
    + CONSUMER_OUTPUT
    + "GUEST_EXIT_CODE_PRODUCER=0\n"
    + PRODUCER_OUTPUT
    + f"QEMU_SYSCALL_TRACE_CONSUMER={','.join(CONSUMER_SYSCALLS)}\n"
    + f"QEMU_SYSCALL_TRACE_PRODUCER={','.join(PRODUCER_SYSCALLS)}\n"
)

_ROLES = ("consumer", "producer")
_ERROR_STAGES = frozenset(
    {
        "fixed_argument",
        "clock_read",
        "create_request",
        "create_acknowledgment",
        "request_attributes",
        "acknowledgment_attributes",
        "queue_readiness_timeout",
        "open_request",
        "open_acknowledgment",
        "request_send",
        "request_timeout",
        "request_payload",
        "request_priority",
        "acknowledgment_send",
        "acknowledgment_timeout",
        "acknowledgment_payload",
        "acknowledgment_priority",
        "close_request",
        "close_acknowledgment",
        "unlink_request",
        "unlink_acknowledgment",
        "cleanup_close_request",
        "cleanup_close_acknowledgment",
        "cleanup_unlink_request",
        "cleanup_unlink_acknowledgment",
    }
)
_ERRNO_CODES = {
    "NONE": 0,
    "EACCES": 13,
    "EAGAIN": 11,
    "EBADF": 9,
    "EEXIST": 17,
    "EINTR": 4,
    "EINVAL": 22,
    "EMFILE": 24,
    "ENFILE": 23,
    "ENOENT": 2,
    "ENOMEM": 12,
    "ENOSPC": 28,
    "ENOSYS": 38,
    "EPERM": 1,
    "OTHER": -1,
}
_OPERATION_MARKERS = (
    ("QUEUE_CREATE_REQUEST=ok", "consumer_created_request_queue"),
    ("QUEUE_CREATE_ACK=ok", "consumer_created_acknowledgment_queue"),
    ("QUEUE_OPEN_REQUEST=ok", "producer_opened_request_queue"),
    ("QUEUE_OPEN_ACK=ok", "producer_opened_acknowledgment_queue"),
    ("REQUEST_SEND=ok", "producer_sent_request"),
    ("REQUEST_RECEIVE=ok", "consumer_received_request"),
    ("ACK_SEND=ok", "consumer_sent_acknowledgment"),
    ("ACK_RECEIVE=ok", "producer_received_acknowledgment"),
    ("QUEUE_CLOSE_REQUEST=ok", "closed_request_queue"),
    ("QUEUE_CLOSE_ACK=ok", "closed_acknowledgment_queue"),
    ("QUEUE_UNLINK_REQUEST=ok", "consumer_unlinked_request_queue"),
    ("QUEUE_UNLINK_ACK=ok", "consumer_unlinked_acknowledgment_queue"),
)


def _failure(
    stage: str, *, role: str = "container", errno_name: str = "NONE", errno_number: int = 0
) -> dict[str, Any]:
    return {
        "status": "failed",
        "failure": {
            "role": role,
            "stage": stage,
            "errno": errno_name,
            "errno_number": errno_number,
        },
    }


def _read_exit_codes(lines: list[str]) -> dict[str, int]:
    values: dict[str, int] = {}
    for role in _ROLES:
        key = f"GUEST_EXIT_CODE_{role.upper()}="
        matches = [line[len(key) :] for line in lines if line.startswith(key)]
        if len(matches) == 1 and re.fullmatch(r"[0-9]{1,3}", matches[0]):
            code = int(matches[0])
            if code <= 255:
                values[role] = code
    return values


def _read_failures(lines: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    fields = {
        "HANDOFF_ERROR_ROLE": "role",
        "HANDOFF_ERROR_STAGE": "stage",
        "HANDOFF_ERROR_NAME": "errno",
        "HANDOFF_ERROR_ERRNO": "errno_number",
    }
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if key == "HANDOFF_ERROR_ROLE":
            if current is not None:
                records.append(current)
            current = {"role": value}
        elif key in fields and current is not None:
            current[fields[key]] = value
    if current is not None:
        records.append(current)

    failures: list[dict[str, Any]] = []
    for record in records[:4]:
        role = record.get("role", "")
        stage = record.get("stage", "")
        errno_name = record.get("errno", "")
        errno_text = record.get("errno_number", "")
        if (
            role not in {*_ROLES, "unknown"}
            or stage not in _ERROR_STAGES
            or errno_name not in _ERRNO_CODES
            or not re.fullmatch(r"[0-9]{1,4}", errno_text)
        ):
            continue
        errno_number = int(errno_text)
        expected_number = _ERRNO_CODES[errno_name]
        if errno_number > 4095 or (expected_number >= 0 and expected_number != errno_number):
            continue
        failures.append(
            {
                "role": role,
                "stage": stage,
                "errno": errno_name,
                "errno_number": errno_number,
            }
        )
    return failures


def _success_observations() -> dict[str, Any]:
    return {
        "status": "passed",
        "processes": {
            "count": 2,
            "roles": list(_ROLES),
            "distinct_qemu_processes": True,
            "shared_container": True,
            "shared_private_ipc_namespace": True,
            "overlap_proven_by_request_ack_round_trip": True,
        },
        "guest_exit_codes": {"consumer": 0, "producer": 0},
        "queue_attributes": {
            "request": {**QUEUE_ATTRIBUTES, "current_messages": 0},
            "acknowledgment": {**QUEUE_ATTRIBUTES, "current_messages": 0},
        },
        "operations": [operation for marker, operation in _OPERATION_MARKERS],
        "messages": {
            "request": {
                "verified": True,
                "bytes": len(REQUEST_PAYLOAD),
                "sha256": REQUEST_PAYLOAD_SHA256,
                "priority": REQUEST_PRIORITY,
            },
            "acknowledgment": {
                "verified": True,
                "bytes": len(ACK_PAYLOAD),
                "sha256": ACK_PAYLOAD_SHA256,
                "priority": ACK_PRIORITY,
            },
        },
        "queue_cleanup": {
            "consumer_closed_both": True,
            "consumer_unlinked_both": True,
            "linked_at_exit": False,
        },
        "qemu_strace_syscalls": {
            "consumer": list(CONSUMER_SYSCALLS),
            "producer": list(PRODUCER_SYSCALLS),
        },
        "role_outputs": {
            "consumer": {
                "bytes": len(CONSUMER_OUTPUT.encode("ascii")),
                "sha256": hashlib.sha256(CONSUMER_OUTPUT.encode("ascii")).hexdigest(),
            },
            "producer": {
                "bytes": len(PRODUCER_OUTPUT.encode("ascii")),
                "sha256": hashlib.sha256(PRODUCER_OUTPUT.encode("ascii")).hexdigest(),
            },
        },
    }


def parse_execution_output(output: str) -> dict[str, Any]:
    """Parse only fixed guest outcomes; never retain arbitrary container text."""
    try:
        encoded = output.encode("ascii")
    except UnicodeEncodeError:
        return _failure("output_not_ascii")
    if len(encoded) > OUTPUT_LIMIT_BYTES:
        return _failure("output_limit")
    if output == EXPECTED_CONTAINER_OUTPUT:
        return _success_observations()

    lines = output.splitlines()
    exit_codes = _read_exit_codes(lines)
    failures = _read_failures(lines)
    if failures:
        failure = failures[0]
        result = _failure(
            failure["stage"],
            role=failure["role"],
            errno_name=failure["errno"],
            errno_number=failure["errno_number"],
        )
        result["guest_exit_codes"] = exit_codes
        if len(failures) > 1:
            result["additional_failures"] = failures[1:]
        result["completed_operations"] = [
            operation for marker, operation in _OPERATION_MARKERS if marker in lines
        ]
        return result
    for role in _ROLES:
        code = exit_codes.get(role)
        if code is not None and code != 0:
            return {
                **_failure(
                    f"{role}_timeout" if code == 124 else f"{role}_exit",
                    role=role,
                ),
                "guest_exit_codes": exit_codes,
                "failure": {
                    "role": role,
                    "stage": f"{role}_timeout" if code == 124 else f"{role}_exit",
                    "errno": "NONE",
                    "errno_number": 0,
                    "exit_code": code,
                },
            }
    for role in _ROLES:
        if f"HANDOFF_ROLE={role}" not in lines:
            return {
                **_failure(f"{role}_output_missing", role=role),
                "guest_exit_codes": exit_codes,
            }
    return {
        **_failure("output_mismatch"),
        "guest_exit_codes": exit_codes,
        "completed_operations": [
            operation for marker, operation in _OPERATION_MARKERS if marker in lines
        ],
    }


def _session_summary(session: dict[str, Any]) -> dict[str, Any]:
    execution = session.get("execution", {})
    handoff = execution.get("handoff", {})
    return {
        key: session[key]
        for key in ("session_id", "session_identity", "case", "status", "lifecycle")
        if key in session
    } | {
        "execution": {
            key: execution[key]
            for key in (
                "exit_code",
                "duration_seconds",
                "stdout_sha256",
                "stdout_bytes",
                "timed_out",
                "guest_exit_codes",
            )
            if key in execution
        },
        "observations": handoff,
        "isolation": session.get("isolation", {}),
        "cleanup": session.get("cleanup", {}),
    }


def _receipt(
    evidence: dict[str, Any], sessions: list[dict[str, Any]], *, status: str
) -> dict[str, Any]:
    guest = evidence.get("synthetic_ipc_handoff_guest", {})
    artifacts = [
        item for item in evidence.get("artifacts", []) if item.get("name") == "qemu-mipsel"
    ]
    first, second = (sessions + [{}, {}])[:2]
    first_cleanup = first.get("cleanup", {})
    first_observations = first.get("execution", {}).get("handoff", {})
    second_observations = second.get("execution", {}).get("handoff", {})
    identities_distinct = bool(
        first.get("session_identity")
        and second.get("session_identity")
        and first.get("session_identity") != second.get("session_identity")
    )
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "scope": "first-party synthetic two-process POSIX queue handoff",
        "protocol": {
            "request_queue": REQUEST_QUEUE,
            "acknowledgment_queue": ACK_QUEUE,
            "queue_attributes": dict(QUEUE_ATTRIBUTES),
            "request": {
                "payload_bytes": len(REQUEST_PAYLOAD),
                "payload_sha256": REQUEST_PAYLOAD_SHA256,
                "priority": REQUEST_PRIORITY,
            },
            "acknowledgment": {
                "payload_bytes": len(ACK_PAYLOAD),
                "payload_sha256": ACK_PAYLOAD_SHA256,
                "priority": ACK_PRIORITY,
            },
        },
        "identities": {
            "qemu_mipsel_sha256": artifacts[0].get("sha256") if len(artifacts) == 1 else None,
            "guest_source_sha256": guest.get("source", {}).get("sha256"),
            "guest_elf_sha256": guest.get("elf", {}).get("sha256"),
        },
        "processes": {
            "roles": list(_ROLES),
            "distinct_qemu_processes": first_observations.get("processes", {}).get(
                "distinct_qemu_processes", False
            ),
            "shared_container_per_session": first_observations.get("processes", {}).get(
                "shared_container", False
            ),
            "shared_private_ipc_namespace": first_observations.get("processes", {}).get(
                "shared_private_ipc_namespace", False
            ),
            "overlap_proven_by_request_ack_round_trip": first_observations.get("processes", {}).get(
                "overlap_proven_by_request_ack_round_trip", False
            ),
            "ipc_mode": "none",
        },
        "sessions": [_session_summary(session) for session in sessions],
        "fresh_session_isolation": {
            "first_container_removed_before_second": first_cleanup.get("container_removed") is True,
            "distinct_session_identities": identities_distinct,
            "same_protocol_succeeded": (
                second.get("status") == "passed" and second_observations.get("status") == "passed"
            ),
        },
        "container_security": {
            "profiles": [session.get("isolation", {}) for session in sessions],
            "mqueue_mount_added": False,
            "limits_or_sysctls_changed": False,
        },
        "cleanup": {
            "all_containers_removed": all(
                session.get("cleanup", {}).get("container_removed") is True for session in sessions
            )
            and len(sessions) == 2,
            "all_private_tmpfs_released": all(
                session.get("cleanup", {}).get("private_tmpfs_released") is True
                for session in sessions
            )
            and len(sessions) == 2,
            "persistent_shared_queue": False,
        },
        "stock_compatibility": {
            "stock_ipc_compatibility": "UNVERIFIED",
            "m1_04_stock_boot": "NOT RUN",
        },
    }
    if status == "failed":
        errors = [
            session.get("execution", {}).get("handoff", {}).get("failure")
            for session in sessions
            if session.get("execution", {}).get("handoff", {}).get("status") == "failed"
        ]
        result["failure"] = (
            {"category": "guest-handoff", **errors[-1]}
            if errors
            else {"category": "session-or-cleanup-failed"}
        )
    return result


def _persist_receipt(store: Path, receipt: dict[str, Any]) -> None:
    path = store / "synthetic-ipc-handoff-acceptance.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")


def acceptance(inputs: Path, evidence: dict[str, Any], store: Path) -> dict[str, Any]:
    """Run the fixed protocol twice in independently owned, inspected containers."""
    from .synthetic_runtime import RuntimeRefused, launch

    sessions: list[dict[str, Any]] = []
    try:
        for suffix in ("first", "second"):
            session = launch(
                inputs,
                evidence,
                store,
                session_id=f"ipc-handoff-{suffix}",
                _case="ipc-handoff",
            )
            sessions.append(session)
            if (
                session.get("status") != "passed"
                or session.get("cleanup", {}).get("container_removed") is not True
            ):
                raise RuntimeRefused("handoff session did not complete owned cleanup")
        if sessions[0].get("session_identity") == sessions[1].get("session_identity"):
            raise RuntimeRefused("handoff sessions did not receive separate identities")
        receipt = _receipt(evidence, sessions, status="passed")
        if not receipt["cleanup"]["all_private_tmpfs_released"]:
            raise RuntimeRefused("handoff private state cleanup was incomplete")
    except RuntimeRefused as exc:
        if exc.receipt is not None:
            sessions.append(exc.receipt)
        receipt = _receipt(evidence, sessions, status="failed")
        _persist_receipt(store, receipt)
        error = RuntimeRefused("synthetic IPC handoff acceptance failed")
        error.receipt = receipt
        raise error from exc
    _persist_receipt(store, receipt)
    return receipt
