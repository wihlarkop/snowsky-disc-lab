"""Strict, deterministic reports over sanitized firmware-free Lab receipts."""

from __future__ import annotations

import json
import re
from typing import Any

MAX_RECEIPT_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA = "firmware-free-synthetic-runtime-acceptance/v1"
_TOP_KEYS = {
    "schema_version",
    "status",
    "identities",
    "guest_source_sha256",
    "synthetic_input_sha256",
    "isolation",
    "sessions",
    "host_refusals",
    "session_isolation",
    "posix_mqueue",
    "synthetic_ipc_handoff",
    "synthetic_ipc_supervision",
    "toolchain",
    "unsupported_or_unverified",
    "failure",
}
_BUILD_KEYS = {
    "schema_version",
    "status",
    "primary_build_status",
    "repeat_build_status",
    "host_resources_before_build",
    "host_resources_before_optional_repeat",
    "source_identity",
    "base_image",
    "qemu_source_review",
    "license_review",
    "build",
    "network_boundary",
    "apt_sandbox",
    "runtime_and_device_boundaries",
    "synthetic_execution_smoke",
    "synthetic_runtime",
    "elapsed_seconds",
}
_BUILD_SOURCE_KEYS = {
    "repository",
    "commit",
    "projection_digest",
    "source_lock_changed",
    "firmware_tree_fetched",
    "reviewed_file_sha256",
    "reviewed_file_bytes",
    "build_input_manifest_sha256",
}
_BUILD_BOUNDARY_KEYS = {
    "firmware_processed",
    "qemu_executable_invoked",
    "synthetic_guest_executed",
    "guest_booted",
    "binfmt_registered",
    "runtime_image_built",
    "container_image_published",
    "compiled_binary_published",
    "usb_or_hardware_accessed",
    "compatibility_claimed",
}
_BUILD_PAYLOAD_KEYS = {
    "qemu_version",
    "qemu_descriptor_sha256",
    "qemu_archives",
    "qemu_patch_sha256",
    "qemu_configure_flags",
    "shim_recipe_sha256",
    "shim_source_sha256",
    "artifact_sha256_and_elf",
    "debian_snapshot_inrelease",
    "debian_archive_keyring_sha256",
    "installed_package_bom_sha256",
    "installed_package_count",
    "installed_packages",
    "toolchain",
    "container_limits",
    "build_logs",
    "elapsed_seconds",
    "temporary_container_cleanup",
    "repeated_clean_build_comparison",
}
_SESSION_KEYS = {
    "session_id",
    "session_identity",
    "case",
    "status",
    "lifecycle",
    "execution",
    "isolation",
    "cleanup",
}
_CASES = {
    "filesystem": "synthetic-filesystem",
    "failure": "synthetic-expected-failure",
    "timeout": "synthetic-timeout",
    "mqueue-first": "synthetic-mqueue-first-session",
    "mqueue-second": "synthetic-mqueue-second-session",
    "ipc-handoff": "synthetic-ipc-handoff",
}
_FAILURE_CATEGORIES = {
    "queue-syscall",
    "queue-timeout",
    "fixed-probe-or-container-check-failed",
    "synthetic-ipc-handoff-failed",
}
_IPC_HANDOFF_SCHEMA = "firmware-free-mips32le-synthetic-ipc-handoff/v1"
_IPC_HANDOFF_ELF = "mips32le-posix-ipc-handoff.elf"
_IPC_HANDOFF_SOURCE_SHA256 = "f03c5fdd638038dfc96ee9684fe6a044cba2a16accbf219c31a3d81c042ed6aa"
_IPC_HANDOFF_REQUEST_SHA256 = "a27944201ce35b61283b9b24f246c935070e81d7f2fc241170c8a47bb9b12354"
_IPC_HANDOFF_ACK_SHA256 = "35cc983cb77d4d7b5f3f2b489a92d3f5324d131328f354f23fb0a352545dfa7c"
_IPC_HANDOFF_ROLES = ("consumer", "producer")
_IPC_HANDOFF_ROLE_OUTPUTS = {
    "consumer": {
        "bytes": 425,
        "sha256": "d093763953c4dfa3eda1c03b1fcda977ef41de090a6f64ebccb7d9d3c385cafd",
    },
    "producer": {
        "bytes": 239,
        "sha256": "ce265f3a0ee5c44e8aef6b9a89a31f848b3883618b361cafbbeca5f960aaff49",
    },
}
_IPC_HANDOFF_OPERATIONS = (
    "consumer_created_request_queue",
    "consumer_created_acknowledgment_queue",
    "producer_opened_request_queue",
    "producer_opened_acknowledgment_queue",
    "producer_sent_request",
    "consumer_received_request",
    "consumer_sent_acknowledgment",
    "producer_received_acknowledgment",
    "closed_request_queue",
    "closed_acknowledgment_queue",
    "consumer_unlinked_request_queue",
    "consumer_unlinked_acknowledgment_queue",
)
_IPC_HANDOFF_CONSUMER_SYSCALLS = (
    "mq_open",
    "mq_getsetattr",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_unlink",
    "close",
)
_IPC_HANDOFF_PRODUCER_SYSCALLS = (
    "mq_open",
    "mq_getsetattr",
    "mq_timedsend",
    "mq_timedreceive",
    "close",
)
_IPC_HANDOFF_ERROR_STAGES = {
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
    "consumer_exit",
    "producer_exit",
    "consumer_timeout",
    "producer_timeout",
    "consumer_output_missing",
    "producer_output_missing",
    "output_not_ascii",
    "output_limit",
    "output_mismatch",
}
_IPC_HANDOFF_ERRNOS = {
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
_IPC_SUPERVISION_SCHEMA = "firmware-free-mips32le-synthetic-ipc-supervision/v1"
_IPC_SUPERVISION_ELF = "mips32le-posix-ipc-supervision.elf"
_IPC_SUPERVISION_SOURCE_SHA256 = "1d151ccbe7fb4c0965ad6d9bf290de8e6caaed0ca0a2dc7067aba91749c52e9f"
_IPC_SUPERVISION_ROLES = ("consumer", "producer")
_IPC_SUPERVISION_SCENARIOS: dict[str, dict[str, Any]] = {
    "normal": {
        "protocol": "request-ack-verified",
        "request": "/snowsky_disc_lab_handoff_req_v1",
        "acknowledgment": "/snowsky_disc_lab_handoff_ack_v1",
        "acknowledgment_state": "consumed",
        "failure": None,
        "queue_created": True,
        "deadline_seconds": 5,
        "deadline_expired": False,
        "term_sent": [],
        "exit_statuses": {"consumer": 0, "producer": 0},
        "outputs": {
            "consumer": "d093763953c4dfa3eda1c03b1fcda977ef41de090a6f64ebccb7d9d3c385cafd",
            "producer": "ce265f3a0ee5c44e8aef6b9a89a31f848b3883618b361cafbbeca5f960aaff49",
        },
    },
    "consumer-exits-before-request": {
        "protocol": "consumer-exit-before-request",
        "request": "/snowsky_disc_lab_supervision_consumer_exit_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_consumer_exit_ack_v1",
        "acknowledgment_state": "not-sent",
        "failure": {"kind": "guest-exit", "reason": "exit:42", "role": "consumer"},
        "queue_created": True,
        "deadline_seconds": 5,
        "deadline_expired": False,
        "term_sent": ["producer"],
        "exit_statuses": {"consumer": 42, "producer": "signal"},
        "outputs": {
            "consumer": "6401cb6e5792066a4fe429e1c71ac9ee207475a11e1378d081a5a824728fffe7",
            "producer": "b3f90efbdd4d24751304f65d8c0a1aa3fbc33ea23ebdf3ca628200413a388b46",
        },
    },
    "producer-exits-before-ack": {
        "protocol": "producer-exit-before-ack",
        "request": "/snowsky_disc_lab_supervision_producer_exit_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_producer_exit_ack_v1",
        "acknowledgment_state": "queued-unconsumed",
        "failure": {"kind": "guest-exit", "reason": "exit:43", "role": "producer"},
        "queue_created": True,
        "deadline_seconds": 5,
        "deadline_expired": False,
        "term_sent": ["consumer"],
        "exit_statuses": {"consumer": "signal", "producer": 43},
        "outputs": {
            "consumer": "c6783bf9a27c62c8219a991cc0cd69833ebb0ef8d05a3ebd39bcb5a5e523af82",
            "producer": "7bec62279d63d589f2e7a468df162beacaf0d28ceaa1672eac72dca5203c2bd5",
        },
    },
    "producer-exceeds-deadline": {
        "protocol": "producer-deadline-exceeded",
        "request": "/snowsky_disc_lab_supervision_deadline_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_deadline_ack_v1",
        "acknowledgment_state": "queued-unconsumed",
        "failure": {"kind": "deadline", "reason": "deadline", "role": "producer"},
        "queue_created": True,
        "deadline_seconds": 2,
        "deadline_expired": True,
        "term_sent": ["consumer", "producer"],
        "exit_statuses": {"consumer": "signal", "producer": "signal"},
        "outputs": {
            "consumer": "c6783bf9a27c62c8219a991cc0cd69833ebb0ef8d05a3ebd39bcb5a5e523af82",
            "producer": "fa6a9d569be3e0904d59946b529d4eb1f86282b87dc186da6a234c1a5564b39c",
        },
    },
    "producer-failure-cancels-sibling": {
        "protocol": "producer-failure-cancelled-consumer",
        "request": "/snowsky_disc_lab_supervision_sibling_req_v1",
        "acknowledgment": "/snowsky_disc_lab_supervision_sibling_ack_v1",
        "acknowledgment_state": "not-created",
        "failure": {"kind": "guest-exit", "reason": "exit:44", "role": "producer"},
        "queue_created": False,
        "deadline_seconds": 5,
        "deadline_expired": False,
        "term_sent": ["consumer"],
        "exit_statuses": {"consumer": "signal", "producer": 44},
        "outputs": {
            "consumer": "23739fc116c4ec77cf310c3aaa37bf72d8f8043d86e3cbcc3e8a92222b882378",
            "producer": "11985b97bf703badbb637e8d30324a06feecb2cff90657766474f6dce99548c3",
        },
    },
}
_IPC_SUPERVISION_OUTPUT_LIMIT = 6144
_RUNTIME_LIFECYCLE = ["reserved", "created", "validated", "start-requested", "exited", "removed"]
_SUPERVISION_OBSERVATIONS = {
    "container_lifecycle": "actual owned Docker inspection and cleanup in hosted acceptance",
    "deadline_and_signals": "actual bounded supervisor timer and child PID signals",
    "guest_process_status": "actual fixed QEMU child wait statuses",
    "raw_guest_diagnostics_exported": False,
    "unit_test_fixtures": "simulated; not counted as acceptance evidence",
}


class CompatibilityEvidenceError(ValueError):
    """The input is not a recognized sanitized Lab runtime receipt."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CompatibilityEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise CompatibilityEvidenceError(f"invalid SHA-256 identity: {field}")
    return value


def _reject_nonstandard_constant(value: str) -> None:
    raise CompatibilityEvidenceError(f"invalid JSON constant: {value}")


def _validate_optional_sections(receipt: dict[str, Any]) -> None:
    if (
        receipt.get("status") == "passed"
        and {
            "isolation",
            "host_refusals",
            "session_isolation",
        }
        - receipt.keys()
    ):
        raise CompatibilityEvidenceError("incomplete passed synthetic runtime receipt")
    if "isolation" in receipt:
        _validate_isolation(receipt["isolation"])
    if "host_refusals" in receipt and (
        not isinstance(receipt["host_refusals"], list)
        or any(not isinstance(item, str) for item in receipt["host_refusals"])
    ):
        raise CompatibilityEvidenceError("invalid host_refusals section")
    if "session_isolation" in receipt and not isinstance(receipt["session_isolation"], str):
        raise CompatibilityEvidenceError("invalid session_isolation section")


def _validate_session(session: dict[str, Any], *, queue: bool = False) -> None:
    queue = queue or session.get("case", "").startswith("mqueue-")
    if "session_id" in session and (
        not isinstance(session["session_id"], str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", session["session_id"])
    ):
        raise CompatibilityEvidenceError("invalid session id")
    for field in ("session_identity",):
        if field in session and not isinstance(session[field], str):
            raise CompatibilityEvidenceError(f"invalid session {field}")
    if "lifecycle" in session and (
        not isinstance(session["lifecycle"], list)
        or any(not isinstance(item, str) for item in session["lifecycle"])
    ):
        raise CompatibilityEvidenceError("invalid session lifecycle")
    if "execution" in session:
        execution = session["execution"]
        allowed = {
            "exit_code",
            "duration_seconds",
            "stdout_sha256",
            "stdout_bytes",
            "timed_out",
            "terminated",
            "observations",
            "queue_syscall_error",
        }
        if not isinstance(execution, dict) or execution.keys() - allowed:
            raise CompatibilityEvidenceError("invalid session execution")
        if "exit_code" in execution and (
            not isinstance(execution["exit_code"], int) or isinstance(execution["exit_code"], bool)
        ):
            raise CompatibilityEvidenceError("invalid session exit code")
        if "duration_seconds" in execution:
            _nonnegative_number(execution["duration_seconds"], "execution.duration_seconds")
        if "stdout_sha256" in execution:
            _digest(execution["stdout_sha256"], "execution.stdout_sha256")
        if "stdout_bytes" in execution and (
            not isinstance(execution["stdout_bytes"], int)
            or isinstance(execution["stdout_bytes"], bool)
            or execution["stdout_bytes"] < 0
        ):
            raise CompatibilityEvidenceError("invalid session stdout byte count")
        for field in ("timed_out", "terminated"):
            if field in execution and not isinstance(execution[field], bool):
                raise CompatibilityEvidenceError(f"invalid execution {field}")
        if "observations" in execution:
            expected = {
                "input_read",
                "readonly_write_errno",
                "private_create_read",
                "temporary_create_read",
                "outside_write_errno",
                "host_path_errno",
                "fresh_session",
            }
            observations = execution["observations"]
            if not isinstance(observations, dict) or observations.keys() - expected:
                raise CompatibilityEvidenceError("invalid execution observations")
            if any(
                not isinstance(value, (str, int)) or isinstance(value, bool)
                for value in observations.values()
            ):
                raise CompatibilityEvidenceError("invalid execution observation value")
        if "queue_syscall_error" in execution and execution["queue_syscall_error"] is not None:
            error = execution["queue_syscall_error"]
            if (
                not queue
                or not isinstance(error, dict)
                or error.keys() != {"stage", "errno", "errno_number"}
                or not isinstance(error["stage"], str)
                or not isinstance(error["errno"], str)
                or not isinstance(error["errno_number"], int)
                or isinstance(error["errno_number"], bool)
            ):
                raise CompatibilityEvidenceError("invalid queue syscall error")
    if "cleanup" in session:
        cleanup = session["cleanup"]
        legacy_cleanup_fields = {
            "container_removed",
            "private_tmpfs_released",
            "host_metadata",
        }
        extended_cleanup_fields = legacy_cleanup_fields | {
            "container_stopped",
            "ownership_verified_before_removal",
            "container_stop_command",
        }
        if not isinstance(cleanup, dict) or cleanup.keys() - extended_cleanup_fields:
            raise CompatibilityEvidenceError("invalid session cleanup")
        if cleanup.keys() & (extended_cleanup_fields - legacy_cleanup_fields) and (
            cleanup.keys() != extended_cleanup_fields
        ):
            raise CompatibilityEvidenceError("incomplete extended session cleanup evidence")
        if "container_removed" in cleanup and not isinstance(cleanup["container_removed"], bool):
            raise CompatibilityEvidenceError("invalid container cleanup status")
        if "private_tmpfs_released" in cleanup and not isinstance(
            cleanup["private_tmpfs_released"], bool
        ):
            raise CompatibilityEvidenceError("invalid tmpfs cleanup status")
        if "host_metadata" in cleanup and not isinstance(cleanup["host_metadata"], str):
            raise CompatibilityEvidenceError("invalid retained host metadata")
        if "container_stopped" in cleanup and not isinstance(cleanup["container_stopped"], bool):
            raise CompatibilityEvidenceError("invalid container stopped status")
        if "ownership_verified_before_removal" in cleanup and not isinstance(
            cleanup["ownership_verified_before_removal"], bool
        ):
            raise CompatibilityEvidenceError("invalid container ownership evidence")
        if "container_stop_command" in cleanup and (
            not isinstance(cleanup["container_stop_command"], str)
            or cleanup["container_stop_command"] not in {"not-needed", "succeeded", "failed"}
        ):
            raise CompatibilityEvidenceError("invalid exact-container stop result")
        if cleanup.get("container_removed") is True and "removed" not in session.get(
            "lifecycle", []
        ):
            raise CompatibilityEvidenceError("container cleanup contradicts session lifecycle")
        if (
            cleanup.get("private_tmpfs_released") is True
            and cleanup.get("container_removed") is not True
        ):
            raise CompatibilityEvidenceError("tmpfs release contradicts container cleanup")
    if "isolation" in session:
        _validate_isolation(session["isolation"])
    if (
        session.get("status") == "passed"
        and {
            "session_id",
            "session_identity",
            "lifecycle",
            "execution",
            "cleanup",
            *({"isolation"} if queue else set()),
        }
        - session.keys()
    ):
        raise CompatibilityEvidenceError("incomplete passed runtime session")
    if session.get("status") == "passed":
        if any(
            item not in session["lifecycle"]
            for item in ("reserved", "created", "validated", "start-requested", "exited", "removed")
        ):
            raise CompatibilityEvidenceError("incomplete passed session lifecycle")
        execution_fields = {
            "exit_code",
            "duration_seconds",
            "stdout_sha256",
            "stdout_bytes",
            "timed_out",
            "terminated",
            "queue_syscall_error" if queue else "observations",
        }
        if session["execution"].keys() != execution_fields:
            raise CompatibilityEvidenceError("incomplete passed session execution")
        if (
            session["cleanup"].get("container_removed") is not True
            or session["cleanup"].get("private_tmpfs_released") is not True
        ):
            raise CompatibilityEvidenceError("incomplete passed session cleanup")
        if "container_stopped" in session["cleanup"] and (
            session["cleanup"]["container_stopped"] is not True
            or session["cleanup"]["ownership_verified_before_removal"] is not True
            or session["cleanup"]["container_stop_command"] == "failed"
            or session["cleanup"]["host_metadata"] != "retained; no recursive cleanup"
        ):
            raise CompatibilityEvidenceError("contradictory passed session cleanup evidence")
        execution = session["execution"]
        case = session["case"]
        expected_exit_timeout = {
            "filesystem": (0, False),
            "failure": (23, False),
            "timeout": (124, True),
            "mqueue-first": (0, False),
            "mqueue-second": (0, False),
        }[case]
        if (
            execution["exit_code"] != expected_exit_timeout[0]
            or execution["timed_out"] is not expected_exit_timeout[1]
            or execution["terminated"] is not True
        ):
            raise CompatibilityEvidenceError("session execution contradicts named case")
        if queue:
            if execution["queue_syscall_error"] is not None:
                raise CompatibilityEvidenceError("queue session execution contradicts named case")
        else:
            expected_observations = (
                {
                    "input_read": "ok",
                    "readonly_write_errno": 30,
                    "private_create_read": "ok",
                    "temporary_create_read": "ok",
                    "outside_write_errno": 30,
                    "host_path_errno": 2,
                    "fresh_session": "ok",
                }
                if case == "filesystem"
                else {}
            )
            if execution["observations"] != expected_observations:
                raise CompatibilityEvidenceError("session execution contradicts named case")


def _validate_isolation(value: Any) -> None:
    fields = {
        "mounts",
        "private_writable_tmpfs",
        "verified_host_config",
        "all_capabilities_dropped",
        "no_new_privileges",
        "uid_gid",
        "host_devices",
        "docker_socket",
        "host_home",
        "shared_source_cache",
        "guest_deadline_seconds",
        "timeout_probe_seconds",
        "term_to_kill_grace_seconds",
        "outer_deadline_seconds",
        "stdout_limit_bytes",
        "diagnostic_file_limit_bytes",
        "kernel_boundary",
    }
    if not isinstance(value, dict) or value.keys() != fields:
        raise CompatibilityEvidenceError("invalid runtime isolation fields")
    mounts = value["mounts"]
    if (
        not isinstance(mounts, list)
        or len(mounts) != 2
        or any(
            not isinstance(mount, dict)
            or mount.keys() != {"source", "target", "read_only"}
            or any(not isinstance(mount[key], str) for key in ("source", "target"))
            or not isinstance(mount["read_only"], bool)
            for mount in mounts
        )
    ):
        raise CompatibilityEvidenceError("invalid runtime isolation mounts")
    expected_tmpfs = {
        path: "rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=65534,gid=65534"
        for path in ("/session-data", "/session-tmp", "/session-diagnostics")
    }
    if value["private_writable_tmpfs"] != expected_tmpfs:
        raise CompatibilityEvidenceError("invalid private tmpfs configuration")
    host = value["verified_host_config"]
    host_keys = {
        "NetworkMode",
        "CapDrop",
        "ReadonlyRootfs",
        "Privileged",
        "Memory",
        "MemorySwap",
        "NanoCpus",
        "PidsLimit",
        "IpcMode",
        "Tmpfs",
    }
    if not isinstance(host, dict) or host.keys() != host_keys:
        raise CompatibilityEvidenceError("invalid verified host configuration")
    expected_host = {
        "NetworkMode": "none",
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "Privileged": False,
        "Memory": 256 * 1024**2,
        "MemorySwap": 256 * 1024**2,
        "NanoCpus": 1_000_000_000,
        "PidsLimit": 16,
        "IpcMode": "none",
        "Tmpfs": expected_tmpfs,
    }
    if host != expected_host:
        raise CompatibilityEvidenceError("unsafe verified host configuration")
    if mounts != [
        {"source": "<verified-execution-inputs>", "target": "/inputs", "read_only": True},
        {"source": "<owned-synthetic-input>", "target": "/synthetic-rootfs", "read_only": True},
    ]:
        raise CompatibilityEvidenceError("unsafe runtime isolation mounts")
    bool_fields = {
        "all_capabilities_dropped",
        "no_new_privileges",
        "host_devices",
        "docker_socket",
        "host_home",
        "shared_source_cache",
    }
    if any(not isinstance(value[field], bool) for field in bool_fields):
        raise CompatibilityEvidenceError("invalid runtime isolation boolean")
    if any(
        value[field] is not True for field in ("all_capabilities_dropped", "no_new_privileges")
    ) or any(
        value[field] is not False
        for field in ("host_devices", "docker_socket", "host_home", "shared_source_cache")
    ):
        raise CompatibilityEvidenceError("unsafe runtime isolation boundary")
    for field in (
        "guest_deadline_seconds",
        "timeout_probe_seconds",
        "term_to_kill_grace_seconds",
        "outer_deadline_seconds",
        "stdout_limit_bytes",
        "diagnostic_file_limit_bytes",
    ):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 0:
            raise CompatibilityEvidenceError(f"invalid runtime isolation limit: {field}")
    if not isinstance(value["uid_gid"], str) or not isinstance(value["kernel_boundary"], str):
        raise CompatibilityEvidenceError("invalid runtime isolation description")
    if value["uid_gid"] != "65534:65534" or value["kernel_boundary"] != (
        "Docker-managed kernel interfaces; QEMU user mode shares host kernel"
    ):
        raise CompatibilityEvidenceError("unexpected runtime isolation identity")
    expected_limits = {
        "guest_deadline_seconds": 5,
        "timeout_probe_seconds": 2,
        "term_to_kill_grace_seconds": 1,
        "outer_deadline_seconds": 15,
        "stdout_limit_bytes": 1024,
        "diagnostic_file_limit_bytes": 65536,
    }
    if any(value[key] != expected for key, expected in expected_limits.items()):
        raise CompatibilityEvidenceError("unexpected runtime isolation limits")


def _validate_failure(value: Any, field: str) -> None:
    allowed = {"category", "stage", "errno", "errno_number"}
    if (
        not isinstance(value, dict)
        or value.keys() - allowed
        or not isinstance(value.get("category"), str)
        or value["category"] not in _FAILURE_CATEGORIES
        or ("stage" in value and not isinstance(value["stage"], str))
        or ("errno" in value and not isinstance(value["errno"], str))
        or (
            "errno_number" in value
            and (
                not isinstance(value["errno_number"], int)
                or isinstance(value["errno_number"], bool)
            )
        )
    ):
        raise CompatibilityEvidenceError(f"invalid {field} record")


def _expect_object(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.keys() != fields:
        raise CompatibilityEvidenceError(f"invalid {field} fields")
    return value


def _validate_ipc_failure(value: Any, *, category: bool) -> dict[str, Any]:
    allowed = {"role", "stage", "errno", "errno_number", "exit_code"}
    required = {"role", "stage", "errno", "errno_number"}
    if category:
        allowed.add("category")
        required.add("category")
    if (
        not isinstance(value, dict)
        or value.keys() - allowed
        or required - value.keys()
        or not isinstance(value.get("role"), str)
        or value["role"] not in {*_IPC_HANDOFF_ROLES, "container", "unknown"}
        or not isinstance(value.get("stage"), str)
        or value["stage"] not in _IPC_HANDOFF_ERROR_STAGES
        or not isinstance(value.get("errno"), str)
        or value["errno"] not in _IPC_HANDOFF_ERRNOS
        or not isinstance(value.get("errno_number"), int)
        or isinstance(value.get("errno_number"), bool)
        or value["errno_number"] < 0
        or value["errno_number"] > 4095
        or (
            _IPC_HANDOFF_ERRNOS[value["errno"]] >= 0
            and value["errno_number"] != _IPC_HANDOFF_ERRNOS[value["errno"]]
        )
        or (
            "exit_code" in value
            and (
                not isinstance(value["exit_code"], int)
                or isinstance(value["exit_code"], bool)
                or not 0 <= value["exit_code"] <= 255
            )
        )
    ):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff failure details")
    return value


def _validate_ipc_exit_codes(value: Any, field: str, *, complete: bool) -> dict[str, int]:
    if not isinstance(value, dict) or value.keys() - set(_IPC_HANDOFF_ROLES):
        raise CompatibilityEvidenceError(f"invalid {field}")
    if complete and value.keys() != set(_IPC_HANDOFF_ROLES):
        raise CompatibilityEvidenceError(f"incomplete {field}")
    if any(
        not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255
        for code in value.values()
    ):
        raise CompatibilityEvidenceError(f"invalid {field}")
    return value


def _matches_fixed_json(value: Any, expected: Any) -> bool:
    """Compare receipt JSON while distinguishing booleans from numbers."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(
            _matches_fixed_json(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _matches_fixed_json(actual, wanted)
            for actual, wanted in zip(value, expected, strict=True)
        )
    return value == expected


def _validate_ipc_observations(value: Any, *, passed: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff observations")
    if passed:
        fields = {
            "status",
            "processes",
            "guest_exit_codes",
            "queue_attributes",
            "operations",
            "messages",
            "queue_cleanup",
            "qemu_strace_syscalls",
            "role_outputs",
        }
        observations = _expect_object(value, fields, "synthetic IPC handoff observations")
        expected_processes = {
            "count": 2,
            "roles": list(_IPC_HANDOFF_ROLES),
            "distinct_qemu_processes": True,
            "shared_container": True,
            "shared_private_ipc_namespace": True,
            "overlap_proven_by_request_ack_round_trip": True,
        }
        if observations["status"] != "passed" or not _matches_fixed_json(
            observations["processes"], expected_processes
        ):
            raise CompatibilityEvidenceError("contradictory synthetic IPC handoff processes")
        if not _matches_fixed_json(
            observations["guest_exit_codes"], {"consumer": 0, "producer": 0}
        ):
            raise CompatibilityEvidenceError("contradictory synthetic IPC handoff guest exits")
        attributes = {
            "permissions": "0600",
            "max_messages": 2,
            "max_message_bytes": 64,
            "current_messages": 0,
        }
        if not _matches_fixed_json(
            observations["queue_attributes"],
            {"request": attributes, "acknowledgment": attributes},
        ):
            raise CompatibilityEvidenceError("contradictory synthetic IPC queue attributes")
        if not _matches_fixed_json(observations["operations"], list(_IPC_HANDOFF_OPERATIONS)):
            raise CompatibilityEvidenceError("contradictory synthetic IPC handoff operations")
        expected_messages = {
            "request": {
                "verified": True,
                "bytes": 26,
                "sha256": _IPC_HANDOFF_REQUEST_SHA256,
                "priority": 7,
            },
            "acknowledgment": {
                "verified": True,
                "bytes": 22,
                "sha256": _IPC_HANDOFF_ACK_SHA256,
                "priority": 3,
            },
        }
        if not _matches_fixed_json(observations["messages"], expected_messages):
            raise CompatibilityEvidenceError("contradictory synthetic IPC request/ack evidence")
        if not _matches_fixed_json(
            observations["queue_cleanup"],
            {
                "consumer_closed_both": True,
                "consumer_unlinked_both": True,
                "linked_at_exit": False,
            },
        ):
            raise CompatibilityEvidenceError("contradictory synthetic IPC queue cleanup")
        expected_syscalls = {
            "consumer": list(_IPC_HANDOFF_CONSUMER_SYSCALLS),
            "producer": list(_IPC_HANDOFF_PRODUCER_SYSCALLS),
        }
        if not _matches_fixed_json(observations["qemu_strace_syscalls"], expected_syscalls):
            raise CompatibilityEvidenceError("contradictory synthetic IPC syscall observations")
        role_outputs = _expect_object(
            observations["role_outputs"], set(_IPC_HANDOFF_ROLES), "synthetic IPC role outputs"
        )
        for role in _IPC_HANDOFF_ROLES:
            output = _expect_object(
                role_outputs[role], {"bytes", "sha256"}, f"synthetic IPC {role} output"
            )
            if not _matches_fixed_json(output, _IPC_HANDOFF_ROLE_OUTPUTS[role]):
                raise CompatibilityEvidenceError(f"contradictory synthetic IPC {role} output")
        return observations

    allowed = {
        "status",
        "failure",
        "guest_exit_codes",
        "additional_failures",
        "completed_operations",
    }
    if value.keys() - allowed or value.get("status") != "failed" or "failure" not in value:
        raise CompatibilityEvidenceError("invalid failed synthetic IPC handoff observations")
    if "failure" in value:
        _validate_ipc_failure(value["failure"], category=False)
    if "guest_exit_codes" in value:
        _validate_ipc_exit_codes(
            value["guest_exit_codes"], "IPC handoff guest exits", complete=False
        )
    if "additional_failures" in value:
        failures = value["additional_failures"]
        if not isinstance(failures, list) or len(failures) > 3:
            raise CompatibilityEvidenceError("invalid additional IPC handoff failures")
        for failure in failures:
            _validate_ipc_failure(failure, category=False)
    if "completed_operations" in value:
        completed = value["completed_operations"]
        if (
            not isinstance(completed, list)
            or any(not isinstance(item, str) for item in completed)
            or any(item not in _IPC_HANDOFF_OPERATIONS for item in completed)
            or len(set(completed)) != len(completed)
            or completed != [item for item in _IPC_HANDOFF_OPERATIONS if item in completed]
        ):
            raise CompatibilityEvidenceError("invalid completed IPC handoff operations")
    return value


def _validate_ipc_session(session: Any, position: int) -> dict[str, Any]:
    fields = {
        "session_id",
        "session_identity",
        "case",
        "status",
        "lifecycle",
        "execution",
        "observations",
        "isolation",
        "cleanup",
    }
    session = _expect_object(session, fields, "synthetic IPC handoff session")
    label = ("first", "second")[position]
    identity = session["session_identity"]
    if (
        session["session_id"] != f"ipc-handoff-{label}"
        or not isinstance(identity, str)
        or not identity
        or len(identity) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in identity)
        or session["case"] != "ipc-handoff"
        or not isinstance(session["status"], str)
        or session["status"] not in {"passed", "quarantined"}
    ):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff session identity or status")
    lifecycle = session["lifecycle"]
    lifecycle_order = ["reserved", "created", "validated", "start-requested", "exited", "removed"]
    if (
        not isinstance(lifecycle, list)
        or any(not isinstance(item, str) for item in lifecycle)
        or any(item not in lifecycle_order for item in lifecycle)
        or len(set(lifecycle)) != len(lifecycle)
        or [item for item in lifecycle_order if item in lifecycle] != lifecycle
    ):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff lifecycle")
    execution_fields = {
        "exit_code",
        "duration_seconds",
        "stdout_sha256",
        "stdout_bytes",
        "timed_out",
        "guest_exit_codes",
    }
    execution = session["execution"]
    if not isinstance(execution, dict) or execution.keys() - execution_fields:
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff execution fields")
    if "exit_code" in execution and (
        not isinstance(execution["exit_code"], int) or isinstance(execution["exit_code"], bool)
    ):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff exit code")
    if "duration_seconds" in execution:
        _nonnegative_number(execution["duration_seconds"], "IPC handoff duration")
    if "stdout_sha256" in execution:
        _digest(execution["stdout_sha256"], "IPC handoff stdout_sha256")
    if "stdout_bytes" in execution and (
        not isinstance(execution["stdout_bytes"], int)
        or isinstance(execution["stdout_bytes"], bool)
        or not 0 <= execution["stdout_bytes"] <= 1024
    ):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff stdout length")
    if "timed_out" in execution and not isinstance(execution["timed_out"], bool):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff timeout status")
    if "guest_exit_codes" in execution:
        _validate_ipc_exit_codes(
            execution["guest_exit_codes"], "IPC handoff guest exits", complete=False
        )
    if session["status"] == "passed":
        if (
            lifecycle != lifecycle_order
            or execution.keys()
            != {
                "exit_code",
                "duration_seconds",
                "stdout_sha256",
                "stdout_bytes",
                "timed_out",
                "guest_exit_codes",
            }
            or execution["exit_code"] != 0
            or execution["timed_out"] is not False
            or execution["guest_exit_codes"] != {"consumer": 0, "producer": 0}
            or execution["stdout_bytes"] == 0
        ):
            raise CompatibilityEvidenceError("contradictory successful IPC handoff execution")

    isolation = session["isolation"]
    if isolation:
        _validate_isolation(isolation)
    elif session["status"] == "passed":
        raise CompatibilityEvidenceError("passed IPC handoff session lacks isolation evidence")

    cleanup = session["cleanup"]
    legacy_cleanup_fields = {
        "container_removed",
        "private_tmpfs_released",
        "host_metadata",
    }
    extended_cleanup_fields = legacy_cleanup_fields | {
        "container_stopped",
        "ownership_verified_before_removal",
        "container_stop_command",
    }
    if not isinstance(cleanup, dict) or cleanup.keys() - extended_cleanup_fields:
        raise CompatibilityEvidenceError("invalid IPC handoff cleanup evidence")
    if cleanup.keys() & (extended_cleanup_fields - legacy_cleanup_fields) and (
        cleanup.keys() != extended_cleanup_fields
    ):
        raise CompatibilityEvidenceError("incomplete extended IPC handoff cleanup evidence")
    if (
        any(
            key in cleanup and not isinstance(cleanup[key], bool)
            for key in (
                "container_removed",
                "private_tmpfs_released",
                "container_stopped",
                "ownership_verified_before_removal",
            )
        )
        or (
            "host_metadata" in cleanup
            and cleanup["host_metadata"] != "retained; no recursive cleanup"
        )
        or (
            "container_stop_command" in cleanup
            and (
                not isinstance(cleanup["container_stop_command"], str)
                or cleanup["container_stop_command"] not in {"not-needed", "succeeded", "failed"}
            )
        )
    ):
        raise CompatibilityEvidenceError("invalid IPC handoff cleanup evidence")
    if (
        cleanup.get("private_tmpfs_released") is True
        and cleanup.get("container_removed") is not True
    ):
        raise CompatibilityEvidenceError("contradictory IPC handoff cleanup evidence")
    expected_cleanup = {
        "container_removed": True,
        "private_tmpfs_released": True,
        "host_metadata": "retained; no recursive cleanup",
    }
    if cleanup.keys() == extended_cleanup_fields:
        expected_cleanup.update(
            {
                "container_stopped": True,
                "ownership_verified_before_removal": True,
                "container_stop_command": cleanup["container_stop_command"],
            }
        )
    if session["status"] == "passed" and (
        cleanup != expected_cleanup or cleanup.get("container_stop_command") == "failed"
    ):
        raise CompatibilityEvidenceError("incomplete successful IPC handoff cleanup")
    if cleanup.get("container_removed") is True and "removed" not in lifecycle:
        raise CompatibilityEvidenceError("IPC handoff lifecycle contradicts container cleanup")

    if not isinstance(session["observations"], dict):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff observations")
    observation_status = session["observations"].get("status")
    if session["status"] == "passed" and observation_status != "passed":
        raise CompatibilityEvidenceError("passed IPC handoff session lacks successful observations")
    if observation_status == "passed":
        observations = _validate_ipc_observations(session["observations"], passed=True)
    elif observation_status == "failed":
        observations = _validate_ipc_observations(session["observations"], passed=False)
    elif session["observations"] == {} and session["status"] == "quarantined":
        observations = session["observations"]
    else:
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff observation status")
    if session["status"] == "passed":
        if observations["guest_exit_codes"] != execution["guest_exit_codes"]:
            raise CompatibilityEvidenceError("IPC observations contradict process exits")
    elif observations.get("status") == "failed" and "guest_exit_codes" in observations:
        if (
            "guest_exit_codes" in execution
            and observations["guest_exit_codes"] != execution["guest_exit_codes"]
        ):
            raise CompatibilityEvidenceError("IPC failure observations contradict process exits")
    return session


def _validate_ipc_handoff(
    receipt: dict[str, Any], artifacts: dict[str, str], *, parent_status: str
) -> dict[str, Any] | None:
    if "synthetic_ipc_handoff" not in receipt:
        return None
    handoff = receipt["synthetic_ipc_handoff"]
    if not isinstance(handoff, dict):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff receipt")
    status = handoff.get("status")
    fields = {
        "schema_version",
        "status",
        "scope",
        "protocol",
        "identities",
        "processes",
        "sessions",
        "fresh_session_isolation",
        "container_security",
        "cleanup",
        "stock_compatibility",
    }
    if status == "failed":
        fields.add("failure")
    handoff = _expect_object(handoff, fields, "synthetic IPC handoff receipt")
    if (
        handoff["schema_version"] != _IPC_HANDOFF_SCHEMA
        or not isinstance(status, str)
        or status not in {"passed", "failed"}
    ):
        raise CompatibilityEvidenceError("unsupported synthetic IPC handoff schema or status")
    if handoff["scope"] != "first-party synthetic two-process POSIX queue handoff":
        raise CompatibilityEvidenceError("unsupported synthetic IPC handoff scope")
    expected_protocol = {
        "request_queue": "/snowsky_disc_lab_handoff_req_v1",
        "acknowledgment_queue": "/snowsky_disc_lab_handoff_ack_v1",
        "queue_attributes": {
            "permissions": "0600",
            "max_messages": 2,
            "max_message_bytes": 64,
        },
        "request": {
            "payload_bytes": 26,
            "payload_sha256": _IPC_HANDOFF_REQUEST_SHA256,
            "priority": 7,
        },
        "acknowledgment": {
            "payload_bytes": 22,
            "payload_sha256": _IPC_HANDOFF_ACK_SHA256,
            "priority": 3,
        },
    }
    if not _matches_fixed_json(handoff["protocol"], expected_protocol):
        raise CompatibilityEvidenceError("contradictory synthetic IPC handoff protocol")
    identities = _expect_object(
        handoff["identities"],
        {"qemu_mipsel_sha256", "guest_source_sha256", "guest_elf_sha256"},
        "synthetic IPC handoff identities",
    )
    for key, value in identities.items():
        _digest(value, f"synthetic_ipc_handoff.identities.{key}")
    if (
        identities["qemu_mipsel_sha256"] != artifacts["qemu-mipsel"]
        or identities["guest_source_sha256"] != _IPC_HANDOFF_SOURCE_SHA256
        or identities["guest_elf_sha256"] != artifacts[_IPC_HANDOFF_ELF]
    ):
        raise CompatibilityEvidenceError("contradictory synthetic IPC handoff artifact identities")

    processes = _expect_object(
        handoff["processes"],
        {
            "roles",
            "distinct_qemu_processes",
            "shared_container_per_session",
            "shared_private_ipc_namespace",
            "overlap_proven_by_request_ack_round_trip",
            "ipc_mode",
        },
        "IPC handoff process summary",
    )
    if (
        processes["roles"] != list(_IPC_HANDOFF_ROLES)
        or processes["ipc_mode"] != "none"
        or any(
            not isinstance(processes[field], bool)
            for field in (
                "distinct_qemu_processes",
                "shared_container_per_session",
                "shared_private_ipc_namespace",
                "overlap_proven_by_request_ack_round_trip",
            )
        )
    ):
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff process summary")

    sessions = handoff["sessions"]
    if not isinstance(sessions, list) or not 1 <= len(sessions) <= 2:
        raise CompatibilityEvidenceError("invalid synthetic IPC handoff sessions")
    parsed_sessions = [
        _validate_ipc_session(session, index) for index, session in enumerate(sessions)
    ]
    if status == "passed" and (
        len(parsed_sessions) != 2
        or any(session["status"] != "passed" for session in parsed_sessions)
    ):
        raise CompatibilityEvidenceError("incomplete passed synthetic IPC handoff sessions")
    first = parsed_sessions[0]
    second = parsed_sessions[1] if len(parsed_sessions) == 2 else {}
    if status == "passed" and (
        first["execution"]["stdout_bytes"] != second["execution"]["stdout_bytes"]
        or first["execution"]["stdout_sha256"] != second["execution"]["stdout_sha256"]
        or first["observations"]["role_outputs"] != second["observations"]["role_outputs"]
    ):
        raise CompatibilityEvidenceError("contradictory repeated IPC handoff outputs")
    first_observations = first["observations"]
    observed_processes = first_observations.get("processes", {})
    expected_processes = {
        "roles": list(_IPC_HANDOFF_ROLES),
        "distinct_qemu_processes": observed_processes.get("distinct_qemu_processes", False),
        "shared_container_per_session": observed_processes.get("shared_container", False),
        "shared_private_ipc_namespace": observed_processes.get(
            "shared_private_ipc_namespace", False
        ),
        "overlap_proven_by_request_ack_round_trip": observed_processes.get(
            "overlap_proven_by_request_ack_round_trip", False
        ),
        "ipc_mode": "none",
    }
    if not _matches_fixed_json(processes, expected_processes):
        raise CompatibilityEvidenceError("contradictory synthetic IPC handoff process summary")
    if status == "passed" and not all(
        processes[key]
        for key in (
            "distinct_qemu_processes",
            "shared_container_per_session",
            "shared_private_ipc_namespace",
            "overlap_proven_by_request_ack_round_trip",
        )
    ):
        raise CompatibilityEvidenceError("incomplete passed synthetic IPC process evidence")

    session_identities = [session["session_identity"] for session in parsed_sessions]
    identities_distinct = (
        len(session_identities) == 2 and session_identities[0] != session_identities[1]
    )
    fresh = _expect_object(
        handoff["fresh_session_isolation"],
        {
            "first_container_removed_before_second",
            "distinct_session_identities",
            "same_protocol_succeeded",
        },
        "synthetic IPC fresh-session isolation",
    )
    expected_fresh = {
        "first_container_removed_before_second": (
            first["cleanup"].get("container_removed") is True
        ),
        "distinct_session_identities": identities_distinct,
        "same_protocol_succeeded": (
            len(parsed_sessions) == 2
            and second.get("status") == "passed"
            and second.get("observations", {}).get("status") == "passed"
        ),
    }
    if any(not isinstance(value, bool) for value in fresh.values()) or fresh != expected_fresh:
        raise CompatibilityEvidenceError("contradictory synthetic IPC fresh-session isolation")
    if status == "passed" and not all(fresh.values()):
        raise CompatibilityEvidenceError("incomplete passed synthetic IPC session isolation")

    security = _expect_object(
        handoff["container_security"],
        {"profiles", "mqueue_mount_added", "limits_or_sysctls_changed"},
        "synthetic IPC container security",
    )
    profiles = security["profiles"]
    if not isinstance(profiles, list) or len(profiles) != len(parsed_sessions):
        raise CompatibilityEvidenceError("incomplete synthetic IPC session isolation profiles")
    for profile, session in zip(profiles, parsed_sessions, strict=True):
        if profile != session["isolation"]:
            raise CompatibilityEvidenceError(
                "contradictory synthetic IPC session isolation profile"
            )
        if profile:
            _validate_isolation(profile)
    if (
        security["mqueue_mount_added"] is not False
        or security["limits_or_sysctls_changed"] is not False
    ):
        raise CompatibilityEvidenceError("unsafe synthetic IPC container security boundary")

    cleanup = _expect_object(
        handoff["cleanup"],
        {"all_containers_removed", "all_private_tmpfs_released", "persistent_shared_queue"},
        "synthetic IPC cleanup summary",
    )
    expected_cleanup = {
        "all_containers_removed": len(parsed_sessions) == 2
        and all(session["cleanup"].get("container_removed") is True for session in parsed_sessions),
        "all_private_tmpfs_released": len(parsed_sessions) == 2
        and all(
            session["cleanup"].get("private_tmpfs_released") is True for session in parsed_sessions
        ),
        "persistent_shared_queue": False,
    }
    if (
        any(not isinstance(value, bool) for value in cleanup.values())
        or cleanup != expected_cleanup
    ):
        raise CompatibilityEvidenceError("contradictory synthetic IPC cleanup summary")
    if status == "passed" and (
        cleanup["all_containers_removed"] is not True
        or cleanup["all_private_tmpfs_released"] is not True
    ):
        raise CompatibilityEvidenceError("incomplete passed synthetic IPC cleanup")

    stock = _expect_object(
        handoff["stock_compatibility"],
        {"stock_ipc_compatibility", "m1_04_stock_boot"},
        "synthetic IPC stock compatibility boundary",
    )
    if stock != {"stock_ipc_compatibility": "UNVERIFIED", "m1_04_stock_boot": "NOT RUN"}:
        raise CompatibilityEvidenceError("contradictory synthetic IPC stock compatibility boundary")

    scenario_status = "PASS" if status == "passed" else "BLOCKED"
    if status == "failed":
        failure = handoff["failure"]
        if not isinstance(failure, dict) or not isinstance(failure.get("category"), str):
            raise CompatibilityEvidenceError("invalid synthetic IPC handoff failure")
        if failure["category"] == "guest-handoff":
            failure = _validate_ipc_failure(failure, category=True)
            matching = [
                session
                for session in parsed_sessions
                if session["status"] == "quarantined"
                and session["observations"].get("failure")
                == {key: value for key, value in failure.items() if key != "category"}
            ]
            if len(matching) != 1:
                raise CompatibilityEvidenceError(
                    "IPC handoff failure contradicts session observations"
                )
            failed_cleanup = matching[0]["cleanup"]
            scenario_status = (
                "FAIL"
                if failed_cleanup.get("container_removed") is True
                and failed_cleanup.get("private_tmpfs_released") is True
                else "BLOCKED"
            )
        elif failure == {"category": "session-or-cleanup-failed"}:
            if any(
                session["status"] == "quarantined"
                and session["observations"].get("status") == "failed"
                for session in parsed_sessions
            ):
                raise CompatibilityEvidenceError(
                    "IPC guest failure is mislabeled as a session or cleanup failure"
                )
            has_session_or_cleanup_failure = any(
                session["status"] == "quarantined"
                and (
                    session["observations"] == {}
                    or (
                        session["observations"].get("status") == "passed"
                        and (
                            session["cleanup"].get("container_removed") is not True
                            or session["cleanup"].get("private_tmpfs_released") is not True
                        )
                    )
                )
                for session in parsed_sessions
            )
            repeated_or_missing_session = not fresh["distinct_session_identities"] and all(
                session["status"] == "passed" for session in parsed_sessions
            )
            if not has_session_or_cleanup_failure and not repeated_or_missing_session:
                raise CompatibilityEvidenceError("IPC session failure lacks a blocked session")
        else:
            raise CompatibilityEvidenceError("unknown synthetic IPC handoff failure category")
        if parent_status != "failed":
            raise CompatibilityEvidenceError("contradictory parent and IPC handoff status")
        if receipt.get("failure") != {"category": "synthetic-ipc-handoff-failed"}:
            raise CompatibilityEvidenceError("parent receipt does not identify IPC handoff failure")
    elif receipt.get("failure", {}).get("category") == "synthetic-ipc-handoff-failed":
        raise CompatibilityEvidenceError("parent receipt contradicts passed IPC handoff")

    return {
        "status": scenario_status,
        "receipt_status": status,
        "sessions": len(parsed_sessions),
        "roles": list(_IPC_HANDOFF_ROLES),
        "identities": {
            "qemu-mipsel": identities["qemu_mipsel_sha256"],
            "guest-source": identities["guest_source_sha256"],
            "guest-elf": identities["guest_elf_sha256"],
        },
        "independently_authenticated": False,
    }


def _validate_toolchain(value: Any, artifacts: dict[str, str]) -> None:
    fields = {
        "base_image",
        "base_image_amd64_manifest",
        "base_image_index_sha256",
        "build_input_manifest_sha256",
        "device_patch_sha256",
        "mipsel_cross_toolchain",
        "prior_reproducible_build",
        "qemu_binary",
        "qemu_package_version",
        "qemu_source_archives",
        "qemu_source_descriptor_sha256",
        "upstream_commit",
        "upstream_projection_digest",
    }
    value = _expect_object(value, fields, "runtime toolchain")
    base_image = value["base_image"]
    if not isinstance(base_image, str) or not re.fullmatch(
        r"docker\.io/library/debian:12@sha256:[0-9a-f]{64}", base_image
    ):
        raise CompatibilityEvidenceError("invalid runtime toolchain base image")
    for field in ("base_image_amd64_manifest", "base_image_index_sha256"):
        digest = value[field]
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise CompatibilityEvidenceError("invalid runtime toolchain image digest")
    if (
        base_image.rsplit("sha256:", 1)[1] != value["base_image_index_sha256"][7:]
        or not isinstance(value["qemu_package_version"], str)
        or not value["qemu_package_version"]
        or not isinstance(value["upstream_commit"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", value["upstream_commit"])
        or not isinstance(value["upstream_projection_digest"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", value["upstream_projection_digest"])
    ):
        raise CompatibilityEvidenceError("contradictory runtime toolchain identity")
    for field in (
        "build_input_manifest_sha256",
        "device_patch_sha256",
        "qemu_source_descriptor_sha256",
    ):
        _digest(value[field], f"runtime toolchain.{field}")

    qemu = _expect_object(value["qemu_binary"], {"bytes", "sha256"}, "runtime QEMU binary")
    if (
        not isinstance(qemu["bytes"], int)
        or isinstance(qemu["bytes"], bool)
        or qemu["bytes"] <= 0
        or _digest(qemu["sha256"], "runtime toolchain.qemu_binary.sha256")
        != artifacts["qemu-mipsel"]
    ):
        raise CompatibilityEvidenceError("contradictory runtime QEMU identity")

    archives = value["qemu_source_archives"]
    if not isinstance(archives, dict) or set(archives) != {
        "qemu_7.2+dfsg-7+deb12u18.debian.tar.xz",
        "qemu_7.2+dfsg.orig.tar.xz",
    }:
        raise CompatibilityEvidenceError("invalid runtime QEMU source archives")
    for archive in archives.values():
        archive = _expect_object(archive, {"bytes", "sha256", "verified"}, "QEMU archive")
        if (
            not isinstance(archive["bytes"], int)
            or isinstance(archive["bytes"], bool)
            or archive["bytes"] <= 0
            or archive["verified"] is not True
        ):
            raise CompatibilityEvidenceError("invalid runtime QEMU source archive")
        _digest(archive["sha256"], "runtime toolchain.qemu_source_archives.sha256")

    compiler = _expect_object(
        value["mipsel_cross_toolchain"],
        {
            "compiler",
            "compiler_packages",
            "compiler_version",
            "reported_sysroot",
            "sysroot_entry_count",
            "sysroot_file_count",
            "sysroot_sha256",
            "sysroot_tree",
            "target",
            "version",
        },
        "MIPS cross toolchain",
    )
    if (
        compiler["compiler"] != "mipsel-linux-gnu-gcc"
        or compiler["target"] != "mipsel-linux-gnu"
        or compiler["reported_sysroot"] != "/"
        or compiler["sysroot_tree"] != "/usr/mipsel-linux-gnu"
        or not isinstance(compiler["compiler_version"], str)
        or not compiler["compiler_version"]
        or not isinstance(compiler["version"], str)
        or not compiler["version"]
        or any(
            not isinstance(compiler[field], int)
            or isinstance(compiler[field], bool)
            or compiler[field] <= 0
            for field in ("sysroot_entry_count", "sysroot_file_count")
        )
    ):
        raise CompatibilityEvidenceError("invalid MIPS cross toolchain identity")
    _digest(compiler["sysroot_sha256"], "runtime toolchain.sysroot_sha256")
    packages = compiler["compiler_packages"]
    if not isinstance(packages, list) or len(packages) != 3:
        raise CompatibilityEvidenceError("invalid MIPS cross toolchain packages")
    package_names = set()
    for package in packages:
        package = _expect_object(
            package, {"architecture", "package", "version"}, "toolchain package"
        )
        if any(not isinstance(package[field], str) or not package[field] for field in package):
            raise CompatibilityEvidenceError("invalid MIPS cross toolchain package")
        if package["package"] in package_names:
            raise CompatibilityEvidenceError("duplicate MIPS cross toolchain package")
        package_names.add(package["package"])

    prior = _expect_object(
        value["prior_reproducible_build"],
        {"head", "match_scope", "result", "reused", "workflow_run"},
        "prior reproducible build",
    )
    if (
        not isinstance(prior["head"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", prior["head"])
        or not isinstance(prior["match_scope"], str)
        or not prior["match_scope"]
        or prior["result"] != "matching second clean build"
        or prior["reused"] is not True
        or not isinstance(prior["workflow_run"], int)
        or isinstance(prior["workflow_run"], bool)
        or prior["workflow_run"] <= 0
    ):
        raise CompatibilityEvidenceError("invalid prior reproducible build evidence")


def _validate_supervision_child(value: Any, role: str, expected: Any) -> dict[str, Any]:
    child = _expect_object(
        value,
        {"pid", "status", "exit_reason", "reaped", "stdout_sha256"},
        f"supervision {role} child",
    )
    if (
        not isinstance(child["pid"], int)
        or isinstance(child["pid"], bool)
        or not 1 <= child["pid"] <= 1_000_000
        or not isinstance(child["status"], int)
        or isinstance(child["status"], bool)
        or not 0 <= child["status"] <= 255
        or child["reaped"] is not True
    ):
        raise CompatibilityEvidenceError("invalid supervision child status or reaping")
    _digest(child["stdout_sha256"], f"supervision.{role}.stdout_sha256")
    if expected == "signal":
        if child["status"] not in {143, 137}:
            raise CompatibilityEvidenceError("supervision child signal status contradicts scenario")
        expected_reason = "signal:TERM" if child["status"] == 143 else "signal:KILL"
    else:
        if child["status"] != expected:
            raise CompatibilityEvidenceError("supervision child exit status contradicts scenario")
        expected_reason = f"exit:{expected}"
    if child["exit_reason"] != expected_reason:
        raise CompatibilityEvidenceError("supervision child exit reason contradicts status")
    return child


def _validate_supervision_scenario(value: Any, name: str) -> dict[str, Any]:
    fields = {
        "scenario",
        "status",
        "protocol",
        "queue_names",
        "queue_creation_observed",
        "acknowledgment_state",
        "failure",
        "actual_qemu_processes",
        "children",
        "deadline",
        "term_sent",
        "kill_sent",
        "sibling_reaped",
    }
    row = _expect_object(value, fields, "synthetic IPC supervision scenario")
    expected = _IPC_SUPERVISION_SCENARIOS[name]
    queue_names = {
        "request": expected["request"],
        "acknowledgment": expected["acknowledgment"],
    }
    if (
        row["scenario"] != name
        or row["status"] != "passed"
        or row["protocol"] != expected["protocol"]
        or not _matches_fixed_json(row["queue_names"], queue_names)
        or row["queue_creation_observed"] is not expected["queue_created"]
        or row["acknowledgment_state"] != expected["acknowledgment_state"]
        or not _matches_fixed_json(row["failure"], expected["failure"])
        or row["actual_qemu_processes"] is not True
        or row["sibling_reaped"] is not (expected["failure"] is not None)
    ):
        raise CompatibilityEvidenceError("contradictory synthetic IPC supervision scenario")
    children = _expect_object(row["children"], set(_IPC_SUPERVISION_ROLES), "supervision children")
    parsed_children = {
        role: _validate_supervision_child(children[role], role, expected["exit_statuses"][role])
        for role in _IPC_SUPERVISION_ROLES
    }
    if parsed_children["consumer"]["pid"] == parsed_children["producer"]["pid"] or any(
        parsed_children[role]["stdout_sha256"] != expected["outputs"][role]
        for role in _IPC_SUPERVISION_ROLES
    ):
        raise CompatibilityEvidenceError("contradictory synthetic IPC supervision child identity")
    expected_kills = [
        role for role in _IPC_SUPERVISION_ROLES if parsed_children[role]["status"] == 137
    ]
    deadline = _expect_object(
        row["deadline"],
        {"seconds", "expired", "term_sent", "kill_sent"},
        "supervision deadline",
    )
    for sent in (row["term_sent"], row["kill_sent"], deadline["term_sent"], deadline["kill_sent"]):
        if not isinstance(sent, list) or any(role not in _IPC_SUPERVISION_ROLES for role in sent):
            raise CompatibilityEvidenceError("invalid supervision signal recipients")
    if (
        deadline["seconds"] != expected["deadline_seconds"]
        or deadline["expired"] is not expected["deadline_expired"]
        or not _matches_fixed_json(deadline["term_sent"], expected["term_sent"])
        or not _matches_fixed_json(row["term_sent"], expected["term_sent"])
        or not _matches_fixed_json(deadline["kill_sent"], expected_kills)
        or not _matches_fixed_json(row["kill_sent"], expected_kills)
        or any(role not in expected["term_sent"] for role in expected_kills)
    ):
        raise CompatibilityEvidenceError(
            "contradictory synthetic IPC supervision deadline or signals"
        )
    return row


def _validate_ipc_supervision(
    receipt: dict[str, Any], artifacts: dict[str, str], *, parent_status: str
) -> dict[str, Any] | None:
    if "synthetic_ipc_supervision" not in receipt:
        return None
    fields = {
        "schema_version",
        "status",
        "scope",
        "identities",
        "roles",
        "scenarios",
        "sessions",
        "fresh_container_repeat",
        "container_cleanup",
        "container_isolation",
        "observations_are_actual_qemu",
        "stock_compatibility",
        "m1_04_stock_boot",
    }
    supervision = _expect_object(
        receipt["synthetic_ipc_supervision"], fields, "synthetic IPC supervision receipt"
    )
    if (
        supervision["schema_version"] != _IPC_SUPERVISION_SCHEMA
        or supervision["status"] != "passed"
        or supervision["scope"] != "fixed first-party MIPS32LE two-process failure supervision"
        or parent_status == "passed"
        and supervision["status"] != parent_status
        or supervision["observations_are_actual_qemu"] is not True
        or supervision["stock_compatibility"] != "UNVERIFIED"
        or supervision["m1_04_stock_boot"] != "NOT RUN"
    ):
        raise CompatibilityEvidenceError(
            "unsupported or contradictory synthetic IPC supervision status"
        )
    identities = _expect_object(
        supervision["identities"],
        {"qemu_mipsel_sha256", "guest_source_sha256", "guest_elf_sha256"},
        "synthetic IPC supervision identities",
    )
    for key, digest in identities.items():
        _digest(digest, f"synthetic_ipc_supervision.identities.{key}")
    if (
        identities["qemu_mipsel_sha256"] != artifacts["qemu-mipsel"]
        or identities["guest_source_sha256"] != _IPC_SUPERVISION_SOURCE_SHA256
        or identities["guest_elf_sha256"] != artifacts[_IPC_SUPERVISION_ELF]
    ):
        raise CompatibilityEvidenceError(
            "contradictory synthetic IPC supervision artifact identities"
        )
    roles = _expect_object(
        supervision["roles"],
        {"consumer", "producer", "process_identity"},
        "synthetic IPC supervision roles",
    )
    if roles != {
        "consumer": "fixed request reader and acknowledgment sender",
        "producer": "fixed request sender and acknowledgment observer",
        "process_identity": "container-local QEMU PID recorded independently per role",
    }:
        raise CompatibilityEvidenceError("contradictory synthetic IPC supervision roles")

    sessions = supervision["sessions"]
    if not isinstance(sessions, list) or len(sessions) != 2:
        raise CompatibilityEvidenceError("incomplete synthetic IPC supervision sessions")
    parsed_sessions = []
    session_ids = set()
    lifecycle = _RUNTIME_LIFECYCLE
    session_fields = {
        "case",
        "cleanup",
        "execution",
        "isolation",
        "lifecycle",
        "observations",
        "session_id",
        "session_identity",
        "status",
    }
    for index, session in enumerate(sessions):
        session = _expect_object(session, session_fields, "synthetic IPC supervision session")
        label = ("first", "fresh")[index]
        identity = session["session_identity"]
        if (
            session["session_id"] != f"ipc-supervision-{label}"
            or session["case"] != "ipc-supervision"
            or session["status"] != "passed"
            or not isinstance(identity, str)
            or not re.fullmatch(r"[0-9a-f]{32}", identity)
            or identity in session_ids
            or session["lifecycle"] != lifecycle
        ):
            raise CompatibilityEvidenceError(
                "invalid synthetic IPC supervision session identity or status"
            )
        session_ids.add(identity)
        execution = _expect_object(
            session["execution"],
            {
                "duration_seconds",
                "exit_code",
                "stdout_bytes",
                "stdout_sha256",
                "terminated",
                "timed_out",
            },
            "synthetic IPC supervision execution",
        )
        _nonnegative_number(execution["duration_seconds"], "IPC supervision duration")
        _digest(execution["stdout_sha256"], "IPC supervision stdout_sha256")
        if (
            execution["duration_seconds"] <= 0
            or execution["duration_seconds"] > 15
            or execution["exit_code"] != 0
            or isinstance(execution["exit_code"], bool)
            or not isinstance(execution["stdout_bytes"], int)
            or isinstance(execution["stdout_bytes"], bool)
            or not 0 < execution["stdout_bytes"] <= _IPC_SUPERVISION_OUTPUT_LIMIT
            or execution["terminated"] is not True
            or execution["timed_out"] is not False
        ):
            raise CompatibilityEvidenceError(
                "contradictory synthetic IPC supervision wrapper execution"
            )
        if session["lifecycle"] != lifecycle:
            raise CompatibilityEvidenceError("incomplete synthetic IPC supervision lifecycle")
        cleanup = _expect_object(
            session["cleanup"],
            {
                "container_removed",
                "container_stop_command",
                "container_stopped",
                "host_metadata",
                "ownership_verified_before_removal",
                "private_tmpfs_released",
            },
            "synthetic IPC supervision session cleanup",
        )
        if cleanup != {
            "container_removed": True,
            "container_stop_command": "not-needed",
            "container_stopped": True,
            "host_metadata": "retained; no recursive cleanup",
            "ownership_verified_before_removal": True,
            "private_tmpfs_released": True,
        }:
            raise CompatibilityEvidenceError(
                "incomplete or unsafe synthetic IPC supervision cleanup"
            )
        _validate_isolation(session["isolation"])
        observations = _expect_object(
            session["observations"],
            {"actual_vs_simulated", "scenario_count", "scenarios", "status"},
            "synthetic IPC supervision observations",
        )
        if (
            observations["status"] != "passed"
            or observations["scenario_count"] != len(_IPC_SUPERVISION_SCENARIOS)
            or isinstance(observations["scenario_count"], bool)
            or not _matches_fixed_json(
                observations["actual_vs_simulated"], _SUPERVISION_OBSERVATIONS
            )
        ):
            raise CompatibilityEvidenceError("invalid synthetic IPC supervision observations")
        rows = observations["scenarios"]
        if not isinstance(rows, list) or [
            row.get("scenario") if isinstance(row, dict) else None for row in rows
        ] != list(_IPC_SUPERVISION_SCENARIOS):
            raise CompatibilityEvidenceError(
                "incomplete or reordered synthetic IPC supervision matrix"
            )
        parsed_rows = [
            _validate_supervision_scenario(row, name)
            for row, name in zip(rows, _IPC_SUPERVISION_SCENARIOS, strict=True)
        ]
        session["observations"] = {**observations, "scenarios": parsed_rows}
        parsed_sessions.append(session)

    if not _matches_fixed_json(
        supervision["scenarios"], parsed_sessions[0]["observations"]["scenarios"]
    ):
        raise CompatibilityEvidenceError("contradictory top-level synthetic IPC supervision matrix")
    if not all(
        row["children"][role]["reaped"]
        for session in parsed_sessions
        for row in session["observations"]["scenarios"]
        for role in _IPC_SUPERVISION_ROLES
    ):
        raise CompatibilityEvidenceError("synthetic IPC supervision left a child unreaped")

    fresh = _expect_object(
        supervision["fresh_container_repeat"],
        {
            "distinct_session_identities",
            "first_container_removed_before_second",
            "no_child_processes_left",
            "same_fixed_queue_names_recreated",
        },
        "synthetic IPC supervision container repeat",
    )
    if not _matches_fixed_json(
        fresh,
        {
            "distinct_session_identities": True,
            "first_container_removed_before_second": True,
            "no_child_processes_left": True,
            "same_fixed_queue_names_recreated": True,
        },
    ):
        raise CompatibilityEvidenceError("contradictory synthetic IPC supervision repeat evidence")
    cleanup_summary = _expect_object(
        supervision["container_cleanup"],
        {
            "all_containers_stopped_and_removed",
            "all_private_tmpfs_released",
            "ownership_verified_before_removal",
            "queue_state_persists_after_container_removal",
        },
        "synthetic IPC supervision container cleanup",
    )
    if not _matches_fixed_json(
        cleanup_summary,
        {
            "all_containers_stopped_and_removed": True,
            "all_private_tmpfs_released": True,
            "ownership_verified_before_removal": True,
            "queue_state_persists_after_container_removal": False,
        },
    ):
        raise CompatibilityEvidenceError("contradictory synthetic IPC supervision cleanup summary")
    isolation = _expect_object(
        supervision["container_isolation"],
        {"ipc_mode", "network_mode", "new_mounts_or_sysctls", "profiles"},
        "synthetic IPC supervision container isolation",
    )
    profiles = [session["isolation"] for session in parsed_sessions]
    if (
        isolation["ipc_mode"] != "none"
        or isolation["network_mode"] != "none"
        or isolation["new_mounts_or_sysctls"] is not False
        or not _matches_fixed_json(isolation["profiles"], profiles)
    ):
        raise CompatibilityEvidenceError("unsafe synthetic IPC supervision isolation")

    return {
        "status": "PASS",
        "receipt_status": "passed",
        "sessions": len(parsed_sessions),
        "roles": list(_IPC_SUPERVISION_ROLES),
        "identities": {
            "qemu-mipsel": identities["qemu_mipsel_sha256"],
            "guest-source": identities["guest_source_sha256"],
            "guest-elf": identities["guest_elf_sha256"],
        },
        "scenarios": [
            {
                "scenario": row["scenario"],
                "status": "PASS",
                "observed_failure": row["failure"],
                "child_exit_statuses": {
                    role: row["children"][role]["status"] for role in _IPC_SUPERVISION_ROLES
                },
                "children_reaped": all(
                    row["children"][role]["reaped"] for role in _IPC_SUPERVISION_ROLES
                ),
                "deadline": row["deadline"],
            }
            for row in parsed_sessions[0]["observations"]["scenarios"]
        ],
        "stock_compatibility": "UNVERIFIED",
        "m1_04_stock_boot": "NOT RUN",
        "independently_authenticated": False,
    }


def _nonnegative_number(value: Any, field: str) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise CompatibilityEvidenceError(f"invalid numeric value: {field}")


def parse_receipt(document: str | bytes, *, source: str) -> dict[str, Any]:
    """Parse one exact synthetic-runtime acceptance receipt into report data."""
    if (
        not isinstance(source, str)
        or not source
        or any(ord(character) < 32 or ord(character) == 127 for character in source)
    ):
        raise CompatibilityEvidenceError("source must be a non-empty single-line identifier")
    if isinstance(document, bytes):
        raw = document
        try:
            text = document.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise CompatibilityEvidenceError("receipt is not UTF-8") from error
    elif isinstance(document, str):
        text = document
        try:
            raw = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CompatibilityEvidenceError("receipt is not valid Unicode") from error
    else:
        raise CompatibilityEvidenceError("receipt must be JSON text or UTF-8 bytes")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise CompatibilityEvidenceError("receipt exceeds the 1 MiB limit")
    try:
        receipt = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_constant,
        )
    except CompatibilityEvidenceError:
        raise
    except (ValueError, RecursionError) as error:
        raise CompatibilityEvidenceError("malformed JSON receipt") from error
    if not isinstance(receipt, dict):
        raise CompatibilityEvidenceError("receipt must be a JSON object")
    if receipt.get("schema_version") == "firmware-free-qemu-runtime-build/v1":
        unknown = receipt.keys() - _BUILD_KEYS
        if unknown:
            raise CompatibilityEvidenceError(f"unknown build receipt field: {sorted(unknown)[0]}")
        required_build_fields = _BUILD_KEYS - {"synthetic_execution_smoke"}
        if required_build_fields - receipt.keys():
            raise CompatibilityEvidenceError("incomplete QEMU build receipt")
        for field in (
            "host_resources_before_build",
            "base_image",
            "qemu_source_review",
            "license_review",
        ):
            if not isinstance(receipt[field], dict):
                raise CompatibilityEvidenceError(f"invalid QEMU build section: {field}")
        optional_resources = receipt["host_resources_before_optional_repeat"]
        if optional_resources is not None and not isinstance(optional_resources, dict):
            raise CompatibilityEvidenceError("invalid optional QEMU host resource section")
        if "synthetic_execution_smoke" in receipt and not isinstance(
            receipt["synthetic_execution_smoke"], dict
        ):
            raise CompatibilityEvidenceError("invalid synthetic execution smoke section")
        if not isinstance(receipt["network_boundary"], str) or not isinstance(
            receipt["apt_sandbox"], str
        ):
            raise CompatibilityEvidenceError("invalid QEMU build boundary descriptions")
        _nonnegative_number(receipt["elapsed_seconds"], "elapsed_seconds")
        build = receipt["build"]
        if not isinstance(build, dict) or build.keys() != _BUILD_PAYLOAD_KEYS:
            raise CompatibilityEvidenceError("incomplete or unknown QEMU build fields")
        for field in (
            "qemu_descriptor_sha256",
            "qemu_patch_sha256",
            "shim_recipe_sha256",
            "debian_archive_keyring_sha256",
            "installed_package_bom_sha256",
        ):
            _digest(build[field], f"build.{field}")
        for field in ("shim_source_sha256", "toolchain", "container_limits", "build_logs"):
            if not isinstance(build[field], dict):
                raise CompatibilityEvidenceError(f"invalid QEMU build field: {field}")
        if any(
            not isinstance(value, str) or not _SHA256.fullmatch(value)
            for value in build["shim_source_sha256"].values()
        ):
            raise CompatibilityEvidenceError("invalid shim source digest")
        if (
            not isinstance(build["qemu_archives"], (list, dict))
            or not isinstance(build["qemu_configure_flags"], list)
            or not isinstance(build["artifact_sha256_and_elf"], list)
            or not isinstance(build["installed_packages"], list)
        ):
            raise CompatibilityEvidenceError("invalid QEMU build array field")
        if (
            not isinstance(build["installed_package_count"], int)
            or isinstance(build["installed_package_count"], bool)
            or build["installed_package_count"] < 0
        ):
            raise CompatibilityEvidenceError("invalid installed package count")
        _nonnegative_number(build["elapsed_seconds"], "build.elapsed_seconds")
        if not isinstance(build["qemu_version"], str) or not build["qemu_version"]:
            raise CompatibilityEvidenceError("invalid QEMU version")
        if isinstance(build["qemu_archives"], dict):
            if set(build["qemu_archives"]) != {
                "qemu_7.2+dfsg-7+deb12u18.debian.tar.xz",
                "qemu_7.2+dfsg.orig.tar.xz",
            }:
                raise CompatibilityEvidenceError("invalid QEMU archive map")
            for archive in build["qemu_archives"].values():
                archive = _expect_object(archive, {"bytes", "sha256", "verified"}, "QEMU archive")
                if (
                    not isinstance(archive["bytes"], int)
                    or isinstance(archive["bytes"], bool)
                    or archive["bytes"] <= 0
                    or archive["verified"] is not True
                ):
                    raise CompatibilityEvidenceError("invalid QEMU source archive")
                _digest(archive["sha256"], "build.qemu_archives.sha256")
        for field in ("qemu_configure_flags", "artifact_sha256_and_elf", "installed_packages"):
            if not isinstance(build[field], list):
                raise CompatibilityEvidenceError(f"invalid QEMU build array: {field}")
        if not isinstance(build["shim_source_sha256"], dict) or any(
            not isinstance(key, str) for key in build["shim_source_sha256"]
        ):
            raise CompatibilityEvidenceError("invalid shim source map")
        for field in ("toolchain", "container_limits", "build_logs"):
            if not isinstance(build[field], dict):
                raise CompatibilityEvidenceError(f"invalid QEMU build map: {field}")
        inrelease = build["debian_snapshot_inrelease"]
        if isinstance(inrelease, list):
            allowed_codenames = {"bookworm", "bookworm-updates", "bookworm-security"}
            if len(inrelease) != 3:
                raise CompatibilityEvidenceError("incomplete Debian snapshot evidence")
            seen_codenames = set()
            for record in inrelease:
                record = _expect_object(
                    record,
                    {"codename", "file", "sha256", "valid_signature_fingerprint", "verified"},
                    "Debian snapshot record",
                )
                if (
                    not isinstance(record["codename"], str)
                    or record["codename"] not in allowed_codenames
                    or record["codename"] in seen_codenames
                    or not isinstance(record["file"], str)
                    or not record["file"]
                    or not isinstance(record["valid_signature_fingerprint"], str)
                    or not re.fullmatch(r"[0-9A-F]{40}", record["valid_signature_fingerprint"])
                    or record["verified"] is not True
                ):
                    raise CompatibilityEvidenceError("invalid Debian snapshot evidence")
                _digest(record["sha256"], "build.debian_snapshot_inrelease.sha256")
                seen_codenames.add(record["codename"])
            if seen_codenames != allowed_codenames:
                raise CompatibilityEvidenceError("incomplete Debian snapshot evidence")
        elif not isinstance(inrelease, dict):
            raise CompatibilityEvidenceError("invalid legacy Debian snapshot map")
        if not isinstance(build["temporary_container_cleanup"], str):
            raise CompatibilityEvidenceError("invalid temporary container cleanup status")
        repeated = build["repeated_clean_build_comparison"]
        repeated_fields = {
            "status",
            "reason",
            "elapsed_seconds",
            "resource_recheck",
            "compared",
            "differences",
            "second_artifact_sha256",
            "second_package_bom_sha256",
            "second_sysroot_sha256",
        }
        if (
            not isinstance(repeated, dict)
            or repeated.keys() - repeated_fields
            or not isinstance(repeated.get("status"), str)
        ):
            raise CompatibilityEvidenceError("invalid repeated clean build comparison")
        for field in ("reason",):
            if field in repeated and not isinstance(repeated[field], str):
                raise CompatibilityEvidenceError(f"invalid repeated build {field}")
        if "elapsed_seconds" in repeated:
            _nonnegative_number(repeated["elapsed_seconds"], "repeat.elapsed_seconds")
        if "resource_recheck" in repeated and not isinstance(repeated["resource_recheck"], dict):
            raise CompatibilityEvidenceError("invalid repeated build resource report")
        if repeated["status"] in {"identical", "different"}:
            if (
                not {
                    "compared",
                    "differences",
                    "second_artifact_sha256",
                    "second_package_bom_sha256",
                    "second_sysroot_sha256",
                }
                <= repeated.keys()
            ):
                raise CompatibilityEvidenceError("incomplete repeated build comparison")
            if any(
                not isinstance(repeated[field], list)
                or any(not isinstance(item, str) for item in repeated[field])
                for field in ("compared", "differences")
            ):
                raise CompatibilityEvidenceError("invalid repeated build comparison lists")
            if not isinstance(repeated["second_artifact_sha256"], dict) or any(
                not isinstance(name, str) for name in repeated["second_artifact_sha256"]
            ):
                raise CompatibilityEvidenceError("invalid repeated build artifact map")
            for digest_field in ("second_package_bom_sha256", "second_sysroot_sha256"):
                _digest(repeated[digest_field], f"repeat.{digest_field}")
        elif repeated["status"] == "attempted-failed" and "reason" not in repeated:
            raise CompatibilityEvidenceError("failed repeated build is missing its reason")
        if build["temporary_container_cleanup"] != "verified":
            raise CompatibilityEvidenceError("unverified QEMU build container cleanup")
        repeated = build["repeated_clean_build_comparison"]
        if not isinstance(repeated, dict) or repeated.get("status") != receipt.get(
            "repeat_build_status"
        ):
            raise CompatibilityEvidenceError("contradictory nested QEMU repeat-build status")
        boundaries = receipt.get("runtime_and_device_boundaries")
        if not isinstance(boundaries, dict) or any(
            boundaries.get(key) is not expected
            for key, expected in (
                ("firmware_processed", False),
                ("guest_booted", False),
                ("compatibility_claimed", False),
            )
        ):
            raise CompatibilityEvidenceError("QEMU build receipt crosses a firmware boundary")
        identity = receipt.get("source_identity")
        if not isinstance(identity, dict):
            raise CompatibilityEvidenceError("QEMU source identity is missing")
        if identity.keys() - _BUILD_SOURCE_KEYS:
            raise CompatibilityEvidenceError("unknown QEMU source identity field")
        if identity.keys() != _BUILD_SOURCE_KEYS:
            raise CompatibilityEvidenceError("incomplete QEMU source identity")
        if boundaries.keys() != _BUILD_BOUNDARY_KEYS:
            raise CompatibilityEvidenceError("unknown or incomplete QEMU boundary fields")
        forbidden_boundaries = {
            "binfmt_registered",
            "runtime_image_built",
            "container_image_published",
            "compiled_binary_published",
            "usb_or_hardware_accessed",
        }
        if any(boundaries.get(key) is not False for key in forbidden_boundaries):
            raise CompatibilityEvidenceError("QEMU build receipt crosses a device boundary")
        repo = identity.get("repository")
        commit = identity.get("commit")
        projection = identity.get("projection_digest")
        if (
            not isinstance(repo, str)
            or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", repo)
            or not isinstance(commit, str)
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not isinstance(projection, str)
            or not re.fullmatch(r"(?:[0-9a-f]{32}|[0-9a-f]{64})", projection)
            or identity.get("firmware_tree_fetched") is not False
            or not isinstance(identity.get("source_lock_changed"), bool)
            or not isinstance(identity.get("reviewed_file_sha256"), dict)
            or not isinstance(identity.get("reviewed_file_bytes"), dict)
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in identity["reviewed_file_bytes"].values()
            )
            or not isinstance(identity.get("build_input_manifest_sha256"), str)
            or not _SHA256.fullmatch(identity["build_input_manifest_sha256"])
            or receipt.get("primary_build_status") != "passed"
            or not isinstance(receipt.get("status"), str)
            or receipt.get("status")
            not in {
                "firmware-free-build-passed-repeat-identical",
                "firmware-free-build-passed-repeat-different",
                "firmware-free-build-passed-repeat-failed",
                "firmware-free-build-passed-repeat-not-run",
            }
        ):
            raise CompatibilityEvidenceError("invalid QEMU source identity")
        expected_repeat_status = {
            "identical": "firmware-free-build-passed-repeat-identical",
            "different": "firmware-free-build-passed-repeat-different",
            "attempted-failed": "firmware-free-build-passed-repeat-failed",
            "not-run": "firmware-free-build-passed-repeat-not-run",
        }
        repeat_status = receipt.get("repeat_build_status")
        if (
            not isinstance(repeat_status, str)
            or expected_repeat_status.get(repeat_status) != receipt.get("status")
            or repeat_status != "not-run"
        ):
            raise CompatibilityEvidenceError("contradictory QEMU repeat-build status")
        if (
            boundaries.get("qemu_executable_invoked") is not True
            or boundaries.get("synthetic_guest_executed") is not True
        ):
            raise CompatibilityEvidenceError("QEMU receipt lacks synthetic execution evidence")
        if any(
            not isinstance(value, str) or not _SHA256.fullmatch(value)
            for value in identity["reviewed_file_sha256"].values()
        ):
            raise CompatibilityEvidenceError("invalid reviewed QEMU source digest")
        if any(not isinstance(name, str) for name in identity["reviewed_file_sha256"]):
            raise CompatibilityEvidenceError("invalid reviewed QEMU source filename")
        if any(not isinstance(name, str) for name in identity["reviewed_file_bytes"]):
            raise CompatibilityEvidenceError("invalid reviewed QEMU source filename")
        nested = receipt.get("synthetic_runtime")
        if not isinstance(nested, dict):
            raise CompatibilityEvidenceError("QEMU receipt has no synthetic runtime evidence")
        report = parse_receipt(json.dumps(nested), source=source)
        runtime_toolchain = nested.get("toolchain")
        runtime_archives = (
            runtime_toolchain.get("qemu_source_archives")
            if isinstance(runtime_toolchain, dict)
            else None
        )
        build_archives = build["qemu_archives"]
        if (
            isinstance(build_archives, dict)
            and isinstance(runtime_archives, dict)
            and (
                build_archives.keys() != runtime_archives.keys()
                or any(
                    build_archives[name]["sha256"] != runtime_archives[name]["sha256"]
                    or build_archives[name]["bytes"] != runtime_archives[name]["bytes"]
                    for name in build_archives.keys() & runtime_archives.keys()
                )
            )
        ):
            raise CompatibilityEvidenceError("conflicting nested QEMU source archive identities")
        qemu_build_artifacts = [
            artifact
            for artifact in build["artifact_sha256_and_elf"]
            if isinstance(artifact, dict) and artifact.get("name") == "qemu-mipsel"
        ]
        if qemu_build_artifacts and (
            len(qemu_build_artifacts) != 1
            or _digest(qemu_build_artifacts[0].get("sha256"), "build QEMU artifact sha256")
            != report["artifacts"]["qemu-mipsel"]
        ):
            raise CompatibilityEvidenceError("conflicting nested QEMU executable identities")
        report["build_source"] = dict(identity)
        report["build_receipt_status"] = receipt["status"]
        report["repeat_build_status"] = repeat_status
        report["source"] = source
        return report
    unknown = receipt.keys() - _TOP_KEYS
    if unknown:
        raise CompatibilityEvidenceError(f"unknown receipt field: {sorted(unknown)[0]}")
    if receipt.get("schema_version") != _SCHEMA:
        raise CompatibilityEvidenceError("unsupported receipt schema")
    required = {
        "status",
        "identities",
        "guest_source_sha256",
        "synthetic_input_sha256",
        "sessions",
        "posix_mqueue",
        "unsupported_or_unverified",
    }
    if required - receipt.keys():
        raise CompatibilityEvidenceError("incomplete synthetic runtime receipt")
    status = receipt.get("status")
    if not isinstance(status, str) or status not in {"passed", "failed", "quarantined"}:
        raise CompatibilityEvidenceError("unknown receipt status")
    identities = receipt.get("identities")
    if not isinstance(identities, dict) or not identities:
        raise CompatibilityEvidenceError("receipt identities are missing")
    expected_artifact_names = {
        "qemu-mipsel",
        "mips32le-execution-smoke.elf",
        "mips32le-posix-mqueue.elf",
    }
    if "synthetic_ipc_handoff" in receipt:
        expected_artifact_names.add(_IPC_HANDOFF_ELF)
    if "synthetic_ipc_supervision" in receipt:
        expected_artifact_names.add(_IPC_SUPERVISION_ELF)
    if set(identities) != expected_artifact_names:
        raise CompatibilityEvidenceError("unknown or incomplete artifact identities")
    artifacts = {name: _digest(value, name) for name, value in identities.items()}
    if "toolchain" in receipt:
        _validate_toolchain(receipt["toolchain"], artifacts)
    guest_source = _digest(receipt.get("guest_source_sha256"), "guest_source_sha256")
    synthetic_input = _digest(receipt.get("synthetic_input_sha256"), "synthetic_input_sha256")
    sessions = receipt.get("sessions")
    if not isinstance(sessions, list):
        raise CompatibilityEvidenceError("sessions must be an array")
    parsed_sessions: dict[str, list[str]] = {}
    for session in sessions:
        if not isinstance(session, dict):
            raise CompatibilityEvidenceError("session must be an object")
        extra = session.keys() - _SESSION_KEYS
        if extra:
            raise CompatibilityEvidenceError(f"unknown session field: {sorted(extra)[0]}")
        case = session.get("case")
        result = session.get("status")
        if not isinstance(case, str) or case not in {"filesystem", "failure", "timeout"}:
            raise CompatibilityEvidenceError("unknown or duplicate scenario case")
        if case in parsed_sessions and case != "filesystem":
            raise CompatibilityEvidenceError("unknown or duplicate scenario case")
        if case == "filesystem" and len(parsed_sessions.get(case, [])) >= 2:
            raise CompatibilityEvidenceError("too many filesystem sessions")
        if not isinstance(result, str) or result not in {"passed", "quarantined"}:
            raise CompatibilityEvidenceError("unknown session status")
        _validate_session(session)
        parsed_sessions.setdefault(case, []).append(result)
    unverified = receipt.get("unsupported_or_unverified")
    if not isinstance(unverified, list) or any(not isinstance(item, str) for item in unverified):
        raise CompatibilityEvidenceError("unsupported_or_unverified must be a string array")
    if status == "passed" and (
        set(parsed_sessions) != {"filesystem", "failure", "timeout"}
        or len(parsed_sessions.get("filesystem", [])) != 2
        or len(parsed_sessions.get("failure", [])) != 1
        or len(parsed_sessions.get("timeout", [])) != 1
        or any(value != "passed" for results in parsed_sessions.values() for value in results)
    ):
        raise CompatibilityEvidenceError("contradictory receipt and session statuses")
    if status == "failed":
        _validate_failure(receipt.get("failure"), "synthetic runtime failure")
    elif "failure" in receipt:
        raise CompatibilityEvidenceError("contradictory synthetic runtime failure record")
    _validate_optional_sections(receipt)
    ipc_handoff_result = _validate_ipc_handoff(receipt, artifacts, parent_status=status)
    ipc_supervision_result = _validate_ipc_supervision(receipt, artifacts, parent_status=status)
    if receipt.get("failure", {}).get("category") == "synthetic-ipc-handoff-failed" and (
        ipc_handoff_result is None or ipc_handoff_result["receipt_status"] != "failed"
    ):
        raise CompatibilityEvidenceError("synthetic IPC failure is missing its nested evidence")
    if "posix_mqueue" in receipt:
        queue = receipt["posix_mqueue"]
        if not isinstance(queue, dict) or queue.get("schema_version") != (
            "firmware-free-mips32le-posix-mqueue-acceptance/v1"
        ):
            raise CompatibilityEvidenceError("unsupported POSIX queue receipt schema")
        allowed_queue_keys = {
            "schema_version",
            "status",
            "scope",
            "queue",
            "identities",
            "sessions",
            "observed_syscalls",
            "session_separation",
            "isolation",
            "stock_compatibility",
            "outputs",
            "cleanup",
            "failure",
        }
        if queue.keys() - allowed_queue_keys:
            raise CompatibilityEvidenceError("unknown POSIX queue receipt field")
        queue_required = {
            "scope",
            "queue",
            "identities",
            "sessions",
            "observed_syscalls",
            "session_separation",
            "isolation",
            "stock_compatibility",
        }
        if queue_required - queue.keys():
            raise CompatibilityEvidenceError("incomplete POSIX queue receipt")
        if not all(
            isinstance(queue[field], dict)
            for field in (
                "queue",
                "identities",
                "observed_syscalls",
                "session_separation",
                "isolation",
                "stock_compatibility",
            )
        ) or not isinstance(queue["scope"], str):
            raise CompatibilityEvidenceError("malformed POSIX queue receipt fields")
        if not isinstance(queue.get("status"), str) or queue["status"] not in {
            "passed",
            "failed",
        }:
            raise CompatibilityEvidenceError("unknown POSIX queue receipt status")
        if status == "passed" and queue["status"] != "passed":
            raise CompatibilityEvidenceError("contradictory POSIX queue status")
        queue_sessions = queue.get("sessions")
        if not isinstance(queue_sessions, list):
            raise CompatibilityEvidenceError("POSIX queue sessions are missing")
        queue_cases = set()
        for session in queue_sessions:
            if not isinstance(session, dict) or session.keys() - _SESSION_KEYS:
                raise CompatibilityEvidenceError("invalid POSIX queue session")
            case = session.get("case")
            if (
                not isinstance(case, str)
                or case not in {"mqueue-first", "mqueue-second"}
                or case in queue_cases
            ):
                raise CompatibilityEvidenceError("unknown or duplicate POSIX queue scenario")
            if not isinstance(session.get("status"), str) or session.get("status") not in {
                "passed",
                "quarantined",
            }:
                raise CompatibilityEvidenceError("unknown POSIX queue session status")
            _validate_session(session, queue=True)
            queue_cases.add(case)
        queue_failure = queue.get("failure")
        if queue["status"] == "failed":
            _validate_failure(queue_failure, "POSIX queue failure")
        if queue["status"] == "passed" and queue_failure is not None:
            raise CompatibilityEvidenceError("contradictory POSIX queue failure record")
        if queue["status"] == "failed" and status == "passed":
            raise CompatibilityEvidenceError("contradictory POSIX queue status")
        queue_identity = queue.get("identities")
        if not isinstance(queue_identity, dict) or queue_identity.keys() != {
            "qemu_mipsel_sha256",
            "queue_guest_source_sha256",
            "queue_guest_elf_sha256",
        }:
            raise CompatibilityEvidenceError("invalid POSIX queue artifact identities")
        for key, value in queue_identity.items():
            _digest(value, key)
        if (
            queue_identity["qemu_mipsel_sha256"] != artifacts["qemu-mipsel"]
            or queue_identity["queue_guest_elf_sha256"] != artifacts["mips32le-posix-mqueue.elf"]
        ):
            raise CompatibilityEvidenceError("contradictory POSIX queue artifact identities")
        if queue["status"] == "passed" and (
            queue_cases != {"mqueue-first", "mqueue-second"}
            or any(item.get("status") != "passed" for item in queue_sessions)
        ):
            raise CompatibilityEvidenceError("incomplete passed POSIX queue receipt")
        for field in ("session_separation", "isolation", "stock_compatibility"):
            if not isinstance(queue[field], dict):
                raise CompatibilityEvidenceError(f"invalid POSIX queue {field}")
        if (
            queue["session_separation"].keys()
            != {
                "first_container_removed_before_second_create",
                "distinct_session_identities",
                "second_session_same_name_o_excl_create",
            }
            or any(
                not isinstance(queue["session_separation"][key], bool)
                for key in (
                    "first_container_removed_before_second_create",
                    "distinct_session_identities",
                )
            )
            or queue["session_separation"]["second_session_same_name_o_excl_create"]
            not in {"success", "not-established"}
        ):
            raise CompatibilityEvidenceError("invalid POSIX queue session separation")
        if queue["status"] == "passed" and (
            queue["session_separation"]["first_container_removed_before_second_create"] is not True
            or queue["session_separation"]["distinct_session_identities"] is not True
            or queue["session_separation"]["second_session_same_name_o_excl_create"] != "success"
        ):
            raise CompatibilityEvidenceError("contradictory POSIX queue session separation")
        if queue["isolation"].keys() != {"container_profiles", "mqueue_filesystem_mount_added"} or (
            not isinstance(queue["isolation"]["container_profiles"], list)
            or not isinstance(queue["isolation"]["mqueue_filesystem_mount_added"], bool)
        ):
            raise CompatibilityEvidenceError("invalid POSIX queue isolation")
        if queue["status"] == "passed" and (
            len(queue["isolation"]["container_profiles"]) != 2
            or queue["isolation"]["mqueue_filesystem_mount_added"] is not False
        ):
            raise CompatibilityEvidenceError("incomplete POSIX queue isolation profile")
        for profile in queue["isolation"]["container_profiles"]:
            _validate_isolation(profile)
        stock = queue["stock_compatibility"]
        stock_keys = {"stock_v257_queue_attributes", "stock_ipc_compatibility", "m1_04_stock_boot"}
        if stock.keys() != stock_keys or any(
            not isinstance(value, str) for value in stock.values()
        ):
            raise CompatibilityEvidenceError("invalid stock compatibility boundary")
        if (
            stock["stock_v257_queue_attributes"] != "DOCUMENTED_ONLY_UNVERIFIED"
            or stock["stock_ipc_compatibility"] != "UNVERIFIED"
            or stock["m1_04_stock_boot"] != "NOT RUN"
        ):
            raise CompatibilityEvidenceError("contradictory stock compatibility boundary")
        if not isinstance(queue["scope"], str) or not queue["scope"]:
            raise CompatibilityEvidenceError("invalid POSIX queue scope")
        observed = queue["observed_syscalls"]
        if queue["status"] == "failed":
            if observed != {"complete_observation": False}:
                raise CompatibilityEvidenceError("invalid failed POSIX queue syscall observations")
        elif observed.keys() != {"first_session", "second_session"}:
            raise CompatibilityEvidenceError("incomplete POSIX queue syscall observations")
        syscall_fields = {
            "mq_open_exclusive_create",
            "mq_getattr",
            "mq_timedreceive_empty_queue",
            "fstat_mode",
            "mq_open_duplicate_exclusive",
            "mq_timedsend",
            "mq_timedreceive",
            "mq_close",
            "mq_unlink",
            "mq_open_after_unlink",
            "mq_open_recreate",
            "retained_queue_linked_until_exit",
            "retained_queue_empty_receive",
            "qemu_strace_syscalls",
        }
        second_syscall_fields = syscall_fields - {
            "mq_open_duplicate_exclusive",
            "mq_timedsend",
            "mq_timedreceive",
            "mq_open_recreate",
            "retained_queue_linked_until_exit",
            "retained_queue_empty_receive",
        }
        for name, expected in (
            (("first_session", syscall_fields), ("second_session", second_syscall_fields))
            if queue["status"] == "passed"
            else ()
        ):
            values = observed[name]
            if not isinstance(values, dict) or values.keys() != expected:
                raise CompatibilityEvidenceError(f"invalid {name} syscall observations")
            if not isinstance(values["qemu_strace_syscalls"], list) or any(
                not isinstance(item, str) for item in values["qemu_strace_syscalls"]
            ):
                raise CompatibilityEvidenceError("invalid QEMU syscall trace")
            for key, value in values.items():
                if key in {
                    "mq_getattr",
                    "mq_timedreceive_empty_queue",
                    "mq_open_duplicate_exclusive",
                    "mq_timedreceive",
                    "mq_open_after_unlink",
                    "retained_queue_empty_receive",
                }:
                    nested_keys = {
                        "mq_getattr": {
                            "max_messages",
                            "max_message_bytes",
                            "current_messages",
                            "nonblocking",
                        },
                        "mq_timedreceive_empty_queue": {"result", "errno", "errno_number"},
                        "mq_open_duplicate_exclusive": {"result", "errno", "errno_number"},
                        "mq_timedreceive": {
                            "result",
                            "payload_matches",
                            "payload_bytes",
                            "payload_sha256",
                            "priority",
                        },
                        "mq_open_after_unlink": {"result", "errno", "errno_number"},
                        "retained_queue_empty_receive": {"result", "errno", "errno_number"},
                    }[key]
                    if (
                        not isinstance(value, dict)
                        or value.keys() != nested_keys
                        or any(
                            not isinstance(item, (str, int, bool)) or isinstance(item, float)
                            for item in value.values()
                        )
                    ):
                        raise CompatibilityEvidenceError(f"invalid syscall observation: {key}")
                elif key != "qemu_strace_syscalls" and not isinstance(value, (str, bool)):
                    raise CompatibilityEvidenceError(f"invalid syscall observation: {key}")
        if queue["status"] == "passed":
            description = queue["queue"]
            payload_sha256 = description.get("payload_sha256")
            payload_bytes = description.get("payload_bytes")
            priority = description.get("priority")
            expected_getattr = {
                "max_messages": 2,
                "max_message_bytes": 64,
                "current_messages": 0,
                "nonblocking": True,
            }
            expected_empty = {"result": -1, "errno": "EAGAIN", "errno_number": 11}
            expected_unlinked = {"result": -1, "errno": "ENOENT", "errno_number": 2}
            expected_first = {
                "mq_open_exclusive_create": "success",
                "mq_getattr": expected_getattr,
                "mq_timedreceive_empty_queue": expected_empty,
                "fstat_mode": "0600",
                "mq_open_duplicate_exclusive": {
                    "result": -1,
                    "errno": "EEXIST",
                    "errno_number": 17,
                },
                "mq_timedsend": "success",
                "mq_timedreceive": {
                    "result": "success",
                    "payload_matches": True,
                    "payload_bytes": payload_bytes,
                    "payload_sha256": payload_sha256,
                    "priority": priority,
                },
                "mq_close": "success",
                "mq_unlink": "success",
                "mq_open_after_unlink": expected_unlinked,
                "mq_open_recreate": "success",
                "retained_queue_linked_until_exit": True,
                "retained_queue_empty_receive": expected_empty,
                "qemu_strace_syscalls": [
                    "mq_open",
                    "mq_getsetattr",
                    "mq_timedsend",
                    "mq_timedreceive",
                    "mq_unlink",
                    "close",
                ],
            }
            expected_second = {
                "mq_open_exclusive_create": "success",
                "mq_getattr": expected_getattr,
                "mq_timedreceive_empty_queue": expected_empty,
                "fstat_mode": "0600",
                "mq_close": "success",
                "mq_unlink": "success",
                "mq_open_after_unlink": expected_unlinked,
                "qemu_strace_syscalls": [
                    "mq_open",
                    "mq_getsetattr",
                    "mq_timedreceive",
                    "mq_unlink",
                    "close",
                ],
            }
            if observed != {"first_session": expected_first, "second_session": expected_second}:
                raise CompatibilityEvidenceError(
                    "contradictory successful POSIX queue observations"
                )
        if queue["status"] == "passed":
            outputs = queue.get("outputs")
            output_keys = {"session_identity", "bytes", "sha256", "duration_seconds"}
            if not isinstance(outputs, list) or len(outputs) != 2:
                raise CompatibilityEvidenceError("invalid POSIX queue outputs")
            for output in outputs:
                if not isinstance(output, dict) or output.keys() != output_keys:
                    raise CompatibilityEvidenceError("invalid POSIX queue output")
                if not isinstance(output["session_identity"], str):
                    raise CompatibilityEvidenceError("invalid POSIX queue output identity")
                if (
                    not isinstance(output["bytes"], int)
                    or isinstance(output["bytes"], bool)
                    or output["bytes"] < 0
                ):
                    raise CompatibilityEvidenceError("invalid POSIX queue output bytes")
                _digest(output["sha256"], "posix_mqueue.outputs.sha256")
                _nonnegative_number(
                    output["duration_seconds"], "posix_mqueue.outputs.duration_seconds"
                )
            cleanup = queue.get("cleanup")
            cleanup_keys = {
                "first_container_removed",
                "first_private_tmpfs_released",
                "second_container_removed",
                "second_private_tmpfs_released",
                "persistent_shared_queue",
            }
            if (
                not isinstance(cleanup, dict)
                or cleanup.keys() != cleanup_keys
                or any(not isinstance(value, bool) for value in cleanup.values())
            ):
                raise CompatibilityEvidenceError("invalid POSIX queue cleanup")
            if cleanup != {
                "first_container_removed": True,
                "first_private_tmpfs_released": True,
                "second_container_removed": True,
                "second_private_tmpfs_released": True,
                "persistent_shared_queue": False,
            }:
                raise CompatibilityEvidenceError("contradictory POSIX queue cleanup")
            queue_by_case = {session["case"]: session for session in queue_sessions}
            identities = [
                queue_by_case[case].get("session_identity")
                for case in ("mqueue-first", "mqueue-second")
            ]
            distinct_identities = (
                all(isinstance(identity, str) and identity for identity in identities)
                and identities[0] != identities[1]
            )
            separation_claim = queue["session_separation"]["distinct_session_identities"]
            if separation_claim is not distinct_identities:
                raise CompatibilityEvidenceError("contradictory POSIX queue session identities")
            for output, case in zip(outputs, ("mqueue-first", "mqueue-second"), strict=True):
                session = queue_by_case[case]
                execution = session["execution"]
                if (
                    output["session_identity"] != session["session_identity"]
                    or output["bytes"] != execution["stdout_bytes"]
                    or output["sha256"] != execution["stdout_sha256"]
                    or output["duration_seconds"] != execution["duration_seconds"]
                ):
                    raise CompatibilityEvidenceError("contradictory POSIX queue output identity")
        elif queue.get("outputs") is not None or queue.get("cleanup") is not None:
            raise CompatibilityEvidenceError("contradictory failed POSIX queue summary")
        queue_description = queue.get("queue")
        if queue_description is not None:
            if not isinstance(queue_description, dict) or queue_description.keys() != {
                "name",
                "attributes",
                "payload_bytes",
                "payload_sha256",
                "priority",
            }:
                raise CompatibilityEvidenceError("invalid POSIX queue description")
            if not isinstance(queue_description["name"], str) or not isinstance(
                queue_description["attributes"], dict
            ):
                raise CompatibilityEvidenceError("invalid POSIX queue identity or attributes")
            attributes = queue_description["attributes"]
            attribute_keys = {
                "max_messages",
                "max_message_bytes",
                "current_messages",
                "open_flags",
                "mode",
            }
            if (
                attributes.keys() != attribute_keys
                or any(
                    not isinstance(attributes[key], int)
                    or isinstance(attributes[key], bool)
                    or attributes[key] < 0
                    for key in ("max_messages", "max_message_bytes", "current_messages")
                )
                or not isinstance(attributes["open_flags"], list)
                or any(not isinstance(flag, str) for flag in attributes["open_flags"])
                or not isinstance(attributes["mode"], str)
            ):
                raise CompatibilityEvidenceError("invalid POSIX queue attributes")
            if (
                not isinstance(queue_description["payload_bytes"], int)
                or isinstance(queue_description["payload_bytes"], bool)
                or queue_description["payload_bytes"] < 0
            ):
                raise CompatibilityEvidenceError("invalid POSIX queue payload length")
            if (
                not isinstance(queue_description["priority"], int)
                or isinstance(queue_description["priority"], bool)
                or queue_description["priority"] < 0
            ):
                raise CompatibilityEvidenceError("invalid POSIX queue priority")
            _digest(queue_description["payload_sha256"], "queue.payload_sha256")
        artifacts["mqueue-guest-source"] = queue_identity["queue_guest_source_sha256"]
        artifacts["mqueue-payload"] = _digest(
            queue_description.get("payload_sha256") if queue_description else None,
            "queue.payload_sha256",
        )
    if ipc_handoff_result is not None:
        artifacts["ipc-handoff-guest"] = ipc_handoff_result["identities"]["guest-elf"]
        artifacts["ipc-handoff-guest-source"] = ipc_handoff_result["identities"]["guest-source"]
    if ipc_supervision_result is not None:
        artifacts["ipc-supervision-guest"] = ipc_supervision_result["identities"]["guest-elf"]
        artifacts["ipc-supervision-guest-source"] = ipc_supervision_result["identities"][
            "guest-source"
        ]

    all_session_results = {
        case: ("quarantined" if "quarantined" in results else "passed")
        for case, results in parsed_sessions.items()
    }
    if "posix_mqueue" in receipt and isinstance(receipt["posix_mqueue"], dict):
        queue_sessions = receipt["posix_mqueue"].get("sessions", [])
        if isinstance(queue_sessions, list):
            for session in queue_sessions:
                if isinstance(session, dict) and session.get("case") in {
                    "mqueue-first",
                    "mqueue-second",
                }:
                    all_session_results[session["case"]] = session.get("status")
    if ipc_handoff_result is not None:
        all_session_results["ipc-handoff"] = (
            "passed" if ipc_handoff_result["status"] == "PASS" else "quarantined"
        )
    if ipc_supervision_result is not None:
        all_session_results["ipc-supervision"] = (
            "passed" if ipc_supervision_result["status"] == "PASS" else "quarantined"
        )
    if status == "failed" and not any(
        result == "quarantined" for result in all_session_results.values()
    ):
        raise CompatibilityEvidenceError("failed receipt has no failed or quarantined scenario")
    scenarios = {
        scenario: {
            "status": (
                "PASS"
                if all_session_results.get(case) == "passed"
                else "BLOCKED"
                if all_session_results.get(case) == "quarantined"
                else "NOT RUN"
            ),
            "evidence": "synthetic runtime receipt" if case in all_session_results else None,
        }
        for case, scenario in _CASES.items()
    }
    scenarios["stock-v257-boot"] = {"status": "NOT RUN", "evidence": None}
    scenarios["stock-ipc-compatibility"] = {"status": "NOT RUN", "evidence": None}
    scenarios["arbitrary-user-binary-isolation"] = {
        "status": "UNSUPPORTED" if "arbitrary binary isolation" in unverified else "NOT RUN",
        "evidence": "explicit runtime limitation"
        if "arbitrary binary isolation" in unverified
        else None,
    }
    if status == "failed":
        failure = receipt.get("failure")
        category = failure.get("category") if isinstance(failure, dict) else None
        failed_sessions = (
            receipt.get("posix_mqueue", {}).get("sessions", [])
            if category in {"queue-syscall", "queue-timeout"}
            else receipt.get("sessions", [])
        )
        failed_case = next(
            (
                session.get("case")
                for session in reversed(failed_sessions)
                if isinstance(session, dict) and session.get("status") == "quarantined"
            ),
            None,
        )
        if (
            category in {"queue-syscall", "queue-timeout"}
            and isinstance(failed_case, str)
            and failed_case.startswith("mqueue-")
        ):
            scenario = _CASES.get(failed_case)
            if scenario:
                scenarios[scenario] = {
                    "status": "FAIL",
                    "evidence": "sanitized fixed-probe failure category",
                }
        elif category == "fixed-probe-or-container-check-failed":
            scenario = _CASES.get(failed_case)
            if scenario:
                scenarios[scenario] = {
                    "status": "FAIL",
                    "evidence": "sanitized fixed-probe failure category",
                }
    if ipc_handoff_result is not None:
        scenarios["synthetic-ipc-handoff"] = {
            "status": ipc_handoff_result["status"],
            "evidence": ("receipt-declared handoff evidence; artifact provenance is unverified"),
        }
    if ipc_supervision_result is not None:
        scenarios["synthetic-ipc-supervision"] = {
            "status": ipc_supervision_result["status"],
            "evidence": (
                "receipt-declared supervision evidence; artifact provenance is unverified"
            ),
        }
    else:
        scenarios["synthetic-ipc-supervision"] = {"status": "NOT RUN", "evidence": None}
    return {
        "source": source,
        "receipt_schema": _SCHEMA,
        "receipt_status": status,
        "execution_scope": "firmware-free synthetic execution",
        "support_status": "unknown",
        "artifacts": artifacts,
        "evidence_authentication": {
            "receipt_values": "declared",
            "independent_authentication": "not performed",
            "artifact_bytes_rehashed": False,
        },
        "synthetic_ipc_handoff": ipc_handoff_result,
        "synthetic_ipc_supervision": ipc_supervision_result,
        "guest_source_sha256": guest_source,
        "queue_guest_source_sha256": artifacts["mqueue-guest-source"],
        "synthetic_input_sha256": synthetic_input,
        "scenarios": scenarios,
        "limitations": [
            "Synthetic execution does not establish stock firmware compatibility.",
            "No firmware authenticity, hardware behavior, or UI compatibility is inferred.",
        ],
    }


def render_json(reports: list[dict[str, Any]]) -> str:
    """Render report data as stable JSON with a trailing newline."""
    return json.dumps(reports, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _markdown_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "<", ">", "|"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def render_markdown(reports: list[dict[str, Any]]) -> str:
    """Render report data as stable Markdown."""
    lines = ["# Compatibility evidence", ""]
    for report in reports:
        lines.extend(
            [
                f"## Source: {_markdown_text(report['source'])}",
                "",
                f"- Receipt: `{report['receipt_schema']}` ({report['receipt_status']})",
                f"- Execution scope: {report['execution_scope']}",
                f"- Support status: `{report['support_status']}`",
                "- Receipt values: declared; independently authenticated: no",
                "",
                "| Scenario | Result |",
                "| --- | --- |",
            ]
        )
        for scenario, result in report["scenarios"].items():
            lines.append(f"| {scenario} | {result['status']} |")
        lines.extend(["", "Artifact identities:", ""])
        for name, digest in sorted(report["artifacts"].items()):
            lines.append(f"- `{name}`: `{digest}`")
        if "build_source" in report:
            lines.extend(["", "QEMU source identity:", ""])
            for name, value in report["build_source"].items():
                rendered = (
                    json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    if isinstance(value, (dict, list))
                    else str(value)
                )
                lines.append(f"- `{name}`: `{_markdown_text(rendered)}`")
        lines.extend(["", "Limitations:", ""])
        lines.extend(f"- {item}" for item in report["limitations"])
        lines.append("")
    return "\n".join(lines)
