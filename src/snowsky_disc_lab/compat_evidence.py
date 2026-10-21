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
}
_FAILURE_CATEGORIES = {
    "queue-syscall",
    "queue-timeout",
    "fixed-probe-or-container-check-failed",
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
        if not isinstance(cleanup, dict) or cleanup.keys() - {
            "container_removed",
            "private_tmpfs_released",
            "host_metadata",
        }:
            raise CompatibilityEvidenceError("invalid session cleanup")
        if "container_removed" in cleanup and not isinstance(cleanup["container_removed"], bool):
            raise CompatibilityEvidenceError("invalid container cleanup status")
        if "private_tmpfs_released" in cleanup and not isinstance(
            cleanup["private_tmpfs_released"], bool
        ):
            raise CompatibilityEvidenceError("invalid tmpfs cleanup status")
        if "host_metadata" in cleanup and not isinstance(cleanup["host_metadata"], str):
            raise CompatibilityEvidenceError("invalid retained host metadata")
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
            not isinstance(build["qemu_archives"], list)
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
        for field in (
            "qemu_archives",
            "qemu_configure_flags",
            "artifact_sha256_and_elf",
            "installed_packages",
        ):
            if not isinstance(build[field], list):
                raise CompatibilityEvidenceError(f"invalid QEMU build array: {field}")
        if not isinstance(build["shim_source_sha256"], dict) or any(
            not isinstance(key, str) for key in build["shim_source_sha256"]
        ):
            raise CompatibilityEvidenceError("invalid shim source map")
        for field in ("debian_snapshot_inrelease", "toolchain", "container_limits", "build_logs"):
            if not isinstance(build[field], dict):
                raise CompatibilityEvidenceError(f"invalid QEMU build map: {field}")
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
            or not _SHA256.fullmatch(projection)
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
    if set(identities) != {
        "qemu-mipsel",
        "mips32le-execution-smoke.elf",
        "mips32le-posix-mqueue.elf",
    }:
        raise CompatibilityEvidenceError("unknown or incomplete artifact identities")
    artifacts = {name: _digest(value, name) for name, value in identities.items()}
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
    return {
        "source": source,
        "receipt_schema": _SCHEMA,
        "receipt_status": status,
        "execution_scope": "firmware-free synthetic execution",
        "support_status": "unknown",
        "artifacts": artifacts,
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
