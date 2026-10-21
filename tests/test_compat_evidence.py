"""Strict, deterministic parsing for sanitized synthetic runtime receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app
from snowsky_disc_lab.compat_evidence import (
    CompatibilityEvidenceError,
    parse_receipt,
    render_json,
    render_markdown,
)

runner = CliRunner()


def _isolation() -> dict[str, Any]:
    return {
        "mounts": [
            {"source": "<verified-execution-inputs>", "target": "/inputs", "read_only": True},
            {"source": "<owned-synthetic-input>", "target": "/synthetic-rootfs", "read_only": True},
        ],
        "private_writable_tmpfs": {
            path: "rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=65534,gid=65534"
            for path in ("/session-data", "/session-tmp", "/session-diagnostics")
        },
        "verified_host_config": {
            "NetworkMode": "none",
            "CapDrop": ["ALL"],
            "ReadonlyRootfs": True,
            "Privileged": False,
            "Memory": 256 * 1024**2,
            "MemorySwap": 256 * 1024**2,
            "NanoCpus": 1_000_000_000,
            "PidsLimit": 16,
            "IpcMode": "none",
            "Tmpfs": {
                path: "rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=65534,gid=65534"
                for path in ("/session-data", "/session-tmp", "/session-diagnostics")
            },
        },
        "all_capabilities_dropped": True,
        "no_new_privileges": True,
        "uid_gid": "65534:65534",
        "host_devices": False,
        "docker_socket": False,
        "host_home": False,
        "shared_source_cache": False,
        "guest_deadline_seconds": 5,
        "timeout_probe_seconds": 2,
        "term_to_kill_grace_seconds": 1,
        "outer_deadline_seconds": 15,
        "stdout_limit_bytes": 1024,
        "diagnostic_file_limit_bytes": 65536,
        "kernel_boundary": "Docker-managed kernel interfaces; QEMU user mode shares host kernel",
    }


def _receipt() -> dict[str, Any]:
    return {
        "schema_version": "firmware-free-synthetic-runtime-acceptance/v1",
        "status": "passed",
        "identities": {
            "qemu-mipsel": "a" * 64,
            "mips32le-execution-smoke.elf": "b" * 64,
            "mips32le-posix-mqueue.elf": "c" * 64,
        },
        "guest_source_sha256": "d" * 64,
        "synthetic_input_sha256": "e" * 64,
        "isolation": _isolation(),
        "host_refusals": ["unsafe traversal"],
        "session_isolation": "independent synthetic sessions",
        "sessions": [
            {
                "session_id": str(index),
                "session_identity": f"session-{index}",
                "case": case,
                "status": "passed",
                "lifecycle": [
                    "reserved",
                    "created",
                    "validated",
                    "start-requested",
                    "exited",
                    "removed",
                ],
                "execution": {
                    "exit_code": {"failure": 23, "timeout": 124}.get(case, 0),
                    "duration_seconds": 0.1,
                    "stdout_sha256": str(index) * 64,
                    "stdout_bytes": 20,
                    "timed_out": case == "timeout",
                    "terminated": True,
                    **(
                        {
                            "observations": {
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
                        }
                        if not case.startswith("mqueue-")
                        else {}
                    ),
                    **({"queue_syscall_error": None} if case.startswith("mqueue-") else {}),
                },
                "cleanup": {
                    "container_removed": True,
                    "private_tmpfs_released": True,
                    "host_metadata": "retained; no recursive cleanup",
                },
            }
            for index, case in enumerate(("filesystem", "filesystem", "failure", "timeout"), 1)
        ],
        "posix_mqueue": {
            "schema_version": "firmware-free-mips32le-posix-mqueue-acceptance/v1",
            "status": "passed",
            "scope": "first-party synthetic POSIX message queue syscall acceptance",
            "queue": {
                "name": "/snowsky_disc_lab_mqueue_probe_v1",
                "attributes": {
                    "max_messages": 2,
                    "max_message_bytes": 64,
                    "current_messages": 0,
                    "open_flags": ["O_CREAT", "O_EXCL", "O_NONBLOCK", "O_RDWR"],
                    "mode": "0600",
                },
                "payload_bytes": 28,
                "payload_sha256": (
                    "b8e0b0e98d2906e4b1d5cdaf72e10f44468760938a4c004c85fcbb7a4160e206"
                ),
                "priority": 7,
            },
            "identities": {
                "qemu_mipsel_sha256": "a" * 64,
                "queue_guest_source_sha256": "f" * 64,
                "queue_guest_elf_sha256": "c" * 64,
            },
            "sessions": [
                {
                    "session_id": f"mqueue-{index}",
                    "session_identity": f"queue-session-{index}",
                    "case": f"mqueue-{label}",
                    "status": "passed",
                    "lifecycle": [
                        "reserved",
                        "created",
                        "validated",
                        "start-requested",
                        "exited",
                        "removed",
                    ],
                    "execution": {
                        "exit_code": 0,
                        "duration_seconds": 0.1,
                        "stdout_sha256": str(index) * 64,
                        "stdout_bytes": 20,
                        "timed_out": False,
                        "terminated": True,
                        "queue_syscall_error": None,
                    },
                    "isolation": _isolation(),
                    "cleanup": {
                        "container_removed": True,
                        "private_tmpfs_released": True,
                        "host_metadata": "retained; no recursive cleanup",
                    },
                }
                for index, label in ((1, "first"), (2, "second"))
            ],
            "observed_syscalls": {
                "first_session": {
                    "mq_open_exclusive_create": "success",
                    "mq_getattr": {
                        "max_messages": 2,
                        "max_message_bytes": 64,
                        "current_messages": 0,
                        "nonblocking": True,
                    },
                    "mq_timedreceive_empty_queue": {
                        "result": -1,
                        "errno": "EAGAIN",
                        "errno_number": 11,
                    },
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
                        "payload_bytes": 28,
                        "payload_sha256": (
                            "b8e0b0e98d2906e4b1d5cdaf72e10f44468760938a4c004c85fcbb7a4160e206"
                        ),
                        "priority": 7,
                    },
                    "mq_close": "success",
                    "mq_unlink": "success",
                    "mq_open_after_unlink": {"result": -1, "errno": "ENOENT", "errno_number": 2},
                    "mq_open_recreate": "success",
                    "retained_queue_linked_until_exit": True,
                    "retained_queue_empty_receive": {
                        "result": -1,
                        "errno": "EAGAIN",
                        "errno_number": 11,
                    },
                    "qemu_strace_syscalls": [
                        "mq_open",
                        "mq_getsetattr",
                        "mq_timedsend",
                        "mq_timedreceive",
                        "mq_unlink",
                        "close",
                    ],
                },
                "second_session": {
                    "mq_open_exclusive_create": "success",
                    "mq_getattr": {
                        "max_messages": 2,
                        "max_message_bytes": 64,
                        "current_messages": 0,
                        "nonblocking": True,
                    },
                    "mq_timedreceive_empty_queue": {
                        "result": -1,
                        "errno": "EAGAIN",
                        "errno_number": 11,
                    },
                    "fstat_mode": "0600",
                    "mq_close": "success",
                    "mq_unlink": "success",
                    "mq_open_after_unlink": {"result": -1, "errno": "ENOENT", "errno_number": 2},
                    "qemu_strace_syscalls": [
                        "mq_open",
                        "mq_getsetattr",
                        "mq_timedreceive",
                        "mq_unlink",
                        "close",
                    ],
                },
            },
            "session_separation": {
                "first_container_removed_before_second_create": True,
                "distinct_session_identities": True,
                "second_session_same_name_o_excl_create": "success",
            },
            "isolation": {
                "container_profiles": [_isolation(), _isolation()],
                "mqueue_filesystem_mount_added": False,
            },
            "stock_compatibility": {
                "stock_v257_queue_attributes": "DOCUMENTED_ONLY_UNVERIFIED",
                "stock_ipc_compatibility": "UNVERIFIED",
                "m1_04_stock_boot": "NOT RUN",
            },
            "outputs": [
                {
                    "session_identity": f"queue-session-{index}",
                    "bytes": 20,
                    "sha256": str(index) * 64,
                    "duration_seconds": 0.1,
                }
                for index in (1, 2)
            ],
            "cleanup": {
                "first_container_removed": True,
                "first_private_tmpfs_released": True,
                "second_container_removed": True,
                "second_private_tmpfs_released": True,
                "persistent_shared_queue": False,
            },
        },
        "unsupported_or_unverified": [
            "M1-04 stock V2.57 boot",
            "audio/framebuffer/UI/hardware",
            "arbitrary binary isolation",
        ],
    }


def _qemu_receipt(*, repeat_status: str = "not-run", firmware_processed: bool = False):
    summary_status = {
        "identical": "firmware-free-build-passed-repeat-identical",
        "different": "firmware-free-build-passed-repeat-different",
        "attempted-failed": "firmware-free-build-passed-repeat-failed",
        "not-run": "firmware-free-build-passed-repeat-not-run",
    }[repeat_status]
    digest = "5" * 64
    build: dict[str, Any] = {
        "qemu_version": "7.2.22",
        "qemu_descriptor_sha256": digest,
        "qemu_archives": [],
        "qemu_patch_sha256": digest,
        "qemu_configure_flags": [],
        "shim_recipe_sha256": digest,
        "shim_source_sha256": {"shim.c": digest},
        "artifact_sha256_and_elf": [],
        "debian_snapshot_inrelease": {},
        "debian_archive_keyring_sha256": digest,
        "installed_package_bom_sha256": digest,
        "installed_package_count": 0,
        "installed_packages": [],
        "toolchain": {},
        "container_limits": {},
        "build_logs": {},
        "elapsed_seconds": 1.0,
        "temporary_container_cleanup": "verified",
        "repeated_clean_build_comparison": {"status": repeat_status},
    }
    if repeat_status in {"identical", "different"}:
        repeated: dict[str, Any] = build["repeated_clean_build_comparison"]
        repeated["compared"] = ["artifact hashes"]
        repeated["differences"] = []
        repeated["second_artifact_sha256"] = {}
        repeated["second_package_bom_sha256"] = digest
        repeated["second_sysroot_sha256"] = digest
    return {
        "schema_version": "firmware-free-qemu-runtime-build/v1",
        "status": summary_status,
        "primary_build_status": "passed",
        "repeat_build_status": repeat_status,
        "host_resources_before_build": {},
        "host_resources_before_optional_repeat": None,
        "source_identity": {
            "repository": "https://github.com/eudj1n/snowsky-disc-qemu.git",
            "commit": "1" * 40,
            "projection_digest": "2" * 64,
            "source_lock_changed": False,
            "firmware_tree_fetched": False,
            "reviewed_file_sha256": {"source.c": "3" * 64},
            "reviewed_file_bytes": {"source.c": 1},
            "build_input_manifest_sha256": "4" * 64,
        },
        "base_image": {},
        "qemu_source_review": {},
        "license_review": {},
        "build": build,
        "network_boundary": "fixed reviewed dependencies",
        "apt_sandbox": "fixed reviewed sandbox",
        "runtime_and_device_boundaries": {
            "firmware_processed": firmware_processed,
            "qemu_executable_invoked": True,
            "synthetic_guest_executed": True,
            "guest_booted": False,
            "binfmt_registered": False,
            "runtime_image_built": False,
            "container_image_published": False,
            "compiled_binary_published": False,
            "usb_or_hardware_accessed": False,
            "compatibility_claimed": False,
        },
        "synthetic_runtime": _receipt(),
        "elapsed_seconds": 1.0,
    }


def test_parse_receipt_preserves_identity_and_does_not_promote_stock_compatibility() -> None:
    receipt = _receipt()
    assert [session["case"] for session in receipt["sessions"]] == [
        "filesystem",
        "filesystem",
        "failure",
        "timeout",
    ]
    assert [session["case"] for session in receipt["posix_mqueue"]["sessions"]] == [
        "mqueue-first",
        "mqueue-second",
    ]
    report = parse_receipt(json.dumps(receipt), source="local/receipt.json")

    assert report["source"] == "local/receipt.json"
    assert report["receipt_schema"] == "firmware-free-synthetic-runtime-acceptance/v1"
    assert report["artifacts"]["qemu-mipsel"] == "a" * 64
    assert report["artifacts"]["mqueue-guest-source"] == "f" * 64
    assert report["artifacts"]["mqueue-payload"] == (
        "b8e0b0e98d2906e4b1d5cdaf72e10f44468760938a4c004c85fcbb7a4160e206"
    )
    assert report["execution_scope"] == "firmware-free synthetic execution"
    assert report["support_status"] == "unknown"
    assert report["scenarios"]["synthetic-filesystem"]["status"] == "PASS"
    assert report["scenarios"]["synthetic-expected-failure"]["status"] == "PASS"
    assert report["scenarios"]["synthetic-timeout"]["status"] == "PASS"
    assert report["scenarios"]["synthetic-mqueue-first-session"]["status"] == "PASS"
    assert report["scenarios"]["synthetic-mqueue-second-session"]["status"] == "PASS"
    assert report["scenarios"]["stock-v257-boot"]["status"] == "NOT RUN"
    assert report["scenarios"]["stock-ipc-compatibility"]["status"] == "NOT RUN"
    assert report["scenarios"]["arbitrary-user-binary-isolation"]["status"] == "UNSUPPORTED"


def test_reports_are_deterministic() -> None:
    report = parse_receipt(json.dumps(_receipt()), source="receipt.json")

    assert render_json([report]) == render_json([report])
    assert render_markdown([report]) == render_markdown([report])
    assert "firmware-free synthetic execution" in render_markdown([report])


def test_qemu_envelope_preserves_upstream_commit_and_projection_identity() -> None:
    receipt = _qemu_receipt(repeat_status="not-run")

    report = parse_receipt(json.dumps(receipt), source="qemu-summary.json")

    assert report["build_source"] == receipt["source_identity"]
    assert "1" * 40 in render_markdown([report])
    assert "build_input_manifest_sha256" in render_markdown([report])
    assert report["repeat_build_status"] == "not-run"


def test_rejects_contradictory_qemu_repeat_build_status() -> None:
    receipt = _qemu_receipt(repeat_status="identical")
    receipt["status"] = "firmware-free-build-passed-repeat-not-run"

    with pytest.raises(CompatibilityEvidenceError, match="repeat-build"):
        parse_receipt(json.dumps(receipt), source="inconsistent-build.json")


def test_rejects_qemu_receipt_that_claims_firmware_execution() -> None:
    receipt = _qemu_receipt(firmware_processed=True)

    with pytest.raises(CompatibilityEvidenceError, match="firmware boundary"):
        parse_receipt(json.dumps(receipt), source="unsafe-build.json")


def test_rejects_malformed_qemu_optional_source_identity_fields() -> None:
    receipt = _qemu_receipt()
    receipt["source_identity"]["reviewed_file_bytes"]["source.c"] = True

    with pytest.raises(CompatibilityEvidenceError, match="source identity"):
        parse_receipt(json.dumps(receipt), source="malformed-source-identity.json")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt["posix_mqueue"]["sessions"][0]["isolation"].update(
            all_capabilities_dropped=False
        ),
        lambda receipt: receipt["posix_mqueue"]["sessions"][0]["isolation"].update(
            no_new_privileges=False
        ),
        lambda receipt: receipt["posix_mqueue"]["sessions"][0]["isolation"].update(
            host_devices=True
        ),
        lambda receipt: receipt["posix_mqueue"]["sessions"][0]["isolation"][
            "verified_host_config"
        ].update(Privileged=True),
        lambda receipt: receipt["posix_mqueue"]["sessions"][0]["isolation"]["mounts"][0].update(
            read_only=False
        ),
    ],
)
def test_rejects_receipt_with_unsafe_isolation_evidence(mutate) -> None:
    receipt = _receipt()
    mutate(receipt)

    with pytest.raises(CompatibilityEvidenceError, match="isolation|host configuration"):
        parse_receipt(json.dumps(receipt), source="unsafe-isolation.json")


def test_rejects_unsafe_top_level_isolation_profile() -> None:
    receipt = _receipt()
    receipt["isolation"]["host_devices"] = True

    with pytest.raises(CompatibilityEvidenceError, match="unsafe runtime isolation"):
        parse_receipt(json.dumps(receipt), source="unsafe-top-level-isolation.json")


@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_compat_report_cli_emits_local_report(tmp_path: Path, output_format: str) -> None:
    source = tmp_path / "synthetic-receipt.json"
    source.write_text(json.dumps(_receipt()), encoding="utf-8")

    result = runner.invoke(app, ["compat", "report", str(source), "--format", output_format])

    assert result.exit_code == 0, result.output
    assert "firmware-free synthetic execution" in result.stdout


def test_compat_report_cli_refuses_bad_receipt_without_traceback(tmp_path: Path) -> None:
    source = tmp_path / "bad.json"
    source.write_text('{"schema_version":"unknown"}', encoding="utf-8")

    result = runner.invoke(app, ["compat", "report", str(source)])

    assert result.exit_code == 2
    assert "Compatibility report refused" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt.update(extra="unknown"),
        lambda receipt: receipt["posix_mqueue"].update(status="failed"),
        lambda receipt: receipt["posix_mqueue"].update(unreviewed="value"),
        lambda receipt: receipt.update(status=[]),
        lambda receipt: receipt["sessions"][0].update(case=[]),
        lambda receipt: receipt.update(schema_version="vendor-runtime/v9"),
        lambda receipt: receipt["identities"].update({"qemu-mipsel": "not-a-digest"}),
    ],
)
def test_rejects_unknown_or_malformed_receipt_fields(mutate) -> None:
    receipt = _receipt()
    mutate(receipt)

    with pytest.raises(CompatibilityEvidenceError):
        parse_receipt(json.dumps(receipt), source="bad.json")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt["sessions"][0].update(lifecycle="exited"),
        lambda receipt: receipt["sessions"][0]["execution"].update(stdout_sha256="bad"),
        lambda receipt: receipt["posix_mqueue"]["outputs"][0].update(bytes=True),
        lambda receipt: receipt["posix_mqueue"]["observed_syscalls"]["first_session"].update(
            mq_getattr=[]
        ),
        lambda receipt: receipt["posix_mqueue"]["session_separation"].update(
            distinct_session_identities="yes"
        ),
    ],
)
def test_rejects_malformed_known_nested_values(mutate) -> None:
    receipt = _receipt()
    mutate(receipt)

    with pytest.raises(CompatibilityEvidenceError):
        parse_receipt(json.dumps(receipt), source="bad-nested.json")


def test_rejects_duplicate_json_keys() -> None:
    document = json.dumps(_receipt())[:-1] + ',"status":"failed"}'

    with pytest.raises(CompatibilityEvidenceError, match="duplicate"):
        parse_receipt(document, source="duplicate.json")


@pytest.mark.parametrize("document", ["\ud800", '{"value":' + "9" * 5000 + "}"])
def test_rejects_decoder_value_errors_without_leaking_them(document: str) -> None:
    with pytest.raises(CompatibilityEvidenceError):
        parse_receipt(document, source="malformed.json")


def test_rejects_contradictory_scenario_and_parent_status() -> None:
    receipt = _receipt()
    receipt["sessions"][0]["status"] = "quarantined"

    with pytest.raises(CompatibilityEvidenceError, match="contradict"):
        parse_receipt(json.dumps(receipt), source="contradictory.json")


def test_rejects_failed_receipt_without_a_failed_scenario() -> None:
    receipt = _receipt()
    receipt["status"] = "failed"
    receipt["failure"] = {"category": "fixed-probe-or-container-check-failed"}

    with pytest.raises(CompatibilityEvidenceError, match="no failed or quarantined"):
        parse_receipt(json.dumps(receipt), source="empty-failure.json")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt["posix_mqueue"]["observed_syscalls"]["first_session"].update(
            mq_open_exclusive_create="failed"
        ),
        lambda receipt: receipt["posix_mqueue"]["observed_syscalls"]["first_session"][
            "mq_timedreceive"
        ].update(payload_matches=False),
        lambda receipt: receipt["posix_mqueue"]["observed_syscalls"]["second_session"][
            "mq_timedreceive_empty_queue"
        ].update(errno="EINVAL"),
    ],
)
def test_rejects_contradictory_successful_queue_observation(mutate) -> None:
    receipt = _receipt()
    mutate(receipt)

    with pytest.raises(CompatibilityEvidenceError, match="contradictory successful POSIX queue"):
        parse_receipt(json.dumps(receipt), source="contradictory-queue.json")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt["posix_mqueue"]["cleanup"].update(first_container_removed=False),
        lambda receipt: receipt["posix_mqueue"]["cleanup"].update(persistent_shared_queue=True),
        lambda receipt: receipt["posix_mqueue"]["outputs"][0].update(bytes=19),
        lambda receipt: receipt["posix_mqueue"]["outputs"][1].update(
            session_identity="queue-session-1"
        ),
        lambda receipt: receipt["posix_mqueue"]["sessions"][1].update(
            session_identity="queue-session-1"
        ),
    ],
)
def test_rejects_contradictory_queue_cleanup_output_or_session_identity(mutate) -> None:
    receipt = _receipt()
    mutate(receipt)

    with pytest.raises(CompatibilityEvidenceError):
        parse_receipt(json.dumps(receipt), source="contradictory-queue-summary.json")


@pytest.mark.parametrize(
    "case,mutate",
    [
        ("filesystem", lambda execution: execution.update(exit_code=1)),
        ("failure", lambda execution: execution.update(exit_code=0)),
        ("timeout", lambda execution: execution.update(timed_out=False)),
        ("filesystem", lambda execution: execution["observations"].update(outside_write_errno=0)),
        ("timeout", lambda execution: execution.update(terminated=False)),
    ],
)
def test_rejects_passed_session_execution_that_disagrees_with_case(case, mutate) -> None:
    receipt = _receipt()
    session = next(item for item in receipt["sessions"] if item["case"] == case)
    mutate(session["execution"])

    with pytest.raises(CompatibilityEvidenceError, match="contradicts named case"):
        parse_receipt(json.dumps(receipt), source="contradictory-case.json")


def test_rejects_queue_session_execution_inconsistent_with_successful_observations() -> None:
    receipt = _receipt()
    receipt["posix_mqueue"]["sessions"][0]["execution"].update(exit_code=124, timed_out=True)

    with pytest.raises(CompatibilityEvidenceError, match="contradicts named case"):
        parse_receipt(json.dumps(receipt), source="contradictory-queue-session.json")


def test_known_non_queue_fixed_probe_failure_marks_its_scenario_fail() -> None:
    receipt = _receipt()
    receipt["status"] = "failed"
    receipt["failure"] = {"category": "fixed-probe-or-container-check-failed"}
    receipt["sessions"][0]["status"] = "quarantined"

    report = parse_receipt(json.dumps(receipt), source="failed-filesystem-probe.json")

    assert report["scenarios"]["synthetic-filesystem"]["status"] == "FAIL"


def test_known_queue_syscall_failure_is_reported_as_fail() -> None:
    receipt = _receipt()
    receipt["status"] = "failed"
    receipt["failure"] = {"category": "queue-timeout"}
    receipt["posix_mqueue"]["status"] = "failed"
    receipt["posix_mqueue"]["sessions"][-1]["status"] = "quarantined"
    receipt["posix_mqueue"]["failure"] = {"category": "queue-timeout"}
    receipt["posix_mqueue"].pop("outputs")
    receipt["posix_mqueue"].pop("cleanup")
    receipt["posix_mqueue"]["observed_syscalls"] = {"complete_observation": False}
    receipt["posix_mqueue"]["sessions"][-1]["execution"]["queue_syscall_error"] = {
        "stage": "guest_deadline",
        "errno": "NONE",
        "errno_number": 0,
    }

    report = parse_receipt(json.dumps(receipt), source="failed-queue.json")

    assert report["scenarios"]["synthetic-mqueue-second-session"]["status"] == "FAIL"
